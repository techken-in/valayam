use crate::plugin_rpc::plugin_service_client::PluginServiceClient;
use crate::plugin_rpc::{ExecuteRequest, InitRequest, ShutdownRequest};
use crate::traits::{FindingOwned, PluginOutcome, ScanContext, ScanPlugin};
use rand::Rng;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tonic::transport::Channel;
use valayam_models::error::ScannerError;

/// Documentation for this item.
pub struct GrpcPluginBridge {
    name: String,
    exe_path: PathBuf,
    /// Shared tonic Channel (Arc internally — clone is cheap).
    channel: tokio::sync::RwLock<Option<Channel>>,
    child_process: tokio::sync::Mutex<Option<Child>>,
    supported_protocols: tokio::sync::RwLock<Vec<String>>,
    supported_template_ids: tokio::sync::RwLock<Vec<String>>,
    supported_tags: tokio::sync::RwLock<Vec<String>>,
}

impl GrpcPluginBridge {
    /// Documentation for this item.
    pub fn new(name: impl Into<String>, exe_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            exe_path,
            channel: tokio::sync::RwLock::new(None),
            child_process: tokio::sync::Mutex::new(None),
            supported_protocols: tokio::sync::RwLock::new(Vec::new()),
            supported_template_ids: tokio::sync::RwLock::new(Vec::new()),
            supported_tags: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl ScanPlugin for GrpcPluginBridge {
    fn name(&self) -> &str {
        &self.name
    }

    fn validate_config(
        &self,
        _template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    fn is_applicable(
        &self,
        template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> bool {
        // Attempt to read capabilities synchronously
        let Ok(protocols) = self.supported_protocols.try_read() else {
            return true;
        };
        let Ok(ids) = self.supported_template_ids.try_read() else {
            return true;
        };
        let Ok(tags) = self.supported_tags.try_read() else {
            return true;
        };

        // If capabilities haven't been populated yet (e.g. init still running), assume applicable
        if protocols.is_empty() && ids.is_empty() && tags.is_empty() {
            return true;
        }

        // Check template ID match
        if ids.contains(&template.id) {
            return true;
        }

        // Check protocol match
        if !template.requests.is_empty()
            && (protocols.contains(&"http".to_string()) || protocols.contains(&"https".to_string()))
        {
            return true;
        }
        if !template.network.is_empty()
            && (protocols.contains(&"tcp".to_string()) || protocols.contains(&"udp".to_string()))
        {
            return true;
        }
        if !template.grpc_audit.is_empty() && protocols.contains(&"grpc".to_string()) {
            return true;
        }

        // Tags are not currently implemented on TemplateInfo, skipping tag check

        false
    }

    async fn init(&self) -> Result<(), ScannerError> {
        let mut cmd;
        if let Some(ext) = self.exe_path.extension().and_then(|e| e.to_str()) {
            if ext == "py" {
                #[cfg(target_os = "windows")]
                {
                    cmd = Command::new("python");
                }
                #[cfg(not(target_os = "windows"))]
                {
                    cmd = Command::new("python3");
                }

                cmd.arg(&self.exe_path);
            } else if ext == "bat" || ext == "cmd" {
                cmd = Command::new("cmd");
                let exe_str = self.exe_path.to_str().ok_or_else(|| {
                    ScannerError::PluginInitializationError(format!(
                        "plugin path is not valid UTF-8: {:?}",
                        self.exe_path
                    ))
                })?;
                cmd.args(["/C", exe_str]);
            } else {
                cmd = Command::new(&self.exe_path);
            }
        } else {
            cmd = Command::new(&self.exe_path);
        }

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                ScannerError::PluginInitializationError(format!("Failed to spawn plugin: {}", e))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            ScannerError::PluginInitializationError(
                "failed to capture plugin stdout — stdio was not piped".into(),
            )
        })?;
        let mut reader = BufReader::new(stdout).lines();

        // Wait for the HashiCorp-style handshake line
        // Format: 1|plugin|tcp|127.0.0.1:<PORT>|grpc
        let mut port = None;
        while let Ok(Some(line)) = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
            .await
            .map_err(|_| {
                ScannerError::PluginInitializationError(
                    "Timeout waiting for plugin handshake".into(),
                )
            })?
        {
            if line.starts_with("1|") && line.contains("|grpc") {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 4 {
                    let addr = parts[3]; // 127.0.0.1:PORT
                    port = Some(addr.to_string());
                    break;
                }
            } else {
                tracing::debug!(plugin = %self.name, "stdout: {}", line);
            }
        }

        let addr = port.ok_or_else(|| {
            ScannerError::PluginInitializationError("Plugin failed to output gRPC port".into())
        })?;
        let endpoint = format!("http://{}", addr);

        // Step 3.3: Connect with retry + exponential backoff
        let channel = connect_with_retry(&endpoint).await?;

        // Verify plugin with Init RPC
        let mut client = PluginServiceClient::new(channel.clone());
        let res = client
            .init(InitRequest {
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .await
            .map_err(|e| {
                ScannerError::PluginInitializationError(format!("RPC Init failed: {}", e))
            })?;

        let response = res.into_inner();
        if !response.success {
            return Err(ScannerError::PluginInitializationError(format!(
                "Plugin rejected init: {}",
                response.error_message
            )));
        }

        // Store capabilities
        *self.supported_protocols.write().await = response.supported_protocols;
        *self.supported_template_ids.write().await = response.supported_template_ids;
        *self.supported_tags.write().await = response.supported_tags;

        // Store child process and shared channel
        *self.child_process.lock().await = Some(child);
        *self.channel.write().await = Some(channel);

        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let channel_guard = self.channel.read().await;
        let channel = match channel_guard.as_ref() {
            Some(c) => c.clone(), // cheap: Channel is Arc<Inner> internally
            None => {
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError("Plugin not initialized".into()),
                    retryable: true,
                };
            }
        };
        drop(channel_guard); // release lock early

        let mut client = PluginServiceClient::new(channel);

        let template_json = match serde_json::to_string(&*ctx.template) {
            Ok(j) => j,
            Err(_) => return PluginOutcome::NoMatch,
        };

        let vars = ctx.snapshot_variables().await;
        let context_json = serde_json::to_string(&vars).unwrap_or_default();

        let mut req = tonic::Request::new(ExecuteRequest {
            template_json,
            target: ctx.target.clone(),
            target_host: ctx.target_host.clone(),
            context_json,
        });

        // OpenTelemetry context propagation
        use opentelemetry::global;
        use opentelemetry::propagation::Injector;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        struct MetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);

        impl<'a> Injector for MetadataInjector<'a> {
            fn set(&mut self, key: &str, value: String) {
                if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes()) {
                    if let Ok(val) = tonic::metadata::MetadataValue::try_from(value) {
                        self.0.insert(key, val);
                    }
                }
            }
        }

        let context = tracing::Span::current().context();
        global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&context, &mut MetadataInjector(req.metadata_mut()));
        });

        let mut count = 0;
        match client.execute(req).await {
            Ok(response) => {
                let mut stream = response.into_inner();
                while let Ok(Some(resp)) = stream.message().await {
                    if let Ok(finding) = serde_json::from_str::<FindingOwned>(&resp.finding_json) {
                        let _ = ctx.finding_tx.send(finding).await;
                        count += 1;
                    }
                }
            }
            Err(e) => {
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("RPC execute failed: {}", e)),
                    retryable: false,
                };
            }
        }

        if count > 0 {
            PluginOutcome::Matched { count }
        } else {
            PluginOutcome::NoMatch
        }
    }

    async fn shutdown(&self) -> Result<(), ScannerError> {
        // Send shutdown RPC if we have a channel
        if let Some(channel) = self.channel.write().await.take() {
            let mut client = PluginServiceClient::new(channel);
            let _ = client.shutdown(ShutdownRequest {}).await;
        }

        // Kill child process
        let mut child_guard = self.child_process.lock().await;
        if let Some(mut child) = child_guard.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        Ok(())
    }
}

/// Connect to a gRPC endpoint with exponential backoff and jitter.
async fn connect_with_retry(endpoint: &str) -> Result<Channel, ScannerError> {
    let max_attempts = 3;
    let base_delay_ms = 500u64;

    for attempt in 0..max_attempts {
        match Channel::from_shared(endpoint.to_string()) {
            Ok(ch) => match ch.connect().await {
                Ok(connected) => return Ok(connected),
                Err(e) if attempt < max_attempts - 1 => {
                    let delay = base_delay_ms * 2u64.pow(attempt);
                    let jitter = rand::thread_rng().gen_range(0..100);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_attempts,
                        delay_ms = delay + jitter,
                        error = %e,
                        "gRPC connection failed, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay + jitter)).await;
                }
                Err(e) => {
                    return Err(ScannerError::PluginInitializationError(format!(
                        "Failed to connect to gRPC plugin after {} attempts: {}",
                        max_attempts, e
                    )));
                }
            },
            Err(e) => {
                return Err(ScannerError::PluginInitializationError(format!(
                    "Invalid gRPC endpoint '{}': {}",
                    endpoint, e
                )));
            }
        }
    }

    Err(ScannerError::PluginInitializationError(format!(
        "Failed to connect to gRPC plugin at '{}' after {} attempts",
        endpoint, max_attempts
    )))
}
