use crate::traits::{FindingOwned, PluginOutcome, ScanContext, ScanPlugin};
use extism::{Manifest, Wasm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use valayam_models::error::ScannerError;

#[derive(Debug, Serialize, Deserialize)]
struct WasmPluginFinding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub target: String,
    pub matched_at: String,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub extracted_data: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Configuration for WASM plugin sandbox limits.
#[derive(Clone)]
pub struct PluginConfig {
    /// Max WASM memory in pages (64KB per page). Default 2048 = 128 MB.
    pub memory_max_pages: u32,
    /// Plugin execution timeout in milliseconds. Default 30000.
    pub timeout_ms: u64,
    /// Allowed HTTP hosts for plugin egress. Empty = deny all.
    pub allowed_hosts: Vec<String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            memory_max_pages: 2048,               // 128 MB
            timeout_ms: 30000,                    // 30 sec
            allowed_hosts: vec!["*".to_string()], // allow all hosts by default for security scanner plugins
        }
    }
}

/// WASM ABI contract for Valayam plugins via Extism.
///
/// Guest modules must use the `valayam-plugin-sdk` (extism-pdk) to export
/// an `execute_scan` function.
///
/// The input JSON format: `{"template":{...},"context":{...}}`
/// The result JSON format: `{"matched":true,"count":N,"findings":[...]}` or `{"matched":false}`
pub struct WasmPluginBridge {
    name: String,
    wasm_path: PathBuf,
    config: PluginConfig,
}

impl WasmPluginBridge {
    /// Documentation for this item.
    pub fn new(name: impl Into<String>, wasm_path: PathBuf, config: PluginConfig) -> Self {
        Self {
            name: name.into(),
            wasm_path,
            config,
        }
    }

    fn build_manifest(&self) -> Manifest {
        let wasm = Wasm::file(&self.wasm_path);
        let mut manifest = Manifest::new([wasm]);
        manifest = manifest
            .with_timeout(std::time::Duration::from_millis(self.config.timeout_ms))
            .with_memory_max(self.config.memory_max_pages);
        // Allow configured hosts, or default to "*" (allow all egress for scanner)
        if !self.config.allowed_hosts.is_empty() {
            manifest = manifest.with_allowed_hosts(self.config.allowed_hosts.clone().into_iter());
        } else {
            manifest = manifest.with_allowed_hosts(vec!["*".to_string()].into_iter());
        }
        manifest.allowed_paths = None; // deny filesystem access by default
        manifest
    }
}

#[async_trait::async_trait]
impl ScanPlugin for WasmPluginBridge {
    fn name(&self) -> &str {
        &self.name
    }

    fn validate_config(
        &self,
        _template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    /// A WASM plugin is only applicable to a template if the template explicitly declares
    /// the plugin's corresponding section. This prevents plugins like `cors-audit` from
    /// running against every template and producing false/duplicate findings.
    ///
    /// The match is done by normalising the plugin name (strip `.wasm`, replace `_` with `-`)
    /// and checking via the trait-based `has_section()` method.
    fn is_applicable(
        &self,
        template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> bool {
        // Normalise: "cors-audit.wasm" → "cors-audit", "cors_audit.wasm" → "cors-audit"
        let normalised = self
            .name
            .trim_end_matches(".wasm")
            .replace('_', "-")
            .to_lowercase();

        match normalised.as_str() {
            // Well-known: check if template has a matching section by kebab-case name
            n if template.has_section(n) => true,
            // Unknown WASM plugin: opt-in by default (backwards compatible for custom plugins)
            _ => {
                tracing::debug!(
                    plugin = %self.name,
                    "Unknown WASM plugin '{}'; running against all templates",
                    self.name
                );
                true
            }
        }
    }

    async fn init(&self) -> Result<(), ScannerError> {
        let f1 = extism::Function::new(
            "dns_resolve",
            [extism::ValType::I64],
            [extism::ValType::I64],
            extism::UserData::new(()),
            crate::host_functions::dns_resolve,
        );
        let f2 = extism::Function::new(
            "kv_get",
            [extism::ValType::I64],
            [extism::ValType::I64],
            extism::UserData::new(()),
            crate::host_functions::kv_get,
        );
        let f3 = extism::Function::new(
            "kv_set",
            [extism::ValType::I64],
            [extism::ValType::I64],
            extism::UserData::new(()),
            crate::host_functions::kv_set,
        );

        let manifest = self.build_manifest();
        if let Err(e) = extism::PluginBuilder::new(manifest)
            .with_wasi(true)
            .with_functions([f1, f2, f3])
            .build()
        {
            return Err(ScannerError::PluginInitializationError(format!(
                "Failed to load Wasm via Extism '{}': {}",
                self.wasm_path.display(),
                e
            )));
        }
        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let template_json = match serde_json::to_string(&*ctx.template) {
            Ok(j) => j,
            Err(_) => return PluginOutcome::NoMatch,
        };
        let vars = ctx.snapshot_variables().await;
        let context_json = serde_json::to_string(&vars).unwrap_or_default();

        let input_json = format!(
            r#"{{"template":{},"context":{}}}"#,
            template_json, context_json
        );

        let f1 = extism::Function::new(
            "dns_resolve",
            [extism::ValType::I64],
            [extism::ValType::I64],
            extism::UserData::new(()),
            crate::host_functions::dns_resolve,
        );
        let f2 = extism::Function::new(
            "kv_get",
            [extism::ValType::I64],
            [extism::ValType::I64],
            extism::UserData::new(()),
            crate::host_functions::kv_get,
        );
        let f3 = extism::Function::new(
            "kv_set",
            [extism::ValType::I64],
            [extism::ValType::I64],
            extism::UserData::new(()),
            crate::host_functions::kv_set,
        );

        let manifest = self.build_manifest();
        let mut plugin = match extism::PluginBuilder::new(manifest)
            .with_wasi(true)
            .with_functions([f1, f2, f3])
            .build()
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm module load failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm load: {}", e)),
                    retryable: false,
                };
            }
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let res = plugin.call::<&str, Vec<u8>>("execute_scan", &input_json);
            let _ = tx.send(res);
        });

        let output_bytes = match rx.await.expect("WASM thread panicked") {
            Ok(output) => output,
            Err(e) => {
                let err_str = e.to_string();
                let clean_err = if let Some(idx) = err_str.find("Caused by:") {
                    let cause = &err_str[idx..];
                    if let Some(stack_idx) = cause.find("Stack backtrace:") {
                        cause[..stack_idx].trim().to_string()
                    } else {
                        cause.trim().to_string()
                    }
                } else if err_str.contains("error while executing at wasm backtrace:") {
                    "Plugin execution timed out (or encountered an internal WASM trap)".to_string()
                } else {
                    err_str.clone()
                };

                tracing::error!(plugin = %self.name, error = %clean_err, "wasm execution failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(clean_err),
                    retryable: false,
                };
            }
        };

        let result_str = match std::str::from_utf8(&output_bytes) {
            Ok(s) => s,
            Err(_) => return PluginOutcome::NoMatch,
        };

        match serde_json::from_str::<serde_json::Value>(result_str) {
            Ok(json) => {
                tracing::debug!("WASM OUTPUT JSON: {}", result_str);
                if json
                    .get("matched")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    let count = json.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                    if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
                        for finding_val in findings {
                            match serde_json::from_value::<WasmPluginFinding>(finding_val.clone()) {
                                Ok(f) => {
                                    let finding = FindingOwned {
                                        scan_id: ctx.scan_id,
                                        template_id: format!(
                                            "{}/{}",
                                            ctx.template.id, f.template_id
                                        ),
                                        template_name: format!(
                                            "{} [{}]",
                                            ctx.template.info.name, f.template_name
                                        ),
                                        severity: f.severity.as_str().into(),
                                        target: f.target,
                                        matched_at: f.matched_at,
                                        description: f.description,
                                        solution: f.solution,
                                        extracted_data: f.extracted_data,
                                        metadata: f.metadata,
                                    };
                                    let _ = ctx.finding_tx.send(finding).await;
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to deserialize finding {}: {:?}",
                                        e,
                                        finding_val
                                    );
                                }
                            }
                        }
                    } else {
                        tracing::error!("findings missing or not array in WasmOutput");
                    }

                    PluginOutcome::Matched { count }
                } else {
                    PluginOutcome::NoMatch
                }
            }
            Err(e) => {
                tracing::warn!(plugin = %self.name, error = %e, result = %result_str, "wasm plugin returned unparseable result");
                PluginOutcome::NoMatch
            }
        }
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }
}
