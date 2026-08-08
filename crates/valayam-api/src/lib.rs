use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tonic::{transport::Server, Request, Response, Status};
use valayam_engine::reflection::ValayamReflection;
use valayam_engine::rpc::scanner_server::{Scanner, ScannerServer};
use valayam_engine::rpc::{
    ControlRequest, ControlResponse, ScanRequest, ScanResponse, TelemetryEvent, TelemetryResponse,
};
use valayam_engine::scan_state::ScanState;
use valayam_proto::reflection::v1::server_reflection_server::ServerReflectionServer;

/// Optional TLS configuration for the gRPC control plane.
/// When `ca_pem` is provided, the server requires client certificates signed by that CA (mTLS).
#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Option<Vec<u8>>,
}

pub struct TelemetryService {
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
}

#[tonic::async_trait]
impl Scanner for TelemetryService {
    async fn scan(&self, request: Request<ScanRequest>) -> Result<Response<ScanResponse>, Status> {
        let req = request.into_inner();
        let target = req.target_url;
        let template: valayam_models::templates::schema::VulnerabilityTemplate =
            match serde_yaml::from_str(&req.template_yaml) {
                Ok(t) => t,
                Err(e) => {
                    return Err(Status::invalid_argument(format!(
                        "Invalid template YAML: {}",
                        e
                    )))
                }
            };

        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let registry = std::sync::Arc::new(valayam_engine::registry::PluginRegistry::new());
        let token = tokio_util::sync::CancellationToken::new();
        let executor = valayam_engine::executor::ScanExecutor::new(tx, registry, None, token);

        let template_arc = std::sync::Arc::new(template);
        executor.execute(&target, template_arc).await;

        let mut findings = Vec::new();
        // tx is dropped when executor is dropped at end of scope? Wait, executor doesn't drop tx until execute completes, wait execute consumes tx?
        // Actually execute just takes &self, so tx is cloned. But wait, we need to drop the original tx so rx will close!
        drop(executor); // or drop tx before creating executor? We moved tx into executor, so dropping executor drops tx.

        while let Some(finding) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&finding) {
                findings.push(json);
            }
        }

        Ok(Response::new(ScanResponse {
            findings_json: findings,
        }))
    }

    async fn stream_telemetry(
        &self,
        request: Request<tonic::Streaming<TelemetryEvent>>,
    ) -> Result<Response<TelemetryResponse>, Status> {
        let mut stream = request.into_inner();

        while let Some(event) = stream.message().await? {
            tracing::info!(
                event_type = %event.event_type,
                payload = %event.payload_json,
                "Received eBPF Telemetry Event"
            );
        }

        Ok(Response::new(TelemetryResponse { received: true }))
    }

    async fn pause_scan(
        &self,
        _req: Request<ControlRequest>,
    ) -> Result<Response<ControlResponse>, Status> {
        if let Some(tx) = &self.state_tx {
            let _ = tx.send(ScanState::Paused);
            return Ok(Response::new(ControlResponse {
                success: true,
                message: "Paused".into(),
            }));
        }
        Err(Status::unavailable("Control plane not active"))
    }

    async fn resume_scan(
        &self,
        _req: Request<ControlRequest>,
    ) -> Result<Response<ControlResponse>, Status> {
        if let Some(tx) = &self.state_tx {
            let _ = tx.send(ScanState::Running);
            return Ok(Response::new(ControlResponse {
                success: true,
                message: "Resumed".into(),
            }));
        }
        Err(Status::unavailable("Control plane not active"))
    }

    async fn cancel_scan(
        &self,
        _req: Request<ControlRequest>,
    ) -> Result<Response<ControlResponse>, Status> {
        if let Some(token) = &self.cancellation_token {
            token.cancel();
            return Ok(Response::new(ControlResponse {
                success: true,
                message: "Cancelled".into(),
            }));
        }
        Err(Status::unavailable("Control plane not active"))
    }
}

/// Spawn a minimal HTTP server on `metrics_addr` that serves prometheus metrics
/// at GET /metrics. Runs until the returned CancellationToken is cancelled.
fn spawn_metrics_http_server(metrics_addr: std::net::SocketAddr) -> CancellationToken {
    let shutdown_token = CancellationToken::new();
    let token = shutdown_token.clone();

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(metrics_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    "Failed to bind metrics HTTP server on {}: {}",
                    metrics_addr,
                    e
                );
                return;
            }
        };
        tracing::info!(
            "Prometheus metrics endpoint listening on http://{}/metrics",
            metrics_addr
        );

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("Metrics HTTP server shutting down");
                    break;
                }
                result = listener.accept() => {
                    let (stream, _) = match result {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!("Metrics HTTP accept error: {}", e);
                            continue;
                        }
                    };
                    tokio::spawn(handle_metrics_connection(stream));
                }
            }
        }
    });

    shutdown_token
}

async fn handle_metrics_connection(stream: tokio::net::TcpStream) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Only respond to GET /metrics; 404 everything else
    let (status_line, content_type, body) = if request_line.starts_with("GET /metrics") {
        let metrics_body = valayam_engine::metrics::gather_metrics();
        (
            "HTTP/1.1 200 OK\r\n",
            "content-type: text/plain; version=0.0.4\r\n",
            metrics_body,
        )
    } else {
        (
            "HTTP/1.1 404 Not Found\r\n",
            "content-type: text/plain\r\n",
            "404 Not Found\n".to_string(),
        )
    };

    // Drain remaining request headers
    let mut header = String::new();
    loop {
        header.clear();
        if reader.read_line(&mut header).await.is_err() || header.trim().is_empty() {
            break;
        }
    }

    let response = format!(
        "{}content-length: {}\r\n{}\r\n{}",
        status_line,
        body.len(),
        content_type,
        body,
    );

    let mut writer = reader.into_inner();
    let _ = writer.write_all(response.as_bytes()).await;
    let _ = writer.flush().await;
}

/// Start the gRPC telemetry server (plaintext).
pub async fn start_telemetry_server(
    addr: std::net::SocketAddr,
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
) -> Result<(), Box<dyn std::error::Error>> {
    start_telemetry_server_tls(addr, state_tx, cancellation_token, None).await
}

/// Start the gRPC telemetry server with optional TLS and a /metrics HTTP endpoint.
///
/// When `tls_config` is `Some`, the server uses the provided PEM-encoded
/// certificate and private key for TLS encryption.
/// If `tls_config.ca_pem` is also provided, the server enforces mTLS — clients
/// must present a certificate signed by that CA.
/// Automatically spawns a prometheus /metrics HTTP server on port 9090.
pub async fn start_telemetry_server_tls(
    addr: std::net::SocketAddr,
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
    tls_config: Option<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Spawn the /metrics HTTP endpoint
    let metrics_addr: std::net::SocketAddr = ([0, 0, 0, 0], 9090).into();
    let _metrics_shutdown = spawn_metrics_http_server(metrics_addr);

    let telemetry = TelemetryService {
        state_tx,
        cancellation_token,
    };

    let mut builder = Server::builder();

    if let Some(tls) = tls_config {
        let cert_pem_str = String::from_utf8(tls.cert_pem)
            .map_err(|e| format!("TLS cert is not valid UTF-8: {}", e))?;
        let key_pem_str = String::from_utf8(tls.key_pem)
            .map_err(|e| format!("TLS key is not valid UTF-8: {}", e))?;

        let identity = tonic::transport::Identity::from_pem(cert_pem_str, key_pem_str);

        if let Some(ca_raw) = tls.ca_pem {
            let ca_pem_str = String::from_utf8(ca_raw)
                .map_err(|e| format!("TLS CA cert is not valid UTF-8: {}", e))?;
            let ca = tonic::transport::Certificate::from_pem(ca_pem_str);
            let server_tls = tonic::transport::ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(ca);
            tracing::info!("gRPC mTLS enabled — client certificates required");
            builder = builder
                .tls_config(server_tls)
                .map_err(|e| format!("Failed to configure mTLS: {}", e))?;
        } else {
            let server_tls = tonic::transport::ServerTlsConfig::new().identity(identity);
            tracing::info!("gRPC TLS enabled (server-only)");
            builder = builder
                .tls_config(server_tls)
                .map_err(|e| format!("Failed to configure TLS: {}", e))?;
        }
    }

    tracing::info!("Starting Valayam Telemetry Server on {}", addr);
    builder
        .add_service(ServerReflectionServer::new(ValayamReflection))
        .add_service(ScannerServer::new(telemetry))
        .serve(addr)
        .await?;

    Ok(())
}

/// Start a minimal HTTP server serving Prometheus metrics at `/metrics`.
pub async fn start_metrics_server(
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "Starting Valayam metrics endpoint on http://{}/metrics",
        addr
    );

    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let _ = stream.read(&mut buf).await;

            let body = valayam_engine::metrics::gather_metrics();
            let body_bytes = body.as_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_bytes.len()
            );

            if stream.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            let _ = stream.write_all(body_bytes).await;
        });
    }
}
