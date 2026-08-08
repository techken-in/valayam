use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use valayam_proto::plugin::plugin_service_server::{PluginService, PluginServiceServer};
use valayam_proto::plugin::{
    ExecuteRequest, ExecuteResponse, InitRequest, InitResponse, ShutdownRequest, ShutdownResponse,
    ValidateConfigRequest, ValidateConfigResponse,
};

#[derive(Default)]
pub struct ExamplePlugin {}

#[tonic::async_trait]
impl PluginService for ExamplePlugin {
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<InitResponse>, Status> {
        Ok(Response::new(InitResponse {
            success: true,
            error_message: String::new(),
            supported_protocols: vec!["grpc".to_string()],
            supported_template_ids: vec!["grpc-example".to_string()],
            supported_tags: vec![],
        }))
    }

    async fn validate_config(
        &self,
        _request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        Ok(Response::new(ValidateConfigResponse {
            valid: true,
            error_message: String::new(),
        }))
    }

    type ExecuteStream = ReceiverStream<Result<ExecuteResponse, Status>>;

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(4);

        // Functional network check: DNS resolution
        tokio::spawn(async move {
            let target = req.target.clone();
            let host_port = if target.contains(':') && !target.starts_with("http") {
                target.clone()
            } else if let Ok(url) = url::Url::parse(&target) {
                let host = url.host_str().unwrap_or(&target);
                let port = url.port_or_known_default().unwrap_or(80);
                format!("{}:{}", host, port)
            } else {
                format!("{}:80", target)
            };

            let metadata = match tokio::net::lookup_host(&host_port).await {
                Ok(addrs) => {
                    let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                    serde_json::json!({
                        "resolved_ips": ips
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "error": e.to_string()
                    })
                }
            };

            let finding = serde_json::json!({
                "template_id": "grpc-example",
                "template_name": "gRPC Example Plugin",
                "severity": "info",
                "target": req.target,
                "matched_at": "DNS resolution",
                "metadata": metadata
            });

            let finding_json = finding.to_string();
            let _ = tx.send(Ok(ExecuteResponse { finding_json })).await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn shutdown(
        &self,
        _request: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        // Exit process cleanly
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::process::exit(0);
        });
        Ok(Response::new(ShutdownResponse { success: true }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bind to any available port
    let addr: SocketAddr = "127.0.0.1:0".parse()?;

    // Create server and bind to get the dynamic port
    let server = Server::builder().add_service(PluginServiceServer::new(ExamplePlugin::default()));
    let incoming = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = incoming.local_addr()?;

    // HashiCorp go-plugin protocol handshake
    println!("1|plugin|tcp|{}|grpc", local_addr);

    // Run the server
    server
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(incoming))
        .await?;

    Ok(())
}
