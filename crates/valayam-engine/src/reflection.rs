//! Lightweight gRPC Server Reflection implementation.
//!
//! Implements the gRPC reflection protocol (v1) so tools like `grpcurl` can
//! discover services and methods at runtime. Uses the compiled file descriptor
//! set from `valayam-proto`.

use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use valayam_proto::reflection::v1::{
    server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
    server_reflection_server::ServerReflection, FileDescriptorResponse, ListServicesResponse,
    ServerReflectionRequest, ServerReflectionResponse, ServiceResponse,
};

/// Registered gRPC service names in this server.
const SERVICES: &[&str] = &["valayam.Scanner", "grpc.reflection.v1.ServerReflection"];

/// Lightweight reflection service backed by `valayam_proto::FILE_DESCRIPTOR_SET`.
#[derive(Clone, Default)]
pub struct ValayamReflection;

#[tonic::async_trait]
impl ServerReflection for ValayamReflection {
    type ServerReflectionInfoStream =
        tokio_stream::wrappers::ReceiverStream<Result<ServerReflectionResponse, Status>>;

    async fn server_reflection_info(
        &self,
        req: Request<Streaming<ServerReflectionRequest>>,
    ) -> Result<Response<Self::ServerReflectionInfoStream>, Status> {
        let mut stream = req.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(8);

        tokio::spawn(async move {
            while let Some(Ok(incoming)) = stream.next().await {
                let host = incoming.host.clone();
                let orig = incoming.clone();
                let resp = match incoming.message_request {
                    // File / symbol / extension queries → return the full descriptor set.
                    Some(MessageRequest::FileByFilename(_))
                    | Some(MessageRequest::FileContainingSymbol(_))
                    | Some(MessageRequest::FileContainingExtension(_)) => {
                        ServerReflectionResponse {
                            valid_host: host,
                            original_request: Some(orig),
                            message_response: Some(MessageResponse::FileDescriptorResponse(
                                FileDescriptorResponse {
                                    file_descriptor_proto: vec![
                                        valayam_proto::FILE_DESCRIPTOR_SET.to_vec()
                                    ],
                                },
                            )),
                        }
                    }
                    // No message_request → return list of services (grpcurl discovery).
                    None => ServerReflectionResponse {
                        valid_host: host,
                        original_request: Some(orig),
                        message_response: Some(MessageResponse::ListServicesResponse(
                            ListServicesResponse {
                                service: SERVICES
                                    .iter()
                                    .map(|s| ServiceResponse {
                                        name: s.to_string(),
                                    })
                                    .collect(),
                            },
                        )),
                    },
                };
                if tx.send(Ok(resp)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}
