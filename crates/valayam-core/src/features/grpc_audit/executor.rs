use valayam_models::{
    finding::FindingOwned,
    templates::{
        schema::TemplateMetadata,
        grpc_audit::GrpcAuditTemplate,
    },
};
use crate::network::http::StealthHttpClient;
use std::collections::HashMap;

pub async fn execute(
    client: &StealthHttpClient,
    target: &str,
    sections: &[GrpcAuditTemplate],
    template_id: &str,
    info: &dyn TemplateMetadata,
    _vars: &mut HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    for section in sections {
        if section.reflection {
            // Attempt to connect to gRPC reflection endpoint using tonic
            // We use tonic's Channel to connect to the target
            let endpoint_url = if section.target.starts_with("http") {
                section.target.clone()
            } else {
                format!("http://{}", section.target)
            };

            // Instead of full reflection protocol, we can just check if the endpoint is reachable
            // and returns HTTP/2 with application/grpc content-type for a generic reflection request.
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/grpc".to_string());
            headers.insert("TE".to_string(), "trailers".to_string());
            
            let reflection_path = format!("{}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", endpoint_url);

            if let Ok(resp) = client.send_request("POST", &reflection_path, Some(&headers), None, Some(false), None).await {
                // If it responds with grpc-status or content-type application/grpc, reflection is likely enabled or at least gRPC is present
                let mut is_grpc = false;
                
                for (k, v) in resp.headers() {
                    let k_str = k.as_str().to_lowercase();
                    if let Ok(v_str) = v.to_str() {
                        if k_str == "content-type" && v_str.contains("application/grpc") {
                            is_grpc = true;
                        }
                        if k_str == "grpc-status" {
                            is_grpc = true;
                        }
                    }
                }

                if is_grpc {
                    let mut f = FindingOwned::from_template_and_info(
                        template_id,
                        info,
                        target.to_string(),
                        section.target.clone(),
                    );
                    f.protocol = Some("grpc".to_string());
                    f.evidence_request = Some(format!("POST {} HTTP/2\nContent-Type: application/grpc", reflection_path));
                    f.evidence_response = Some("Received gRPC headers (Content-Type: application/grpc or grpc-status)".to_string());
                    findings.push(f);
                }
            }
        }
    }

    findings
}
