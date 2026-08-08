use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner, PluginResult};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::WithReturnCode<extism_pdk::Error>> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("BaseURL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();
        
        let endpoints = vec!["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"];
        let base_url = target_url.trim_end_matches('/');

        for ep in endpoints {
            let w_url = format!("{}{}", base_url, ep);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("POST".to_string());
            req.headers.insert("Content-Type".to_string(), "application/grpc".to_string());
            
            let payload = vec![0, 0, 0, 0, 0]; 
            
            if let Ok(res) = extism_pdk::http::request::<Vec<u8>>(&req, Some(payload)) {
                let status = res.status_code();
                if status == 200 || status == 501 || status == 415 {
                    let headers = res.headers();
                    if headers.iter().any(|(k, _)| k.to_lowercase() == "grpc-status" || k.to_lowercase() == "grpc-message") {
                        let mut metadata = HashMap::new();
                        metadata.insert("template_id".to_string(), template_id.clone());
                        
                        all_findings.push(Finding {
                            template_id: template_id.clone(),
                            template_name: format!("{} (gRPC Reflection)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("gRPC Audit")),
                            severity: "Medium".to_string(),
                            target: target_url.to_string(),
                            matched_at: w_url.clone(),
                            description: Some("gRPC Server Reflection is enabled or exposed. This can allow attackers to list all available methods and message types, aiding in further attacks.".to_string()),
                            solution: Some("Disable gRPC Server Reflection in production environments.".to_string()),
                            extracted_data: None,
                            metadata,
                        });
                        break; 
                    }
                }
            }
        }

        if all_findings.is_empty() {
            Ok(WasmOutput { matched: false, count: 0, findings: vec![] })
        } else {
            let count = all_findings.len();
            Ok(WasmOutput { matched: true, count, findings: all_findings })
        }
    }
}

export_plugin!(WasmScannerImpl);
