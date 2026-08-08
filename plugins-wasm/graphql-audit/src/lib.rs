use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("BaseURL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();
        
        // GraphQL Introspection Query
        let query = r#"{"query":"\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n      }\n    }\n  "}"#;
        
        // Typical GraphQL endpoints
        let endpoints = vec!["/graphql", "/api/graphql", "/v1/graphql"];
        let base_url = target_url.trim_end_matches('/');

        for ep in endpoints {
            let w_url = format!("{}{}", base_url, ep);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("POST".to_string());
            req.headers.insert("Content-Type".to_string(), "application/json".to_string());
            
            if let Ok(res) = extism_pdk::http::request::<Vec<u8>>(&req, Some(query.as_bytes().to_vec())) {
                if res.status_code() == 200 {
                    let body = res.body();
                    let body_str = String::from_utf8_lossy(&body);
                    if body_str.contains("__schema") || body_str.contains("queryType") {
                        let mut metadata = HashMap::new();
                        metadata.insert("template_id".to_string(), template_id.clone());
                        
                        all_findings.push(Finding {
                            template_id: template_id.clone(),
                            template_name: format!("{} (Introspection)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("GraphQL Audit")),
                            severity: "High".to_string(),
                            target: target_url.to_string(),
                            matched_at: w_url.clone(),
                            description: Some("GraphQL Introspection is enabled. This exposes the entire schema API, which can lead to further exploitation.".to_string()),
                            solution: Some("Disable GraphQL introspection in production.".to_string()),
                            extracted_data: None,
                            metadata,
                        });
                        break; // No need to check other endpoints if we found one
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
