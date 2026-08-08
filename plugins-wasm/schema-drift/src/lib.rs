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
        let base_url = target_url.trim_end_matches('/');

        // Checking common OpenAPI/Swagger paths
        let endpoints = vec![
            "/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/v2/api-docs"
        ];

        for ep in endpoints {
            let w_url = format!("{}{}", base_url, ep);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("GET".to_string());
            
            if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
                let status = res.status_code();
                if status == 200 {
                    let mut metadata = HashMap::new();
                    metadata.insert("template_id".to_string(), template_id.clone());
                    
                    all_findings.push(Finding {
                        template_id: template_id.clone(),
                        template_name: format!("{} (Schema Drift)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("Schema Drift Audit")),
                        severity: "Low".to_string(),
                        target: target_url.to_string(),
                        matched_at: w_url.clone(),
                        description: Some("OpenAPI/Swagger schema is publicly accessible. This exposes API surface area and can be used to identify shadow APIs or undocumented endpoints.".to_string()),
                        solution: Some("Restrict access to API documentation in production environments unless it is a public API.".to_string()),
                        extracted_data: None,
                        metadata,
                    });
                    break;
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
