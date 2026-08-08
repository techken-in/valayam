use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();
        let mut metadata = HashMap::new();
        metadata.insert("template_id".to_string(), template_id.clone());
        
        let base_url = target_url.trim_end_matches('/');
        let checks = vec![
            ("/.well-known/apple-app-site-association", "iOS Universal Links"),
            ("/.well-known/assetlinks.json", "Android App Links"),
        ];

        for (path, platform) in checks {
            let w_url = format!("{}{}", base_url, path);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("GET".to_string());
            
            if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
                if res.status_code() == 200 {
                    let body = String::from_utf8_lossy(&res.body());
                    // Very simple naive check for wildcard paths in JSON strings
                    if body.contains("\"*\"") || body.contains("\"/*\"") || body.contains("\"/.+\"") {
                        all_findings.push(Finding {
                            template_id: template_id.clone(),
                            template_name: format!("{} (Permissive Deep Linking)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("Mobile Audit")),
                            severity: "Medium".to_string(),
                            target: target_url.to_string(),
                            matched_at: w_url.clone(),
                            description: Some(format!("The {} configuration contains an overly permissive wildcard path.", platform)),
                            solution: Some("Restrict the deep linking configuration to explicitly defined paths to prevent deep link hijacking.".to_string()),
                            extracted_data: Some(format!("Found wildcard path in {}", platform)),
                            metadata: metadata.clone(),
                        });
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
