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
        
        // Audit package.json exposure
        let w_url = format!("{}/package.json", target_url.trim_end_matches('/'));
        let mut req = HttpRequest::new(&w_url);
        req.method = Some("GET".to_string());
        
        if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
            if res.status_code() == 200 {
                let body = res.body();
                let body_str = String::from_utf8_lossy(&body);
                
                // If it looks like a valid package.json, flag it!
                if body_str.contains("\"dependencies\"") || body_str.contains("\"devDependencies\"") {
                    let mut metadata = HashMap::new();
                    metadata.insert("template_id".to_string(), template_id.clone());
                    
                    all_findings.push(Finding {
                        template_id,
                        template_name: format!("{} (Dependency Exposure)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("Dependency Audit")),
                        severity: "High".to_string(),
                        target: target_url.to_string(),
                        matched_at: w_url.clone(),
                        description: Some("Exposed package.json file found. This leaks the internal dependency tree.".to_string()),
                        solution: Some("Restrict public access to package.json.".to_string()),
                        extracted_data: None,
                        metadata,
                    });
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
