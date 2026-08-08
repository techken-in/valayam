use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        extism_pdk::info!("Starting scan for iot_audit");
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();
        
        let mut metadata = HashMap::new();
        metadata.insert("template_id".to_string(), template_id.clone());
        
        let base_url = target_url.trim_end_matches('/');
        let paths_to_check = vec!["/setup", "/cgi-bin/config.exp", "/info", "/"];
        
        for path in paths_to_check {
            let w_url = format!("{}{}", base_url, path);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("GET".to_string());
            
            if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
                let status = res.status_code();
                let headers = res.headers();
                
                let mut is_iot = false;
                let mut matched_reason = String::new();

                // Check for common IoT web server headers
                if let Some(server_header) = headers.get("server").or_else(|| headers.get("Server")) {
                    let server_lower = server_header.to_lowercase();
                    if server_lower.contains("goahead") 
                        || server_lower.contains("rompager") 
                        || server_lower.contains("lighttpd") 
                        || server_lower.contains("app-webs") {
                        is_iot = true;
                        matched_reason = format!("Detected embedded IoT web server: {}", server_header);
                    }
                }

                // Or if we hit an unauthenticated config endpoint
                if status == 200 && (path == "/setup" || path == "/cgi-bin/config.exp") {
                    is_iot = true;
                    matched_reason = format!("Detected exposed administrative IoT endpoint at {}", path);
                }

                if is_iot {
                    all_findings.push(Finding {
                        template_id: template_id.clone(),
                        template_name: format!("{} (IoT Exposure)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("IoT Audit")),
                        severity: "High".to_string(),
                        target: target_url.to_string(),
                        matched_at: w_url.clone(),
                        description: Some(format!("Exposed IoT infrastructure detected. {}", matched_reason)),
                        solution: Some("Restrict access to IoT administrative interfaces and do not expose them to the public internet.".to_string()),
                        extracted_data: Some(matched_reason),
                        metadata: metadata.clone(),
                    });
                    
                    // We can break early once we find it
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
