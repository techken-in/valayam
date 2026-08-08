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

        let payloads = vec![
            ("Chunked Encoding Bypass", "Transfer-Encoding: chunked"),
            ("Unicode Normalization", "param=%EF%BC%9Cscript%EF%BC%9E"), // ＜script＞
            ("HTTP Parameter Pollution", "param=val1&param=val2"),
        ];

        for (bypass_type, payload) in payloads {
            let w_url = if payload.starts_with("param=") {
                format!("{}/?{}", base_url, payload)
            } else {
                format!("{}/", base_url)
            };
            
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("POST".to_string());
            
            if payload == "Transfer-Encoding: chunked" {
                req.headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
            }
            
            if let Ok(res) = extism_pdk::http::request::<Vec<u8>>(&req, Some(vec![])) {
                let status = res.status_code();
                if status == 200 {
                    let mut metadata = HashMap::new();
                    metadata.insert("bypass_type".to_string(), bypass_type.to_string());
                    
                    all_findings.push(Finding {
                        template_id: template_id.clone(),
                        template_name: format!("{} (WAF Bypass)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("WAF Bypass Audit")),
                        severity: "High".to_string(),
                        target: target_url.to_string(),
                        matched_at: w_url.clone(),
                        description: Some(format!("WAF bypass detected using {}. This indicates the WAF is not normalizing requests properly.", bypass_type)),
                        solution: Some("Ensure WAF normalizes unicode, handles HTTP parameter pollution, and strictly parses chunked encoding.".to_string()),
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
