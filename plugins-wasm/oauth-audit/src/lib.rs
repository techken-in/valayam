use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL")
            .or_else(|| input.context.get("BaseURL"))
            .map(|s| s.as_str())
            .unwrap_or("");
        if target_url.is_empty() {
            return Ok(WasmOutput { matched: false, count: 0, findings: vec![] });
        }
        
        let mut all_findings = Vec::new();
        let mut metadata = HashMap::new();
        metadata.insert("template_id".to_string(), template_id.clone());
        
        let base_url = target_url.trim_end_matches('/');
        let checks = vec![
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ];

        for path in checks {
            let w_url = format!("{}{}", base_url, path);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("GET".to_string());
            
            if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
                if res.status_code() == 200 {
                    let body = String::from_utf8_lossy(&res.body());
                    
                    // Check for HTTP usage in issuer or endpoints
                    if body.contains("\"http://") {
                        all_findings.push(Finding {
                            template_id: template_id.clone(),
                            template_name: format!("{} (Insecure OAuth Transport)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("OAuth Audit")),
                            severity: "High".to_string(),
                            target: target_url.to_string(),
                            matched_at: w_url.clone(),
                            description: Some("The OAuth/OpenID configuration exposes non-HTTPS endpoints. This allows interception of authorization codes and tokens.".to_string()),
                            solution: Some("Ensure all OAuth endpoints use HTTPS exclusively.".to_string()),
                            extracted_data: Some("Found http:// endpoint in configuration".to_string()),
                            metadata: metadata.clone(),
                        });
                    }
                    
                    // Check for Implicit Grant flow (response_types_supported containing "token")
                    // A simple string contains is an MVP for parsing JSON
                    if body.contains("\"token\"") && body.contains("response_types_supported") {
                        all_findings.push(Finding {
                            template_id: template_id.clone(),
                            template_name: format!("{} (Implicit Grant Enabled)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("OAuth Audit")),
                            severity: "Medium".to_string(),
                            target: target_url.to_string(),
                            matched_at: w_url.clone(),
                            description: Some("The OAuth server supports the deprecated Implicit Grant flow ('token' response type).".to_string()),
                            solution: Some("Disable Implicit Grant and use Authorization Code flow with PKCE instead.".to_string()),
                            extracted_data: Some("response_types_supported contains 'token'".to_string()),
                            metadata: metadata.clone(),
                        });
                    }
                    
                    // Break after finding the first valid well-known config to avoid duplicates
                    if body.contains("\"issuer\"") {
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
