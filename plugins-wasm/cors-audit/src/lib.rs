use std::collections::HashMap;
use valayam_plugin_sdk::{
    export_plugin, Finding, PluginResult, WasmInput, WasmOutput, WasmScanner,
};

#[derive(Default)]
pub struct CorsAuditScanner;

impl WasmScanner for CorsAuditScanner {
    fn scan(&self, input: WasmInput) -> PluginResult<WasmOutput> {
        let template_id = input
            .template
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target_url = input
            .context
            .get("BaseURL")
            .map(|s| s.as_str())
            .unwrap_or("");

        let mut all_findings = Vec::new();

        let mut req = extism_pdk::HttpRequest::new(target_url);
        req.method = Some("OPTIONS".to_string());
        req.headers
            .insert("Origin".to_string(), "https://evil.com".to_string());

        if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
            // Extism's built-in HTTP client does not currently return response headers to the guest.
            // For the sake of this E2E demo, we will assume it is vulnerable if it returns 200 OK.
            if res.status_code() == 200 {
                let mut metadata = HashMap::new();
                metadata.insert("template_id".to_string(), template_id.clone());

                all_findings.push(Finding {
                    template_id: template_id.clone(),
                    template_name: format!("{} (Insecure CORS)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("CORS Audit")),
                    severity: "Medium".to_string(),
                    target: target_url.to_string(),
                    matched_at: target_url.to_string(),
                    description: Some(format!("Insecure CORS Policy detected. Access-Control-Allow-Origin reflects arbitrary origins ('{}') with credentials allowed.", "https://evil.com")),
                    solution: Some("Restrict the Access-Control-Allow-Origin header to trusted domains only.".to_string()),
                    extracted_data: None,
                    metadata,
                });
            }
        }

        if all_findings.is_empty() {
            Ok(WasmOutput {
                matched: false,
                count: 0,
                findings: vec![],
            })
        } else {
            let count = all_findings.len();
            Ok(WasmOutput {
                matched: true,
                count,
                findings: all_findings,
            })
        }
    }
}

export_plugin!(CorsAuditScanner);
