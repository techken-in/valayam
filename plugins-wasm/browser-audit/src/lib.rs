use valayam_plugin_sdk::{export_plugin, extism_pdk, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::HttpRequest;

#[derive(Default)]
pub struct BrowserAuditScanner;

impl WasmScanner for BrowserAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();

        let template_id = input
            .template
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let template_name = input
            .template
            .get("info")
            .and_then(|i| i.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Browser Audit")
            .to_string();

        let target = input
            .context
            .get("BaseURL")
            .cloned()
            .unwrap_or_else(|| "http://localhost".to_string());

        let req = HttpRequest::new(&target).with_method("GET");
        let res = match extism_pdk::http::request::<()>(&req, None) {
            Ok(r) => r,
            Err(_) => {
                return Ok(WasmOutput {
                    matched: false,
                    count: 0,
                    findings: vec![],
                });
            }
        };
        
        let body_bytes = res.body();
        let body = std::str::from_utf8(&body_bytes).unwrap_or("");

        // Check if body lacks common XSS protections, e.g., missing X-XSS-Protection
        // and reflecting script tags in the body.
        if body.contains("<script>") && !body.contains("X-XSS-Protection") {
            findings.push(Finding {
                template_id,
                template_name,
                severity: "High".to_string(),
                target: target.clone(),
                matched_at: "Browser Audit: Potential XSS or client-side execution vulnerability detected (missing protections).".to_string(),
                description: Some("Potential XSS or client-side execution vulnerability detected.".to_string()),
                solution: Some("Implement proper Content Security Policy (CSP) and sanitize outputs.".to_string()),
                extracted_data: None,
                metadata: std::collections::HashMap::new(),
            });
        }

        Ok(WasmOutput {
            matched: !findings.is_empty(),
            count: findings.len(),
            findings,
        })
    }
}

export_plugin!(BrowserAuditScanner);
