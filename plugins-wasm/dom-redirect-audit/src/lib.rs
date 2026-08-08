use valayam_plugin_sdk::{export_plugin, extism_pdk, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::HttpRequest;
use regex::Regex;

#[derive(Default)]
pub struct DomRedirectAuditScanner;

impl WasmScanner for DomRedirectAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();

        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let template_name = input.template.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or("DOM Redirect Audit").to_string();
        
        let target = input.context.get("BaseURL")
            .or_else(|| input.context.get("TARGET_URL"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| "http://localhost".to_string());
        if target.is_empty() {
            return Ok(WasmOutput { matched: false, count: 0, findings: vec![] });
        }

        let req = HttpRequest::new(&target).with_method("GET");
        let res = match extism_pdk::http::request::<()>(&req, None) {
            Ok(r) => r,
            Err(_) => return Ok(WasmOutput { matched: false, count: 0, findings: vec![] }),
        };

        let body_bytes = res.body();
        let body = std::str::from_utf8(&body_bytes).unwrap_or("");

        let dom_re = Regex::new(r"(?i)(window\.location|location\.href|location\.replace)\s*=\s*[^;]*(location\.hash|location\.search|window\.location\.search)").unwrap();
        
        if dom_re.is_match(body) {
            findings.push(Finding {
                template_id,
                template_name,
                severity: "High".to_string(),
                target,
                matched_at: "DOM-based Open Redirect vulnerability pattern detected in JavaScript.".to_string(),
                description: Some("DOM-based Open Redirect vulnerability pattern detected in JavaScript.".to_string()),
                solution: Some("Avoid using untrusted user input directly in DOM sinks that control navigation or document location.".to_string()),
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

export_plugin!(DomRedirectAuditScanner);
