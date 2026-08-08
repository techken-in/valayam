use valayam_plugin_sdk::{export_plugin, extism_pdk, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::HttpRequest;
use regex::Regex;

#[derive(Default)]
pub struct PiiLeakAuditScanner;

impl WasmScanner for PiiLeakAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();

        let template_id = input
            .template
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let template_name = input
            .template
            .get("info")
            .and_then(|info| info.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("PII Leak Audit");

        let target = input
            .context
            .get("BaseURL")
            .cloned()
            .unwrap_or_else(|| "http://localhost".to_string());

        let req = HttpRequest::new(&target).with_method("GET");
        let res = extism_pdk::http::request::<()>(&req, None)?;
        let body_bytes = res.body();
        let body = String::from_utf8_lossy(&body_bytes);

        let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        let cc_re = Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap();
        let email_re = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        let apikey_re = Regex::new(r"(?i)(api[_-]?key|token|secret)[=:\s]+[A-Za-z0-9_\-]{16,}\b").unwrap();

        let mut found_pii = Vec::new();
        if ssn_re.is_match(&body) {
            found_pii.push("SSN");
        }
        if cc_re.is_match(&body) {
            found_pii.push("Credit Card");
        }
        if email_re.is_match(&body) {
            found_pii.push("Email");
        }
        if apikey_re.is_match(&body) {
            found_pii.push("API Key/Secret");
        }

        if !found_pii.is_empty() {
            findings.push(Finding {
                template_id: template_id.to_string(),
                template_name: template_name.to_string(),
                severity: "High".to_string(),
                target: target.clone(),
                matched_at: format!(
                    "PII Leak Detected: Found potentially exposed data types: {:?}",
                    found_pii
                ),
                description: None,
                solution: None,
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

export_plugin!(PiiLeakAuditScanner);
