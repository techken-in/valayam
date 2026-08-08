use valayam_plugin_sdk::{export_plugin, extism_pdk, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::HttpRequest;

#[derive(Default)]
pub struct HeaderScorecardScanner;

impl WasmScanner for HeaderScorecardScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();

        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("header-scorecard");
        let template_name = input.template.get("info").and_then(|info| info.get("name")).and_then(|v| v.as_str()).unwrap_or("Security Headers Scorecard");
        
        let target = input.context.get("BaseURL").cloned().unwrap_or_else(|| "http://localhost".to_string());

        let req = HttpRequest::new(&target).with_method("GET");
        let res = extism_pdk::http::request::<()>(&req, None)?;
        let headers = res.headers();

        let required_headers = vec![
            ("strict-transport-security", "Missing HSTS Header (Strict-Transport-Security)"),
            ("x-frame-options", "Missing X-Frame-Options Header (Clickjacking)"),
            ("x-content-type-options", "Missing X-Content-Type-Options Header (MIME Sniffing)"),
            ("content-security-policy", "Missing Content-Security-Policy Header"),
        ];

        let lower_headers: std::collections::HashSet<String> = headers.keys().map(|k| k.to_lowercase()).collect();

        for (header, msg) in required_headers {
            if !lower_headers.contains(header) {
                findings.push(Finding {
                    template_id: template_id.to_string(),
                    template_name: template_name.to_string(),
                    severity: "Low".to_string(),
                    target: target.clone(),
                    matched_at: header.to_string(),
                    description: Some(msg.to_string()),
                    solution: Some(format!("Add the {} header to the HTTP response.", header)),
                    extracted_data: None,
                    metadata: std::collections::HashMap::new(),
                });
            }
        }

        let count = findings.len();
        Ok(WasmOutput { 
            matched: count > 0,
            findings,
            count,
        })
    }
}

export_plugin!(HeaderScorecardScanner);
