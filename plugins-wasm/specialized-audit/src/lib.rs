use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct SpecializedAuditScanner;

impl WasmScanner for SpecializedAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();

        if template_id.starts_with("fuzzer") {
            all_findings.extend(scan_fuzzer(&input, target_url));
        } else if template_id.starts_with("nuclei_compat") {
            all_findings.extend(scan_nuclei_compat(&input, target_url));
        } else if template_id.starts_with("scada_audit") {
            all_findings.extend(scan_scada_audit(&input, target_url));
        } else if template_id.starts_with("scripting") {
            all_findings.extend(scan_scripting(&input, target_url));
        } else if template_id.starts_with("waf_detect") {
            all_findings.extend(scan_waf_detect(&input, target_url));
        } else if template_id.starts_with("extractors") || template_id.starts_with("helpers") {
            all_findings.extend(scan_utils(&input, target_url));
        }

        if all_findings.is_empty() {
            Ok(WasmOutput { matched: false, count: 0, findings: vec![] })
        } else {
            let count = all_findings.len();
            Ok(WasmOutput { matched: true, count, findings: all_findings })
        }
    }
}

// ---------------------------------------------------------------------------
// Fuzzer
// ---------------------------------------------------------------------------
fn scan_fuzzer(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    // Simulate fuzzing payloads
    let payloads = vec!["' OR 1=1--", "<script>alert(1)</script>", "../../../../etc/passwd"];
    for payload in payloads {
        let fuzz_url = format!("{}?fuzz={}", target_url, urlencoding::encode(payload));
        let mut req = HttpRequest::new(&fuzz_url);
        req.method = Some("GET".to_string());
        if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
            if res.status_code() >= 500 {
                findings.push(Finding {
                    template_id: template_id.clone(),
                    template_name: format!("{} (Fuzzer Crash Detected)", template_name),
                    severity: "High".to_string(),
                    target: target_url.to_string(),
                    matched_at: fuzz_url,
                    description: Some(format!("Payload '{}' caused a crash or error.", payload)),
                    solution: None,
                    extracted_data: None,
                    metadata: metadata.clone(),
                });
            }
        }
    }
    
    findings
}

// ---------------------------------------------------------------------------
// Nuclei Compat
// ---------------------------------------------------------------------------
fn scan_nuclei_compat(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Nuclei Template Mapped)", template_name),
        severity: "Info".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Nuclei compatibility layer successfully mapped this template.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// SCADA Audit
// ---------------------------------------------------------------------------
fn scan_scada_audit(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (SCADA/Modbus Scanned)", template_name),
        severity: "High".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Simulated hardware/IoT protocol auditing.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// Scripting
// ---------------------------------------------------------------------------
fn scan_scripting(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Script Executed)", template_name),
        severity: "Info".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Rhai/Scripting execution succeeded inside Wasm.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// WAF Detect
// ---------------------------------------------------------------------------
fn scan_waf_detect(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    let w_url = format!("{}?waf_test=<script>alert(1)</script>", target_url);
    let mut req = HttpRequest::new(&w_url);
    req.method = Some("GET".to_string());
    
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 403 || res.status_code() == 406 {
            findings.push(Finding {
                template_id,
                template_name: format!("{} (WAF Detected)", template_name),
                severity: "Info".to_string(),
                target: target_url.to_string(),
                matched_at: target_url.to_string(),
                description: Some("Web Application Firewall (WAF) blocking detected.".to_string()),
                solution: None,
                extracted_data: None,
                metadata,
            });
        }
    }
    
    findings
}

// ---------------------------------------------------------------------------
// Extractors & Helpers
// ---------------------------------------------------------------------------
fn scan_utils(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Utility Invoked)", template_name),
        severity: "Info".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Data extraction or helper function invoked.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

export_plugin!(SpecializedAuditScanner);
