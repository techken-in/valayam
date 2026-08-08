use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct ReconAuditScanner;

impl WasmScanner for ReconAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        let target_host = input.context.get("TARGET_HOST").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();

        if template_id.starts_with("easm") {
            all_findings.extend(scan_easm(&input, target_host));
        } else if template_id.starts_with("ct_log_audit") {
            all_findings.extend(scan_ct_log(&input, target_host));
        } else if template_id.starts_with("subdomain_takeover") {
            all_findings.extend(scan_subdomain_takeover(&input, target_host));
        } else if template_id.starts_with("drift_detect") {
            all_findings.extend(scan_drift_detect(&input, target_url));
        } else if template_id.starts_with("waf_bypass_verify") {
            all_findings.extend(scan_waf_bypass(&input, target_url));
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
// EASM
// ---------------------------------------------------------------------------
fn scan_easm(input: &WasmInput, target_host: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let domain = input.template.get("domain").and_then(|v| v.as_str()).unwrap_or("").replace("{{Hostname}}", target_host);
    if domain.is_empty() { return vec![]; }
    
    let mut subdomains = HashSet::new();
    
    // crt.sh
    let crtsh_url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let req = HttpRequest::new(&crtsh_url);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 200 {
            if let Ok(body) = String::from_utf8(res.body()) {
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    if let Some(arr) = json.as_array() {
                        for item in arr {
                            if let Some(name) = item.get("name_value").and_then(|v| v.as_str()) {
                                for sub in name.split('\n') {
                                    let sub = sub.trim().trim_start_matches("*.");
                                    if !sub.is_empty() && sub.ends_with(&domain) {
                                        subdomains.insert(sub.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Alienvault
    let alienvault_url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    let req = HttpRequest::new(&alienvault_url);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 200 {
            if let Ok(body) = String::from_utf8(res.body()) {
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    if let Some(passive_dns) = json.get("passive_dns").and_then(|v| v.as_array()) {
                        for item in passive_dns {
                            if let Some(hostname) = item.get("hostname").and_then(|v| v.as_str()) {
                                if hostname.ends_with(&domain) {
                                    subdomains.insert(hostname.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if !subdomains.is_empty() {
        let mut results = subdomains.into_iter().collect::<Vec<_>>();
        results.sort();
        let subdomains_str = results.join(", ");
        
        let mut metadata = HashMap::new();
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        metadata.insert("template_id".to_string(), template_id.clone());
        
        findings_list.push(Finding {
            template_id,
            template_name,
            severity: "Info".to_string(),
            target: domain.clone(),
            matched_at: domain.clone(),
            description: Some(format!("discovered_subdomains: {}", subdomains_str)),
            solution: None,
            extracted_data: Some(subdomains_str),
            metadata,
        });
    }

    findings_list
}

// ---------------------------------------------------------------------------
// CT Log Audit
// ---------------------------------------------------------------------------
fn scan_ct_log(input: &WasmInput, target_host: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let domain = input.template.get("domain").and_then(|v| v.as_str()).unwrap_or("").replace("{{Hostname}}", target_host);
    if domain.is_empty() { return vec![]; }
    
    let crtsh_url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let req = HttpRequest::new(&crtsh_url);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 200 {
            if let Ok(body) = String::from_utf8(res.body()) {
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    if let Some(arr) = json.as_array() {
                        let count = arr.len();
                        if count > 0 {
                            let mut metadata = HashMap::new();
                            let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            metadata.insert("template_id".to_string(), template_id.clone());
                            
                            findings_list.push(Finding {
                                template_id,
                                template_name,
                                severity: "Info".to_string(),
                                target: domain.clone(),
                                matched_at: crtsh_url.clone(),
                                description: Some(format!("Found {} certificate log entries.", count)),
                                solution: None,
                                extracted_data: None,
                                metadata,
                            });
                        }
                    }
                }
            }
        }
    }
    findings_list
}

// ---------------------------------------------------------------------------
// Subdomain Takeover
// ---------------------------------------------------------------------------
const VULNERABLE_CNAMES: &[&str] = &[
    "github.io",
    "s3.amazonaws.com",
    "herokuapp.com",
    "azurewebsites.net",
    "elasticbeanstalk.com",
    "cloudfront.net",
];

fn scan_subdomain_takeover(input: &WasmInput, target_host: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let domain = input.template.get("target").and_then(|v| v.as_str()).unwrap_or("").replace("{{Hostname}}", target_host);
    if domain.is_empty() { return vec![]; }

    if let Some(cnames) = valayam_plugin_sdk::host_funcs::resolve_dns(&domain) {
        for cname in &cnames {
            for &vuln in VULNERABLE_CNAMES {
                if cname.contains(vuln) {
                    let mut metadata = HashMap::new();
                    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    metadata.insert("template_id".to_string(), template_id.clone());
                    
                    findings_list.push(Finding {
                        template_id,
                        template_name,
                        severity: "High".to_string(),
                        target: domain.clone(),
                        matched_at: domain.clone(),
                        description: Some(format!("Dangling CNAME record detected pointing to {}. Vulnerable to subdomain takeover.", cname)),
                        solution: None,
                        extracted_data: None,
                        metadata,
                    });
                }
            }
        }
    }
    
    findings_list
}

// ---------------------------------------------------------------------------
// Drift Detect
// ---------------------------------------------------------------------------
fn generate_headers_hash(res: &extism_pdk::http::HttpResponse) -> String {
    let mut header_entries: Vec<String> = Vec::new();
    for (key, value) in res.headers() {
        header_entries.push(format!("{}:{}", key.to_lowercase(), value));
    }
    header_entries.sort();
    let summary = header_entries.join("|");
    format!("{:x}", md5::compute(summary.as_bytes()))
}

fn scan_drift_detect(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let target = input.template.get("target").and_then(|v| v.as_str()).unwrap_or("").replace("{{BaseURL}}", target_url);
    if target.is_empty() { return vec![]; }

    let req = HttpRequest::new(&target);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        let status = res.status_code();
        let headers_hash = generate_headers_hash(&res);
        let body_len = res.body().len();

        let current_state_json = format!(r#"{{"status":{},"headers_hash":"{}","body_len":{}}}"#, status, headers_hash, body_len);
        let state_key = format!("drift:{}", target);

        if let Some(baseline_json) = valayam_plugin_sdk::host_funcs::get_state(&state_key) {
            if let Ok(baseline) = serde_json::from_str::<Value>(&baseline_json) {
                let mut diffs = Vec::new();
                let b_status = baseline.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                if status != b_status {
                    diffs.push(format!("HTTP status code changed: {} -> {}", b_status, status));
                }
                
                let b_hash = baseline.get("headers_hash").and_then(|v| v.as_str()).unwrap_or("");
                if headers_hash != b_hash {
                    diffs.push("HTTP headers structural hash changed".to_string());
                }

                if !diffs.is_empty() {
                    let mut metadata = HashMap::new();
                    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    metadata.insert("template_id".to_string(), template_id.clone());
                    
                    findings_list.push(Finding {
                        template_id,
                        template_name,
                        severity: "Medium".to_string(),
                        target: target.clone(),
                        matched_at: target.clone(),
                        description: Some(format!("Drift detected on target {}:\n{}", target, diffs.join("\n"))),
                        solution: None,
                        extracted_data: None,
                        metadata,
                    });
                }
            }
        }
        valayam_plugin_sdk::host_funcs::set_state(&state_key, &current_state_json);
    }
    
    findings_list
}

// ---------------------------------------------------------------------------
// WAF Bypass Verify
// ---------------------------------------------------------------------------
const BASE_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../../etc/passwd",
    ";cat /etc/passwd",
];

fn scan_waf_bypass(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let target = input.template.get("target").and_then(|v| v.as_str()).unwrap_or("").replace("{{BaseURL}}", target_url);
    if target.is_empty() { return vec![]; }
    
    // Baseline req
    let req = HttpRequest::new(&target);
    let mut baseline_status = 200;
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        baseline_status = res.status_code();
    }

    let mut successful_bypasses = Vec::new();
    
    for payload in BASE_PAYLOADS {
        // Send payload in query parameter
        let url = if target.contains('?') {
            format!("{}&q={}", target, urlencoding::encode(payload))
        } else {
            format!("{}?q={}", target, urlencoding::encode(payload))
        };
        
        let req = HttpRequest::new(&url);
        if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
            let status = res.status_code();
            if status == baseline_status && (status == 200 || status == 302 || status == 404) {
                // If it returns the baseline status (e.g. 200 OK) for an attack payload, it bypassed WAF
                successful_bypasses.push(payload.to_string());
            }
        }
    }
    
    if !successful_bypasses.is_empty() {
        let mut metadata = HashMap::new();
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        metadata.insert("template_id".to_string(), template_id.clone());
        
        findings_list.push(Finding {
            template_id,
            template_name,
            severity: "High".to_string(),
            target: target.clone(),
            matched_at: target.clone(),
            description: Some(format!("WAF Bypass Verification: Successful payloads: {:?}", successful_bypasses)),
            solution: None,
            extracted_data: None,
            metadata,
        });
    }

    findings_list
}

export_plugin!(ReconAuditScanner);
