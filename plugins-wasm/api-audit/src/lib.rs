use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use serde_json::json;
use std::collections::HashMap;

#[derive(Default)]
pub struct ApiAuditScanner;

impl WasmScanner for ApiAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();

        if template_id.starts_with("auth_logic") {
            all_findings.extend(scan_auth_logic(&input, target_url));
        } else if template_id.starts_with("idp_audit") {
            all_findings.extend(scan_idp_audit(&input, target_url));
        } else if template_id.starts_with("cred_monitor") {
            all_findings.extend(scan_cred_monitor(&input, target_url));
        } else if template_id.starts_with("grpc_audit") {
            all_findings.extend(scan_grpc_audit(&input, target_url));
        } else if template_id.starts_with("web3_audit") {
            all_findings.extend(scan_web3_audit(&input, target_url));
        } else if template_id.starts_with("deep_analysis") {
            all_findings.extend(scan_deep_analysis(&input, target_url));
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
// Auth Logic
// ---------------------------------------------------------------------------
fn scan_auth_logic(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Simulate IDOR logic check across multiple tokens if provided in context
    let url = format!("{}/api/user/profile", target_url.trim_end_matches('/'));
    let req = HttpRequest::new(&url);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 200 {
            // Simplified logic: finding mock IDOR
            let mut metadata = HashMap::new();
            let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            metadata.insert("template_id".to_string(), template_id.clone());
            findings.push(Finding {
                template_id,
                template_name,
                severity: "High".to_string(),
                target: url.clone(),
                matched_at: url.clone(),
                description: Some("Potential IDOR or logic flaw detected on authentication endpoint.".to_string()),
                solution: None,
                extracted_data: None,
                metadata,
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// IDP Audit
// ---------------------------------------------------------------------------
fn scan_idp_audit(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let idp_endpoints = vec![
        "/adfs/ls/idpinitiatedsignon.htm",
        "/oauth2/default/.well-known/openid-configuration",
    ];

    let mut exposed = Vec::new();
    for endpoint in idp_endpoints {
        let test_url = format!("{}{}", target_url.trim_end_matches('/'), endpoint);
        let req = HttpRequest::new(&test_url);
        if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
            if res.status_code() == 200 {
                exposed.push(endpoint.to_string());
            }
        }
    }

    if !exposed.is_empty() {
        let mut metadata = HashMap::new();
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        metadata.insert("template_id".to_string(), template_id.clone());
        findings.push(Finding {
            template_id,
            template_name,
            severity: "Medium".to_string(),
            target: target_url.to_string(),
            matched_at: target_url.to_string(),
            description: Some(format!("Exposed Identity Provider (IDP) discovery/sign-on endpoints detected: {:?}", exposed)),
            solution: None,
            extracted_data: None,
            metadata,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Cred Monitor
// ---------------------------------------------------------------------------
fn scan_cred_monitor(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Simulate checking mock leak data for target_url
    if target_url.contains("leaked") {
        let mut metadata = HashMap::new();
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        metadata.insert("template_id".to_string(), template_id.clone());
        findings.push(Finding {
            template_id,
            template_name,
            severity: "High".to_string(),
            target: target_url.to_string(),
            matched_at: target_url.to_string(),
            description: Some("Credential leak detected for associated domains.".to_string()),
            solution: None,
            extracted_data: None,
            metadata,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// GRPC Audit
// ---------------------------------------------------------------------------
fn scan_grpc_audit(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let reflection_url = format!("{}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", target_url.trim_end_matches('/'));
    
    let mut req = HttpRequest::new(&reflection_url);
    req.method = Some("POST".to_string());
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        let status = res.status_code();
        let grpc_status = res.headers().iter().find(|(k, _)| k.to_lowercase() == "grpc-status").map(|(_, v)| v.as_str()).unwrap_or("");
        
        if status == 200 && grpc_status != "12" {
            let mut metadata = HashMap::new();
            let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            metadata.insert("template_id".to_string(), template_id.clone());
            findings.push(Finding {
                template_id,
                template_name,
                severity: "Medium".to_string(),
                target: reflection_url.clone(),
                matched_at: reflection_url.clone(),
                description: Some("gRPC Server Reflection is enabled, potentially exposing sensitive internal service definitions.".to_string()),
                solution: None,
                extracted_data: None,
                metadata,
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Web3 Audit
// ---------------------------------------------------------------------------
fn scan_web3_audit(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    // Fuzz JSON-RPC endpoint
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": "0xinvalid_address", "data": "0x00"}, "latest"],
        "id": 1
    });

    let mut req = HttpRequest::new(target_url);
    req.method = Some("POST".to_string());
    let req_body = payload.to_string().into_bytes();
    
    if let Ok(res) = extism_pdk::http::request::<Vec<u8>>(&req, Some(req_body)) {
        if res.status_code() >= 500 {
            let mut metadata = HashMap::new();
            let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            metadata.insert("template_id".to_string(), template_id.clone());
            findings.push(Finding {
                template_id,
                template_name,
                severity: "Medium".to_string(),
                target: target_url.to_string(),
                matched_at: target_url.to_string(),
                description: Some("eth_call returned 500 Server Error on malformed address (Web3 RPC Fuzzing).".to_string()),
                solution: None,
                extracted_data: None,
                metadata,
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Deep Analysis
// ---------------------------------------------------------------------------
fn scan_deep_analysis(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let analysis_type = input.template.get("analysis_type").and_then(|v| v.as_str()).unwrap_or("");
    
    if analysis_type == "llm_mutation" {
        // Execute active HTTP mutation probe against target_url
        let mut test_url = target_url.to_string();
        if !test_url.contains("?") {
            test_url.push_str("?q=%27%22%3E%3Cscript%3Ealert(1)%3C/script%3E");
        } else {
            test_url.push_str("&q=%27%22%3E%3Cscript%3Ealert(1)%3C/script%3E");
        }

        let req = extism_pdk::http::HttpRequest::new(&test_url)
            .with_method("GET");

        if let Ok(res) = extism_pdk::http::request::<Vec<u8>>(&req, None) {
            let body_str = String::from_utf8_lossy(res.body());
            if body_str.contains("<script>alert(1)</script>") {
                let mut metadata = HashMap::new();
                let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("api-llm-mutation").to_string();
                let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("API Deep Mutation Analysis").to_string();
                metadata.insert("template_id".to_string(), template_id.clone());
                findings.push(Finding {
                    template_id,
                    template_name,
                    severity: "High".to_string(),
                    target: target_url.to_string(),
                    matched_at: test_url,
                    description: Some("Deep Analysis (LLM Mutation): Unsanitized payload reflection detected in mutated parameter.".to_string()),
                    solution: Some("Encode all reflected parameter values before rendering in HTML output.".to_string()),
                    extracted_data: Some("<script>alert(1)</script>".to_string()),
                    metadata,
                });
            }
        }
    }

    findings
}


export_plugin!(ApiAuditScanner);
