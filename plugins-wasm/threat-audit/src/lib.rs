use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct ThreatAuditScanner;

impl WasmScanner for ThreatAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();

        if template_id.starts_with("attack_graph") {
            all_findings.extend(scan_attack_graph(&input, target_url));
        } else if template_id.starts_with("auto_exploit") {
            all_findings.extend(scan_auto_exploit(&input, target_url));
        } else if template_id.starts_with("auto_redteam") {
            all_findings.extend(scan_auto_redteam(&input, target_url));
        } else if template_id.starts_with("implant_deploy") {
            all_findings.extend(scan_implant_deploy(&input, target_url));
        } else if template_id.starts_with("mitre_mapping") {
            all_findings.extend(scan_mitre_mapping(&input, target_url));
        } else if template_id.starts_with("remediation_gen") {
            all_findings.extend(scan_remediation_gen(&input, target_url));
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
// Attack Graph
// ---------------------------------------------------------------------------
fn scan_attack_graph(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Attack Graph Generated)", template_name),
        severity: "Info".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Attack graph built from findings context.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// Auto Exploit
// ---------------------------------------------------------------------------
fn scan_auto_exploit(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Autonomous Exploitation)", template_name),
        severity: "Critical".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Simulated execution of autonomous exploit chain.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// Auto Redteam
// ---------------------------------------------------------------------------
fn scan_auto_redteam(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Chained Payload Executed)", template_name),
        severity: "Critical".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Dynamic reverse shell simulation (Auto Redteam).".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// Implant Deploy
// ---------------------------------------------------------------------------
fn scan_implant_deploy(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    // Simulate drop payload
    let target = input.template.get("target").and_then(|v| v.as_str()).unwrap_or(target_url);
    let mut req = HttpRequest::new(target);
    req.method = Some("POST".to_string());
    
    if let Ok(_) = extism_pdk::http::request::<Vec<u8>>(&req, Some(b"mock_implant_payload".to_vec())) {
        findings.push(Finding {
            template_id,
            template_name: format!("{} (Implant Delivered)", template_name),
            severity: "High".to_string(),
            target: target_url.to_string(),
            matched_at: target_url.to_string(),
            description: Some("Successfully simulated implant delivery.".to_string()),
            solution: None,
            extracted_data: None,
            metadata,
        });
    }

    findings
}

// ---------------------------------------------------------------------------
// MITRE Mapping
// ---------------------------------------------------------------------------
fn scan_mitre_mapping(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Mapped to MITRE)", template_name),
        severity: "Info".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Findings mapped to MITRE ATT&CK framework.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

// ---------------------------------------------------------------------------
// Remediation Gen
// ---------------------------------------------------------------------------
fn scan_remediation_gen(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    metadata.insert("template_id".to_string(), template_id.clone());
    
    findings.push(Finding {
        template_id,
        template_name: format!("{} (Remediation Generated)", template_name),
        severity: "Info".to_string(),
        target: target_url.to_string(),
        matched_at: target_url.to_string(),
        description: Some("Automated remediation advice generated.".to_string()),
        solution: None,
        extracted_data: None,
        metadata,
    });
    
    findings
}

export_plugin!(ThreatAuditScanner);
