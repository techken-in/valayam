use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner, PluginResult};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::WithReturnCode<extism_pdk::Error>> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("BaseURL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();
        let base_url = target_url.trim_end_matches('/');

        // Checking common SBOM paths
        let endpoints = vec!["/sbom.json", "/bom.json", "/.well-known/sbom", "/cyclonedx.json", "/spdx.json"];

        for ep in endpoints {
            let w_url = format!("{}{}", base_url, ep);
            let mut req = HttpRequest::new(&w_url);
            req.method = Some("GET".to_string());
            
            if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
                let status = res.status_code();
                if status == 200 {
                    let mut metadata = HashMap::new();
                    metadata.insert("template_id".to_string(), template_id.clone());
                    
                    all_findings.push(Finding {
                        template_id: template_id.clone(),
                        template_name: format!("{} (SBOM Exposure)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("SBOM Audit")),
                        severity: "Low".to_string(),
                        target: target_url.to_string(),
                        matched_at: w_url.clone(),
                        description: Some("Software Bill of Materials (SBOM) file is publicly exposed. This reveals internal library versions which could assist an attacker.".to_string()),
                        solution: Some("Restrict public access to SBOM files.".to_string()),
                        extracted_data: None,
                        metadata,
                    });
                    break;
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
