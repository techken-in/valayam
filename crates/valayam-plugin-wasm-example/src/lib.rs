use std::collections::HashMap;
use valayam_plugin_sdk::{
    export_plugin, Finding, PluginResult, WasmInput, WasmOutput, WasmScanner,
};

/// Example scanner that performs a basic HTTP health check against the target.
///
/// Demonstrates the WasmScanner trait pattern:
/// 1. Reads target URL from context
/// 2. Sends a GET request via Extism's host HTTP API
/// 3. Reports findings with status code and response metadata
#[derive(Default)]
pub struct HealthCheckScanner;

impl WasmScanner for HealthCheckScanner {
    fn scan(&self, input: WasmInput) -> PluginResult<WasmOutput> {
        let target_url = input
            .context
            .get("BaseURL")
            .map(|s| s.as_str())
            .unwrap_or("");

        let template_id = input
            .template
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("health-check")
            .to_string();

        let template_name = input
            .template
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Health Check")
            .to_string();

        if target_url.is_empty() {
            return Ok(WasmOutput {
                matched: false,
                count: 0,
                findings: vec![],
            });
        }

        let mut req = extism_pdk::HttpRequest::new(target_url);
        req.method = Some("GET".to_string());

        let mut findings = Vec::new();

        match extism_pdk::http::request::<()>(&req, None) {
            Ok(res) => {
                let status = res.status_code();
                let mut metadata = HashMap::new();
                metadata.insert("status_code".to_string(), status.to_string());
                metadata.insert("template_id".to_string(), template_id.clone());

                findings.push(Finding {
                    template_id: template_id.clone(),
                    template_name: template_name.clone(),
                    severity: if status < 400 {
                        "info".into()
                    } else {
                        "medium".into()
                    },
                    target: target_url.to_string(),
                    matched_at: format!("GET {}", target_url),
                    description: Some(format!("HTTP health check returned status {}", status)),
                    solution: Some("Verify the target is healthy and accessible.".to_string()),
                    extracted_data: None,
                    metadata,
                });
            }
            Err(e) => {
                let mut metadata = HashMap::new();
                metadata.insert("template_id".to_string(), template_id.clone());
                metadata.insert("error".to_string(), e.to_string());

                findings.push(Finding {
                    template_id,
                    template_name,
                    severity: "high".into(),
                    target: target_url.to_string(),
                    matched_at: format!("GET {} (failed)", target_url),
                    description: Some(format!("HTTP health check failed to reach target: {}", e)),
                    solution: Some(
                        "Ensure the target is reachable from the scanner network.".to_string(),
                    ),
                    extracted_data: None,
                    metadata,
                });
            }
        }

        let count = findings.len();
        Ok(WasmOutput {
            matched: count > 0,
            count,
            findings,
        })
    }
}

export_plugin!(HealthCheckScanner);
