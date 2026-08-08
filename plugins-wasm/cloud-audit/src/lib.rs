use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct CloudAuditScanner;

impl WasmScanner for CloudAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let template_name = input.template.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or("Cloud/Container Audit").to_string();
        
        // We'll read the target URL directly from the context.
        let target_url = input.context.get("BaseURL").cloned().unwrap_or_else(|| "http://localhost".to_string());
        let target_url = target_url.trim_end_matches('/');

        // Determine which cloud/container probes to run based on template metadata or ID
        let mut severity = "High";
        
        // 1. Check Docker API
        if template_id.contains("docker") || template_id.contains("container") {
            let docker_url = format!("{}/containers/json", target_url);
            let req = HttpRequest::new(&docker_url).with_method("GET");
            if let Ok(resp) = extism_pdk::http::request::<()>(&req, None) {
                if resp.status_code() == 200 {
                    let body_bytes = resp.body();
                    let body = String::from_utf8_lossy(&body_bytes);
                    if body.contains("\"Id\"") && body.contains("\"Image\"") {
                        findings.push(format!("Exposed Docker Socket API Detected at {}", docker_url));
                        severity = "Critical";
                    }
                }
            }
        }
        
        // 2. Check Kubernetes Kubelet
        if template_id.contains("k8s") || template_id.contains("kubelet") {
            let kubelet_url = format!("{}/pods", target_url);
            let req = HttpRequest::new(&kubelet_url).with_method("GET");
            if let Ok(resp) = extism_pdk::http::request::<()>(&req, None) {
                if resp.status_code() == 200 {
                    let body_bytes = resp.body();
                    let body = String::from_utf8_lossy(&body_bytes);
                    if body.contains("\"kind\":\"PodList\"") {
                        findings.push(format!("Exposed Kubernetes Kubelet API Detected (Pods list readable) at {}", kubelet_url));
                        severity = "Critical";
                    }
                }
            }
        }

        // 3. AWS SSRF Escalate check
        if template_id.contains("aws") || template_id.contains("ssrf") {
            let payload_url = "http://169.254.169.254/latest/meta-data/";
            let test_url = format!("{}?url={}", target_url, urlencode(payload_url));
            let req = HttpRequest::new(&test_url).with_method("GET");
            if let Ok(resp) = extism_pdk::http::request::<()>(&req, None) {
                if resp.status_code() == 200 {
                    let body_bytes = resp.body();
                    let body = String::from_utf8_lossy(&body_bytes);
                    if body.contains("ami-id") && body.contains("instance-id") {
                        findings.push(format!("AWS Escalate: SSRF vulnerability leading to AWS IMDSv1 metadata exposure detected at {}", test_url));
                        severity = "Critical";
                    }
                }
            }
        }

        // 4. GCP SSRF Escalate check
        if template_id.contains("gcp") || template_id.contains("ssrf") {
            let payload_url = "http://metadata.google.internal/computeMetadata/v1/";
            let test_url = format!("{}?url={}", target_url, urlencode(payload_url));
            let req = HttpRequest::new(&test_url).with_method("GET");
            if let Ok(resp) = extism_pdk::http::request::<()>(&req, None) {
                if resp.status_code() == 200 {
                    let body_bytes = resp.body();
                    let body = String::from_utf8_lossy(&body_bytes);
                    if body.contains("instance/") || body.contains("project/") {
                        findings.push(format!("GCP Escalate: SSRF vulnerability leading to GCP metadata exposure detected at {}", test_url));
                        severity = "Critical";
                    }
                }
            }
        }

        // Output findings
        let out_findings = if !findings.is_empty() {
            let mut f = Finding {
                template_id,
                template_name,
                severity: severity.to_string(),
                target: target_url.to_string(),
                matched_at: target_url.to_string(),
                description: Some(findings.join("\n")),
                solution: Some("Restrict access to cloud metadata services, secure container sockets, and validate all user-supplied URLs to prevent SSRF.".to_string()),
                extracted_data: None,
                metadata: HashMap::new(),
            };
            f.metadata.insert("category".to_string(), "Cloud/Container Security".to_string());
            vec![f]
        } else {
            Vec::new()
        };

        Ok(WasmOutput {
            matched: !out_findings.is_empty(),
            count: out_findings.len(),
            findings: out_findings,
        })
    }
}

// Extism HTTP utilities do not have urlencode built in, we implement a simple one here.
mod extism_pdk_http_ext {
    pub fn urlencode(s: &str) -> String {
        let mut encoded = String::with_capacity(s.len() * 3);
        for byte in s.bytes() {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                b' ' => encoded.push('+'),
                _ => encoded.push_str(&format!("%{:02X}", byte)),
            }
        }
        encoded
    }
}
use extism_pdk_http_ext::urlencode;

export_plugin!(CloudAuditScanner);
