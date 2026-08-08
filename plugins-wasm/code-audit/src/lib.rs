use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use regex::Regex;

#[derive(Default)]
pub struct CodeAuditScanner;

impl WasmScanner for CodeAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();

        if template_id.starts_with("sast_secrets") {
            let pattern = r#"(?i)(api_key|apikey|secret|password|passwd|pwd|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['""][a-zA-Z0-9/+=]{10,}['""]"#;
            all_findings.extend(scan_sast(&input, pattern, "SAST Secrets", "Critical"));
        } else if template_id.starts_with("sast_taint") {
            let pattern = r"(?i)(execute|eval|exec|system|query)\s*\([^)]*\$";
            all_findings.extend(scan_sast(&input, pattern, "SAST Taint", "High"));
        } else if template_id.starts_with("cicd_audit") {
            all_findings.extend(scan_cicd(&input));
        } else if template_id.starts_with("client_secret_audit") {
            all_findings.extend(scan_client_secret(&input, target_url));
        } else if template_id.starts_with("sbom_audit") {
            all_findings.extend(scan_sbom(&input, target_url));
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
// SAST Secrets & Taint
// ---------------------------------------------------------------------------
fn scan_sast(input: &WasmInput, pattern_str: &str, finding_prefix: &str, severity: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let dir_val = input.template.get("target_dir").and_then(|v| v.as_str()).unwrap_or(".");
    let dir_path = Path::new(dir_val);

    if !dir_path.exists() || !dir_path.is_dir() {
        return vec![];
    }

    if let Ok(pattern) = Regex::new(pattern_str) {
        let mut dirs = vec![dir_path.to_path_buf()];
        let mut findings = Vec::new();

        while let Some(current_dir) = dirs.pop() {
            if let Ok(entries) = fs::read_dir(&current_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        dirs.push(path);
                    } else if let Ok(content) = fs::read_to_string(&path) {
                        for (i, line) in content.lines().enumerate() {
                            if pattern.is_match(line) {
                                findings.push(format!("{}:{} -> {}", path.display(), i + 1, line.trim()));
                            }
                        }
                    }
                }
            }
        }

        if !findings.is_empty() {
            let mut metadata = HashMap::new();
            metadata.insert("template_id".to_string(), input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string());
            let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            findings_list.push(Finding {
                template_id,
                template_name,
                severity: severity.to_string(),
                target: dir_val.to_string(),
                matched_at: dir_val.to_string(),
                description: Some(format!("{}: Found {} issues in source files.", finding_prefix, findings.len())),
                solution: None,
                extracted_data: None,
                metadata,
            });
        }
    }
    findings_list
}

// ---------------------------------------------------------------------------
// CI/CD Audit
// ---------------------------------------------------------------------------
fn scan_cicd(input: &WasmInput) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let dir_val = input.template.get("target_repo").and_then(|v| v.as_str()).unwrap_or(".");
    let dir_path = Path::new(dir_val);

    if !dir_path.exists() {
        return vec![];
    }

    let workflows_dir = dir_path.join(".github").join("workflows");
    if workflows_dir.exists() && workflows_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(workflows_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "yml" || ext == "yaml" {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if content.contains("pull_request_target:") && content.contains("checkout") {
                                let mut metadata = HashMap::new();
                                metadata.insert("template_id".to_string(), input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string());
                                let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                findings_list.push(Finding {
                                    template_id,
                                    template_name,
                                    severity: "High".to_string(),
                                    target: path.to_string_lossy().to_string(),
                                    matched_at: path.to_string_lossy().to_string(),
                                    description: Some("CI/CD Audit: GitHub Action workflow uses 'pull_request_target' with 'actions/checkout', which is vulnerable to malicious PRs (Pwn Request).".to_string()),
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
    }
    findings_list
}

// ---------------------------------------------------------------------------
// Client Secret Audit
// ---------------------------------------------------------------------------
fn scan_client_secret(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let target = input.template.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let host = target.replace("{{Hostname}}", target_url);
    if host.is_empty() { return vec![]; }

    let req = HttpRequest::new(&host);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 200 {
            if let Ok(body) = String::from_utf8(res.body()) {
                let pattern_str = r#"(?i)(api_key|apikey|secret|password|passwd|pwd|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['""][a-zA-Z0-9/+=]{10,}['""]"#;
                if let Ok(secret_re) = Regex::new(pattern_str) {
                    if secret_re.is_match(&body) {
                        let mut metadata = HashMap::new();
                        metadata.insert("template_id".to_string(), input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string());
                        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        findings_list.push(Finding {
                            template_id,
                            template_name,
                            severity: "High".to_string(),
                            target: host.clone(),
                            matched_at: host.clone(),
                            description: Some("Hardcoded client secret or API token found in client-side bundle response.".to_string()),
                            solution: None,
                            extracted_data: None,
                            metadata,
                        });
                    }
                }
            }
        }
    }
    findings_list
}

// ---------------------------------------------------------------------------
// SBOM Audit / OSV.dev
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PackageEntry {
    name: String,
    version: Option<String>,
}

fn detect_ecosystem_from_file(file_name: &str) -> &'static str {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with("package.json") || lower.ends_with("package-lock.json") || lower.ends_with("yarn.lock") {
        "npm"
    } else if lower.ends_with("cargo.toml") || lower.ends_with("cargo.lock") {
        "crates.io"
    } else if lower.ends_with("requirements.txt") || lower.ends_with("setup.py") || lower.ends_with("pyproject.toml") {
        "PyPI"
    } else {
        ""
    }
}

fn parse_packages(body: &str, file_type: &str) -> Vec<PackageEntry> {
    let mut packages = Vec::new();
    let lower = file_type.to_ascii_lowercase();
    if lower.contains("package.json") {
        if let Ok(json) = serde_json::from_str::<Value>(body) {
            if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
                for (name, val) in deps {
                    let version = val.as_str().map(|s| s.trim_start_matches('^').trim_start_matches('~').to_string());
                    packages.push(PackageEntry { name: name.clone(), version });
                }
            }
        }
    } else if lower.contains("cargo.toml") {
        if let Ok(toml_value) = toml::from_str::<toml::Value>(body) {
            if let Some(deps) = toml_value.get("dependencies").and_then(|v| v.as_table()) {
                for (name, value) in deps {
                    let version = match value {
                        toml::Value::String(s) => Some(s.clone()),
                        toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        _ => None,
                    };
                    packages.push(PackageEntry { name: name.clone(), version });
                }
            }
        }
    } else if lower.contains("requirements.txt") {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') { continue; }
            let separators = &["==", ">=", "<=", "!=", "~=", ">", "<"];
            if let Some((name, version)) = separators.iter().find_map(|sep| {
                line.split_once(sep).map(|(n, v)| (n.trim(), v.trim()))
            }) {
                let version = version.split('#').next().unwrap_or(version).trim();
                let version = version.split(" --").next().unwrap_or(version).trim();
                packages.push(PackageEntry { name: name.to_string(), version: Some(version.to_string()) });
            } else {
                packages.push(PackageEntry { name: line.to_string(), version: None });
            }
        }
    }
    packages
}

#[derive(Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
}

fn scan_sbom(input: &WasmInput, target_url: &str) -> Vec<Finding> {
    let mut findings_list = Vec::new();
    let target = input.template.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let host = target.replace("{{Hostname}}", target_url);
    if host.is_empty() { return vec![]; }
    
    let base = host.trim_end_matches('/');
    let file_type = input.template.get("type").and_then(|v| v.as_str()).unwrap_or("").trim_start_matches('/');
    let url = format!("{}/{}", base, file_type);

    let req = HttpRequest::new(&url);
    if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
        if res.status_code() == 200 {
            if let Ok(body) = String::from_utf8(res.body()) {
                let packages = parse_packages(&body, file_type);
                if packages.is_empty() { return vec![]; }
                
                let ecosystem = detect_ecosystem_from_file(file_type);
                let mut total_cves = 0;
                
                for pkg in &packages {
                    let req_body = OsvQueryRequest {
                        package: OsvPackage {
                            name: pkg.name.clone(),
                            ecosystem: if ecosystem.is_empty() { None } else { Some(ecosystem.to_string()) },
                        },
                        version: pkg.version.clone(),
                    };
                    let osv_url = "https://api.osv.dev/v1/query";
                    let mut osv_req = HttpRequest::new(osv_url).with_method("POST");
                    osv_req.headers.insert("Content-Type".to_string(), "application/json".to_string());
                    
                    let json_bytes = serde_json::to_vec(&req_body).unwrap_or_default();
                    if let Ok(osv_res) = extism_pdk::http::request(&osv_req, Some(json_bytes)) {
                        if osv_res.status_code() == 200 {
                            if let Ok(osv_body) = String::from_utf8(osv_res.body()) {
                                if let Ok(json) = serde_json::from_str::<Value>(&osv_body) {
                                    if let Some(vulns) = json.get("vulns").and_then(|v| v.as_array()) {
                                        total_cves += vulns.len();
                                    }
                                }
                            }
                        }
                    }
                }
                
                if total_cves > 0 {
                    let mut metadata = HashMap::new();
                    metadata.insert("template_id".to_string(), input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string());
                    metadata.insert("::tags".to_string(), "sbom,cve,vulnerable".to_string());
                    metadata.insert("recon".to_string(), "SBOM".to_string());
                    
                    let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let template_name = input.template.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    findings_list.push(Finding {
                        template_id,
                        template_name,
                        severity: "High".to_string(),
                        target: url.clone(),
                        matched_at: url.clone(),
                        description: Some(format!("SBOM audit: {} package(s) analyzed, {} CVE(s) found.", packages.len(), total_cves)),
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

export_plugin!(CodeAuditScanner);
