use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner, PluginResult};
use extism_pdk::*;
use lazy_static::lazy_static;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// CSP directive knowledge base (const data, no runtime mutability)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CspDirectiveCheck {
    pub directive: &'static str,
    pub label: &'static str,
    pub severity_if_missing: Option<&'static str>,
    pub cvss_if_missing: Option<f32>,
    pub severity_if_weak: Option<&'static str>,
    pub cvss_if_weak: Option<f32>,
    pub weak_patterns: &'static [&'static str],
    pub exempting_patterns: &'static [&'static str],
    pub cwe: &'static str,
    pub _solution: &'static str,
    pub _reference: &'static str,
}

const DIRECTIVE_CHECKS: &[CspDirectiveCheck] = &[
    CspDirectiveCheck {
        directive: "script-src",
        label: "script-src allows unsafe inline scripts or has wildcard sources",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(5.0),
        severity_if_weak: Some("Critical"),
        cvss_if_weak: Some(9.0),
        weak_patterns: &["*", "'unsafe-inline'", "'unsafe-eval'"],
        exempting_patterns: &["'nonce-", "'sha256-", "'sha384-", "'sha512-"],
        cwe: "CWE-79",
        _solution: "Specify strict script-src: use nonces or hashes instead of 'unsafe-inline'. Avoid wildcards.",
        _reference: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    },
    CspDirectiveCheck {
        directive: "object-src",
        label: "object-src is missing or allows all sources (plugins enabled)",
        severity_if_missing: Some("High"),
        cvss_if_missing: Some(7.0),
        severity_if_weak: Some("High"),
        cvss_if_weak: Some(7.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'none'"],
        cwe: "CWE-1024",
        _solution: "Set object-src 'none' to disable plugin execution (Flash, Java applets).",
        _reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src",
    },
    CspDirectiveCheck {
        directive: "base-uri",
        label: "base-uri is not restricted (open to base tag injection)",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(5.0),
        severity_if_weak: Some("Medium"),
        cvss_if_weak: Some(5.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'none'", "'self'"],
        cwe: "CWE-20",
        _solution: "Restrict base-uri to 'self' or a specific origin to prevent base tag injection.",
        _reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri",
    },
    CspDirectiveCheck {
        directive: "frame-ancestors",
        label: "frame-ancestors is missing (vulnerable to clickjacking)",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(6.0),
        severity_if_weak: Some("Medium"),
        cvss_if_weak: Some(6.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'none'", "'self'"],
        cwe: "CWE-1021",
        _solution: "Add frame-ancestors 'self' or 'none' to prevent clickjacking attacks.",
        _reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
    },
    CspDirectiveCheck {
        directive: "form-action",
        label: "form-action is not restricted (forms can submit to any origin)",
        severity_if_missing: Some("Low"),
        cvss_if_missing: Some(4.0),
        severity_if_weak: Some("Low"),
        cvss_if_weak: Some(4.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'self'", "'none'"],
        cwe: "CWE-345",
        _solution: "Restrict form-action to 'self' or a specific endpoint to limit form submission targets.",
        _reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action",
    },
    CspDirectiveCheck {
        directive: "upgrade-insecure-requests",
        label: "upgrade-insecure-requests is missing (mixed content not auto-upgraded)",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(4.0),
        severity_if_weak: None,
        cvss_if_weak: None,
        weak_patterns: &[],
        exempting_patterns: &[],
        cwe: "CWE-319",
        _solution: "Add 'upgrade-insecure-requests' directive to automatically upgrade HTTP resources to HTTPS.",
        _reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests",
    },
    CspDirectiveCheck {
        directive: "block-all-mixed-content",
        label: "block-all-mixed-content is missing",
        severity_if_missing: Some("Low"),
        cvss_if_missing: Some(3.0),
        severity_if_weak: None,
        cvss_if_weak: None,
        weak_patterns: &[],
        exempting_patterns: &[],
        cwe: "CWE-319",
        _solution: "Add 'block-all-mixed-content' directive to prevent mixed content loading.",
        _reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content",
    },
];

impl CspDirectiveCheck {
    fn is_exempted(&self, value: &str) -> bool {
        self.exempting_patterns.iter().any(|p| value.contains(p))
    }
    fn has_weak_pattern(&self, value: &str) -> bool {
        self.weak_patterns.iter().any(|p| value.contains(p))
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

lazy_static! {
    static ref META_CSP_HTTP_EQUIV: Regex = Regex::new(
        r#"(?i)<meta\s[^>]*http-equiv\s*=\s*['"]content-security-policy['"][^>]*>"#
    ).expect("Valid CSP meta-tag regex");
}

fn parse_csp(csp_str: &str) -> HashMap<String, String> {
    let mut directives: HashMap<String, String> = HashMap::new();
    for part in csp_str.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(pos) = trimmed.find(char::is_whitespace) {
            let name = trimmed[..pos].trim().to_lowercase();
            let value = trimmed[pos + 1..].trim().to_string();
            if !name.is_empty() {
                directives.insert(name, value);
            }
        } else {
            directives.insert(trimmed.to_lowercase(), String::new());
        }
    }
    directives
}

fn extract_csp_from_meta(html: &str) -> Vec<String> {
    let mut results = Vec::new();
    let document = Html::parse_document(html);

    if let Ok(selector) = Selector::parse("meta[http-equiv='Content-Security-Policy']") {
        for element in document.select(&selector) {
            if let Some(content) = element.value().attr("content") {
                results.push(content.to_string());
            }
        }
    }

    for cap in META_CSP_HTTP_EQUIV.captures_iter(html) {
        let full_tag = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        if let Some(content) = extract_meta_content(full_tag) {
            if !results.iter().any(|r| r == content) {
                results.push(content.to_string());
            }
        }
    }

    results
}

fn extract_meta_content(meta_tag: &str) -> Option<&str> {
    lazy_static! {
        static ref CONTENT_RE: Regex = Regex::new(
            r#"content\s*=\s*(?:"([^"]*)"|'([^']*)')"#
        ).expect("Valid content attribute regex");
    }
    CONTENT_RE.captures(meta_tag).and_then(|cap| {
        cap.get(1).or_else(|| cap.get(2)).map(|m| m.as_str())
    })
}

#[derive(Default)]
pub struct CspAuditScanner;

impl WasmScanner for CspAuditScanner {
    fn scan(&self, input: WasmInput) -> PluginResult<WasmOutput> {

        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let template_name = input.template.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or("CSP Audit").to_string();
        
        let target = input.context.get("BaseURL").cloned().unwrap_or_else(|| "http://localhost".to_string());

        let req = HttpRequest::new(&target).with_method("GET");
        let res = match extism_pdk::http::request::<()>(&req, None) {
            Ok(r) => r,
            Err(_) => return Ok(WasmOutput { matched: false, count: 0, findings: vec![] }),
        };
        
        let res_headers = res.headers();
        let body_bytes = res.body();

        let mut header_csp = Vec::new();
        if let Some(csp) = res_headers.get("content-security-policy") {
            header_csp.push(csp.clone());
        }
        
        let mut report_only_csp = Vec::new();
        if let Some(csp) = res_headers.get("content-security-policy-report-only") {
            report_only_csp.push(csp.clone());
        }

        let body_str = String::from_utf8_lossy(&body_bytes);
        let meta_csp = extract_csp_from_meta(&body_str);

        let all_csp_strings: Vec<String> = header_csp.into_iter().chain(report_only_csp).chain(meta_csp).collect();

        if all_csp_strings.is_empty() {
            let mut metadata = HashMap::new();
            metadata.insert("::cvss_score".to_string(), "8.0".to_string());
            metadata.insert("::reference".to_string(), "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string());
            metadata.insert("::tags".to_string(), "csp,missing-header".to_string());
            metadata.insert("owasp".to_string(), "OWASP-XXE-1".to_string());
            metadata.insert("cwe".to_string(), "CWE-693".to_string());
            metadata.insert("severity".to_string(), "High (CVSS: 8.0)".to_string());

            return Ok(WasmOutput {
                matched: true,
                count: 1,
                findings: vec![Finding {
                    template_id,
                    template_name,
                    severity: "High".to_string(),
                    target,
                    matched_at: "Content Security Policy (CSP) header is missing entirely. The application is vulnerable to XSS and data injection attacks without a defense-in-depth layer.".to_string(),
                    description: Some("Content Security Policy (CSP) header is missing entirely.".to_string()),
                    solution: Some("Implement a Content Security Policy using the strictest possible directives.".to_string()),
                    extracted_data: None,
                    metadata,
                }],
            });
        }

        let mut findings: Vec<(String, String, f32)> = Vec::new();
        let mut worst_severity: u8 = 0;
        let mut worst_severity_label = "Info".to_string();

        for csp_str in &all_csp_strings {
            let directives = parse_csp(csp_str);
            for check in DIRECTIVE_CHECKS {
                match directives.get(check.directive) {
                    None => {
                        if let Some(sev) = check.severity_if_missing {
                            if let Some(cvss) = check.cvss_if_missing {
                                let rank = severity_rank(sev);
                                if rank > worst_severity {
                                    worst_severity = rank;
                                    worst_severity_label = sev.to_string();
                                }
                                findings.push((format!("Missing '{}' directive — {}", check.directive, check.label), check.cwe.to_string(), cvss));
                            }
                        }
                    }
                    Some(val) => {
                        if check.is_exempted(val) { continue; }
                        if check.has_weak_pattern(val) {
                            if let Some(sev) = check.severity_if_weak {
                                if let Some(cvss) = check.cvss_if_weak {
                                    let rank = severity_rank(sev);
                                    if rank > worst_severity {
                                        worst_severity = rank;
                                        worst_severity_label = sev.to_string();
                                    }
                                    let weak_keywords: Vec<&str> = check.weak_patterns.iter().filter(|p| val.contains(*p)).copied().collect();
                                    findings.push((format!("'{}' directive contains weak keyword(s) {:?} — {}", check.directive, weak_keywords, check.label), check.cwe.to_string(), cvss));
                                }
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            return Ok(WasmOutput { matched: false, count: 0, findings: vec![] });
        }

        let csp_source_info = if all_csp_strings.len() == 1 { "1 CSP source".to_string() } else { format!("{} CSP sources", all_csp_strings.len()) };
        let payload_lines: Vec<String> = findings.iter().map(|(label, cwe, cvss)| format!("[{}] (CVSS: {:.1}) {}", cwe, cvss, label)).collect();
        let payload = format!("CSP Audit found {} issue(s) across {}:\n{}", findings.len(), csp_source_info, payload_lines.join("\n"));
        let worst_cvss = findings.iter().map(|(_, _, cvss)| *cvss).fold(0.0f32, f32::max);
        
        let cwe_set: std::collections::BTreeSet<&str> = findings.iter().map(|(_, cwe, _)| cwe.as_str()).collect();
        let cwe_list: Vec<&str> = cwe_set.into_iter().collect();

        let mut metadata = HashMap::new();
        metadata.insert("::cvss_score".to_string(), worst_cvss.to_string());
        metadata.insert("::reference".to_string(), "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string());
        metadata.insert("::tags".to_string(), format!("csp,finding-count:{}", findings.len()));
        metadata.insert("csp-issues".to_string(), findings.len().to_string());
        metadata.insert("cwe".to_string(), cwe_list.join(", "));

        let finding_obj = Finding {
            template_id,
            template_name,
            severity: worst_severity_label,
            target,
            matched_at: payload.clone(),
            description: Some(payload),
            solution: Some("Review each CSP directive highlighted above. Use strict directives: script-src with nonces/hashes, object-src 'none', base-uri 'self', frame-ancestors 'self', form-action 'self', and add upgrade-insecure-requests together with block-all-mixed-content.".to_string()),
            extracted_data: None,
            metadata,
        };

        Ok(WasmOutput {
            matched: true,
            count: 1,
            findings: vec![finding_obj],
        })
    }
}

export_plugin!(CspAuditScanner);
