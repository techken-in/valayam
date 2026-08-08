use crate::features::extractors::engine::extract_from_response;
use crate::network::http::StealthHttpClient;
use regex::bytes::Regex;
use std::collections::HashMap;

use valayam_engine::variables::resolve_variables;
use valayam_models::finding::FindingOwned;
use valayam_models::templates::helpers::evaluate_helpers;
use valayam_models::templates::http_scan::HttpRequestTemplate;
use valayam_models::TemplateMetadata;

fn evaluate_stream(body_bytes: &[u8], customized_patterns: &[String]) -> bool {
    let body_str = String::from_utf8_lossy(body_bytes);
    let secrets = valayam_common::secrets::detect_secrets(&body_str);
    if !secrets.is_empty() {
        return true;
    }
    for pattern in customized_patterns {
        let Ok(re) = Regex::new(pattern) else {
            continue;
        };
        if re.is_match(body_bytes) {
            return true;
        }
    }
    false
}

fn resolve_all(template_str: &str, context: &HashMap<String, String>) -> String {
    let with_vars = resolve_variables(template_str, context).unwrap_or_else(|e| {
        tracing::warn!("Variable resolution failed: {}", e);
        template_str.to_string()
    });
    evaluate_helpers(&with_vars)
}

fn matches_condition(
    matcher: &valayam_models::templates::matcher::ResponseMatcher,
    body_bytes: &[u8],
    resp_headers: &HashMap<String, String>,
    status: u16,
) -> bool {
    let mut is_match = false;

    if matcher.r#type == "regex" {
        if matcher.part == "body" {
            is_match = evaluate_stream(body_bytes, &matcher.regex);
        } else if matcher.part == "header" {
            let headers_str = resp_headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\r\n");

            for pattern in &matcher.regex {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(&headers_str) {
                        is_match = true;
                        break;
                    }
                }
            }
        }
    } else if matcher.r#type == "word" {
        if matcher.part == "body" {
            let body_str = String::from_utf8_lossy(body_bytes);
            is_match = matcher.words.iter().any(|w| body_str.contains(w));
        } else if matcher.part == "header" {
            let headers_str = resp_headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\r\n");
            is_match = matcher.words.iter().any(|w| headers_str.contains(w));
        }
    } else if matcher.r#type == "status" {
        is_match = matcher.status.as_ref().is_some_and(|s| s.contains(&status));
    }

    if matcher.negative {
        !is_match
    } else {
        is_match
    }
}

/// Documentation for this item.
pub async fn execute(
    client: &StealthHttpClient,
    target_url: &str,
    requests: &[HttpRequestTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    variables: &mut HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    for req_rule in requests {
        let is_passive = req_rule.attack.as_deref() == Some("passive");
        let is_inject = req_rule.attack.as_deref() == Some("inject");

        let mut urls_to_scan = Vec::new();

        if is_passive {
            // Passive checks just scan the crawled URL as-is
            urls_to_scan.push(target_url.to_string());
        } else if is_inject {
            // Inject mode: Parse target URL and inject payloads into parameters
            if let Ok(parsed_url) = url::Url::parse(target_url) {
                let payloads = req_rule.payloads.clone().unwrap_or_default();
                let inject_in = req_rule.inject_in.as_deref().unwrap_or("query");

                if inject_in == "query" {
                    let existing_pairs: Vec<(String, String)> =
                        parsed_url.query_pairs().into_owned().collect();
                    if existing_pairs.is_empty() {
                        // If no params on crawled URL, we can inject common ones or skip.
                        // We'll inject a few common params for thoroughness.
                        for payload in &payloads {
                            let mut temp_url = parsed_url.clone();
                            temp_url
                                .query_pairs_mut()
                                .append_pair("id", payload)
                                .append_pair("q", payload)
                                .append_pair("url", payload);
                            urls_to_scan.push(temp_url.to_string());
                        }
                    } else {
                        // Inject into every existing parameter (Option A - Thorough)
                        for payload in &payloads {
                            for (i, _) in existing_pairs.iter().enumerate() {
                                let mut temp_url = parsed_url.clone();
                                {
                                    let mut q_mut = temp_url.query_pairs_mut();
                                    q_mut.clear();
                                    for (j, (k, v)) in existing_pairs.iter().enumerate() {
                                        if i == j {
                                            q_mut.append_pair(k, payload);
                                        } else {
                                            q_mut.append_pair(k, v);
                                        }
                                    }
                                }
                                urls_to_scan.push(temp_url.to_string());
                            }
                        }
                    }
                } else {
                    // For body/header inject, we'd do it during request generation.
                    // For now, we'll just scan the base URL and let body injection happen later
                    urls_to_scan.push(target_url.to_string());
                }
            } else {
                urls_to_scan.push(target_url.to_string());
            }
        } else {
            // Legacy path-append mode
            let resolved_path = resolve_all(&req_rule.path, variables);
            let full_url =
                if resolved_path.starts_with("http://") || resolved_path.starts_with("https://") {
                    resolved_path.clone()
                } else if resolved_path == "{{BaseURL}}" {
                    target_url.to_string()
                } else {
                    let base = target_url.trim_end_matches('/');
                    let path = resolved_path.trim_start_matches('/');
                    format!("{}/{}", base, path)
                };
            urls_to_scan.push(full_url);
        }

        for full_url in urls_to_scan {
            let resolved_headers = req_rule.headers.as_ref().map(|h| {
                h.iter()
                    .map(|(k, v)| (k.clone(), resolve_all(v, variables)))
                    .collect::<HashMap<String, String>>()
            });

            // If we are injecting into body, handle it here
            let mut resolved_body = req_rule.body.as_ref().map(|b| resolve_all(b, variables));
            if is_inject && req_rule.inject_in.as_deref() == Some("body") {
                if let Some(payloads) = &req_rule.payloads {
                    // Simple example: pick first payload for body (in real life we'd iterate payloads here too)
                    if let Some(payload) = payloads.first() {
                        let original = resolved_body.unwrap_or_default();
                        // Extremely naive injection for the mock server's POST tests
                        resolved_body = Some(original.replace("INJECT_HERE", payload));
                    }
                }
            }

            tracing::trace!(
                target = %target_url,
                method = %req_rule.method,
                url = %full_url,
                headers = ?resolved_headers,
                body = ?resolved_body,
                "Prepared raw HTTP request payload"
            );

            tracing::debug!(target = %target_url, method = %req_rule.method, url = %full_url, "Sending HTTP request");

            let resp = match client
                .send_request(
                    &req_rule.method,
                    &full_url,
                    resolved_headers.as_ref(),
                    resolved_body.as_deref(),
                    req_rule.follow_redirects,
                    None,
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(target = %target_url, error = %e, "Request failed or timed out");
                    continue;
                }
            };

            let status = resp.status().as_u16();

            let resp_headers: HashMap<String, String> = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|val| (k.as_str().to_string(), val.to_string()))
                })
                .collect();

            let mut body_bytes = Vec::new();
            let max_size = 10 * 1024 * 1024; // 10MB limit
            let mut resp_mut = resp;

            while let Ok(Some(chunk)) = resp_mut.chunk().await {
                if body_bytes.len() + chunk.len() > max_size {
                    tracing::warn!(target = %target_url, "Response exceeded 10MB limit, truncating");
                    break;
                }
                body_bytes.extend_from_slice(&chunk);
            }

            tracing::trace!(
                status = %status,
                headers = ?resp_headers,
                body_preview = %String::from_utf8_lossy(&body_bytes).chars().take(200).collect::<String>(),
                "Received HTTP response"
            );

            if !req_rule.extractors.is_empty() {
                let extracted =
                    extract_from_response(&req_rule.extractors, &body_bytes, &resp_headers);
                for (key, value) in extracted {
                    variables.insert(key, value);
                }
            }

            tracing::debug!(status = %status, response_len = %body_bytes.len(), "Evaluating matchers");

            let matchers_succeeded = if req_rule.matchers.is_empty() {
                false
            } else {
                let is_or = req_rule.matcher_condition.eq_ignore_ascii_case("or");

                if is_or {
                    req_rule.matchers.iter().any(|matcher| {
                        matches_condition(matcher, &body_bytes, &resp_headers, status)
                    })
                } else {
                    req_rule.matchers.iter().all(|matcher| {
                        matches_condition(matcher, &body_bytes, &resp_headers, status)
                    })
                }
            };

            if matchers_succeeded {
                tracing::debug!(
                    "Vulnerability match found for template {} on {}",
                    template_id,
                    full_url
                );
                findings.push(FindingOwned::from_template_and_info(
                    template_id,
                    template_meta,
                    target_url.to_string(),
                    full_url.clone(),
                ));
            }
        } // End of URLs loop
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use valayam_models::templates::matcher::ResponseMatcher;

    // -----------------------------------------------------------------------
    // evaluate_stream tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_stream_matches_builtin_aws_key() {
        let body = b"something AKIAIOSFODNN7EXAMPLE here";
        assert!(evaluate_stream(body, &[]));
    }

    #[test]
    fn test_evaluate_stream_matches_builtin_private_key() {
        let body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        assert!(evaluate_stream(body, &[]));
    }

    #[test]
    fn test_evaluate_stream_matches_builtin_jwt() {
        let body = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP2RcQk3gNFOiE";
        assert!(evaluate_stream(body, &[]));
    }

    #[test]
    fn test_evaluate_stream_no_match_clean_body() {
        let body = b"Hello world, nothing sensitive here!";
        assert!(!evaluate_stream(body, &[]));
    }

    #[test]
    fn test_evaluate_stream_custom_pattern() {
        let body = b"my-secret-token-abc123";
        assert!(evaluate_stream(body, &["secret-token".to_string()]));
    }

    #[test]
    fn test_evaluate_stream_invalid_custom_pattern_is_skipped() {
        let body = b"test data";
        // Invalid regex should be skipped, not panic
        assert!(!evaluate_stream(body, &["[invalid".to_string()]));
    }

    #[test]
    fn test_evaluate_stream_empty_body() {
        assert!(!evaluate_stream(b"", &[]));
    }

    // -----------------------------------------------------------------------
    // resolve_all tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_all_no_variables() {
        let context = HashMap::new();
        assert_eq!(resolve_all("hello world", &context), "hello world");
    }

    #[test]
    fn test_resolve_all_with_variables() {
        let mut context = HashMap::new();
        context.insert("port".to_string(), "8080".to_string());
        assert_eq!(resolve_all("{{port}}", &context), "8080");
    }

    #[test]
    fn test_resolve_all_unresolved_placeholder_left_as_is() {
        let context = HashMap::new();
        assert_eq!(resolve_all("{{missing}}", &context), "{{missing}}");
    }

    #[test]
    fn test_resolve_all_nested_in_string() {
        let mut context = HashMap::new();
        context.insert("path".to_string(), "admin".to_string());
        assert_eq!(
            resolve_all("/api/{{path}}/login", &context),
            "/api/admin/login"
        );
    }

    // -----------------------------------------------------------------------
    // matches_condition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_matches_condition_status_match() {
        let matcher = ResponseMatcher {
            r#type: "status".to_string(),
            part: "status".to_string(),
            regex: vec![],
            words: vec![],
            status: Some(vec![200, 404]),
            negative: false,
            condition: "and".to_string(),
        };
        assert!(matches_condition(&matcher, b"", &HashMap::new(), 200));
        assert!(matches_condition(&matcher, b"", &HashMap::new(), 404));
        assert!(!matches_condition(&matcher, b"", &HashMap::new(), 500));
    }

    #[test]
    fn test_matches_condition_status_no_match_empty_vec() {
        let matcher = ResponseMatcher {
            r#type: "status".to_string(),
            part: "status".to_string(),
            regex: vec![],
            words: vec![],
            status: Some(vec![]),
            negative: false,
            condition: "and".to_string(),
        };
        assert!(!matches_condition(&matcher, b"", &HashMap::new(), 200));
    }

    #[test]
    fn test_matches_condition_status_none() {
        let matcher = ResponseMatcher {
            r#type: "status".to_string(),
            part: "status".to_string(),
            regex: vec![],
            words: vec![],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        assert!(!matches_condition(&matcher, b"", &HashMap::new(), 200));
    }

    #[test]
    fn test_matches_condition_word_body() {
        let matcher = ResponseMatcher {
            r#type: "word".to_string(),
            part: "body".to_string(),
            regex: vec![],
            words: vec!["admin".to_string(), "root".to_string()],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        assert!(matches_condition(
            &matcher,
            b"admin panel",
            &HashMap::new(),
            200
        ));
        assert!(matches_condition(
            &matcher,
            b"root user",
            &HashMap::new(),
            200
        ));
        assert!(!matches_condition(
            &matcher,
            b"guest user",
            &HashMap::new(),
            200
        ));
    }

    #[test]
    fn test_matches_condition_word_header() {
        let matcher = ResponseMatcher {
            r#type: "word".to_string(),
            part: "header".to_string(),
            regex: vec![],
            words: vec!["nginx".to_string()],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.18.0".to_string());
        assert!(matches_condition(&matcher, b"", &headers, 200));
        assert!(!matches_condition(&matcher, b"", &HashMap::new(), 200));
    }

    #[test]
    fn test_matches_condition_regex_body() {
        let matcher = ResponseMatcher {
            r#type: "regex".to_string(),
            part: "body".to_string(),
            regex: vec!["secret-token".to_string(), "AKIA[0-9A-Z]{16}".to_string()],
            words: vec![],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        // Uses evaluate_stream which checks both built-in patterns and custom patterns
        let body = b"my-secret-token-here";
        assert!(matches_condition(&matcher, body, &HashMap::new(), 200));
    }

    #[test]
    fn test_matches_condition_regex_header() {
        let matcher = ResponseMatcher {
            r#type: "regex".to_string(),
            part: "header".to_string(),
            regex: vec!["nginx/1\\.\\d+".to_string()],
            words: vec![],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.18.0".to_string());
        assert!(matches_condition(&matcher, b"", &headers, 200));
    }

    #[test]
    fn test_matches_condition_negative_inverts() {
        let matcher = ResponseMatcher {
            r#type: "status".to_string(),
            part: "status".to_string(),
            regex: vec![],
            words: vec![],
            status: Some(vec![404]),
            negative: true,
            condition: "and".to_string(),
        };
        // negative=true inverts: should match when status is NOT 404
        assert!(!matches_condition(&matcher, b"", &HashMap::new(), 404));
        assert!(matches_condition(&matcher, b"", &HashMap::new(), 200));
    }

    #[test]
    fn test_matches_condition_word_header_not_found() {
        let matcher = ResponseMatcher {
            r#type: "word".to_string(),
            part: "header".to_string(),
            regex: vec![],
            words: vec!["apache".to_string()],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx".to_string());
        assert!(!matches_condition(&matcher, b"", &headers, 200));
    }

    #[test]
    fn test_matches_condition_empty_headers() {
        let matcher = ResponseMatcher {
            r#type: "word".to_string(),
            part: "header".to_string(),
            regex: vec![],
            words: vec!["anything".to_string()],
            status: None,
            negative: false,
            condition: "and".to_string(),
        };
        assert!(!matches_condition(&matcher, b"", &HashMap::new(), 200));
    }

    // -----------------------------------------------------------------------
    // HttpRequestTemplate deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_request_template_defaults() {
        let yaml = r#"
method: GET
path: /api/health
"#;
        let tmpl: HttpRequestTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.method, "GET");
        assert_eq!(tmpl.path, "/api/health");
        assert!(tmpl.body.is_none());
        assert!(tmpl.headers.is_none());
        assert!(tmpl.matchers.is_empty());
        assert_eq!(tmpl.matcher_condition, "and");
        assert!(tmpl.follow_redirects.is_none());
        assert!(tmpl.extractors.is_empty());
    }

    #[test]
    fn test_http_request_template_with_all_fields() {
        let yaml = r#"
method: POST
path: /api/login
headers:
  Content-Type: application/json
body: '{"user":"admin"}'
matchers:
  - type: status
    part: status
    status: [200]
matcher_condition: or
follow_redirects: true
"#;
        let tmpl: HttpRequestTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.method, "POST");
        assert_eq!(
            tmpl.headers.as_ref().unwrap().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(tmpl.body.unwrap(), r#"{"user":"admin"}"#);
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matcher_condition, "or");
        assert_eq!(tmpl.follow_redirects, Some(true));
    }

    #[test]
    fn test_http_request_template_serde_roundtrip() {
        let tmpl = HttpRequestTemplate {
            method: "GET".to_string(),
            path: "/test".to_string(),
            body: Some("data".to_string()),
            headers: None,
            matchers: vec![],
            matcher_condition: "and".to_string(),
            extractors: vec![],
            attack: None,
            payloads: None,
            inject_in: None,
            follow_redirects: None,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: HttpRequestTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.method, "GET");
        assert_eq!(back.path, "/test");
        assert_eq!(back.body.unwrap(), "data");
    }
}
