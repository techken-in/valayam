use crate::templates::extractors::Extractor;
use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Defines a single HTTP request step within a native template.
/// Supports optional request body (for POST/PUT), extractors for dynamic
/// value capture, and matchers for response validation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpRequestTemplate {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
    #[serde(default = "default_matcher_condition")]
    pub matcher_condition: String,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    #[serde(default)]
    pub attack: Option<String>,
    #[serde(default)]
    pub payloads: Option<Vec<String>>,
    #[serde(default)]
    pub inject_in: Option<String>,
    #[serde(default)]
    pub follow_redirects: Option<bool>,
}

fn default_matcher_condition() -> String {
    "and".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_template_minimal() {
        let json = r#"{"method": "GET", "path": "/api/test"}"#;
        let tmpl: HttpRequestTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.method, "GET");
        assert_eq!(tmpl.path, "/api/test");
        assert_eq!(tmpl.matcher_condition, "and");
    }

    #[test]
    fn test_http_request_template_full() {
        let json = r#"{
            "method": "POST",
            "path": "/api/login",
            "body": "user=admin",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "matchers": [{"type": "word", "part": "body", "words": ["welcome"]}],
            "matcher_condition": "or",
            "follow_redirects": true
        }"#;
        let tmpl: HttpRequestTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.method, "POST");
        assert!(tmpl.body.is_some());
        assert_eq!(tmpl.body.unwrap(), "user=admin");
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matcher_condition, "or");
        assert_eq!(tmpl.follow_redirects, Some(true));
    }

    #[test]
    fn test_http_request_template_serde_roundtrip() {
        let tmpl = HttpRequestTemplate {
            method: "GET".into(),
            path: "/".into(),
            body: None,
            headers: None,
            matchers: vec![],
            matcher_condition: "and".into(),
            extractors: vec![],
            attack: None,
            payloads: None,
            inject_in: None,
            follow_redirects: None,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: HttpRequestTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.method, "GET");
    }
}
