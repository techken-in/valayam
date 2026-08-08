use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines configuration schema for parameter fuzzing targets.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FuzzTemplate {
    pub part: String, // e.g., "query", "body", "headers"
    #[serde(default)]
    pub keys: Vec<String>, // Parameter names to target; if empty, fuzzes all detected keys.
    pub payloads: Vec<String>, // Payloads to inject
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_template_minimal() {
        let json = r#"{"part": "query", "payloads": ["<script>", "' OR 1=1"]}"#;
        let tmpl: FuzzTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.part, "query");
        assert_eq!(tmpl.payloads.len(), 2);
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_fuzz_template_with_keys_and_matchers() {
        let json = r#"{"part": "body", "keys": ["username", "password"], "payloads": ["admin", "test"], "matchers": [{"type": "word", "part": "body", "words": ["error"]}]}"#;
        let tmpl: FuzzTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.keys.len(), 2);
        assert_eq!(tmpl.matchers.len(), 1);
    }

    #[test]
    fn test_fuzz_template_serde_roundtrip() {
        let tmpl = FuzzTemplate {
            part: "query".into(),
            keys: vec![],
            payloads: vec!["test".into()],
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: FuzzTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payloads, vec!["test"]);
    }
}
