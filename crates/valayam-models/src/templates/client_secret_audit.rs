use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientSecretAuditTemplate {
    pub target: String,
    pub matchers: Vec<ResponseMatcher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_secret_template_deser() {
        let json = r#"{"target": "https://example.com", "matchers": []}"#;
        let tmpl: ClientSecretAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_client_secret_template_with_matchers() {
        let json = r#"{"target": "https://example.com", "matchers": [{"type": "word", "part": "body", "words": ["client_secret"]}]}"#;
        let tmpl: ClientSecretAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matchers[0].words, vec!["client_secret"]);
    }

    #[test]
    fn test_client_secret_serde_roundtrip() {
        let tmpl = ClientSecretAuditTemplate {
            target: "https://api.example.com".into(),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: ClientSecretAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "https://api.example.com");
    }
}
