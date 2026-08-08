use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OauthAuditTemplate {
    pub target: String,
    pub flow_type: String, // "authorization_code", "implicit", "client_credentials"
    pub jwt_mutations: Vec<String>, // e.g. "none_alg", "key_confusion"
    pub matchers: Vec<ResponseMatcher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_template_minimal() {
        let json = r#"{"target": "https://example.com", "flow_type": "authorization_code", "jwt_mutations": [], "matchers": []}"#;
        let tmpl: OauthAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
        assert_eq!(tmpl.flow_type, "authorization_code");
        assert!(tmpl.jwt_mutations.is_empty());
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_oauth_template_with_jwt_mutations() {
        let json = r#"{"target": "https://example.com/oauth", "flow_type": "implicit", "jwt_mutations": ["none_alg", "key_confusion"], "matchers": []}"#;
        let tmpl: OauthAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.jwt_mutations.len(), 2);
        assert!(tmpl.jwt_mutations.contains(&"none_alg".to_string()));
    }

    #[test]
    fn test_oauth_template_with_matchers() {
        let json = r#"{
            "target": "https://example.com",
            "flow_type": "client_credentials",
            "jwt_mutations": ["none_alg"],
            "matchers": [{"type": "status", "part": "body", "status": [200]}]
        }"#;
        let tmpl: OauthAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.matchers.len(), 1);
    }

    #[test]
    fn test_oauth_template_serde_roundtrip() {
        let tmpl = OauthAuditTemplate {
            target: "https://example.com".into(),
            flow_type: "authorization_code".into(),
            jwt_mutations: vec!["none_alg".into()],
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: OauthAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.flow_type, "authorization_code");
        assert_eq!(back.jwt_mutations.len(), 1);
    }
}
