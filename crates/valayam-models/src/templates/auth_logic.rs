use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AuthTemplate {
    pub primary: String,
    pub secondary: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogicTemplate {
    pub r#type: String, // E.g., "idor"
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_template_minimal() {
        let tmpl = AuthTemplate {
            primary: "email".to_string(),
            secondary: "password".to_string(),
        };
        assert_eq!(tmpl.primary, "email");
        assert_eq!(tmpl.secondary, "password");
    }

    #[test]
    fn test_auth_template_default() {
        let tmpl = AuthTemplate::default();
        assert!(tmpl.primary.is_empty());
        assert!(tmpl.secondary.is_empty());
    }

    #[test]
    fn test_auth_template_json_roundtrip() {
        let json = r#"{"primary": "oauth", "secondary": "jwt"}"#;
        let tmpl: AuthTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.primary, "oauth");
        let back = serde_json::to_string(&tmpl).unwrap();
        assert!(back.contains("oauth"));
    }

    #[test]
    fn test_logic_template_minimal() {
        let json = r#"{"type": "idor", "method": "GET", "path": "/api/users/{{id}}"}"#;
        let tmpl: LogicTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.r#type, "idor");
        assert_eq!(tmpl.method, "GET");
        assert_eq!(tmpl.path, "/api/users/{{id}}");
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_logic_template_with_matchers() {
        let json = r#"{
            "type": "idor",
            "method": "POST",
            "path": "/api/delete",
            "matchers": [{"type": "status", "part": "body", "status": [403]}]
        }"#;
        let tmpl: LogicTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.r#type, "idor");
        assert_eq!(tmpl.matchers.len(), 1);
    }

    #[test]
    fn test_logic_template_multiple_matchers() {
        let json = r#"{
            "type": "bfla",
            "method": "GET",
            "path": "/api/admin",
            "matchers": [
                {"type": "status", "part": "body", "status": [200]},
                {"type": "word", "part": "body", "words": ["admin"]}
            ]
        }"#;
        let tmpl: LogicTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.matchers.len(), 2);
    }
}
