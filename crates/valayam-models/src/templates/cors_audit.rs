use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsAuditTemplate {
    pub target: String,
    pub origins_to_test: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_template_minimal() {
        let yaml = "target: https://example.com";
        let tmpl: CorsAuditTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
        assert!(tmpl.origins_to_test.is_none());
    }

    #[test]
    fn test_cors_template_with_origins() {
        let yaml = "target: https://api.example.com\norigins_to_test:\n  - https://evil.com\n  - https://attacker.org";
        let tmpl: CorsAuditTemplate = serde_yaml::from_str(yaml).unwrap();
        let origins = tmpl.origins_to_test.unwrap();
        assert_eq!(origins.len(), 2);
        assert!(origins.contains(&"https://evil.com".to_string()));
    }

    #[test]
    fn test_cors_template_serde_roundtrip() {
        let tmpl = CorsAuditTemplate {
            target: "https://example.com".to_string(),
            origins_to_test: Some(vec!["https://origin1.com".to_string()]),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: CorsAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "https://example.com");
        assert_eq!(back.origins_to_test.unwrap().len(), 1);
    }
}
