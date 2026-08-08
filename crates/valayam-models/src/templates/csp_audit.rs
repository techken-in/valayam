use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CspAuditTemplate {
    pub target: String,
    pub strict_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_audit_template_deser() {
        let json = r#"{"target": "https://example.com", "strict_mode": true}"#;
        let tmpl: CspAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
        assert!(tmpl.strict_mode);
    }

    #[test]
    fn test_csp_audit_strict_mode_false() {
        let json = r#"{"target": "https://test.com", "strict_mode": false}"#;
        let tmpl: CspAuditTemplate = serde_json::from_str(json).unwrap();
        assert!(!tmpl.strict_mode);
    }

    #[test]
    fn test_csp_audit_serde_roundtrip() {
        let tmpl = CspAuditTemplate {
            target: "https://app.com".into(),
            strict_mode: true,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: CspAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "https://app.com");
    }
}
