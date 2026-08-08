use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CtLogAuditTemplate {
    pub target: String,
    pub query_domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_log_audit_template_deser() {
        let json = r#"{"target": "crtsh", "query_domain": "example.com"}"#;
        let tmpl: CtLogAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "crtsh");
        assert_eq!(tmpl.query_domain, "example.com");
    }

    #[test]
    fn test_ct_log_audit_variants() {
        let json = r#"{"target": "crt.sh", "query_domain": "test.org"}"#;
        let tmpl: CtLogAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "crt.sh");
        assert_eq!(tmpl.query_domain, "test.org");
    }

    #[test]
    fn test_ct_log_audit_serde_roundtrip() {
        let tmpl = CtLogAuditTemplate {
            target: "crtsh".into(),
            query_domain: "roundtrip.dev".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: CtLogAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.query_domain, deser.query_domain);
    }
}
