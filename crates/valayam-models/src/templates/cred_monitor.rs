use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredMonitorTemplate {
    pub target_domain: String,
    pub emails: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cred_monitor_template_deser() {
        let json = r#"{"target_domain": "example.com", "emails": ["admin@example.com"]}"#;
        let tmpl: CredMonitorTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_domain, "example.com");
        assert_eq!(tmpl.emails, vec!["admin@example.com"]);
    }

    #[test]
    fn test_cred_monitor_variants() {
        let json = r#"{"target_domain": "test.org", "emails": ["a@b.com", "c@d.com"]}"#;
        let tmpl: CredMonitorTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_domain, "test.org");
        assert_eq!(tmpl.emails.len(), 2);
    }

    #[test]
    fn test_cred_monitor_serde_roundtrip() {
        let tmpl = CredMonitorTemplate {
            target_domain: "roundtrip.com".into(),
            emails: vec!["user@roundtrip.com".into()],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: CredMonitorTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target_domain, deser.target_domain);
        assert_eq!(tmpl.emails, deser.emails);
    }
}
