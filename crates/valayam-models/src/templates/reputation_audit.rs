use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReputationAuditTemplate {
    pub target: String,
    pub blocklists: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_audit_template_deser() {
        let json = r#"{"target": "example.com", "blocklists": ["alienvault", "abuseipdb"]}"#;
        let tmpl: ReputationAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.blocklists.len(), 2);
    }

    #[test]
    fn test_reputation_audit_variants() {
        let json = r#"{"target": "1.2.3.4", "blocklists": ["virustotal"]}"#;
        let tmpl: ReputationAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "1.2.3.4");
        assert_eq!(tmpl.blocklists, vec!["virustotal"]);
    }

    #[test]
    fn test_reputation_audit_serde_roundtrip() {
        let tmpl = ReputationAuditTemplate {
            target: "192.168.1.1".into(),
            blocklists: vec!["spamhaus".into()],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: ReputationAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.blocklists, deser.blocklists);
    }
}
