use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PiiLeakAuditTemplate {
    pub target: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_leak_template_deser() {
        let json = r#"{"target": "https://example.com"}"#;
        let tmpl: PiiLeakAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
    }

    #[test]
    fn test_pii_leak_serde_roundtrip() {
        let tmpl = PiiLeakAuditTemplate {
            target: "https://api.example.com".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: PiiLeakAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "https://api.example.com");
    }
}
