use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafBypassVerifyTemplate {
    pub target: String,
    pub payloads: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_bypass_verify_template_deser() {
        let json =
            r#"{"target": "example.com", "payloads": ["' OR 1=1--", "<script>alert(1)</script>"]}"#;
        let tmpl: WafBypassVerifyTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.payloads.len(), 2);
    }

    #[test]
    fn test_waf_bypass_verify_serde_roundtrip() {
        let tmpl = WafBypassVerifyTemplate {
            target: "test.local".into(),
            payloads: vec!["payload1".into()],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: WafBypassVerifyTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.payloads, deser.payloads);
    }
}
