use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines a DNS query audit step within a native template.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsRequestTemplate {
    pub domain: String,
    /// DNS record type: "A", "AAAA", "CNAME", "TXT", "MX".
    pub query_type: String,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_audit_template_deser() {
        let json = r#"{
            "domain": "example.com",
            "query_type": "A",
            "matchers": [{"type": "word", "part": "body", "words": ["192.168"]}]
        }"#;
        let tmpl: DnsRequestTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.domain, "example.com");
        assert_eq!(tmpl.query_type, "A");
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matchers[0].r#type, "word");
    }

    #[test]
    fn test_dns_audit_variants() {
        let json = r#"{
            "domain": "test.org",
            "query_type": "TXT",
            "matchers": []
        }"#;
        let tmpl: DnsRequestTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.domain, "test.org");
        assert_eq!(tmpl.query_type, "TXT");
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_dns_audit_serde_roundtrip() {
        let tmpl = DnsRequestTemplate {
            domain: "roundtrip.dev".into(),
            query_type: "MX".into(),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: DnsRequestTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.domain, deser.domain);
        assert_eq!(tmpl.query_type, deser.query_type);
        assert_eq!(tmpl.matchers.len(), deser.matchers.len());
    }
}
