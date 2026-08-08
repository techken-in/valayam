use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines a TLS/SSL certificate audit step within a native template.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsAuditTemplate {
    pub host: String,
    #[serde(default = "default_tls_port")]
    pub port: u16,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_expiry_days: Option<u32>,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

fn default_tls_port() -> u16 {
    443
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_audit_template_deser() {
        let json = r#"{
            "host": "example.com",
            "port": 443,
            "min_version": "TLSv1.2",
            "max_expiry_days": 30,
            "matchers": [{"type": "word", "part": "body", "words": ["certificate"]}]
        }"#;
        let tmpl: TlsAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.host, "example.com");
        assert_eq!(tmpl.port, 443);
        assert_eq!(tmpl.min_version, Some("TLSv1.2".into()));
        assert_eq!(tmpl.max_expiry_days, Some(30));
        assert_eq!(tmpl.matchers.len(), 1);
    }

    #[test]
    fn test_tls_audit_variants() {
        let json = r#"{
            "host": "test.dev",
            "port": 8443,
            "matchers": []
        }"#;
        let tmpl: TlsAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.host, "test.dev");
        assert_eq!(tmpl.port, 8443);
        assert!(tmpl.min_version.is_none());
        assert!(tmpl.max_expiry_days.is_none());
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_tls_audit_serde_roundtrip() {
        let tmpl = TlsAuditTemplate {
            host: "roundtrip.secure".into(),
            port: 443,
            min_version: Some("TLSv1.3".into()),
            max_expiry_days: Some(90),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: TlsAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.host, deser.host);
        assert_eq!(tmpl.port, deser.port);
        assert_eq!(tmpl.min_version, deser.min_version);
        assert_eq!(tmpl.max_expiry_days, deser.max_expiry_days);
        assert_eq!(tmpl.matchers.len(), deser.matchers.len());
    }
}
