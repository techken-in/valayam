use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines a network (TCP/UDP) scan step within a native template.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkRequestTemplate {
    pub host: String,
    pub ports: Vec<String>,
    /// Timeout in milliseconds for banner grabbing. If set, the scanner will
    /// attempt to read initial bytes from each open TCP port.
    #[serde(default)]
    pub banner_timeout_ms: Option<u64>,
    /// Protocol to use: "tcp" (default) or "udp".
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub send_probe: Option<String>,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_scan_template_deser() {
        let json = r#"{
            "host": "10.0.0.1",
            "ports": ["80", "443"],
            "banner_timeout_ms": 5000,
            "protocol": "tcp",
            "send_probe": "GET / HTTP/1.1\r\n\r\n",
            "matchers": [{"type": "word", "part": "body", "words": ["HTTP"]}]
        }"#;
        let tmpl: NetworkRequestTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.host, "10.0.0.1");
        assert_eq!(tmpl.ports, vec!["80", "443"]);
        assert_eq!(tmpl.banner_timeout_ms, Some(5000));
        assert_eq!(tmpl.protocol, "tcp");
        assert!(tmpl.send_probe.is_some());
        assert_eq!(tmpl.matchers.len(), 1);
    }

    #[test]
    fn test_network_scan_variants() {
        let json = r#"{
            "host": "192.168.1.1",
            "ports": ["22"],
            "protocol": "udp",
            "matchers": []
        }"#;
        let tmpl: NetworkRequestTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.host, "192.168.1.1");
        assert_eq!(tmpl.protocol, "udp");
        assert!(tmpl.banner_timeout_ms.is_none());
        assert!(tmpl.send_probe.is_none());
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_network_scan_serde_roundtrip() {
        let tmpl = NetworkRequestTemplate {
            host: "roundtrip.local".into(),
            ports: vec!["8080".into()],
            banner_timeout_ms: None,
            protocol: "tcp".into(),
            send_probe: None,
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: NetworkRequestTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.host, deser.host);
        assert_eq!(tmpl.ports, deser.ports);
        assert_eq!(tmpl.protocol, deser.protocol);
        assert_eq!(tmpl.matchers.len(), deser.matchers.len());
    }
}
