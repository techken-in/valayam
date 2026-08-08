use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortScanTemplate {
    #[serde(default)]
    pub target: Option<String>,
    pub ports: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_scan_template_minimal() {
        let json = r#"{"ports": [22, 80, 443]}"#;
        let tmpl: PortScanTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.ports, vec![22, 80, 443]);
        assert!(tmpl.target.is_none());
    }

    #[test]
    fn test_port_scan_template_with_target() {
        let json = r#"{"target": "localhost", "ports": [8080, 8443]}"#;
        let tmpl: PortScanTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target.unwrap(), "localhost");
        assert_eq!(tmpl.ports.len(), 2);
    }

    #[test]
    fn test_port_scan_template_serde_roundtrip() {
        let tmpl = PortScanTemplate {
            target: Some("10.0.0.1".into()),
            ports: vec![22, 443],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: PortScanTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ports, vec![22, 443]);
    }
}
