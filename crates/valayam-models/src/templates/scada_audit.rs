use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScadaAuditTemplate {
    pub target: String,
    pub protocol: String, // "modbus", "dnp3"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scada_audit_template_deser() {
        let json = r#"{"target": "10.0.0.1:502", "protocol": "modbus"}"#;
        let tmpl: ScadaAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "10.0.0.1:502");
        assert_eq!(tmpl.protocol, "modbus");
    }

    #[test]
    fn test_scada_audit_variants() {
        let json = r#"{"target": "10.0.0.2:20000", "protocol": "dnp3"}"#;
        let tmpl: ScadaAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "10.0.0.2:20000");
        assert_eq!(tmpl.protocol, "dnp3");
    }

    #[test]
    fn test_scada_audit_serde_roundtrip() {
        let tmpl = ScadaAuditTemplate {
            target: "192.168.1.100:502".into(),
            protocol: "modbus".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: ScadaAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.protocol, deser.protocol);
    }
}
