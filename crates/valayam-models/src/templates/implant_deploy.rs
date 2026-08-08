use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImplantDeployTemplate {
    pub target: String,
    pub payload_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_implant_deploy_template_deser() {
        let json = r#"{"target": "victim-host", "payload_name": "reverse_shell"}"#;
        let tmpl: ImplantDeployTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "victim-host");
        assert_eq!(tmpl.payload_name, "reverse_shell");
    }

    #[test]
    fn test_implant_deploy_variants() {
        let json = r#"{"target": "target-server", "payload_name": "beacon"}"#;
        let tmpl: ImplantDeployTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "target-server");
        assert_eq!(tmpl.payload_name, "beacon");
    }

    #[test]
    fn test_implant_deploy_serde_roundtrip() {
        let tmpl = ImplantDeployTemplate {
            target: "server.local".into(),
            payload_name: "meterpreter".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: ImplantDeployTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.payload_name, deser.payload_name);
    }
}
