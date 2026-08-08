use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AzureGcpEscalateTemplate {
    pub target: String,
    pub provider: String, // "azure", "gcp"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_gcp_escalate_template_deser() {
        let json = r#"{"target": "example.com", "provider": "azure"}"#;
        let tmpl: AzureGcpEscalateTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.provider, "azure");
    }

    #[test]
    fn test_azure_gcp_escalate_variants() {
        let json = r#"{"target": "gcp-project", "provider": "gcp"}"#;
        let tmpl: AzureGcpEscalateTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "gcp-project");
        assert_eq!(tmpl.provider, "gcp");
    }

    #[test]
    fn test_azure_gcp_escalate_serde_roundtrip() {
        let tmpl = AzureGcpEscalateTemplate {
            target: "roundtrip.test".into(),
            provider: "azure".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: AzureGcpEscalateTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.provider, deser.provider);
    }
}
