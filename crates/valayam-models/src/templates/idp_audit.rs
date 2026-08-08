use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdpAuditTemplate {
    pub target: String,
    pub provider: String, // "azure_ad", "okta", "saml_generic"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idp_template_deser() {
        let json = r#"{"target": "https://idp.example.com", "provider": "azure_ad"}"#;
        let tmpl: IdpAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://idp.example.com");
        assert_eq!(tmpl.provider, "azure_ad");
    }

    #[test]
    fn test_idp_template_serde_roundtrip() {
        let tmpl = IdpAuditTemplate {
            target: "https://okta.example.com".into(),
            provider: "okta".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: IdpAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, "okta");
    }
}
