use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudTemplate {
    pub provider: String,
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_template_deser() {
        let json = r#"{"provider": "aws", "action": "iam_enum"}"#;
        let tmpl: CloudTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.provider, "aws");
        assert_eq!(tmpl.action, "iam_enum");
    }

    #[test]
    fn test_cloud_template_all_providers() {
        for provider in ["aws", "azure", "gcp"] {
            let json = format!(
                r#"{{"provider": "{}", "action": "list_resources"}}"#,
                provider
            );
            let tmpl: CloudTemplate = serde_json::from_str(&json).unwrap();
            assert_eq!(tmpl.provider, provider);
        }
    }

    #[test]
    fn test_cloud_template_serde_roundtrip() {
        let tmpl = CloudTemplate {
            provider: "gcp".into(),
            action: "enum_buckets".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: CloudTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, "enum_buckets");
    }
}
