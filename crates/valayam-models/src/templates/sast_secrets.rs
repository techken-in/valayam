use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SastSecretsTemplate {
    pub target_dir: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sast_secrets_template_deser() {
        let json = r#"{"target_dir": "/path/to/src"}"#;
        let tmpl: SastSecretsTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_dir, "/path/to/src");
    }

    #[test]
    fn test_sast_secrets_template_yaml() {
        let yaml = "target_dir: /repo/source";
        let tmpl: SastSecretsTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.target_dir, "/repo/source");
    }

    #[test]
    fn test_sast_secrets_serde_roundtrip() {
        let tmpl = SastSecretsTemplate {
            target_dir: "/tmp/test".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: SastSecretsTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target_dir, "/tmp/test");
    }
}
