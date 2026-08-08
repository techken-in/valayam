use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MitreMappingTemplate {
    pub enable_mapping: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitre_mapping_template_deser() {
        let json = r#"{"enable_mapping": true}"#;
        let tmpl: MitreMappingTemplate = serde_json::from_str(json).unwrap();
        assert!(tmpl.enable_mapping);
    }

    #[test]
    fn test_mitre_mapping_variants() {
        let json = r#"{"enable_mapping": false}"#;
        let tmpl: MitreMappingTemplate = serde_json::from_str(json).unwrap();
        assert!(!tmpl.enable_mapping);
    }

    #[test]
    fn test_mitre_mapping_serde_roundtrip() {
        let tmpl = MitreMappingTemplate {
            enable_mapping: true,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: MitreMappingTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.enable_mapping, deser.enable_mapping);
    }
}
