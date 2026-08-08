use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomAuditTemplate {
    pub target: String,
    pub r#type: String, // "package.json", "Cargo.toml", "requirements.txt"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbom_audit_template_deser() {
        let json = r#"{"target": "Cargo.toml", "type": "Cargo.toml"}"#;
        let tmpl: SbomAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "Cargo.toml");
        assert_eq!(tmpl.r#type, "Cargo.toml");
    }

    #[test]
    fn test_sbom_audit_types() {
        for t in ["package.json", "Cargo.toml", "requirements.txt"] {
            let json = format!(r#"{{"target": "{}", "type": "{}"}}"#, t, t);
            let tmpl: SbomAuditTemplate = serde_json::from_str(&json).unwrap();
            assert_eq!(tmpl.r#type, t);
        }
    }

    #[test]
    fn test_sbom_audit_serde_roundtrip() {
        let tmpl = SbomAuditTemplate {
            target: "package.json".into(),
            r#type: "package.json".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: SbomAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "package.json");
    }
}
