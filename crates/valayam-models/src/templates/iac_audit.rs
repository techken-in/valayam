use crate::templates::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IacAuditTemplate {
    pub target: String,
    pub r#type: String, // "terraform", "kubernetes", "docker"
    pub matchers: Vec<ResponseMatcher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iac_audit_template_deser() {
        let json = r#"{"target": "main.tf", "type": "terraform", "matchers": []}"#;
        let tmpl: IacAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "main.tf");
        assert_eq!(tmpl.r#type, "terraform");
    }

    #[test]
    fn test_iac_audit_types() {
        for t in ["terraform", "kubernetes", "docker"] {
            let json = format!(r#"{{"target": "file", "type": "{}", "matchers": []}}"#, t);
            let tmpl: IacAuditTemplate = serde_json::from_str(&json).unwrap();
            assert_eq!(tmpl.r#type, t);
        }
    }

    #[test]
    fn test_iac_audit_serde_roundtrip() {
        let tmpl = IacAuditTemplate {
            target: "deploy.yaml".into(),
            r#type: "kubernetes".into(),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: IacAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.r#type, "kubernetes");
    }
}
