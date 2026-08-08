use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomRedirectAuditTemplate {
    pub target: String,
    pub parameters: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dom_redirect_template_deser() {
        let json = r#"{"target": "https://example.com", "parameters": ["url", "redirect"]}"#;
        let tmpl: DomRedirectAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
        assert_eq!(tmpl.parameters, vec!["url", "redirect"]);
    }

    #[test]
    fn test_dom_redirect_serde_roundtrip() {
        let tmpl = DomRedirectAuditTemplate {
            target: "https://example.com".into(),
            parameters: vec!["next".into()],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: DomRedirectAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parameters.len(), 1);
    }
}
