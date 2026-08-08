use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubdomainTakeoverTemplate {
    pub target: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_takeover_template_deser() {
        let json = r#"{"target": "app.example.com"}"#;
        let tmpl: SubdomainTakeoverTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "app.example.com");
    }

    #[test]
    fn test_subdomain_takeover_serde_roundtrip() {
        let tmpl = SubdomainTakeoverTemplate {
            target: "api.example.com".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: SubdomainTakeoverTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "api.example.com");
    }
}
