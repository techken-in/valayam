use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderScorecardTemplate {
    pub target: String,
    pub required_headers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_scorecard_template_deser() {
        let json = r#"{"target": "example.com", "required_headers": ["Strict-Transport-Security", "X-Content-Type-Options"]}"#;
        let tmpl: HeaderScorecardTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.required_headers.len(), 2);
    }

    #[test]
    fn test_header_scorecard_variants() {
        let json = r#"{"target": "test.dev", "required_headers": ["Content-Security-Policy"]}"#;
        let tmpl: HeaderScorecardTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "test.dev");
        assert_eq!(tmpl.required_headers, vec!["Content-Security-Policy"]);
    }

    #[test]
    fn test_header_scorecard_serde_roundtrip() {
        let tmpl = HeaderScorecardTemplate {
            target: "roundtrip.test".into(),
            required_headers: vec!["X-Frame-Options".into()],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: HeaderScorecardTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.required_headers, deser.required_headers);
    }
}
