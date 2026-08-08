use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemediationGenTemplate {
    pub output_format: String, // "markdown", "json", "pdf"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remediation_gen_template_deser() {
        let json = r#"{"output_format": "markdown"}"#;
        let tmpl: RemediationGenTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.output_format, "markdown");
    }

    #[test]
    fn test_remediation_gen_template_formats() {
        for fmt in ["markdown", "json", "pdf"] {
            let json = format!(r#"{{"output_format": "{}"}}"#, fmt);
            let tmpl: RemediationGenTemplate = serde_json::from_str(&json).unwrap();
            assert_eq!(tmpl.output_format, fmt);
        }
    }

    #[test]
    fn test_remediation_gen_serde_roundtrip() {
        let tmpl = RemediationGenTemplate {
            output_format: "json".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: RemediationGenTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.output_format, "json");
    }
}
