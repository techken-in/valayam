use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SastTaintTemplate {
    pub target_dir: String,
    pub language: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sast_taint_template_deser() {
        let json = r#"{"target_dir": "/src/app", "language": "python"}"#;
        let tmpl: SastTaintTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_dir, "/src/app");
        assert_eq!(tmpl.language, "python");
    }

    #[test]
    fn test_sast_taint_all_languages() {
        for lang in ["python", "javascript", "java", "rust", "go"] {
            let json = format!(r#"{{"target_dir": "/src", "language": "{}"}}"#, lang);
            let tmpl: SastTaintTemplate = serde_json::from_str(&json).unwrap();
            assert_eq!(tmpl.language, lang);
        }
    }

    #[test]
    fn test_sast_taint_serde_roundtrip() {
        let tmpl = SastTaintTemplate {
            target_dir: "/project".into(),
            language: "rust".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: SastTaintTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target_dir, "/project");
    }
}
