use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CicdAuditTemplate {
    pub target_repo: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cicd_template_deser() {
        let json = r#"{"target_repo": "/path/to/repo"}"#;
        let tmpl: CicdAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_repo, "/path/to/repo");
    }

    #[test]
    fn test_cicd_template_serde_roundtrip() {
        let tmpl = CicdAuditTemplate {
            target_repo: "/home/user/project".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: CicdAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target_repo, "/home/user/project");
    }
}
