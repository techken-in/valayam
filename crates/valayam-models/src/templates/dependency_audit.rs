use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAuditTemplate {
    pub target_repo: String,
    pub cve_mode: Option<String>,
    pub api_url: Option<String>,
    pub local_db_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_audit_template_minimal() -> anyhow::Result<()> {
        let json = r#"{"target_repo": "/path/to/repo"}"#;
        let tmpl: DependencyAuditTemplate = serde_json::from_str(json)?;
        assert_eq!(tmpl.target_repo, "/path/to/repo");
        assert!(tmpl.cve_mode.is_none());
        assert!(tmpl.api_url.is_none());
        Ok(())
    }

    #[test]
    fn test_dependency_audit_template_api_mode() -> anyhow::Result<()> {
        let json = r#"{"target_repo": "/repo", "cve_mode": "api", "api_url": "https://osv.dev"}"#;
        let tmpl: DependencyAuditTemplate = serde_json::from_str(json)?;
        assert_eq!(tmpl.cve_mode.as_deref(), Some("api"));
        assert_eq!(tmpl.api_url.as_deref(), Some("https://osv.dev"));
        Ok(())
    }

    #[test]
    fn test_dependency_audit_template_local_mode() -> anyhow::Result<()> {
        let json =
            r#"{"target_repo": "/repo", "cve_mode": "local", "local_db_path": "/db/osv.db"}"#;
        let tmpl: DependencyAuditTemplate = serde_json::from_str(json)?;
        assert_eq!(tmpl.cve_mode.as_deref(), Some("local"));
        assert_eq!(tmpl.local_db_path.as_deref(), Some("/db/osv.db"));
        Ok(())
    }

    #[test]
    fn test_dependency_audit_serde_roundtrip() -> anyhow::Result<()> {
        let tmpl = DependencyAuditTemplate {
            target_repo: "/repo".into(),
            cve_mode: Some("api".into()),
            api_url: Some("https://api.osv.dev".into()),
            local_db_path: None,
        };
        let json = serde_json::to_string(&tmpl)?;
        let back: DependencyAuditTemplate = serde_json::from_str(&json)?;
        assert_eq!(back.cve_mode.as_deref(), Some("api"));
        assert_eq!(back.api_url.as_deref(), Some("https://api.osv.dev"));
        Ok(())
    }
}
