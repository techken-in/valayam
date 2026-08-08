use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessAuditTemplate {
    pub target: Option<String>,
    pub action: String,    // "iam_scan" or "trigger_scan"
    pub framework: String, // "serverless" or "aws_sam"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serverless_audit_template_deser() {
        let json = r#"{"target": "my-service", "action": "iam_scan", "framework": "serverless"}"#;
        let tmpl: ServerlessAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, Some("my-service".into()));
        assert_eq!(tmpl.action, "iam_scan");
        assert_eq!(tmpl.framework, "serverless");
    }

    #[test]
    fn test_serverless_audit_variants() {
        let json = r#"{"target": null, "action": "trigger_scan", "framework": "aws_sam"}"#;
        let tmpl: ServerlessAuditTemplate = serde_json::from_str(json).unwrap();
        assert!(tmpl.target.is_none());
        assert_eq!(tmpl.action, "trigger_scan");
        assert_eq!(tmpl.framework, "aws_sam");
    }

    #[test]
    fn test_serverless_audit_serde_roundtrip() {
        let tmpl = ServerlessAuditTemplate {
            target: Some("roundtrip-fn".into()),
            action: "iam_scan".into(),
            framework: "aws_sam".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: ServerlessAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.action, deser.action);
        assert_eq!(tmpl.framework, deser.framework);
    }
}
