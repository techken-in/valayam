use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileAuditTemplate {
    pub target: Option<String>,
    pub action: String,   // "manifest_scan" or "secret_scan"
    pub app_type: String, // "apk" or "ipa"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_audit_template_deser() {
        let json = r#"{"target": "com.example.app", "action": "manifest_scan", "app_type": "apk"}"#;
        let tmpl: MobileAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, Some("com.example.app".into()));
        assert_eq!(tmpl.action, "manifest_scan");
        assert_eq!(tmpl.app_type, "apk");
    }

    #[test]
    fn test_mobile_audit_variants() {
        let json = r#"{"target": null, "action": "secret_scan", "app_type": "ipa"}"#;
        let tmpl: MobileAuditTemplate = serde_json::from_str(json).unwrap();
        assert!(tmpl.target.is_none());
        assert_eq!(tmpl.action, "secret_scan");
        assert_eq!(tmpl.app_type, "ipa");
    }

    #[test]
    fn test_mobile_audit_serde_roundtrip() {
        let tmpl = MobileAuditTemplate {
            target: Some("org.test.app".into()),
            action: "manifest_scan".into(),
            app_type: "apk".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: MobileAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.action, deser.action);
        assert_eq!(tmpl.app_type, deser.app_type);
    }
}
