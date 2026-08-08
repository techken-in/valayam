use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct K8sAuditTemplate {
    pub target_manifest: String,
    pub strict_rbac: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k8s_audit_template_deser() {
        let json = r#"{"target_manifest": "deployment.yaml", "strict_rbac": true}"#;
        let tmpl: K8sAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_manifest, "deployment.yaml");
        assert!(tmpl.strict_rbac);
    }

    #[test]
    fn test_k8s_audit_variants() {
        let json = r#"{"target_manifest": "pod.yaml", "strict_rbac": false}"#;
        let tmpl: K8sAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_manifest, "pod.yaml");
        assert!(!tmpl.strict_rbac);
    }

    #[test]
    fn test_k8s_audit_serde_roundtrip() {
        let tmpl = K8sAuditTemplate {
            target_manifest: "cluster-role.yaml".into(),
            strict_rbac: true,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: K8sAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target_manifest, deser.target_manifest);
        assert_eq!(tmpl.strict_rbac, deser.strict_rbac);
    }
}
