use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContainerAuditTemplate {
    pub target_image: String,
    pub checks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_audit_template_deser() {
        let json = r#"{"target_image": "nginx:latest", "checks": ["trivy", "grype"]}"#;
        let tmpl: ContainerAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_image, "nginx:latest");
        assert_eq!(tmpl.checks.len(), 2);
    }

    #[test]
    fn test_container_audit_variants() {
        let json = r#"{"target_image": "alpine:3.18", "checks": ["docker-bench"]}"#;
        let tmpl: ContainerAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target_image, "alpine:3.18");
        assert_eq!(tmpl.checks, vec!["docker-bench"]);
    }

    #[test]
    fn test_container_audit_serde_roundtrip() {
        let tmpl = ContainerAuditTemplate {
            target_image: "ubuntu:22.04".into(),
            checks: vec!["trivy".into(), "snyk".into()],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: ContainerAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target_image, deser.target_image);
        assert_eq!(tmpl.checks, deser.checks);
    }
}
