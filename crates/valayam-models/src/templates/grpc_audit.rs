use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GrpcAuditTemplate {
    pub target: String,
    pub service: Option<String>,
    pub method: Option<String>,
    pub reflection: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_template_minimal() {
        let json = r#"{"target": "localhost:50051", "reflection": false}"#;
        let tmpl: GrpcAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "localhost:50051");
        assert!(!tmpl.reflection);
        assert!(tmpl.service.is_none());
    }

    #[test]
    fn test_grpc_template_full() {
        let json = r#"{"target": "localhost:50051", "service": "MyService", "method": "SayHello", "reflection": true}"#;
        let tmpl: GrpcAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.service.unwrap(), "MyService");
        assert!(tmpl.reflection);
    }

    #[test]
    fn test_grpc_template_serde_roundtrip() {
        let tmpl = GrpcAuditTemplate {
            target: "localhost:50051".into(),
            service: Some("TestService".into()),
            method: None,
            reflection: true,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: GrpcAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "localhost:50051");
        assert!(back.reflection);
    }
}
