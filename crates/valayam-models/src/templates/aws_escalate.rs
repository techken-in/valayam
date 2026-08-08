use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AwsEscalateTemplate {
    pub target: String,
    pub region: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_escalate_template_deser() {
        let json = r#"{"target": "arn:aws:iam::123456789012:user/admin"}"#;
        let tmpl: AwsEscalateTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "arn:aws:iam::123456789012:user/admin");
        assert!(tmpl.region.is_none());
    }

    #[test]
    fn test_aws_escalate_template_with_region() {
        let json = r#"{"target": "arn:aws:iam::123456789012:role/test", "region": "us-east-1"}"#;
        let tmpl: AwsEscalateTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.region.unwrap(), "us-east-1");
    }

    #[test]
    fn test_aws_escalate_serde_roundtrip() {
        let tmpl = AwsEscalateTemplate {
            target: "arn:aws:iam::111111111111:user/test".into(),
            region: Some("eu-west-1".into()),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: AwsEscalateTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.region.unwrap(), "eu-west-1");
    }
}
