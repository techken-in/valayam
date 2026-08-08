use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IotAuditTemplate {
    pub target: String,
    pub protocol: String, // "mqtt", "coap"
    pub topics: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iot_audit_template_deser() {
        let json =
            r#"{"target": "mqtt://broker.local", "protocol": "mqtt", "topics": ["sensor/temp"]}"#;
        let tmpl: IotAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "mqtt://broker.local");
        assert_eq!(tmpl.protocol, "mqtt");
        assert_eq!(tmpl.topics, Some(vec!["sensor/temp".into()]));
    }

    #[test]
    fn test_iot_audit_variants() {
        let json = r#"{"target": "coap://sensor.local", "protocol": "coap", "topics": null}"#;
        let tmpl: IotAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "coap://sensor.local");
        assert_eq!(tmpl.protocol, "coap");
        assert!(tmpl.topics.is_none());
    }

    #[test]
    fn test_iot_audit_serde_roundtrip() {
        let tmpl = IotAuditTemplate {
            target: "mqtt://hub.local".into(),
            protocol: "mqtt".into(),
            topics: Some(vec!["temp".into(), "humidity".into()]),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: IotAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.protocol, deser.protocol);
        assert_eq!(tmpl.topics, deser.topics);
    }
}
