use serde::{Deserialize, Serialize};

fn default_sensitivity() -> String {
    "medium".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriftDetectTemplate {
    pub target: String,
    pub storage_backend: Option<String>, // "local", "redis"
    pub baseline_id: String,
    /// Drift sensitivity level: "low", "medium" (default), or "high"
    /// - low:   status code and endpoint changes only
    /// - medium: status + body hash changes
    /// - high:  status + body hash + header structure changes
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drift_detect_template_deser() {
        let json = r#"{
            "target": "http://example.com",
            "storage_backend": "local",
            "baseline_id": "bl-001",
            "sensitivity": "high"
        }"#;
        let tmpl: DriftDetectTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "http://example.com");
        assert_eq!(tmpl.storage_backend, Some("local".into()));
        assert_eq!(tmpl.baseline_id, "bl-001");
        assert_eq!(tmpl.sensitivity, "high");
    }

    #[test]
    fn test_drift_detect_variants() {
        let json = r#"{
            "target": "https://test.dev",
            "baseline_id": "bl-002",
            "sensitivity": "low"
        }"#;
        let tmpl: DriftDetectTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://test.dev");
        assert!(tmpl.storage_backend.is_none());
        assert_eq!(tmpl.baseline_id, "bl-002");
        assert_eq!(tmpl.sensitivity, "low");
    }

    #[test]
    fn test_drift_detect_serde_roundtrip() {
        let tmpl = DriftDetectTemplate {
            target: "http://roundtrip.local".into(),
            storage_backend: Some("redis".into()),
            baseline_id: "bl-003".into(),
            sensitivity: "medium".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: DriftDetectTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.storage_backend, deser.storage_backend);
        assert_eq!(tmpl.baseline_id, deser.baseline_id);
        assert_eq!(tmpl.sensitivity, deser.sensitivity);
    }
}
