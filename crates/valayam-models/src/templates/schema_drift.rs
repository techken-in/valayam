use serde::{Deserialize, Serialize};

fn default_crawl_depth() -> u32 {
    2
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SchemaDriftTemplate {
    pub target: String,
    pub openapi_spec: String,
    /// Crawl depth for discovering endpoints. Defaults to 2.
    #[serde(default = "default_crawl_depth")]
    pub crawl_depth: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_drift_template_deser() {
        let json = r#"{"target": "example.com", "openapi_spec": "https://example.com/openapi.json", "crawl_depth": 3}"#;
        let tmpl: SchemaDriftTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.openapi_spec, "https://example.com/openapi.json");
        assert_eq!(tmpl.crawl_depth, 3);
    }

    #[test]
    fn test_schema_drift_variants() {
        let json = r#"{"target": "test.dev", "openapi_spec": "spec.yaml", "crawl_depth": 1}"#;
        let tmpl: SchemaDriftTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "test.dev");
        assert_eq!(tmpl.openapi_spec, "spec.yaml");
        assert_eq!(tmpl.crawl_depth, 1);
    }

    #[test]
    fn test_schema_drift_serde_roundtrip() {
        let tmpl = SchemaDriftTemplate {
            target: "roundtrip.local".into(),
            openapi_spec: "roundtrip.yaml".into(),
            crawl_depth: 5,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: SchemaDriftTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.openapi_spec, deser.openapi_spec);
        assert_eq!(tmpl.crawl_depth, deser.crawl_depth);
    }
}
