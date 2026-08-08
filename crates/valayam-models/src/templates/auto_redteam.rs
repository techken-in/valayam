use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AutoRedteamTemplate {
    pub target: String,
    pub objective: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_redteam_template_deser() {
        let json = r#"{"target": "example.com", "objective": "sql_injection"}"#;
        let tmpl: AutoRedteamTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.objective, "sql_injection");
    }

    #[test]
    fn test_auto_redteam_variants() {
        let json = r#"{"target": "test.app", "objective": "xss_scan"}"#;
        let tmpl: AutoRedteamTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "test.app");
        assert_eq!(tmpl.objective, "xss_scan");
    }

    #[test]
    fn test_auto_redteam_serde_roundtrip() {
        let tmpl = AutoRedteamTemplate {
            target: "roundtrip.dev".into(),
            objective: "idor_check".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: AutoRedteamTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.objective, deser.objective);
    }
}
