use crate::template_info::TemplateMetadata;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn default_schema_version() -> String {
    "1.0.0".to_string()
}

/// Represents a single, validated vulnerability finding.
/// This structure is serialized to JSON for structured logging and can be
/// converted to other formats like SARIF for integration with security tools.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub template_id: String,
    pub template_name: String,
    pub template_severity: String,
    pub target: String,
    pub payload: String,
    /// Additional compliance information (e.g., OWASP, CWE, NIST, MITRE ATT&CK)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub compliance: HashMap<String, String>,
    /// CVSS score for severity standardization (0.0-10.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    /// Solution/remediation guidance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    /// References for further information ( advisories, blogs, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Tags for categorization and filtering
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl ScanResult {
    /// Add a compliance mapping
    pub fn with_compliance(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.compliance.insert(key.into(), value.into());
        self
    }

    /// Add a tag for categorization
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set CVSS score
    pub fn with_cvss_score(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }

    /// Set solution/remediation
    pub fn with_solution(mut self, solution: impl Into<String>) -> Self {
        self.solution = Some(solution.into());
        self
    }

    /// Set reference
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
}

// Default implementation for easier construction
impl Default for ScanResult {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            timestamp: Utc::now(),
            template_id: String::new(),
            template_name: String::new(),
            template_severity: String::new(),
            target: String::new(),
            payload: String::new(),
            compliance: HashMap::new(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: Vec::new(),
        }
    }
}

impl ScanResult {
    pub fn new(template_id: &str, template_meta: &dyn TemplateMetadata, target_url: &str) -> Self {
        Self {
            schema_version: default_schema_version(),
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_meta.template_name().to_string(),
            template_severity: template_meta.template_severity().to_string(),
            target: target_url.to_string(),
            payload: String::new(),
            compliance: template_meta.compliance().clone(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: Vec::new(),
        }
    }

    pub fn set_extracted(&mut self, key: &str, value: String) {
        self.payload = format!("{}: {}", key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_scan_result_default() {
        let sr = ScanResult::default();
        assert!(sr.template_id.is_empty());
        assert!(sr.payload.is_empty());
        assert!(sr.compliance.is_empty());
        assert!(sr.cvss_score.is_none());
        assert!(sr.solution.is_none());
        assert!(sr.reference.is_none());
        assert!(sr.tags.is_empty());
    }

    #[test]
    fn test_scan_result_new() {
        let info = crate::templates::schema::TemplateInfo {
            name: "SQLi Test".into(),
            severity: "high".into(),
            author: None,
            description: Some("Test for SQL injection".into()),
            tags: vec![],
            compliance: [("owasp".into(), "A1:2017".into())].into(),
        };
        let sr = ScanResult::new("sqli-001", &info, "https://example.com/login");
        assert_eq!(sr.template_id, "sqli-001");
        assert_eq!(sr.template_name, "SQLi Test");
        assert_eq!(sr.template_severity, "high");
        assert_eq!(sr.target, "https://example.com/login");
        assert_eq!(sr.compliance.get("owasp").unwrap(), "A1:2017");
        assert!(sr.payload.is_empty());
    }

    #[test]
    fn test_with_compliance() {
        let sr = ScanResult::default()
            .with_compliance("cwe", "89")
            .with_compliance("owasp", "A1:2017");
        assert_eq!(sr.compliance.len(), 2);
        assert_eq!(sr.compliance.get("cwe").unwrap(), "89");
    }

    #[test]
    fn test_with_tag() {
        let sr = ScanResult::default()
            .with_tag("sql-injection")
            .with_tag("critical");
        assert_eq!(sr.tags.len(), 2);
        assert!(sr.tags.contains(&"sql-injection".to_string()));
    }

    #[test]
    fn test_with_cvss_score() {
        let sr = ScanResult::default().with_cvss_score(9.8);
        assert_eq!(sr.cvss_score.unwrap(), 9.8);
    }

    #[test]
    fn test_with_solution() {
        let sr = ScanResult::default().with_solution("Use prepared statements");
        assert_eq!(sr.solution.unwrap(), "Use prepared statements");
    }

    #[test]
    fn test_with_reference() {
        let sr = ScanResult::default()
            .with_reference("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234");
        assert_eq!(
            sr.reference.unwrap(),
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234"
        );
    }

    #[test]
    fn test_set_extracted() {
        let mut sr = ScanResult::default();
        sr.set_extracted("username", "admin".to_string());
        assert_eq!(sr.payload, "username: admin");
    }

    #[test]
    fn test_serde_round_trip() {
        let sr = ScanResult {
            schema_version: "1.0.0".to_string(),
            timestamp: Utc.with_ymd_and_hms(2025, 1, 15, 10, 30, 0).unwrap(),
            template_id: "test-001".into(),
            template_name: "Test Finding".into(),
            template_severity: "medium".into(),
            target: "https://example.com".into(),
            payload: "reflected".into(),
            compliance: [("cwe".into(), "79".into())].into(),
            cvss_score: Some(6.5),
            solution: Some("Sanitize input".into()),
            reference: Some("https://example.com/advisory".into()),
            tags: vec!["xss".into()],
        };

        let json = serde_json::to_string(&sr).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();

        assert_eq!(back.template_id, "test-001");
        assert_eq!(back.template_severity, "medium");
        assert_eq!(back.cvss_score.unwrap(), 6.5);
        assert_eq!(back.compliance.get("cwe").unwrap(), "79");
        assert_eq!(back.tags, vec!["xss"]);
        assert_eq!(back.solution.unwrap(), "Sanitize input");
    }

    #[test]
    fn test_serde_optional_fields_default() {
        let json = r#"{
            "timestamp": 1736939400,
            "template_id": "test",
            "template_name": "Test",
            "template_severity": "info",
            "target": "https://example.com",
            "payload": ""
        }"#;

        let sr: ScanResult = serde_json::from_str(json).unwrap();
        assert!(sr.compliance.is_empty());
        assert!(sr.cvss_score.is_none());
        assert!(sr.solution.is_none());
        assert!(sr.tags.is_empty());
    }

    #[test]
    fn test_chained_builder_methods() {
        let sr = ScanResult::default()
            .with_compliance("cwe", "79")
            .with_tag("xss")
            .with_tag("injection")
            .with_cvss_score(8.2)
            .with_solution("Encode output")
            .with_reference("https://owasp.org/xss");

        assert_eq!(sr.compliance.len(), 1);
        assert_eq!(sr.tags.len(), 2);
        assert_eq!(sr.cvss_score.unwrap(), 8.2);
    }
}
