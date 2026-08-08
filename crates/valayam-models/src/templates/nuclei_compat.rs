use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiTemplate {
    pub id: String,
    pub info: NucleiTemplateInfo,
    #[serde(default)]
    pub requests: Vec<NucleiRequestTemplate>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiTemplateInfo {
    pub name: String,
    pub author: Option<String>,
    pub severity: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiRequestTemplate {
    pub method: String,
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "matchers-condition", default = "default_matchers_condition")]
    pub matchers_condition: String,
    pub matchers: Vec<NucleiMatcher>,
}

fn default_matchers_condition() -> String {
    "or".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiMatcher {
    pub r#type: String, // "word", "status", etc.
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    #[serde(default = "default_matcher_part")]
    pub part: String,
}

fn default_matcher_part() -> String {
    "body".to_string()
}

impl NucleiTemplate {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::error::ScannerError> {
        let file = File::open(path)?;
        let template: NucleiTemplate = serde_yaml::from_reader(file)?;
        Ok(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nuclei_template_minimal() {
        let yaml = r#"
id: test-template
info:
  name: Test Template
  severity: medium
"#;
        let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.id, "test-template");
        assert_eq!(tmpl.info.name, "Test Template");
        assert_eq!(tmpl.info.severity, "medium");
        assert!(tmpl.requests.is_empty());
    }

    #[test]
    fn test_nuclei_template_with_requests() {
        let yaml = r#"
id: dir-lookup
info:
  name: Directory Lookup
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: word
        words:
          - "admin panel"
"#;
        let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.id, "dir-lookup");
        assert_eq!(tmpl.requests.len(), 1);
        assert_eq!(tmpl.requests[0].method, "GET");
        assert_eq!(tmpl.requests[0].path, vec!["{{BaseURL}}/admin"]);
        assert_eq!(tmpl.requests[0].matchers.len(), 1);
        assert_eq!(tmpl.requests[0].matchers[0].r#type, "word");
    }

    #[test]
    fn test_nuclei_template_full() {
        let yaml = r#"
id: full-template
info:
  name: Full Template
  author: Test Author
  severity: high
  description: A full-featured test template
requests:
  - method: POST
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/api/login"
    headers:
      Content-Type: application/json
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "token"
          - "session"
      - type: status
        status:
          - 200
          - 201
"#;
        let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.id, "full-template");
        assert_eq!(tmpl.info.author.unwrap(), "Test Author");
        assert_eq!(
            tmpl.info.description.unwrap(),
            "A full-featured test template"
        );
        assert_eq!(tmpl.requests.len(), 1);
        assert_eq!(tmpl.requests[0].method, "POST");
        assert_eq!(tmpl.requests[0].path.len(), 2);
        assert!(tmpl.requests[0].headers.is_some());
        assert_eq!(tmpl.requests[0].matchers_condition, "and");
        assert_eq!(tmpl.requests[0].matchers.len(), 2);
        assert_eq!(tmpl.requests[0].matchers[0].words, vec!["token", "session"]);
        assert_eq!(tmpl.requests[0].matchers[1].status, Some(vec![200, 201]));
    }

    #[test]
    fn test_nuclei_request_default_matchers_condition() {
        let yaml = r#"
id: test
info:
  name: Test
  severity: low
requests:
  - method: GET
    path:
      - "/"
    matchers: []
"#;
        let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.requests[0].matchers_condition, "or");
    }

    #[test]
    fn test_nuclei_matcher_default_part() {
        let yaml = r#"
id: test
info:
  name: Test
  severity: low
requests:
  - method: GET
    path:
      - "/"
    matchers:
      - type: word
        words:
          - "test"
"#;
        let tmpl: NucleiTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.requests[0].matchers[0].part, "body");
    }

    #[test]
    fn test_nuclei_template_serde_roundtrip() {
        let tmpl = NucleiTemplate {
            id: "roundtrip".to_string(),
            info: NucleiTemplateInfo {
                name: "Roundtrip Test".to_string(),
                author: Some("tester".to_string()),
                severity: "critical".to_string(),
                description: Some("Testing serde roundtrip".to_string()),
            },
            requests: vec![NucleiRequestTemplate {
                method: "GET".to_string(),
                path: vec!["/".to_string()],
                headers: None,
                matchers_condition: "and".to_string(),
                matchers: vec![NucleiMatcher {
                    r#type: "status".to_string(),
                    words: vec![],
                    status: Some(vec![200]),
                    part: "body".to_string(),
                }],
            }],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: NucleiTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "roundtrip");
        assert_eq!(back.info.severity, "critical");
        assert_eq!(back.requests.len(), 1);
        assert_eq!(back.requests[0].matchers[0].status, Some(vec![200]));
    }

    #[test]
    fn test_nuclei_template_load_invalid_path() {
        let result = NucleiTemplate::load("/nonexistent/path.yaml");
        assert!(result.is_err());
    }
}
