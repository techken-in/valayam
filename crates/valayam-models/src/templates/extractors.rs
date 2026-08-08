use serde::{Deserialize, Serialize};

/// Defines a value extraction rule that captures data from HTTP responses.
///
/// When a regex matches against the specified response part (body or header),
/// the engine captures the specified group and stores it as a named variable
/// accessible via `{{name}}` in subsequent requests.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Extractor {
    /// Extraction type. Currently supports "regex".
    pub r#type: String,

    /// Variable name for the extracted value (e.g., "auth_token").
    /// Available as `{{auth_token}}` in subsequent requests.
    pub name: String,

    /// Response part to extract from: "body" or "header".
    #[serde(default = "default_part")]
    pub part: String,

    /// Regex pattern with capture groups. The `group` index selects which
    /// capture group to extract.
    #[serde(default)]
    pub regex: Option<String>,

    /// JSON Pointer path to extract from (e.g. "/data/token").
    #[serde(default)]
    pub json: Option<String>,

    /// CSS selector to extract from (e.g., "input[name=csrf]").
    #[serde(default)]
    pub css: Option<String>,

    /// HTML attribute to extract (e.g. "value"). If None, extracts inner text.
    #[serde(default)]
    pub attribute: Option<String>,

    /// Capture group index to extract (default: 1 = first group).
    #[serde(default = "default_group")]
    pub group: usize,
}

fn default_part() -> String {
    "body".to_string()
}

fn default_group() -> usize {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_regex() {
        let json = r#"{"type": "regex", "name": "auth_token", "regex": "token=(\\w+)"}"#;
        let ext: Extractor = serde_json::from_str(json).unwrap();
        assert_eq!(ext.r#type, "regex");
        assert_eq!(ext.name, "auth_token");
        assert_eq!(ext.part, "body");
        assert_eq!(ext.group, 1);
    }

    #[test]
    fn test_extractor_full() {
        let json = r#"{"type": "regex", "name": "csrf", "part": "header", "regex": "csrf=(\\w+)", "group": 2, "json": "/data/token"}"#;
        let ext: Extractor = serde_json::from_str(json).unwrap();
        assert_eq!(ext.part, "header");
        assert_eq!(ext.group, 2);
        assert!(ext.json.is_some());
    }

    #[test]
    fn test_extractor_serde_roundtrip() {
        let ext = Extractor {
            r#type: "regex".into(),
            name: "token".into(),
            part: "body".into(),
            regex: Some(r"value=(\d+)".into()),
            json: None,
            css: Some("input[name=csrf]".into()),
            attribute: Some("value".into()),
            group: 1,
        };
        let json = serde_json::to_string(&ext).unwrap();
        let back: Extractor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "token");
        assert!(back.regex.is_some());
    }
}
