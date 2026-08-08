use serde::{Deserialize, Serialize};

/// Shared matcher type used across multiple feature slices.
/// Supports regex matching against response bodies/headers, word matching, and HTTP status code matching.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseMatcher {
    pub r#type: String, // e.g., "regex", "status", "word"
    pub part: String,   // e.g., "body", "header", "status", "banner"
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    #[serde(default)]
    pub negative: bool,
    #[serde(default = "default_condition")]
    pub condition: String,
}

fn default_condition() -> String {
    "and".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_matcher_default_condition() {
        let m = ResponseMatcher {
            r#type: "regex".into(),
            part: "body".into(),
            ..Default::default()
        };
        assert_eq!(m.condition, "and");
        assert!(!m.negative);
    }

    #[test]
    fn test_response_matcher_serde_round_trip() {
        let m = ResponseMatcher {
            r#type: "status".into(),
            part: "status".into(),
            regex: vec![],
            words: vec![],
            status: Some(vec![200, 201]),
            negative: false,
            condition: "or".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: ResponseMatcher = serde_json::from_str(&json).unwrap();
        assert_eq!(back.r#type, "status");
        assert_eq!(back.status.unwrap(), vec![200, 201]);
        assert_eq!(back.condition, "or");
    }

    #[test]
    fn test_response_matcher_serde_with_regex() {
        let m = ResponseMatcher {
            r#type: "regex".into(),
            part: "body".into(),
            regex: vec!["admin".into(), "root".into()],
            words: vec![],
            status: None,
            negative: true,
            condition: "and".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: ResponseMatcher = serde_json::from_str(&json).unwrap();
        assert!(back.negative);
        assert_eq!(back.regex.len(), 2);
        assert!(back.status.is_none());
    }

    impl Default for ResponseMatcher {
        fn default() -> Self {
            Self {
                r#type: String::new(),
                part: String::new(),
                regex: vec![],
                words: vec![],
                status: None,
                negative: false,
                condition: default_condition(),
            }
        }
    }
}
