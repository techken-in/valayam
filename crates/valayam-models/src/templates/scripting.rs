use serde::{Deserialize, Serialize};

/// Defines a scripted scan step. The `engine` field is future-proofed
/// for additional scripting runtimes (e.g., "lua") beyond "rhai".
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptTemplate {
    pub engine: String,
    pub source: ScriptSource,
}

/// Supports two deserialization shapes via `#[serde(untagged)]`:
/// - Inline: `{ code: "..." }`
/// - File:   `{ path: "./scripts/foo.rhai" }`
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ScriptSource {
    Inline { code: String },
    File { path: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_template_inline() {
        let json = r#"{"engine": "rhai", "source": {"code": "print(1);"}}"#;
        let tmpl: ScriptTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.engine, "rhai");
        match tmpl.source {
            ScriptSource::Inline { code } => assert_eq!(code, "print(1);"),
            _ => panic!("expected Inline variant"),
        }
    }

    #[test]
    fn test_script_template_file() {
        let json = r#"{"engine": "rhai", "source": {"path": "./scripts/test.rhai"}}"#;
        let tmpl: ScriptTemplate = serde_json::from_str(json).unwrap();
        match tmpl.source {
            ScriptSource::File { path } => assert_eq!(path, "./scripts/test.rhai"),
            _ => panic!("expected File variant"),
        }
    }

    #[test]
    fn test_script_template_serde_roundtrip() {
        let tmpl = ScriptTemplate {
            engine: "rhai".into(),
            source: ScriptSource::Inline {
                code: "let x = 1;".into(),
            },
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: ScriptTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.engine, "rhai");
    }
}
