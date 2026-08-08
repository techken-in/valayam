use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Error type: real extism_pdk::Error on wasm32, stub on host builds.
#[cfg(target_arch = "wasm32")]
pub type PluginError = extism_pdk::Error;
#[cfg(not(target_arch = "wasm32"))]
pub type PluginError = Box<dyn std::error::Error + Send + Sync>;

// Result type matching extism_pdk::FnResult on wasm32.
#[cfg(target_arch = "wasm32")]
pub type PluginResult<T> = extism_pdk::FnResult<T>;
#[cfg(not(target_arch = "wasm32"))]
pub type PluginResult<T> = Result<T, PluginError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmInput {
    pub template: serde_json::Value,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub target: String,
    pub matched_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_data: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmOutput {
    pub matched: bool,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

pub trait WasmScanner {
    fn scan(&self, input: WasmInput) -> PluginResult<WasmOutput>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_input_serialization() {
        let input = WasmInput {
            template: serde_json::json!({"id": "test"}),
            context: [("key".into(), "value".into())].into(),
        };
        let json = serde_json::to_string(&input).expect("serialize");
        let back: WasmInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.template["id"], "test");
        assert_eq!(back.context.get("key").expect("has key"), "value");
    }

    #[test]
    fn test_finding_defaults() {
        let f = Finding {
            template_id: "t1".into(),
            template_name: "Test".into(),
            severity: "high".into(),
            target: "example.com".into(),
            matched_at: "path".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };
        let json = serde_json::to_string(&f).expect("serialize");
        assert!(
            !json.contains("description"),
            "None fields should be skipped"
        );
        assert!(!json.contains("solution"), "None fields should be skipped");
        let back: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.template_id, "t1");
    }

    #[test]
    fn test_wasm_output_defaults() {
        let output = WasmOutput {
            matched: true,
            count: 2,
            findings: vec![],
        };
        let json = serde_json::to_string(&output).expect("serialize");
        assert!(json.contains("\"matched\":true"));
        let back: WasmOutput = serde_json::from_str(&json).expect("deserialize");
        assert!(back.matched);
        assert!(back.findings.is_empty());
    }

    #[test]
    fn test_plugin_result_type() {
        let ok: PluginResult<i32> = Ok(42);
        assert!(ok.is_ok());
        let err: PluginResult<i32> = Err("fail".into());
        assert!(err.is_err());
    }
}
