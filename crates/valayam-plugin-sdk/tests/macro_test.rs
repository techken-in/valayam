use serde::Deserialize;
use valayam_plugin_sdk::{JsonSchema, ValayamConfig};

#[derive(Deserialize, JsonSchema, ValayamConfig)]
struct DummyFuzzerConfig {
    /// The target endpoint to fuzz
    target: String,

    /// Depth of the fuzzing operation (default 3)
    #[serde(default = "default_depth")]
    fuzz_depth: u32,
}

fn default_depth() -> u32 {
    3
}

#[test]
fn test_macro_generates_schema() {
    let schema = DummyFuzzerConfig::export_schema();
    assert!(schema.contains("\"title\": \"DummyFuzzerConfig\""));
    assert!(schema.contains("\"target\": {"));
    assert!(schema.contains("\"fuzz_depth\": {"));
    assert!(schema.contains("\"description\": \"The target endpoint to fuzz\""));
    println!("{}", schema);
}
