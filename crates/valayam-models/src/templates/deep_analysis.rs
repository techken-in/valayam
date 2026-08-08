use serde::{Deserialize, Serialize};

//
// Required Crates:
//   - serde / serde_yaml (template loading)
//   - serde_json (JSON parsing for response processing)
//   - schemars (JSON Schema generation for template autocomplete)
//   - thiserror (ergonomic error derive)
//   - url (URL pattern validation in template targets)
//   - globset (path pattern matching for artifact recovery targets)
//
// Data Structures Needed:
//   - DeepAnalysisType enum (instead of raw String):
//       LlmMutation(LlmConfig),          // see llm_mutator.rs
//       WasmDecompile(WasmConfig),       // future
//       SourceMapReconstruct(SourceMapConfig), // future
//       ArtifactRecovery(ArtifactConfig), // see artifact_recovery.rs
//       Custom(String)
//   - LlmConfig { mutation_strategy: String, max_variants: u32,
//     send_to_fuzzer: bool }
//   - WasmConfig { decompile: bool, export_symbols: bool,
//     extract_strings: bool }
//   - SourceMapConfig { reconstruct: bool, resolve_original: bool,
//     download_missing: bool }
//   - ArtifactConfig { probe_paths: Vec<String>, max_size_bytes: u64,
//     extract_archives: bool, secret_scan: bool, pattern_file: Option<String> }
//   - DeepAnalysisTemplate (extend current):
//       - add analysis_config: Option<serde_json::Value> (flex per-type
//         config parsed at runtime based on analysis_type)
//       - add severity_override: Option<String>
//       - add tags: Option<Vec<String>>
//       - add conditions: Option<Vec<AnalysisCondition>>
//   - AnalysisCondition { metric: String (e.g., "confidence"),
//     operator: String (">", "<", "==", "contains"),
//     value: serde_json::Value }
//
// Error Handling:
//   - TemplateValidationError enum:
//       UnknownAnalysisType(type: String),
//       MissingConfigForType { analysis_type: String,
//         required_fields: Vec<String> },
//       InvalidUrlPattern(url: String),
//       InvalidCondition { condition: String, reason: String },
//       ConfigConversionError { from_type: String, to_type: String,
//         inner: serde_json::Error }
//   - Deserialization with try_from: DeepAnalysisTemplate may implement
//     TryFrom<RawTemplate> to validate and convert
//
// Integration Points:
//   - Template registry: DeepAnalysisTemplate loaded alongside all
//     other templates via the common ScanTemplate trait
//   - Executor modules (llm_mutator, wasm, source_map, artifact):
//     each receives the typed config extracted from analysis_config
//   - Schema generation: schemars derive for IDE autocomplete when
//     editing template YAML files
//
// Template YAML Example (future):
//   ```yaml
//   id: deep-analysis-llm-001
//   info:
//     name: LLM WAF Bypass for SQLi
//     severity: critical
//     tags: [waf-bypass, sqli, ai-assisted]
//   deep_analysis:
//     type: llm_mutation
//     config:
//       mutation_strategy: sql_injection
//       max_variants: 5
//       send_to_fuzzer: true
//       provider: ollama
//       model: codellama
//     conditions:
//       - metric: response_time
//         operator: "<"
//         value: 5000
//   ```
//
// Implementation Phases:
//   1. Phase 1 (Current): Simple struct with String-based discriminator.
//      analysis_type can be "llm_mutation", "wasm_decompile",
//      "source_map", or "artifact_recovery". Single optional prompt field.
//   2. Phase 2: Introduce flexible serde_json::Value config field.
//      Each executor module validates its own config at runtime.
//   3. Phase 3: Full typed enum with per-variant config structs.
//      Deserialize with adjacently-tagged enum representation.
//   4. Phase 4: Template validation on load — report missing fields,
//      invalid combinations, and unsupported analysis types before
//      any scan begins.
// =======================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LlmConfig {
    pub mutation_strategy: String,
    pub max_variants: u32,
    pub send_to_fuzzer: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WasmConfig {
    pub decompile: bool,
    pub export_symbols: bool,
    pub extract_strings: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceMapConfig {
    pub reconstruct: bool,
    pub resolve_original: bool,
    pub download_missing: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ArtifactConfig {
    #[serde(default)]
    pub probe_paths: Vec<String>,
    pub max_size_bytes: u64,
    pub extract_archives: bool,
    pub secret_scan: bool,
    pub pattern_file: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "analysis_type", content = "config", rename_all = "snake_case")]
pub enum DeepAnalysisType {
    LlmMutation(LlmConfig),
    WasmDecompile(WasmConfig),
    SourceMapReconstruct(SourceMapConfig),
    ArtifactRecovery(ArtifactConfig),
    Custom(serde_json::Value),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisCondition {
    pub metric: String,
    pub operator: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeepAnalysisTemplate {
    pub target: String,

    #[serde(flatten)]
    pub analysis: DeepAnalysisType,

    pub prompt: Option<String>,

    pub severity_override: Option<String>,

    pub tags: Option<Vec<String>>,

    pub conditions: Option<Vec<AnalysisCondition>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deep_analysis_template_deser() {
        let json_str = r#"{
            "target": "example.com",
            "prompt": "bypass waf with SQLi",
            "analysis_type": "llm_mutation",
            "config": {
                "mutation_strategy": "sql_injection",
                "max_variants": 5,
                "send_to_fuzzer": true
            }
        }"#;
        let tmpl: DeepAnalysisTemplate = serde_json::from_str(json_str).unwrap();
        assert_eq!(tmpl.target, "example.com");
        assert_eq!(tmpl.prompt, Some("bypass waf with SQLi".into()));
        if let DeepAnalysisType::LlmMutation(cfg) = &tmpl.analysis {
            assert_eq!(cfg.mutation_strategy, "sql_injection");
            assert_eq!(cfg.max_variants, 5);
            assert!(cfg.send_to_fuzzer);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_deep_analysis_variants() {
        let json_str = r#"{
            "target": "test.app",
            "analysis_type": "wasm_decompile",
            "config": {
                "decompile": true,
                "export_symbols": false,
                "extract_strings": true
            }
        }"#;
        let tmpl: DeepAnalysisTemplate = serde_json::from_str(json_str).unwrap();
        assert_eq!(tmpl.target, "test.app");
        assert!(tmpl.prompt.is_none());
        if let DeepAnalysisType::WasmDecompile(cfg) = &tmpl.analysis {
            assert!(cfg.decompile);
            assert!(!cfg.export_symbols);
            assert!(cfg.extract_strings);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_deep_analysis_serde_roundtrip() {
        let tmpl = DeepAnalysisTemplate {
            target: "roundtrip.dev".into(),
            prompt: Some("recover configs".into()),
            severity_override: None,
            tags: None,
            conditions: None,
            analysis: DeepAnalysisType::ArtifactRecovery(ArtifactConfig {
                probe_paths: vec!["/tmp".into()],
                max_size_bytes: 1024,
                extract_archives: true,
                secret_scan: false,
                pattern_file: None,
            }),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: DeepAnalysisTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.target, deser.target);
        assert_eq!(tmpl.prompt, deser.prompt);
    }
}
