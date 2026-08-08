use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn missing_csp_header_is_flagged() {
    let wasm = build_wasm("valayam-plugin-csp-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "CSP Audit"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost".into())]),
    };
    let output = run_plugin(&wasm, &input);
    assert!(output.matched);
    assert_eq!(output.count, 1);
    assert_eq!(output.findings[0].severity, "High");
}