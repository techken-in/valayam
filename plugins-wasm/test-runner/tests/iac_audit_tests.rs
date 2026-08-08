use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn empty_target_returns_nothing() {
    let wasm = build_wasm("valayam-plugin-iac-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "IaC"}, "target": ""}),
        context: HashMap::new(),
    };
    let output = run_plugin(&wasm, &input);
    assert!(!output.matched);
}

#[test]
fn nonexistent_file_returns_nothing() {
    let wasm = build_wasm("valayam-plugin-iac-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "IaC"}, "target": "/nonexistent"}),
        context: HashMap::new(),
    };
    let output = run_plugin(&wasm, &input);
    assert!(!output.matched);
}