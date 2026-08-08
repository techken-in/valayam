use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn empty_context_returns_no_match() {
    let wasm = build_wasm("cors-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "cors"}}),
        context: HashMap::new(),
    };
    let output = run_plugin(&wasm, &input);
    assert!(!output.matched);
}