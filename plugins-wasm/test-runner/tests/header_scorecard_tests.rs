use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn scorecard_no_required_headers() {
    let wasm = build_wasm("valayam-plugin-header-scorecard");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "headers"}, "header_scorecard": []}),
        context: HashMap::from([("BaseURL".into(), "http://localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn scorecard_no_header_key() {
    let wasm = build_wasm("valayam-plugin-header-scorecard");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "headers"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}