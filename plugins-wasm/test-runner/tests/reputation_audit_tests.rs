use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn reputation_localhost_clean() {
    let wasm = build_wasm("valayam-plugin-reputation-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "reputation"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn reputation_clean_domain() {
    let wasm = build_wasm("valayam-plugin-reputation-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "reputation"}}),
        context: HashMap::from([("BaseURL".into(), "https://safe-site.example".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}