use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn no_xss_on_unreachable_host() {
    let wasm = build_wasm("valayam-plugin-browser-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "browser"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost:19999".into())]),
    };
    let output = run_plugin(&wasm, &input);
    assert!(!output.matched);
}

#[test]
fn empty_context_defaults_to_localhost() {
    let wasm = build_wasm("valayam-plugin-browser-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "browser"}}),
        context: HashMap::new(),
    };
    let output = run_plugin(&wasm, &input);
    assert!(!output.matched);
}