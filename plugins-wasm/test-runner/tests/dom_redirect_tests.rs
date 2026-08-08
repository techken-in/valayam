use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn dom_redirect_no_match_on_unreachable() {
    let wasm = build_wasm("valayam-plugin-dom-redirect-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "dom"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost:19900".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}