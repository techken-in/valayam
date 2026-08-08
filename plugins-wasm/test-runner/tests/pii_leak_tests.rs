use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn no_pii_on_unreachable() {
    let wasm = build_wasm("valayam-plugin-pii-leak-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "pii"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost:19998".into())]),
    };
    let result = run_plugin(&wasm, &input);
    assert!(!result.matched);
}