use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn cloud_audit_localhost_no_match() {
    let wasm = build_wasm("valayam-plugin-cloud-audit");
    let input = WasmInput {
        template: json!({"id": "test", "info": {"name": "cloud"}}),
        context: HashMap::from([("BaseURL".into(), "http://localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}