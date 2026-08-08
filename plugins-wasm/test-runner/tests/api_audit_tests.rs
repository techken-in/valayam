use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

fn ctx() -> HashMap<String, String> {
    HashMap::from([("TARGET_URL".into(), "http://localhost".into())])
}

#[test]
fn api_unknown_template_returns_empty() {
    let wasm = build_wasm("valayam-plugin-api-audit");
    let input = WasmInput {
        template: json!({"id": "unknown", "name": "Test"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn api_auth_logic_dispatch() {
    let wasm = build_wasm("valayam-plugin-api-audit");
    let input = WasmInput {
        template: json!({"id": "auth_logic_check", "name": "Auth"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn api_cred_monitor() {
    let wasm = build_wasm("valayam-plugin-api-audit");
    let mut c = HashMap::new();
    c.insert("TARGET_URL".into(), "safe.com".into());
    let input = WasmInput {
        template: json!({"id": "cred_monitor_check", "name": "Cred"}),
        context: c,
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn api_grpc_dispatch() {
    let wasm = build_wasm("valayam-plugin-api-audit");
    let input = WasmInput {
        template: json!({"id": "grpc_audit_test", "name": "gRPC"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn api_web3_dispatch() {
    let wasm = build_wasm("valayam-plugin-api-audit");
    let input = WasmInput {
        template: json!({"id": "web3_audit_test", "name": "Web3"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}