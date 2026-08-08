use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

fn ctx() -> HashMap<String, String> {
    HashMap::from([("TARGET_URL".into(), "http://localhost".into())])
}

#[test]
fn spec_nuclei_compat() {
    let wasm = build_wasm("valayam-plugin-specialized-audit");
    let input = WasmInput {
        template: json!({"id": "nuclei_compat_test", "name": "nuclei"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn spec_scada() {
    let wasm = build_wasm("valayam-plugin-specialized-audit");
    let input = WasmInput {
        template: json!({"id": "scada_audit_test", "name": "scada"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn spec_scripting() {
    let wasm = build_wasm("valayam-plugin-specialized-audit");
    let input = WasmInput {
        template: json!({"id": "scripting_test", "name": "scripting"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn spec_extractors() {
    let wasm = build_wasm("valayam-plugin-specialized-audit");
    let input = WasmInput {
        template: json!({"id": "extractors_test", "name": "extractors"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn spec_unknown() {
    let wasm = build_wasm("valayam-plugin-specialized-audit");
    let input = WasmInput {
        template: json!({"id": "unknown_xyz", "name": "unknown"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}