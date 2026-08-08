use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

#[test]
fn code_empty_template() {
    let wasm = build_wasm("valayam-plugin-code-audit");
    let input = WasmInput {
        template: json!({"id": "", "name": ""}),
        context: HashMap::from([("TARGET_URL".into(), "".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn code_sast_nonexistent_dir() {
    let wasm = build_wasm("valayam-plugin-code-audit");
    let input = WasmInput {
        template: json!({"id": "sast_secrets_scan", "name": "SAST", "target_dir": "/nonexistent"}),
        context: HashMap::new(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn code_cicd_nonexistent() {
    let wasm = build_wasm("valayam-plugin-code-audit");
    let input = WasmInput {
        template: json!({"id": "cicd_audit_x", "name": "CI/CD", "target_repo": "/nonexistent"}),
        context: HashMap::new(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn code_client_secret_empty_target() {
    let wasm = build_wasm("valayam-plugin-code-audit");
    let input = WasmInput {
        template: json!({"id": "client_secret_audit_test", "name": "CS", "target": ""}),
        context: HashMap::from([("TARGET_URL".into(), "localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn code_sbom_empty_target() {
    let wasm = build_wasm("valayam-plugin-code-audit");
    let input = WasmInput {
        template: json!({"id": "sbom_audit_test", "name": "SBOM", "target": "", "type": "package.json"}),
        context: HashMap::from([("TARGET_URL".into(), "localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn code_client_secret_nonempty_target() {
    let wasm = build_wasm("valayam-plugin-code-audit");
    let input = WasmInput {
        template: json!({"id": "client_secret_audit_test", "name": "CS", "target": "http://localhost:19999"}),
        context: HashMap::from([("TARGET_URL".into(), "localhost".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}