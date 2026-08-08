use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

fn ctx() -> HashMap<String, String> {
    HashMap::from([
        ("TARGET_URL".into(), "http://example.com".into()),
        ("TARGET_HOST".into(), "example.com".into()),
    ])
}

#[test]
fn recon_easm_empty_domain() {
    let wasm = build_wasm("valayam-plugin-recon-audit");
    let input = WasmInput {
        template: json!({"id": "easm_scan", "name": "EASM", "domain": ""}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn recon_ct_log_empty_domain() {
    let wasm = build_wasm("valayam-plugin-recon-audit");
    let input = WasmInput {
        template: json!({"id": "ct_log_audit_check", "name": "CT", "domain": ""}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn recon_subdomain_takeover_empty_target() {
    let wasm = build_wasm("valayam-plugin-recon-audit");
    let input = WasmInput {
        template: json!({"id": "subdomain_takeover_check", "name": "Sub", "target": ""}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn recon_drift_detect_empty_target() {
    let wasm = build_wasm("valayam-plugin-recon-audit");
    let input = WasmInput {
        template: json!({"id": "drift_detect_check", "name": "Drift", "target": ""}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn recon_waf_bypass_empty_target() {
    let wasm = build_wasm("valayam-plugin-recon-audit");
    let input = WasmInput {
        template: json!({"id": "waf_bypass_verify_check", "name": "WAF", "target": ""}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn recon_unknown_template() {
    let wasm = build_wasm("valayam-plugin-recon-audit");
    let input = WasmInput {
        template: json!({"id": "unknown_xyz", "name": "Unknown"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}