use serde_json::json;
use std::collections::HashMap;
use test_runner::*;

fn ctx() -> HashMap<String, String> {
    HashMap::from([("TARGET_URL".into(), "http://localhost".into())])
}

#[test]
fn threat_attack_graph() {
    let wasm = build_wasm("valayam-plugin-threat-audit");
    let input = WasmInput {
        template: json!({"id": "attack_graph_default", "name": "threat"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
    assert_eq!(out.findings.len(), 1);
}

#[test]
fn threat_auto_exploit_critical() {
    let wasm = build_wasm("valayam-plugin-threat-audit");
    let input = WasmInput {
        template: json!({"id": "auto_exploit_default", "name": "threat"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
    assert_eq!(out.findings[0].severity, "Critical");
}

#[test]
fn threat_auto_redteam() {
    let wasm = build_wasm("valayam-plugin-threat-audit");
    let input = WasmInput {
        template: json!({"id": "auto_redteam_default", "name": "threat"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn threat_mitre() {
    let wasm = build_wasm("valayam-plugin-threat-audit");
    let input = WasmInput {
        template: json!({"id": "mitre_mapping_default", "name": "mitre"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn threat_remediation() {
    let wasm = build_wasm("valayam-plugin-threat-audit");
    let input = WasmInput {
        template: json!({"id": "remediation_gen_default", "name": "remediation"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
}

#[test]
fn threat_unknown_template() {
    let wasm = build_wasm("valayam-plugin-threat-audit");
    let input = WasmInput {
        template: json!({"id": "unknown_xyz", "name": "test"}),
        context: ctx(),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}