//! Shared test infrastructure for all wasm plugin tests.

use extism::{Function, Manifest, Plugin, ValType, Wasm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct WasmInput {
    pub template: Value,
    pub context: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
pub struct WasmOutput {
    pub matched: bool,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Finding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub target: String,
    pub matched_at: String,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub extracted_data: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub fn wasm_target_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is plugins-wasm/test-runner
    // We want target/wasm32-unknown-unknown/release from the workspace root
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().join("target").join("wasm32-unknown-unknown").join("release")
}

pub fn build_wasm(package_name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    let status = std::process::Command::new("cargo")
        .args(["build", "--target", "wasm32-unknown-unknown", "-p", package_name])
        .current_dir(&root)
        .status()
        .unwrap_or_else(|e| panic!("cargo build failed for {package_name}: {e}"));
    assert!(status.success(), "cargo build failed for {package_name}");
    // We want target/wasm32-unknown-unknown/debug from the workspace root
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().join("target").join("wasm32-unknown-unknown").join("debug").join(&format!("{}.wasm", package_name.replace('-', "_")))
}

extism::host_fn!(dns_resolve(input: String) -> String {
    Ok("[]".to_string())
});

extism::host_fn!(kv_get(input: String) -> String {
    Ok("".to_string())
});

extism::host_fn!(kv_set(input: String) -> String {
    Ok("ok".to_string())
});

pub fn run_plugin(wasm_path: &PathBuf, input: &WasmInput) -> WasmOutput {
    let wasm = Wasm::file(wasm_path);
    let mut manifest = Manifest::new([wasm]);
    manifest = manifest.with_allowed_host("*");
    
    let f1 = Function::new("dns_resolve", [ValType::I64], [ValType::I64], extism::UserData::default(), dns_resolve);
    let f2 = Function::new("kv_get", [ValType::I64], [ValType::I64], extism::UserData::default(), kv_get);
    let f3 = Function::new("kv_set", [ValType::I64], [ValType::I64], extism::UserData::default(), kv_set);

    let mut plugin = Plugin::new(&manifest, [f1, f2, f3], true)
        .unwrap_or_else(|e| panic!("Failed to create plugin for {:?}: {e}", wasm_path));

    let input_json = serde_json::to_string(input).unwrap();
    let result_bytes: Vec<u8> = plugin
        .call::<&str, Vec<u8>>("execute_scan", &input_json)
        .unwrap_or_else(|e| panic!("execute_scan failed for {:?}: {e}", wasm_path));

    serde_json::from_slice(&result_bytes).unwrap()
}