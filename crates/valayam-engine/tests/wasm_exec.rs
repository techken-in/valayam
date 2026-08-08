use extism::{Manifest, Plugin, Wasm};
use std::path::PathBuf;

#[test]
#[ignore = "requires pre-built WASM plugins at ../../plugins/"]
fn test_cors_audit_plugin_raw_extism() {
    let wasm_path = PathBuf::from("../../plugins/cors_audit.wasm");
    let wasm = Wasm::file(&wasm_path);
    let manifest = Manifest::new([wasm]);

    // allow networking to evil.com
    let manifest = manifest.with_allowed_hosts(vec!["*".to_string()].into_iter());

    let mut plugin = Plugin::new(&manifest, [], true).expect("Failed to load Wasm via Extism");

    let input_json = r#"{
        "template": {
            "id": "cors-audit-01",
            "info": { "name": "CORS Misconfiguration" }
        },
        "context": {
            "BaseURL": "https://example.com"
        }
    }"#;

    // Should run successfully without panic
    let result_bytes = plugin
        .call::<&str, Vec<u8>>("execute_scan", input_json)
        .expect("Failed to execute scan");
    let result_str = std::str::from_utf8(&result_bytes).unwrap();
    println!("Scan Output: {}", result_str);

    assert!(result_str.contains("\"matched\""));
}
