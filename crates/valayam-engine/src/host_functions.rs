//! WASM host functions exposed to Extism plugins.
//!
//! Used by: wasm_plugin.rs — plugins call these functions at runtime.
//! Each function provides a sandboxed bridge to the host environment.
use extism::host_fn;

use std::fs;
use std::path::PathBuf;

host_fn!(pub dns_resolve(user_data: (); domain: String) -> String {
    use std::net::ToSocketAddrs;

    let mut ips = Vec::new();
    // Append :0 to the domain to make it a valid socket address for parsing
    if let Ok(addrs) = format!("{}:0", domain).to_socket_addrs() {
        for addr in addrs {
            ips.push(addr.ip().to_string());
        }
    }

    Ok(serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string()))
});

host_fn!(pub kv_get(user_data: (); key: String) -> String {
    let state_dir = PathBuf::from(".valayam-state");
    let file_path = state_dir.join(&key);

    if file_path.exists() {
        if let Ok(content) = fs::read_to_string(file_path) {
            return Ok(content);
        }
    }
    Ok("".to_string())
});

host_fn!(pub kv_set(user_data: (); input: String) -> String {
    let state_dir = PathBuf::from(".valayam-state");
    let _ = fs::create_dir_all(&state_dir);

    // input is JSON: {"key": "foo", "value": "bar"}
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&input) {
        if let Some(key) = json.get("key").and_then(|v| v.as_str()) {
            if let Some(value) = json.get("value").and_then(|v| v.as_str()) {
                let file_path = state_dir.join(key);
                let _ = fs::write(file_path, value);
                return Ok("ok".to_string());
            }
        }
    }
    Ok("error".to_string())
});
