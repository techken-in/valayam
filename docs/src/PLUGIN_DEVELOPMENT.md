# Valayam Plugin Authoring Guide

Valayam features a polyglot plugin architecture supporting **WebAssembly (WASM)** modules via Extism and out-of-process **gRPC** daemons.

---

## 1. Plugin Types & Runtimes

| Type | Runtime | Best Suited For | Sandboxing |
|---|---|---|---|
| **WASM Plugins** | Extism / Wasmtime | Lightweight, high-speed security checks (CORS, CSP, header inspection, API fuzzing) | Strong memory & capability isolation |
| **gRPC Plugins** | Out-of-process process / container | Heavyweight analysis, native OS bindings, or non-WASM languages (Go, Python, Java) | Process-level isolation |

---

## 2. Developing WASM Plugins (Rust)

WASM plugins are compiled with `wasm32-unknown-unknown` and interact with the host through `valayam-plugin-sdk`.

### Step 1: Scaffold Plugin
```bash
cargo run --bin valayam-cli -- plugin init my-audit-plugin --lang rust --runtime wasm
```

### Step 2: Configure `Cargo.toml`
```toml
[package]
name = "my-audit-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
valayam-plugin-sdk = { path = "../../crates/valayam-plugin-sdk" }
extism-pdk = "1.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### Step 3: Implement Scan Logic (`src/lib.rs`)
```rust
use extism_pdk::*;
use valayam_plugin_sdk::prelude::*;

#[plugin_fn]
pub fn scan(input: Json<WasmInput>) -> FnResult<Json<WasmOutput>> {
    let target = input.context.get("TARGET_URL").cloned().unwrap_or_default();

    // Call host-provided HTTP function
    let response = host_http_get(&format!("{}/api/v1/health", target))?;
    
    let mut findings = Vec::new();
    let mut matched = false;

    if response.status_code == 200 && response.body.contains("internal_debug_key") {
        matched = true;
        findings.push(Finding {
            id: "debug-endpoint-exposed".to_string(),
            name: "Internal Debug Key Exposed in API".to_string(),
            severity: Severity::High,
            description: format!("Endpoint {} leaked internal debug key.", target),
            matched_at: target,
        });
    }

    Ok(Json(WasmOutput { matched, findings }))
}
```

### Step 4: Host Functions
The following host functions are exposed to the WASM sandbox:
- `host_http_get(url)`: Perform HTTP GET through host's stealth connection pool.
- `host_dns_resolve(domain)`: Query host DNS resolver.
- `host_kv_get(key)` / `host_kv_set(key, value)`: Access scan-scoped key-value state.

---

## 3. Developing gRPC Plugins (Python / Go)

### Scaffold gRPC Plugin
```bash
cargo run --bin valayam-cli -- plugin init my-python-scanner --lang python --runtime grpc
```

### Python Implementation (`plugin.py`)
```python
from valayam_sdk import PluginServer, ScannerPlugin, Finding, Severity

class MySecurityScanner(ScannerPlugin):
    def execute(self, template, context):
        target = context.get("TARGET_URL", "")
        # Custom scanning logic
        return [
            Finding(
                id="custom-auth-bypass",
                title="Authentication Bypass Identified",
                severity=Severity.CRITICAL,
                description=f"Identified authentication bypass at {target}",
                matched_at=target
            )
        ]

if __name__ == "__main__":
    PluginServer(MySecurityScanner()).serve(port=50052)
```

---

## 4. Packaging, Signing & Distribution (`.vpa`)

Valayam uses **Valayam Plugin Archives (`.vpa`)** — signed zip packages containing:
1. `plugin.yaml` manifest.
2. Compiled `.wasm` binary or executable entrypoint.
3. `signature.sig` (cryptographic ED25519 signature).

### Manifest Format (`plugin.yaml`)
```yaml
name: "my-audit-plugin"
version: "1.0.0"
runtime: "wasm" # or "grpc"
entrypoint: "my_audit_plugin.wasm"
author: "Security Team"
capabilities:
  - "http_scan"
  - "dns_audit"
```

### Package and Sign
```bash
# 1. Generate keypair
valayam plugin generate-key -o release_key

# 2. Package into .vpa with signature
valayam plugin package ./my-audit-plugin -o my-audit.vpa --sign release_key.pem

# 3. Push to OCI registry
valayam plugin push ./my-audit.vpa --repo registry.valayam.io/plugins/my-audit --tag 1.0.0
```
