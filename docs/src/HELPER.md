# Valayam CLI & Operations Guide

Comprehensive guide for operating the `valayam` security scanner, building and packaging plugins, running distributed scans, and managing scans via the control plane.

---

## 1. Quick Start & Basic Usage

### Help Information
```bash
cargo run --bin valayam-cli -- --help
```

### Basic Scans
```bash
# Scan a target using a single YAML template
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo/demo-template.yaml

# Scan using all templates in a directory (concurrent batch execution)
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo/

# Scan with custom concurrency and global rate limiting (e.g. 50 req/sec, 100 workers)
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo/ -r 50 --concurrency 100

# Scan with User-Agent rotation and proxy list
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo/ --random-agent --proxy-file ./proxies.txt
```

---

## 2. CLI Flags & Options Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target` | `-u` | `https://httpbin.org` | Target Base URL or IP |
| `--template` | `-t` | None | Path to Native YAML template file or directory |
| `--nuclei-template` | `-n` | None | Path to Nuclei YAML template file/directory (isolated engine) |
| `--output` | `-o` | None | Path to write output findings |
| `--format` | | `json` | Output report format: `json`, `sarif`, `pdf` |
| `--rate-limit` | `-r` | None | Max requests per second (token bucket limiter) |
| `--concurrency` | | `500` | Max concurrent template executions |
| `--random-agent` | | `false` | Rotate User-Agent headers randomly per request |
| `--proxy-file` | | None | Path to file containing HTTP/SOCKS proxies (one per line) |
| `--log-level` | `-l` | `info` | Logging verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `--log-file` | `-f` | None | Path to output JSON structured log file |
| `--crawl` | | `false` | Crawl target to discover endpoints before running templates |
| `--crawl-depth` | | `3` | Maximum crawl depth |
| `--crawl-headers` | | None | Custom headers for crawler (`Key:Value,Key2:Value2`) |
| `--waf-detect` | | `false` | Detect and fingerprint WAF before scanning |
| `--mitm-proxy` | | None | Start local MITM proxy on specified port to record traffic |
| `--resume` | | None | Resume interrupted scan using scan state ID |
| `--worker` | | None | Delegate execution to gRPC worker node (e.g. `http://127.0.0.1:50051`) |
| `--control-port` | | None | Start execution control API server on specified port |
| `--require-signed-plugins` | | `false` | Reject unsigned WASM/VPA plugins at load time |
| `--allow-internal` | | `false` | Allow scanning internal/private IP ranges (disabled for SSRF protection) |
| `--plugin-memory-limit` | | `128` | Max memory per WASM plugin in MB |
| `--plugin-timeout` | | `30` | Plugin execution timeout in seconds |
| `--plugin-allow-host` | | `[]` | Explicit host egress whitelist for WASM sandboxes |
| `--tls-cert` | | None | Path to TLS certificate (PEM) for gRPC control plane |
| `--tls-key` | | None | Path to TLS private key (PEM) for gRPC control plane |
| `--tls-ca` | | None | Path to CA certificate (PEM) for mTLS client verification |

---

## 3. Subcommands

### A. Plugin Management (`valayam plugin`)

Valayam features a plugin ecosystem supporting WASM (Extism) and out-of-process gRPC plugins.

```bash
# 1. Initialize boilerplate for a new plugin
valayam plugin init my-audit-plugin --lang rust --runtime wasm
valayam plugin init my-grpc-plugin --lang python --runtime grpc

# 2. Generate ED25519 signing keypair
valayam plugin generate-key -o my_signing_key

# 3. Package and cryptographically sign a plugin into a .vpa archive
valayam plugin package ./my-audit-plugin -o my-audit.vpa --sign my_signing_key.pem

# 4. Install a plugin from a remote URL or OCI registry
valayam plugin install my-audit https://registry.valayam.io/plugins/my-audit.vpa
valayam plugin install my-audit oci://registry.valayam.io/plugins/my-audit:v1.0 --pubkey <HEX_PUBKEY>

# 5. Push packaged plugin to an OCI registry
valayam plugin push ./my-audit.vpa --repo localhost:5000/valayam/my-audit --tag 1.0.0
```

### B. Vulnerability Database Synchronization (`valayam sync-vulndb`)

Sync the local vulnerability database from the Valayam CDN for air-gapped deployments:

```bash
valayam sync-vulndb --cdn https://cdn.valayam.io --output data/vuln-db.sqlite
```

### C. Live Scan Control (`valayam control`)

Pause, resume, or cancel active scans on a multi-tenant worker:

```bash
# Pause a scan
valayam control pause --scan-id scan-12345 --port 50051

# Resume a paused scan
valayam control resume --scan-id scan-12345 --port 50051

# Cancel a scan
valayam control cancel --scan-id scan-12345 --port 50051
```

---

## 4. Developing WASM Plugins

Developers can build sandboxed security checks using `valayam-plugin-sdk`.

### Project Setup (`Cargo.toml`)
```toml
[package]
name = "cors-audit"
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

### Plugin Implementation (`src/lib.rs`)
```rust
use extism_pdk::*;
use valayam_plugin_sdk::prelude::*;

#[plugin_fn]
pub fn scan(input: Json<WasmInput>) -> FnResult<Json<WasmOutput>> {
    let target = input.context.get("TARGET_URL").cloned().unwrap_or_default();
    
    // Perform host HTTP request via host functions
    let response = host_http_get(&format!("{}/api/test", target))?;
    
    let mut findings = Vec::new();
    let mut matched = false;

    if response.headers.contains_key("access-control-allow-origin") {
        matched = true;
        findings.push(Finding {
            id: "cors-wildcard".to_string(),
            name: "CORS Misconfiguration Detected".to_string(),
            severity: Severity::Medium,
            description: "Overly permissive CORS header identified.".to_string(),
            matched_at: target,
        });
    }

    Ok(Json(WasmOutput { matched, findings }))
}
```

---

## 5. Distributed Scanning Architecture

### Running as a gRPC Worker Node
```bash
# Start worker listening on port 50051
cargo run --bin valayam-worker -- --port 50051
```

### Delegating Scans via CLI
```bash
# Offload template and WASM execution to remote worker
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo/ --worker http://127.0.0.1:50051
```

### Starting the Agent Daemon
```bash
# Continuous host & network scanner agent
cargo run --bin valayam-agent
```
