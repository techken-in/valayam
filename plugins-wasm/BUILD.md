# WASM Plugin Build Guide

Valayam plugins are WebAssembly modules (`.wasm`) compiled to `wasm32-wasi` or `wasm32-unknown-unknown` targets and run via the Extism runtime. They are excluded from the host workspace — build them independently.

## Prerequisites

```bash
rustup target add wasm32-wasi
```

## Build All Plugins

```bash
cd plugins-wasm && cargo build --target wasm32-wasi --release
```

Output lands in `plugins-wasm/bin/`.

## Build a Single Plugin

```bash
cargo build -p cors-audit --target wasm32-wasi --release
```

## Plugin Structure

Each plugin is a standalone crate under `plugins-wasm/`. It depends on:

- `extism-pdk` — the Extism host bindings (only compiles for WASM targets)
- `valayam-plugin-sdk` — the Valayam plugin SDK (extism-pdk conditionally gated behind `cfg(target_arch = "wasm32")`)

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
extism-pdk = "1.4.1"
valayam-plugin-sdk = { path = "../../crates/valayam-plugin-sdk" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

## Testing with Extism CLI

```bash
extism call plugins-wasm/bin/cors_audit.wasm run \
  --input '{"url":"https://example.com"}' \
  --allow-host "*"
```

## CI / Workspace Note

Plugins under `plugins-wasm/*` are deliberately excluded from the root workspace (`Cargo.toml`):

```toml
exclude = ["plugins-wasm/*"]
```

This prevents host-compilation failures — `extism-pdk` only links against WASM targets. Build plugins separately in CI with:

```bash
cargo build --target wasm32-wasi --release --manifest-path plugins-wasm/cors-audit/Cargo.toml
cargo build --target wasm32-wasi --release --manifest-path plugins-wasm/api-audit/Cargo.toml
# ... repeat for each plugin
```