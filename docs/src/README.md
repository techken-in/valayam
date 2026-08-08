# Valayam

[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-WASM%20%7C%20gRPC%20%7C%20Async-green.svg)](ARCHITECTURE.md)

**Valayam** is a high-performance, modular vulnerability scanner core built in Rust. Designed for modern security operations, it combines a lightweight asynchronous engine with sandboxed WebAssembly (WASM) plugins, gRPC distribution, eBPF telemetry hooks, and advanced network evasion capabilities.

---

## Key Features

- ⚡ **High-Performance Async Engine**: Built on Tokio with topological plugin scheduling, concurrent batch execution, and token-bucket rate limiting with adaptive backoff.
- 🧩 **Extensible WASM Plugin System**: Secure, sandboxed WebAssembly plugins powered by Extism and Wasmtime. Isolate audit logic while maintaining native-speed host FFI.
- 🌐 **Network Stealth & Evasion**: Bypasses WAFs and bot defenses via JA3/JA4 TLS fingerprint spoofing, proxy rotation, and dynamic User-Agent pool randomization.
- 📡 **Distributed gRPC Architecture**: Horizontally scale scan execution across remote worker daemons (`valayam-worker` & `valayam-agent`) managed via gRPC/REST APIs.
- 🔍 **Out-of-Band (OOB) Testing**: Built-in OOB correlation server (`valayam-oob`) for identifying blind vulnerabilities (SSRF, blind SQLi, out-of-band RCE).
- 📜 **API Schema Drift Detection**: Automatically compares live API response structures against OpenAPI/Swagger specifications to detect undocumented endpoints and drift.
- 🛡️ **Cryptographic Verification**: Native ED25519 signature enforcement for plugin integrity (`.vpa` packages) and OCI container registry distribution.
- 📊 **Multi-Format Enterprise Reporting**: Stream findings simultaneously to Console, JSON, SARIF (GitHub CodeQL compatible), and PDF reports.

---

## Workspace Architecture

Valayam is organized as a modular Cargo workspace:

| Crate | Description |
|---|---|
| [`valayam-core`](crates/valayam-core) | Core scanning framework, built-in plugins, template execution, and OCI distribution. |
| [`valayam-engine`](crates/valayam-engine) | Execution DAG, Extism WASM runtime, rate limiter, matcher/extractor engine. |
| [`valayam-cli`](crates/valayam-cli) | Main command-line interface with interactive progress and subcommands. |
| [`valayam-api`](crates/valayam-api) | High-throughput Axum REST and Tonic gRPC control plane API. |
| [`valayam-agent`](crates/valayam-agent) | Continuous scanning daemon for host and network auditing. |
| [`valayam-ebpf-agent`](crates/valayam-ebpf-agent) | Linux eBPF kernel-level event monitoring and network tracing agent. |
| [`valayam-network`](crates/valayam-network) | Stealth HTTP client, JA3/JA4 fingerprinting, and proxy management. |
| [`valayam-common`](crates/valayam-common) | Shared utilities (ports, secret regexes, URL parser, User-Agent rotator). |
| [`valayam-models`](crates/valayam-models) | Strongly-typed schemas for templates, findings, and WASM I/O. |
| [`valayam-threatintel`](crates/valayam-threatintel) | CISA KEV feeds, IOC matcher, and offline vulnerability database sync. |
| [`valayam-oob`](crates/valayam-oob) | Out-of-band interaction and correlation server. |
| [`valayam-crawler`](crates/valayam-crawler) | Target endpoint and asset discovery crawler. |
| [`valayam-schema-drift`](crates/valayam-schema-drift) | Live API vs. OpenAPI schema drift analyzer. |
| [`valayam-reporter`](crates/valayam-reporter) | Multi-sink reporting engine (JSON, SARIF, PDF, console). |
| [`valayam-plugin-sdk`](crates/valayam-plugin-sdk) | Rust SDK for authoring WASM and gRPC plugins. |
| [`valayam-crypto`](crates/valayam-crypto) | ED25519 key generation and plugin signature verification. |
| [`valayam-tests`](crates/valayam-tests) | End-to-end integration and mock server test suite. |

For detailed architectural flow and design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Quick Start

### Build & Run
```bash
# Build release binaries
cargo build --release

# Run scan using YAML templates
cargo run --release --bin valayam-cli -- -u https://example.com -t ./templates_repo/

# Run scan with rate limiting and output to SARIF
cargo run --release --bin valayam-cli -- -u https://example.com -t ./templates_repo/ -r 50 --format sarif -o report.sarif
```

### Distributed Scanning
```bash
# 1. Start gRPC worker node
cargo run --release --bin valayam-worker -- --port 50051

# 2. Delegate execution from CLI
cargo run --release --bin valayam-cli -- -u https://example.com -t ./templates_repo/ --worker http://127.0.0.1:50051
```

### Plugin Development
```bash
# Initialize a new WASM plugin
cargo run --bin valayam-cli -- plugin init my-audit --lang rust --runtime wasm

# Package and sign plugin
cargo run --bin valayam-cli -- plugin package ./my-audit -o my-audit.vpa --sign key.pem
```

For complete CLI flags, subcommands, and operational recipes, see [helper.md](helper.md).

---

## Running Tests

```bash
# Run unit tests across workspace
cargo test --workspace

# Run end-to-end integration scan tests
cargo test -p valayam-tests
```

---

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
