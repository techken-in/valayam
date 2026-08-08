# Valayam Features & Capabilities Overview

Valayam is a full-featured, enterprise-grade security scanner engine. It combines high-throughput asynchronous network scanning with sandboxed WebAssembly execution and threat intelligence pipelines.

---

## 1. Core Scanning Capabilities

- **HTTP Template Execution**: Native YAML and Nuclei-compatible template parsing with multi-step requests, regex/status/header matchers, and dynamic variable extraction.
- **Stealth Network Probing**: Raw TCP/UDP port scanning (`valayam-core-net`), banner grabbing, and DNS record auditing (A, AAAA, CNAME, TXT, MX).
- **Out-of-Band (OOB) Testing**: Built-in DNS and HTTP callback listener (`valayam-oob`) for detecting blind SSRF, RCE, and data exfiltration.
- **Web Asset Discovery**: Multi-threaded crawler (`valayam-crawler`) parsing HTML, SPA JS routes, form parameters, and sitemaps.
- **API Schema Drift Detection**: Automated comparison of live HTTP responses against OpenAPI/Swagger schemas (`valayam-schema-drift`) to detect unauthorized parameters or route drift.
- **Threat Intelligence & KEV**: Direct ingestion of CISA Known Exploited Vulnerabilities feeds (`valayam-threatintel`) with IOC matching.
- **Multi-Sink Reporting**: Seamless generation of console summaries, JSON streams, SARIF exports for GitHub CodeQL, and PDF audit reports (`valayam-reporter`).

---

## 2. Stealth & Evasion Engine (`valayam-network`)

- **JA3 / JA4 Fingerprint Spoofing**: Simulates realistic browser TLS ClientHellos (Chrome, Firefox, Safari) to bypass WAFs and bot blockers.
- **Dynamic Proxy Rotation**: Supports pools of HTTP, HTTPS, and SOCKS5 proxies with automated failover and health checks.
- **User-Agent Pool Rotation**: Randomizes User-Agent strings using `valayam-common::UserAgentRotator`.
- **Token Bucket Rate Limiting**: Global and per-target request throttling to respect target SLAs.

---

## 3. Sandboxed Plugin Architecture

- **Extism WASM Runtime**: Run untrusted or third-party audit checks in isolated WebAssembly sandboxes with strict memory and CPU timeout limits.
- **Host Function Bridge**: Secure host function APIs for DNS resolution, scoped key-value persistence, and rate-limited HTTP dispatch.
- **gRPC Plugin Support**: Out-of-process distributed plugins communicating via Tonic gRPC.
- **Cryptographic Security**: ED25519 signature verification on all `.vpa` plugin packages.
- **OCI Container Distribution**: Push and pull packaged plugins from any OCI-compliant registry.

---

## 4. Distributed & Agent Architecture

- **Control Plane API (`valayam-api`)**: Axum REST and Tonic gRPC server for job dispatching, state management, and real-time finding feeds.
- **Host & Continuous Agent (`valayam-agent`)**: Polling daemon for scheduled and continuous environment security auditing.
- **Kernel-Level eBPF Monitoring (`valayam-ebpf-agent`)**: Linux eBPF tracepoint agent for monitoring raw socket connections and anomalous outbound traffic.
