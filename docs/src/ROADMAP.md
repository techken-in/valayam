# Valayam Core Engine Roadmap: 2026 → 2040

> A strategic evolution plan for the Valayam open-core vulnerability scanner engine, informed by IEEE cybersecurity research, Gartner CTEM frameworks, and emerging technology trajectories in post-quantum cryptography, autonomous AI agents, WebAssembly evolution, and neuromorphic computing.

---

## Current State (v0.1.0 — August 2026)

- Async Tokio-based scan pipeline with topological DAG scheduling
- Extism/Wasmtime WASM plugin sandbox with host FFI (DNS, KV store, HTTP)
- gRPC plugin bridges via Tonic
- JA3/JA4 TLS fingerprint spoofing and proxy rotation
- Token-bucket rate limiting with adaptive backoff
- YAML template engine (Nuclei-compatible) with regex/status/header matchers
- OOB blind vulnerability testing (SSRF, RCE, blind SQLi)
- API schema drift detection (OpenAPI/Swagger)
- CISA KEV threat intelligence feeds
- ED25519 plugin signing and OCI registry distribution
- Multi-format reporting (JSON, SARIF, PDF, console)
- eBPF kernel-level network monitoring agent
- 28 crates in modular workspace

---

## Phase 1: Hardening & Open-Source Readiness (2026 Q3 – 2027 Q2)

> **Goal:** Make valayam production-grade for public open-source adoption.

### Engine Stability
- [ ] Comprehensive integration test suite covering all 28 crates
- [ ] Fuzz testing for template parser, matcher engine, and network layer
- [ ] Deterministic scan reproducibility (seed-based randomization)
- [ ] Structured error hierarchy with actionable diagnostic messages
- [ ] Performance benchmarks: templates/sec, memory/target, latency p99

### Plugin Ecosystem v1
- [ ] Plugin SDK v1.0 stable API with semantic versioning guarantees
- [ ] Plugin marketplace manifest format (JSON schema for discovery)
- [ ] Hot-reload support for WASM plugins during long-running scans
- [ ] Plugin dependency resolution (plugin A requires plugin B)
- [ ] Community plugin contribution guidelines and review process

### WASI 0.3 Migration
- [ ] Migrate from Extism/Wasmtime to WASI 0.3 Component Model
- [ ] Native async support in plugin sandbox (stream<T>, future<T>)
- [ ] Capability-based security model (deny-by-default resource access)
- [ ] Polyglot plugin support (Rust, Go, Python, JS → WASM)

### Documentation & Community
- [ ] mdBook documentation site on GitHub Pages
- [ ] API reference auto-generated from `cargo doc`
- [ ] Plugin development tutorial with worked examples
- [ ] Template authoring guide with real-world vulnerability patterns
- [ ] CHANGELOG automation and release process

---

## Phase 2: Intelligence & Advanced Scanning (2027 Q3 – 2028 Q4)

> **Goal:** Evolve from a scanner into a contextualized risk assessment engine.

### Threat Intelligence Pipeline v2
- [ ] Real-time threat feed ingestion (STIX/TAXII 2.1 protocol support)
- [ ] Indicator of Compromise (IOC) correlation engine with temporal decay
- [ ] Exploit maturity classification (PoC → weaponized → in-the-wild)
- [ ] Software Bill of Materials (SBOM) generation during scanning (CycloneDX, SPDX)
- [ ] Dependency confusion and supply chain attack detection plugins

### Advanced Scanning Capabilities
- [ ] GraphQL introspection and authorization bypass scanning
- [ ] gRPC/Protobuf service reflection and fuzzing
- [ ] WebSocket message injection and testing
- [ ] Server-Side Request Forgery (SSRF) chained exploitation engine
- [ ] Infrastructure-as-Code (IaC) scanning (Terraform, CloudFormation, Pulumi)
- [ ] Container image vulnerability scanning (OCI image layer analysis)

### Stealth Engine v2
- [ ] JA4+ fingerprint support (JA4S, JA4H, JA4X, JA4T)
- [ ] HTTP/3 QUIC protocol support for scanning
- [ ] Dynamic request timing jitter to evade behavioral detection
- [ ] Encrypted DNS (DoH/DoT) for resolver queries during scanning

---

## Phase 3: Post-Quantum Readiness & Crypto-Agility (2029 – 2030)

> **Goal:** Prepare the engine for the post-quantum cryptographic transition (IEEE P1943/P1947).

### Post-Quantum Cryptography (PQC) Migration
- [ ] Replace ED25519 plugin signatures with hybrid classical + PQC scheme
  - ML-DSA (Dilithium) for lattice-based signatures alongside ED25519
  - Gradual deprecation path with dual-signature verification
- [ ] PQC-aware TLS scanning: detect targets still using RSA/ECC-only
- [ ] HNDL (Harvest Now, Decrypt Later) risk assessment plugin
  - Flag assets transmitting long-lived secrets over non-PQC channels
- [ ] Crypto-agility framework: pluggable signature/verification backends
  - Allow swapping algorithms without engine rebuild

### SBOM & Supply Chain Governance
- [ ] Automated SBOM generation for scanned applications (CycloneDX 1.6+)
- [ ] SBOM-to-vulnerability cross-reference engine
- [ ] AIBOM (AI Bill of Materials) support for scanning AI/ML pipelines
  - Track model weights provenance, training data lineage, agent tool permissions
- [ ] Blockchain-anchored artifact integrity (optional module)
  - Immutable audit trail for plugin signatures and scan results

### Scanner Autonomy v1
- [ ] Self-tuning rate limiter (ML-based adaptive backoff using response latencies)
- [ ] Intelligent template selection (skip irrelevant templates based on target fingerprint)
- [ ] Automatic false positive reduction via response similarity clustering

---

## Phase 4: Autonomous AI Integration (2031 – 2034)

> **Goal:** Embed AI agents into the scanning lifecycle for autonomous operation (IEEE autonomous security agent research).

### AI-Augmented Engine
- [ ] Local LLM integration for intelligent payload generation
  - WAF-evasive SQLi, XSS, and command injection payload synthesis
  - Context-aware payload mutation based on target response patterns
- [ ] AI-driven vulnerability verification
  - Reduce false positives by having an LLM agent analyze response context
  - Generate human-readable exploitation narratives for confirmed findings
- [ ] Natural language template authoring
  - "Scan for open redirect on login endpoints" → generates YAML template
- [ ] Explainable AI (XAI) scan reports
  - Every AI-assisted finding includes reasoning chain and confidence score

### Agentic Scanning Framework
- [ ] Multi-agent scan orchestration within the engine
  - Reconnaissance agent → vulnerability discovery agent → exploitation verification agent
  - Agents communicate via structured message passing
- [ ] Agent identity and trust model (Zero Trust for non-human identities)
  - Each WASM plugin agent has cryptographically verified identity
  - Scoped capability grants per agent per scan
- [ ] Federated learning for scan pattern optimization
  - Opt-in anonymized telemetry to improve template selection models
  - No raw scan data leaves the engine; only gradient updates

### Advanced Protocol Support
- [ ] MQTT/AMQP IoT protocol scanning
- [ ] OPC-UA industrial control system (OT) auditing
- [ ] Bluetooth Low Energy (BLE) and Zigbee device enumeration
- [ ] 5G core network element scanning (SBI interfaces)
- [ ] Vehicle-to-Everything (V2X) communication security testing

---

## Phase 5: Neuromorphic & Next-Gen Computing (2035 – 2038)

> **Goal:** Leverage neuromorphic hardware and homomorphic encryption to achieve continuous, real-time, privacy-preserving scanning at unprecedented scale.

### Neuromorphic Scanning Engine
- [ ] Neuromorphic pattern recognition backend (optional hardware acceleration)
  - Real-time zero-day behavioral anomaly detection via spike-timing neural networks
  - Sub-millisecond response classification without traditional CPU overhead
- [ ] Edge-native scanning daemon
  - Lightweight engine variant for ARM/RISC-V edge devices and IoT gateways
  - Local anomaly detection with cloud sync for coordinated defense
- [ ] Moving Target Defense integration
  - Dynamic port/endpoint randomization to test defense resilience
  - Automated attack surface mutation during penetration testing

### Homomorphic Encryption (HE) Module
- [ ] Privacy-preserving scan result aggregation
  - Scan findings encrypted at source; aggregation without decryption
  - Cross-organization threat intelligence sharing on encrypted data
- [ ] Encrypted vulnerability matching
  - Match CVE signatures against encrypted asset inventories
  - Zero-knowledge proof of vulnerability existence without revealing asset details

### WASM Component Model v3+
- [ ] Full WASI threads support (cooperative + preemptive)
- [ ] Zero-copy stream forwarding between plugin components
- [ ] GPU/accelerator passthrough to WASM plugins for ML inference
- [ ] Deterministic plugin resource metering (CPU cycles, memory, I/O)

---

## Phase 6: Cognitive Security Engine (2039 – 2040)

> **Goal:** Achieve fully autonomous, self-evolving security assessment capabilities that anticipate threats before they materialize.

### Predictive Vulnerability Engine
- [ ] Predictive vulnerability forecasting using historical exploit trend analysis
  - "This software pattern will likely have a CVE within 6 months"
- [ ] Pre-emptive patch recommendation engine
  - Suggest hardening measures before vulnerabilities are publicly disclosed
- [ ] Digital twin scanning
  - Create lightweight digital replicas of target systems for non-invasive testing
  - Full exploitation simulation without touching production infrastructure

### Universal Protocol Fabric
- [ ] Auto-discovery and scanning of any network protocol via protocol inference
  - Automatically fingerprint and decompose unknown binary protocols
  - Generate scanning templates from observed protocol behavior
- [ ] Quantum-resistant key exchange for scanner-to-target communications
  - ML-KEM (Kyber) integration for all outbound TLS connections
- [ ] Satellite and space-based network scanning capability
  - LEO satellite communication protocol analysis

### Self-Evolving Plugin Ecosystem
- [ ] AI-generated plugins from vulnerability advisories
  - Ingest a CVE advisory → automatically generate a detection plugin
- [ ] Plugin behavioral verification via formal methods
  - Mathematical proofs that plugins cannot exceed their declared capabilities
- [ ] Cross-plugin learning: plugins share anonymized detection patterns

---

## Technology Dependency Timeline

```
2026 ──────── 2028 ──────── 2030 ──────── 2032 ──────── 2035 ──────── 2038 ──────── 2040
  │             │             │             │             │             │             │
  ├─ Rust 1.78+ ├─ WASI 0.3   ├─ PQC NIST   ├─ LLM Local ├─ Neuromorphic ─ Cognitive
  ├─ Tokio      ├─ HTTP/3     │  Standards   ├─ Agentic   │  Hardware     │  Engine
  ├─ Wasmtime   ├─ STIX 2.1   ├─ ML-DSA     │  AI v1     ├─ HE Practical ├─ Predictive
  ├─ Extism     ├─ CycloneDX  ├─ ML-KEM     ├─ 5G/V2X   ├─ Edge RISC-V  │  Vuln
  ├─ ED25519    ├─ SBOM       ├─ Crypto-    ├─ OT/IoT   ├─ Zero-Copy   ├─ Digital
  ├─ JA3/JA4    ├─ GraphQL    │  Agility    ├─ Federated│  WASM         │  Twins
  └─ gRPC       └─ IaC Scan   └─ AIBOM      │  Learning └─ P2P Mesh    └─ Protocol
                                              └─ ZT Mesh                    Inference
```

---

## IEEE & Industry Standards Alignment

| Standard | Relevance | Phase |
|:---|:---|:---|
| **NIST FIPS 203/204/205** | Post-quantum cryptographic algorithms (ML-KEM, ML-DSA) | Phase 3 |
| **IEEE P1943** | Post-Quantum Network Security framework | Phase 3 |
| **IEEE P1947** | Quantum Cybersecurity Framework | Phase 3 |
| **STIX/TAXII 2.1** | Structured threat intelligence exchange | Phase 2 |
| **CycloneDX / SPDX** | Software Bill of Materials standards | Phase 2-3 |
| **OWASP Top 10** | Web application security benchmark | Phase 1+ |
| **WASI 0.3 Component Model** | WebAssembly system interface for plugin sandboxing | Phase 1-5 |
| **Zero Trust Architecture (NIST SP 800-207)** | Identity-centric security model for agents | Phase 4 |

---

## Contributing to the Roadmap

This roadmap is a living document. To propose changes:

1. Fork the repository
2. Edit `docs/src/ROADMAP.md`
3. Submit a Pull Request with the `roadmap` label
4. Include rationale linking to relevant IEEE papers, Gartner reports, or industry trends

Community input is especially welcome for:
- New scanning protocol support proposals
- Plugin ecosystem governance models
- Regional compliance framework mappings
- Hardware acceleration benchmarks
