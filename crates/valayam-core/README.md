# Valayam Core Engine

`valayam-core` is the highly concurrent, Rust-based execution engine powering the Valayam CLI and Platform Worker Nodes.

## Architecture
The core engine consists of several subsystems:
- **Network Stack**: Provides a `StealthHttpClient`, raw socket support for port scanning, and DNS resolution.
- **Template Engine**: Executes YAML-based vulnerability signatures against targets.
- **Active Scanning Modules**: Implements advanced penetration testing maneuvers like:
  - WAF Bypass & Verification
  - IAM/Cloud SSRF Escalation
  - Active Kubernetes RBAC auditing
  - OAuth misconfiguration checks

## Integration
This crate is designed to be consumed as a library. It is used natively by the `valayam-cli` and the `valayam-worker` node.

## Development
To test the core library independently:
```bash
cargo test -p valayam-core
```
