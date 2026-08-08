# Security Policy

## Supported Versions

Valayam is a security scanner, so we take vulnerabilities in our own codebase extremely seriously. We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Valayam's core engine, networking layer, or official plugins, please **do not** open a public issue. 

Instead, please report it privately to the maintainers. We will review the issue, acknowledge your report within 48 hours, and work with you on a patch before publicly disclosing the vulnerability.

### What to report:
- Sandbox escapes (e.g. escaping the Extism WASM runtime)
- Denial of Service (DoS) vulnerabilities in the core engine
- Authentication or authorization bypasses in the distributed gRPC worker nodes
- Remote Code Execution (RCE) vulnerabilities in any component

### What NOT to report:
- Vulnerabilities found in *targets* that Valayam is scanning (e.g., if you use Valayam to scan `example.com` and find an XSS, do not report that here).
- Vulnerabilities in community-contributed `.wasm` plugins that are not part of the official `valayam/plugins-wasm/` repository.
