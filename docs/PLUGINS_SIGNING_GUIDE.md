# Valayam Plugin Development & Cryptographic Signing Guide

## 1. Overview

Valayam plugins (`.vpa` — Valayam Plugin Archive) are self-contained, sandboxed WebAssembly modules that extend the scanner with specialized auditing, detection, and analysis capabilities.

To guarantee supply-chain security and prevent tampering, Valayam implements asymmetric **Ed25519** digital signatures.

---

## 2. VPA Archive Structure

A valid `.vpa` package is a ZIP archive containing:

```text
my-plugin.vpa
├── plugin.yaml       # Plugin manifest metadata (name, version, entrypoint)
├── my_plugin.wasm    # Compiled WASM binary (WebAssembly/WASI)
├── resources/        # (Optional) Static rules, YAML payloads, or schemas
└── signature.sig     # 64-byte Ed25519 digital signature of plugin.yaml
```

---

## 3. Cryptographic Key Management

Valayam uses 256-bit Ed25519 keypairs (RFC 8032 / FIPS 186-5 compliant).

### 3.1 Generating a Keypair

```bash
valayam plugin generate-key -o keys/my_signer
```

This generates two Base64-armored PEM files:
- **`keys/my_signer.pem`** (Private Key): **KEEP SECRET!** Never commit to git or publish.
- **`keys/my_signer.pub`** (Public Key): **DISTRIBUTE!** Safe to commit to git, publish on GitHub, and share with users.

### 3.2 Key Protection Rules (`.gitignore`)

Always ensure private keys are ignored while public keys remain tracked:

```gitignore
# Secret signing keys
*.pem
*.key
*.priv
keys/*.pem
keys/*.key
keys/*.priv

# Allow public keys
!*.pub
!keys/*.pub
!keys/*.ed25519
```

---

## 4. Creating, Packaging & Signing Plugins

### 4.1 Step 1: Create Plugin Manifest (`plugin.yaml`)

```yaml
name: "my-custom-audit"
version: "0.1.0"
runtime: "wasm"
language: "rust"
entrypoint: "my_custom_audit.wasm"
```

### 4.2 Step 2: Compile WASM Binary

```bash
cargo build --target wasm32-wasip1 --release
```

### 4.3 Step 3: Package & Sign

```bash
valayam plugin package ./my-plugin-dir --sign keys/my_signer.pem -o dist/my-custom-audit-0.1.0.vpa
```

The CLI will:
1. Validate `plugin.yaml` existence and schema.
2. Sign the bytes of `plugin.yaml` using the Ed25519 private key.
3. Package all files, subdirectories, and the resulting `signature.sig` into the `.vpa` file.

---

## 5. Automated Build & Packaging Script

In plugin repositories (such as `valayam-plugins`), use the automated PowerShell script (`package_vpa.ps1`):

```powershell
$root = $PSScriptRoot
$keyPath = "$root/keys/official_signer.pem"
$distDir = "$root/dist"

Get-ChildItem -Directory -Path "$root/plugins-wasm" | ForEach-Object {
    $plugin = $_.Name
    valayam plugin package $_.FullName --sign $keyPath -o "$distDir/$plugin-0.1.0.vpa"
}
```

---

## 6. Runtime Verification & Installation

### 6.1 Installing a Signed Plugin

```bash
valayam plugin install my-plugin \
  --url https://github.com/techken-in/valayam-plugins/releases/download/v0.1.0/my-plugin-0.1.0.vpa \
  --pubkey keys/official_signer.pub
```

### 6.2 Enforcing Signature Verification During Scans

```bash
# Rejects any unverified, modified, or self-signed plugins
valayam -u https://example.com --require-signed-plugins
```

If a `.vpa` signature does not match the trusted public key, the engine aborts loading:
```text
Error: Signature validation failed: untrusted plugin
```
