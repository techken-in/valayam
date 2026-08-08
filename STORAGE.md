# Valayam Storage Architecture (Standalone CLI / Engine)

This document describes the storage system for **plugins (.vpa)** and **YAML templates** in the standalone Valayam CLI and engine.

## Overview

Valayam separates two artifact types with identical storage semantics:

| Artifact | Format | Use Case |
|---|---|---|
| **Plugin** | `.vpa` (ZIP: `plugin.wasm` + `plugin.yaml` + `signature.sig`) | User-defined scan logic |
| **Template** | `.yaml` / `.yml` | Scan definitions, policies, rulesets |

Both are stored via the **ArtifactStore** abstraction (in `valayam-common`), which presents a uniform async interface:
- `put(key, bytes)` / `get(key)` / `delete(key)` / `exists(key)` / `list(prefix)` / `stat(key)`

The **logical key** is a path-like string (e.g., `tenant-abc/xxxx.vpa`) — never a host filesystem path.

---

## Backends

### 1. Local (default)
- Files under `root/` matching the logical key.
- Path traversal blocked (`..` segments rejected).
- Works on any POSIX or Windows filesystem.

### 2. S3 / Minio
- Not yet implemented in standalone `valayam` crate (only `local` backend available).
- Available in `valayam-platform` via the `s3` Cargo feature.

---

## Configuration (Environment Variables)

| Variable | Default | Description |
|---|---|---|
| `VALAYAM_STORAGE_BACKEND` | `local` | Currently only `local` supported in standalone |
| `VALAYAM_OFFLINE_MODE` | `false` | Air-gapped mode; forces `local`, blocks network |
| `VALAYAM_PLUGIN_HOME` | `./data/plugins` or `/var/lib/valayam/plugins` | Plugin `.vpa` directory |
| `VALAYAM_PLUGIN_CACHE` | `./data/plugin_cache` | Extracted WASM cache (runtime) |
| `VALAYAM_TEMPLATE_HOME` | `./data/templates` | Raw YAML templates |
| `VALAYAM_WORKER_PLUGIN_SOURCE` | `local` | `local` (directory watch) \| `store` (fetch-on-demand) |

### Default Resolution (local backend)

- `VALAYAM_PLUGIN_HOME`: checks `./data/plugins` first; if directory exists, uses it. Otherwise `/var/lib/valayam/plugins` (FHS-compliant).
- `VALAYAM_PLUGIN_CACHE`: `./data/plugin_cache` or `$XDG_CACHE_HOME/valayam/plugins_cache`.
- `VALAYAM_TEMPLATE_HOME`: `./data/templates`.

---

## Online (Normal) Usage

### CLI Template Commands
```bash
# Push YAML templates to local storage backend
valayam template push ./my-templates [--prefix templates/]

# Pull templates from storage backend
valayam template pull [--output ./templates] [--prefix templates/]

# List templates in storage
valayam template list [--prefix templates/]
```

### Plugin Registry (valayam-engine)
- `PluginRegistry::with_cache_dir(path)` sets extraction cache.
- `extract_vpa(vpa_path, cache_dir, pubkey, skip_extract_if_cache_hit)`:
  - Reads manifest, computes SHA-256 of entrypoint WASM.
  - If `skip_extract_if_cache_hit` and `{cache_dir}/{hash}.wasm` exists → returns cached path.
  - Otherwise full extraction, then caches entrypoint for future hits.

### Orchestrator (valayam-cli)
- `Orchestrator::run()` detects `VALAYAM_OFFLINE_MODE` and bundle directories automatically.
- In offline mode: configures `registry.cache_dir = bundle/wasm_cache`, loads plugins from `bundle/plugins`, skips hot-reload.

---

## Air-Gapped (Offline) Deployment

Enable with `VALAYAM_OFFLINE_MODE=1` (or `true`, `yes`, `on`).

### Effects
- Forces `VALAYAM_STORAGE_BACKEND=local` (ignores any other value).
- Blocks all network egress in CLI: `install`, `push`, `update` commands fail fast.

### Bundle Workflow

1. **Online machine** (with internet/registry access):
   ```bash
   valayam bundle create \
       --plugins ./plugins \
       --templates ./templates \
       --pubkey ./keys/public.ed25519 \
       --output ./bundle
   ```
   Creates:
   ```
   bundle/
   ├── plugins/           # .vpa files (copied as-is with SHA-256 in manifest)
   ├── templates/         # .yaml files (copied as-is with SHA-256 in manifest)
   ├── wasm_cache/        # Empty directory for runtime cache
   ├── keys/
   │   └── public.ed25519 # Public key for manifest integrity
   └── manifest.json      # Version, timestamp, plugin list, template list, hashes
   ```

2. **Transfer** `bundle/` to air-gapped environment (USB, signed container image, etc.)

3. **Air-gapped machine**:
   ```bash
   export VALAYAM_OFFLINE_MODE=1
   export VALAYAM_PLUGIN_HOME=/path/to/bundle/plugins
   export VALAYAM_PLUGIN_CACHE=/path/to/bundle/wasm_cache
   export VALAYAM_TEMPLATE_HOME=/path/to/bundle/templates
   ```

4. **Verify** bundle integrity on target:
   ```bash
   valayam bundle verify /path/to/bundle
   ```
   Checks all SHA-256 hashes in `manifest.json` match files on disk.

### Runtime Behaviour (offline)
- `VALAYAM_OFFLINE_MODE=1` → CLI `install`/`push`/`update` exit with error.
- `extract_vpa` called with `skip_extract_if_cache_hit=true` → reuses `wasm_cache/` entrypoints if hash matches.
- No network calls attempted.

---

## Key Management

### Plugin Signing (Ed25519)
- `.vpa` contains `signature.sig` = Ed25519 signature over `plugin.wasm || plugin.yaml`.
- Public key distributed via bundle (`keys/public.ed25519`) or configured via `VALAYAM_PLUGIN_PUBKEY`.
- Verification happens on extraction (`extract_vpa`).

### Encryption (AES-256-GCM)
- Optional per-blob encryption at rest via `VALAYAM_PLUGIN_ENC_KEY` (base64, 32 bytes).
- Used by `PluginCrypto::encrypt()` / `decrypt()`.

---

## CLI Commands Summary

### Plugin Management
```bash
# Install plugin from VPA file or URL (requires network, fails in offline mode)
valayam plugin install <name> <url> [--pubkey <pubkey>]

# Push signed plugin to registry (requires network)
valayam plugin push <file.vpa> [--repo <url>] [--tag <tag>] [--signature <sig>]
```

### Template Management
```bash
# Push YAML templates to configured storage backend
valayam template push ./my-templates [--prefix templates/]

# Pull templates from storage backend
valayam template pull [--output ./templates] [--prefix templates/]

# List templates in storage
valayam template list [--prefix templates/]
```

### Bundle Management
```bash
# Create air-gapped bundle
valayam bundle create --plugins ./plugins --templates ./templates --pubkey ./key.pem --output ./bundle

# Verify bundle integrity
valayam bundle verify ./bundle
```

---

## Cross-Repo Contract

Both `valayam-platform` (crates/platform-config) and `valayam` (crates/valayam-common) implement **identical** `StorageConfig::from_env()` logic. The environment variable contract is the single source of truth.

When modifying the contract:
1. Update `valayam-platform/crates/platform-config/src/storage.rs`
2. Update `valayam/crates/valayam-common/src/storage.rs`
3. Update `.env.example` in both repos
4. Update this `STORAGE.md` and `valayam-platform/STORAGE.md`

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `InvalidKey` on put/get | Key contains `..` or starts with `/` | Use relative keys without traversal |
| Offline mode but network calls | `VALAYAM_OFFLINE_MODE` not exported in shell | `export VALAYAM_OFFLINE_MODE=1` before running |
| Bundle verify fails | Files corrupted or manifest tampered | Re-create bundle from trusted source |
| Template push/pull not found | `VALAYAM_TEMPLATE_HOME` dir doesn't exist | Run `valayam template push` which creates it, or `mkdir -p data/templates` |