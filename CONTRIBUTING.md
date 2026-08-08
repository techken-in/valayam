# Contributing to Valayam

Thank you for contributing to Valayam!

---

## 1. Development Setup

Valayam requires Rust 1.78+ and the WASM target:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WebAssembly compilation target
rustup target add wasm32-unknown-unknown

# Build the entire workspace
cargo build

# Run unit and integration tests
cargo test --workspace
cargo test -p valayam-tests
```

---

## 2. Workspace Structure & Guidelines

- **`crates/`**: All core components and modules are organized as individual crates.
- **`plugins-wasm/`**: Standalone WASM plugins compiled with `valayam-plugin-sdk`.
- **`templates_repo/`**: YAML vulnerability templates.

### Code Style & Quality
Before opening a pull request, ensure all checks pass:
```bash
# Format code
cargo fmt --all

# Run Clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Verify documentation builds cleanly
cargo doc --workspace --no-deps
```

---

## 3. Pull Request Process

1. Fork the repo and create a feature branch (`git checkout -b feature/my-feature`).
2. Add tests covering the new functionality.
3. Verify all workspace tests pass (`cargo test --workspace`).
4. Commit your changes and submit a pull request against `main`.
