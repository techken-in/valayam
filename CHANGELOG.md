# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-26

### Added
- **Dynamic WASM Plugin Ecosystem**: Transitioned from a monolithic 53-feature architecture to a modular WebAssembly architecture powered by Extism.
- Added `valayam-plugin-sdk` to allow external developers to easily author sandboxed plugins.
- Distributed gRPC worker architecture for scaling scans across multiple nodes.
- AI orchestration layer for generating and executing test cases autonomously.
- Robust `.github` workflows and CI/CD foundations, including dependabot.

### Changed
- Refactored `valayam-core` into a thin orchestration layer.
- Overhauled documentation (`README.md`, `ARCHITECTURE.md`, `features.md`, `helper.md`) to focus on the WASM plugin architecture.
- Cleaned up root directory by moving all utility Python scripts to `scripts/`.
