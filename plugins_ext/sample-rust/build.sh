#!/bin/bash
# Builds the Rust sample plugin to WebAssembly targeting wasi.
cargo build --target wasm32-wasi --release
cp target/wasm32-wasi/release/*.wasm plugin.wasm
