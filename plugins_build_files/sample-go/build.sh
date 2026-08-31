#!/bin/bash
# Builds the Go sample plugin to WebAssembly using TinyGo.
tinygo build -o plugin.wasm -target wasi main.go
