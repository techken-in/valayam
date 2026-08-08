#!/bin/bash
# Installs dependencies and builds the TypeScript/JS sample plugin to WebAssembly using extism-js.
npm install
extism-js index.js -i index.d.ts -o plugin.wasm
