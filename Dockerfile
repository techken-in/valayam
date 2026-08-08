# syntax=docker/dockerfile:1
# Stage 1: Build WASM plugins + CLI binary with musl target for static linking.
FROM rust:latest AS builder

RUN apt-get update && apt-get install -y musl-tools protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl wasm32-wasip1

WORKDIR /app
COPY Cargo.toml Cargo.lock deny.toml ./
COPY crates/ crates/
COPY plugins-wasm/ plugins-wasm/

# Pre-build WASM plugins first (they don't need the workspace binary)
RUN --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    for plugin in plugins-wasm/*/; do \
        if [ -f "${plugin}Cargo.toml" ]; then \
            cargo build --manifest-path "${plugin}Cargo.toml" --target wasm32-wasip1 --release; \
        fi; \
    done

# Build the CLI binary (static musl)
RUN --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --package valayam-cli --target x86_64-unknown-linux-musl --release

# Collect WASM outputs
RUN --mount=type=cache,target=/app/target \
    mkdir -p /out/plugins-wasm && \
    for plugin in plugins-wasm/*/; do \
        name=$(basename "$plugin"); \
        name_us=$(echo "$name" | tr '-' '_'); \
        wasm_file="target/wasm32-wasip1/release/valayam_plugin_${name_us}.wasm"; \
        if [ -f "$wasm_file" ]; then cp "$wasm_file" "/out/plugins-wasm/${name}.wasm"; fi; \
    done && \
    cp target/x86_64-unknown-linux-musl/release/valayam-cli /out/valayam

# Stage 2: Minimal runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /valayam
COPY --from=builder /out/valayam /usr/local/bin/valayam
COPY --from=builder /out/plugins-wasm/ ./plugins-wasm/

ENTRYPOINT ["valayam"]
CMD ["--help"]