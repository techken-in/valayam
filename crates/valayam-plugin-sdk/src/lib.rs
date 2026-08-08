//! Valayam Plugin SDK for WebAssembly (Extism PDK).
//!
//! On wasm32 targets the real extism_pdk re-export is available.
//! On host builds (non-wasm32) the crate compiles with minimal stubs.

pub mod macros;
pub mod models;

pub use models::*;

pub mod host_funcs;
