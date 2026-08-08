// export_plugin! macro — only meaningful for WASM plugin builds.
#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! export_plugin {
    ($scanner_type:ty) => {
        #[extism_pdk::plugin_fn]
        pub fn execute_scan(input_json: String) -> extism_pdk::FnResult<Vec<u8>> {
            let input: $crate::WasmInput = serde_json::from_str(&input_json)
                .map_err(|e| extism_pdk::Error::msg(format!("JSON parse error: {}", e)))?;

            let scanner = <$scanner_type>::default();
            let result = $crate::WasmScanner::scan(&scanner, input)?;

            let result_bytes = serde_json::to_vec(&result)
                .map_err(|e| extism_pdk::Error::msg(format!("JSON serialize error: {}", e)))?;

            Ok(result_bytes)
        }
    };
}

// No-op on non-WASM targets so the crate compiles on host platforms.
#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! export_plugin {
    ($scanner_type:ty) => {
        // Plugin entry point not compiled on host — only meaningful for wasm32.
    };
}
