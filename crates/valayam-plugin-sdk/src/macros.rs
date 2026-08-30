// export_plugin! macro - only meaningful for WASM plugin builds.
#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! export_plugin {
    ($scanner_type:ty) => {
        #[extism_pdk::plugin_fn]
        pub fn execute_scan(input_json: String) -> extism_pdk::FnResult<Vec<u8>> {
            let input: $crate::WasmInput = $crate::serde_json::from_str(&input_json)
                .map_err(|e| extism_pdk::Error::msg(format!("JSON parse error: {}", e)))?;

            let scanner = <$scanner_type>::default();
            let result = $crate::WasmScanner::scan(&scanner, input)?;

            let result_bytes = $crate::serde_json::to_vec(&result)
                .map_err(|e| extism_pdk::Error::msg(format!("JSON serialize error: {}", e)))?;

            Ok(result_bytes)
        }
    };
    ($scanner_type:ty, $config_type:ty) => {
        $crate::export_plugin!($scanner_type);

        #[extism_pdk::plugin_fn]
        pub fn get_schema() -> extism_pdk::FnResult<String> {
            Ok(<$config_type>::export_schema())
        }

        #[extism_pdk::plugin_fn]
        pub fn validate_config(raw_config: String) -> extism_pdk::FnResult<()> {
            // Valayam Engine converts the YAML block to JSON before passing it to WASM
            // so we parse it as JSON to avoid serde_yaml which bloats WASM
            let _config: $config_type = $crate::serde_json::from_str(&raw_config)
                .map_err(|e| extism_pdk::Error::msg(format!("Config validation error: {}", e)))?;
            Ok(())
        }
    };
}

// No-op on non-WASM targets so the crate compiles on host platforms.
#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! export_plugin {
    ($scanner_type:ty) => {
        // Plugin entry point not compiled on host - only meaningful for wasm32.
    };
    ($scanner_type:ty, $config_type:ty) => {
        // Plugin entry point not compiled on host - only meaningful for wasm32.
    };
}
