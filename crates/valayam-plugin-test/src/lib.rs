use extism::{Plugin, PluginBuilder, Manifest, Wasm, Function, ValType, UserData};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use valayam_engine::vpa::PluginCapability;

/// A mock context for testing Valayam WASM plugins without the full engine.
pub struct MockTestContext {
    pub kv_store: Arc<Mutex<HashMap<String, String>>>,
    pub dns_responses: Arc<Mutex<HashMap<String, String>>>,
    pub capabilities: HashSet<PluginCapability>,
}

impl Default for MockTestContext {
    fn default() -> Self {
        let mut caps = HashSet::new();
        caps.insert(PluginCapability::Network);
        caps.insert(PluginCapability::Http);
        caps.insert(PluginCapability::Oob);
        caps.insert(PluginCapability::Dns);

        Self {
            kv_store: Arc::new(Mutex::new(HashMap::new())),
            dns_responses: Arc::new(Mutex::new(HashMap::new())),
            capabilities: caps,
        }
    }
}

/// A wrapper to easily load and test WASM plugins with snapshot assertion support.
pub struct PluginTester {
    plugin: Plugin,
    /// Captured call snapshots: (func_name, input_hex, output_hex)
    snapshots: Vec<(String, String, String)>,
}

impl PluginTester {
    /// Load a plugin from bytes with a mocked host environment.
    pub fn new(wasm_bytes: &[u8], ctx: MockTestContext) -> Result<Self, extism::Error> {
        let manifest = Manifest::new([Wasm::data(wasm_bytes)]);

        let ctx_arc = Arc::new(ctx);

        let kv_ctx = ctx_arc.clone();
        let kv_get = Function::new(
            "kv_get",
            [ValType::I64],
            [ValType::I64],
            UserData::new(kv_ctx),
            |_plugin, _args, _rets, user_data| {
                let _ctx = user_data.get()?;
                Ok(())
            },
        );

        let kv_ctx2 = ctx_arc.clone();
        let kv_set = Function::new(
            "kv_set",
            [ValType::I64],
            [ValType::I64],
            UserData::new(kv_ctx2),
            |_plugin, _args, _rets, _user_data| Ok(()),
        );

        let dns_ctx = ctx_arc.clone();
        let dns_resolve = Function::new(
            "dns_resolve",
            [ValType::I64],
            [ValType::I64],
            UserData::new(dns_ctx),
            |_plugin, _args, _rets, _user_data| Ok(()),
        );

        let plugin = PluginBuilder::new(manifest)
            .with_wasi(true)
            .with_functions([kv_get, kv_set, dns_resolve])
            .build()?;

        Ok(Self {
            plugin,
            snapshots: Vec::new(),
        })
    }

    /// Call a WASM function and return the raw bytes output.
    pub fn call(&mut self, func_name: &str, input: impl AsRef<[u8]>) -> Result<Vec<u8>, extism::Error> {
        let input_bytes = input.as_ref();
        let output = self.plugin.call::<_, &[u8]>(func_name, input_bytes).map(|b| b.to_vec())?;
        // Record snapshot
        self.snapshots.push((
            func_name.to_string(),
            hex::encode(input_bytes),
            hex::encode(&output),
        ));
        Ok(output)
    }

    /// Call a WASM function and parse the output as a UTF-8 string.
    pub fn call_str(&mut self, func_name: &str, input: &str) -> Result<String, extism::Error> {
        let out = self.call(func_name, input.as_bytes())?;
        String::from_utf8(out).map_err(|e| extism::Error::msg(e.to_string()))
    }

    /// Assert that the output of `func_name(input)` matches the expected string exactly.
    ///
    /// On mismatch, prints a clear diff-style message and panics.
    pub fn assert_output(&mut self, func_name: &str, input: &str, expected: &str) {
        match self.call_str(func_name, input) {
            Ok(actual) if actual == expected => {} // pass
            Ok(actual) => panic!(
                "Snapshot mismatch for {}({:?}):\n  expected: {:?}\n  actual:   {:?}",
                func_name, input, expected, actual
            ),
            Err(e) => panic!("Plugin call {}({:?}) failed: {}", func_name, input, e),
        }
    }

    /// Assert that the JSON output of `func_name(input)` contains a specific key with a specific value.
    pub fn assert_json_field(&mut self, func_name: &str, input: &str, json_key: &str, expected_value: &str) {
        let out = self.call_str(func_name, input)
            .unwrap_or_else(|e| panic!("Plugin call {}({:?}) failed: {}", func_name, input, e));
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("Output of {}({:?}) is not valid JSON: {}\nGot: {}", func_name, input, e, out));
        let actual = parsed.get(json_key)
            .unwrap_or_else(|| panic!("JSON key '{}' not found in output of {}({:?})\nGot: {}", json_key, func_name, input, out));
        assert_eq!(
            actual.to_string().trim_matches('"'),
            expected_value,
            "JSON field '{}' mismatch in {}({:?})",
            json_key, func_name, input
        );
    }

    /// Save the captured call snapshots to a JSON file for regression testing.
    ///
    /// Run with `VALAYAM_UPDATE_SNAPSHOTS=1` to update snapshot files.
    pub fn save_snapshots(&self, snapshot_path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.snapshots)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(snapshot_path, json)
    }

    /// Load and compare snapshots against a previously saved file.
    /// Returns `Ok(())` if all snapshots match, or an error message listing mismatches.
    pub fn verify_snapshots(&self, snapshot_path: &str) -> Result<(), String> {
        let contents = std::fs::read_to_string(snapshot_path)
            .map_err(|e| format!("Cannot read snapshot file '{}': {}", snapshot_path, e))?;
        let saved: Vec<(String, String, String)> = serde_json::from_str(&contents)
            .map_err(|e| format!("Cannot parse snapshot file '{}': {}", snapshot_path, e))?;

        if saved.len() != self.snapshots.len() {
            return Err(format!(
                "Snapshot count mismatch: saved {} but got {}",
                saved.len(), self.snapshots.len()
            ));
        }

        let mut mismatches = Vec::new();
        for (i, (saved_snap, current_snap)) in saved.iter().zip(self.snapshots.iter()).enumerate() {
            if saved_snap != current_snap {
                mismatches.push(format!(
                    "  [{}] fn={}, saved_out={}, current_out={}",
                    i, saved_snap.0, saved_snap.2, current_snap.2
                ));
            }
        }

        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(format!("Snapshot mismatches:\n{}", mismatches.join("\n")))
        }
    }

    /// Return all captured snapshots.
    pub fn snapshots(&self) -> &[(String, String, String)] {
        &self.snapshots
    }
}
