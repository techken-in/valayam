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

/// A wrapper to easily load and test WASM plugins
pub struct PluginTester {
    plugin: Plugin,
}

impl PluginTester {
    /// Load a plugin from bytes with a mocked host environment
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
                // In a real mock, we would read the arg from memory and return from kv_store
                Ok(())
            },
        );

        let kv_ctx2 = ctx_arc.clone();
        let kv_set = Function::new(
            "kv_set",
            [ValType::I64],
            [ValType::I64],
            UserData::new(kv_ctx2),
            |_plugin, _args, _rets, _user_data| {
                Ok(())
            },
        );

        let dns_ctx = ctx_arc.clone();
        let dns_resolve = Function::new(
            "dns_resolve",
            [ValType::I64],
            [ValType::I64],
            UserData::new(dns_ctx),
            |_plugin, _args, _rets, _user_data| {
                Ok(())
            },
        );

        let plugin = PluginBuilder::new(manifest)
            .with_wasi(true)
            .with_functions([kv_get, kv_set, dns_resolve])
            .build()?;

        Ok(Self { plugin })
    }

    pub fn call(&mut self, func_name: &str, input: impl AsRef<[u8]>) -> Result<Vec<u8>, extism::Error> {
        self.plugin.call::<_, &[u8]>(func_name, input.as_ref()).map(|b| b.to_vec())
    }
}
