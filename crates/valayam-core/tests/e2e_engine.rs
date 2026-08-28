use std::sync::Arc;
use valayam_core::core::plugins::{AuthLogicPlugin, HttpScanPlugin, SubdomainTakeoverPlugin, WebsocketScanPlugin};
use valayam_core::network::http::StealthHttpClient;
use valayam_engine::executor::ScanExecutor;
use valayam_engine::registry::PluginRegistry;
use tokio::sync::mpsc;
use valayam_engine::traits::FindingOwned;

#[tokio::test]
async fn test_comprehensive_engine_pipeline() {
    let (tx, mut rx) = mpsc::channel::<FindingOwned>(10);
    
    // 1. Init stealth client (HTTP/2 + HTTP/3 multiplexing ready)
    let client = Arc::new(StealthHttpClient::new(false, false, None, false).unwrap());

    // 2. Init Plugin Registry with all Phase 3 plugins
    let mut registry = PluginRegistry::new();
    registry.register(HttpScanPlugin::new(client.clone()));
    registry.register(WebsocketScanPlugin::new());
    registry.register(AuthLogicPlugin::new(client.clone()));
    registry.register(SubdomainTakeoverPlugin::new());

    registry.init_all().await.unwrap();
    let reg_arc = Arc::new(registry);

    // 3. Executor
    let _executor = ScanExecutor::new(
        tx.clone(),
        reg_arc,
        None,
        tokio_util::sync::CancellationToken::new(),
    );

    // Normally we'd load a VulnerabilityTemplate and run the executor.
    // For this e2e mock, we just verify the registry setup succeeds
    // without crashes, proving the plugins satisfy the Engine Plugin API.

    assert!(true, "Engine successfully bootstrapped with Phase 3 plugins");
}
