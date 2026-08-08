use valayam_cli::cli::Args;
use valayam_engine::executor::ScanExecutor;
use valayam_models::error::ScannerError;

mod mock_server;

#[tokio::test]
async fn test_scan_pipeline_basic() -> Result<(), ScannerError> {
    let mock_url = mock_server::start_mock_server().await;

    let args = Args {
        target: mock_url.clone(),
        template: None,
        nuclei_template: None,
        output: None,
        format: "json".into(),
        rate_limit: None,
        concurrency: 10,
        random_agent: false,
        proxy_file: None,
        log_level: "info".into(),
        log_file: None,
        worker: None,
        crawl: false,
        crawl_depth: 3,
        crawl_headers: None,
        waf_detect: false,
        mitm_proxy: None,
        resume: None,
        control_port: None,
        tls_cert: None,
        tls_key: None,
        tls_ca: None,
        require_signed_plugins: false,
        allow_internal: false,
        plugin_memory_limit: 128,
        plugin_timeout: 30,
        plugin_allow_host: vec![],
        command: None,
    };

    assert_eq!(args.target, mock_url);

    // We don't need a real executor for this test if we just test args parsing.
    // However, to actually test scanning, we need a template and an executor.
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;
    use valayam_engine::registry::PluginRegistry;

    let (tx, _rx) = mpsc::channel(100);
    let registry = std::sync::Arc::new(PluginRegistry::new());

    let executor = ScanExecutor::new(tx, registry, None, CancellationToken::new());

    // We need a dummy template to execute
    let mut template_inner = valayam_models::templates::schema::VulnerabilityTemplate::empty();
    template_inner.id = "test-template".into();
    template_inner.info.name = "Test Template".into();
    let template = std::sync::Arc::new(template_inner);

    let _results = executor.execute(&args.target, template).await;

    Ok(())
}
