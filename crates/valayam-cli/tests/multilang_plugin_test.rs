use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use valayam_core::template::schema::VulnerabilityTemplate;
use valayam_engine::registry::PluginRegistry;
use valayam_engine::traits::FindingOwned;

#[tokio::test]
#[ignore = "requires Go and Python toolchains installed"]
async fn test_multilang_plugins() {
    // 1. Create a temporary directory for plugins
    let temp_dir = tempfile::tempdir().unwrap();
    let plugins_dir = temp_dir.path().join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let project_root = Path::new("../../");
    let go_plugin_dir = project_root.join("plugins_ext/valayam-plugin-go");
    let py_plugin_dir = project_root.join("plugins_ext/valayam-plugin-python");

    // 2. Ensure Go plugin is built (assumes 'go' is in PATH)
    let status = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(plugins_dir.join("valayam-plugin-go.exe"))
        .current_dir(&go_plugin_dir)
        .status()
        .expect("Failed to build Go plugin");
    assert!(status.success(), "Go plugin failed to compile");

    // 3. Create a .bat wrapper that uses the virtual environment python
    let venv_python = std::env::current_dir().unwrap().join(
        py_plugin_dir
            .join("venv")
            .join("Scripts")
            .join("python.exe"),
    );
    let original_plugin_py = std::env::current_dir()
        .unwrap()
        .join(py_plugin_dir.join("plugin.py"));
    let bat_content = format!(
        "@echo off\n\"{}\" \"{}\"\n",
        venv_python.display(),
        original_plugin_py.display()
    );
    std::fs::write(plugins_dir.join("valayam-plugin-python.bat"), bat_content).unwrap();

    // 4. Initialize PluginRegistry
    let reg = PluginRegistry::new();
    reg.load_external_plugins(&plugins_dir).unwrap();

    // We expect at least 2 plugins: Go and Python wrappers
    assert!(reg.len() >= 2, "Failed to load at least 2 external plugins");

    let reg = Arc::new(reg);
    reg.init_all().await.expect("Failed to init plugins");

    // 5. Execute
    let yaml = r#"
id: test-multilang
info:
  name: Test Template
  author: Test
  severity: info
  description: Test multilang template
  tags: test
"#;
    let template: VulnerabilityTemplate =
        serde_yaml::from_str(yaml).expect("Failed to parse dummy template");
    let template = Arc::new(template);

    let (finding_tx, mut finding_rx) = mpsc::channel::<FindingOwned>(10);
    let cancel = CancellationToken::new();

    let target = "http://example.com";

    let metrics = reg
        .execute_template(target, template, &finding_tx, None, cancel)
        .await;

    assert!(
        metrics.len() >= 2,
        "Expected metrics for at least 2 plugins"
    );

    let mut received_findings = Vec::new();
    // Drop sender so receiver will complete when done
    drop(finding_tx);

    while let Some(f) = finding_rx.recv().await {
        received_findings.push(f);
    }

    assert!(received_findings.len() >= 2, "Expected at least 2 findings");

    let template_ids: Vec<_> = received_findings
        .iter()
        .map(|f| f.template_id.as_str())
        .collect();
    assert!(template_ids.contains(&"go-example"), "Missing Go finding");
    assert!(
        template_ids.contains(&"python-example"),
        "Missing Python finding"
    );

    reg.shutdown_all().await;
}
