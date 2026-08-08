use valayam_engine::registry::PluginRegistry;

#[test]
fn test_vpa_plugin_packaging_and_loading() {
    let temp_dir = std::env::temp_dir().join("valayam_vpa_test");
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
    std::fs::create_dir_all(&temp_dir).unwrap();

    let plugin_src_dir = temp_dir.join("mock_plugin");
    std::fs::create_dir_all(&plugin_src_dir).unwrap();

    // 1. Create a mock executable (batch file) that simulates a gRPC plugin
    let bat_content = "@echo off\necho 1^|plugin^|tcp^|127.0.0.1:54321^|grpc\n";
    std::fs::write(plugin_src_dir.join("run.bat"), bat_content).unwrap();

    // 2. Create the plugin.yaml manifest
    let manifest_content = r#"
name: "mock-vpa-plugin"
version: "1.0.0"
runtime: "grpc"
language: "batch"
entrypoint: "run.bat"
"#;
    std::fs::write(plugin_src_dir.join("plugin.yaml"), manifest_content).unwrap();

    // 3. Package the plugin into a .vpa using the CLI
    let vpa_output = temp_dir.join("mock.vpa");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_valayam-cli"))
        .arg("plugin")
        .arg("package")
        .arg(plugin_src_dir.to_str().unwrap())
        .arg("--output")
        .arg(vpa_output.to_str().unwrap())
        .status()
        .expect("Failed to execute valayam-cli");

    assert!(status.success(), "Packaging failed with status: {}", status);

    assert!(vpa_output.exists(), "VPA file was not created");

    // 4. Create a plugins directory and move the .vpa there
    let plugins_dir = temp_dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    std::fs::rename(vpa_output, plugins_dir.join("mock.vpa")).unwrap();

    // 5. Initialize the PluginRegistry and verify it discovers and extracts the VPA
    let registry = PluginRegistry::new();
    registry
        .load_external_plugins(&plugins_dir)
        .expect("Registry should load VPA successfully");

    // We expect exactly 1 plugin to be loaded
    assert_eq!(
        registry.len(),
        1,
        "Expected exactly 1 plugin to be loaded from the VPA"
    );

    // We cannot fully test the gRPC lifecycle of a mock bat file in a simple test without hanging,
    // so we just verify that it parsed the manifest correctly and registered it.
}
