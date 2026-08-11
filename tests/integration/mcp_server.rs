// valayam tests/integration/mcp_server.rs
// Integration tests for valayam-mcp server (security scanner)

use std::process::Command;
use std::time::Duration;
use anyhow::Result;

mod common {
    use std::process::Command;

    pub fn mcp_binary() -> String {
        // Build in release mode if not already built
        let _ = Command::new("cargo")
            .args(["build", "--release", "--package", "valayam-mcp"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to build valayam-mcp");

        format!(
            "{}/target/release/valayam-mcp.exe",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    pub fn config_path() -> String {
        format!("{}/config/mcp.toml", env!("CARGO_MANIFEST_DIR"))
    }
}

#[tokio::test]
async fn test_mcp_server_starts_and_receives_initialize() -> Result<()> {
    let binary = common::mcp_binary();
    let config = common::config_path();

    let mut child = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(init_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    let mut stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(&mut stdout);

    let mut found_initialize = false;
    for line in reader.lines().take(10) {
        let line = line?;
        if line.contains("valayam-mcp") || line.contains("InitializeResult") || line.contains("protocolVersion") {
            found_initialize = true;
            break;
        }
    }

    child.kill()?;
    assert!(found_initialize, "MCP server should respond to initialize");
    Ok(())
}

#[tokio::test]
async fn test_mcp_server_lists_all_tools() -> Result<()> {
    let binary = common::mcp_binary();
    let config = common::config_path();

    let mut child = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    let tools_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(init_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(tools_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    let mut stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(&mut stdout);

    let mut tools_found = Vec::new();
    for line in reader.lines().take(20) {
        let line = line?;
        if line.contains("run_scan") || line.contains("list_templates") ||
           line.contains("get_template") || line.contains("grpc_scan") ||
           line.contains("grpc_telemetry") || line.contains("list_plugins") ||
           line.contains("generate_report") || line.contains("config_get") ||
           line.contains("config_set") || line.contains("project_init") ||
           line.contains("list_agents") || line.contains("health_check") {
            tools_found.push(line);
        }
    }

    child.kill()?;
    assert!(tools_found.len() >= 12, "Expected 12 tools, found: {}", tools_found.len());
    Ok(())
}

#[tokio::test]
async fn test_mcp_tool_call_health_check() -> Result<()> {
    let binary = common::mcp_binary();
    let config = common::config_path();

    let mut child = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    let call_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health_check","arguments":{}}}"#;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(init_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(call_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    let mut stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(&mut stdout);

    let mut found_result = false;
    for line in reader.lines().take(20) {
        let line = line?;
        if line.contains("checks") || line.contains("cli") || line.contains("grpc") ||
           line.contains("templates") || line.contains("plugins") {
            found_result = true;
            break;
        }
    }

    child.kill()?;
    assert!(found_result, "health_check tool should return health status");
    Ok(())
}

#[tokio::test]
async fn test_mcp_tool_call_list_templates() -> Result<()> {
    let binary = common::mcp_binary();
    let config = common::config_path();

    let mut child = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    let call_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_templates","arguments":{}}}"#;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(init_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(call_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    let mut stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(&mut stdout);

    let mut found_result = false;
    for line in reader.lines().take(20) {
        let line = line?;
        if line.contains("templates") {
            found_result = true;
            break;
        }
    }

    child.kill()?;
    assert!(found_result, "list_templates tool should return templates array");
    Ok(())
}

#[tokio::test]
async fn test_mcp_tool_call_list_plugins() -> Result<()> {
    let binary = common::mcp_binary();
    let config = common::config_path();

    let mut child = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    let call_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_plugins","arguments":{}}}"#;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(init_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(call_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    let mut stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(&mut stdout);

    let mut found_result = false;
    for line in reader.lines().take(20) {
        let line = line?;
        if line.contains("plugins") && (line.contains("http") || line.contains("builtin")) {
            found_result = true;
            break;
        }
    }

    child.kill()?;
    assert!(found_result, "list_plugins tool should return builtin plugins");
    Ok(())
}

#[tokio::test]
async fn test_mcp_tool_call_config_roundtrip() -> Result<()> {
    let binary = common::mcp_binary();
    let config = common::config_path();

    let mut child = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    let set_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"config_set","arguments":{"key":"test.integration","value":42}}}"#;
    let get_request = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"config_get","arguments":{"key":"test.integration"}}}"#;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(init_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(set_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(get_request.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    let mut stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(&mut stdout);

    let mut found_get_result = false;
    for line in reader.lines().take(30) {
        let line = line?;
        if line.contains("test.integration") && line.contains("42") {
            found_get_result = true;
            break;
        }
    }

    child.kill()?;
    assert!(found_get_result, "config_set/config_get roundtrip should work");
    Ok(())
}