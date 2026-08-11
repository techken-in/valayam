// valayam-mcp/src/main.rs — MCP server for Valayam security scanner

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Parser;
use rmcp::{
    handler::server::ServerHandler,
    model::{
        CallToolRequestParam, CallToolResult, Content, InitializeResult, ListToolsResult,
        PaginatedRequestParam, ProtocolVersion, ServerCapabilities, Tool,
    },
    service::{serve_server, RequestContext, RoleServer},
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command as TokioCommand;
use tracing::info;

use valayam_models::FindingOwned;
use valayam_proto::valayam::{scanner_client::ScannerClient, ScanRequest, TelemetryEvent};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

// =============================================================================
// Config
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
struct McpConfig {
    #[serde(default = "default_grpc")]
    grpc_endpoint: String,
    #[serde(default)]
    tls_cert_path: Option<String>,
    #[serde(default)]
    tls_key_path: Option<String>,
    #[serde(default)]
    tls_ca_path: Option<String>,
    #[serde(default = "default_valayam_home")]
    valayam_home: String,
    #[serde(default = "default_cli_bin")]
    cli_binary: String,
}

fn default_grpc() -> String { "http://localhost:50051".into() }
fn default_valayam_home() -> String { dirs::home_dir().unwrap_or_default().join(".valayam").to_string_lossy().into() }
fn default_cli_bin() -> String { "valayam".into() }

#[derive(Parser, Debug)]
#[command(name = "valayam-mcp")]
struct Args {
    #[arg(long, default_value = "config/mcp.toml")]
    config: String,
}

// =============================================================================
// State
// =============================================================================

#[derive(Clone)]
struct ValayamState {
    cfg: McpConfig,
    grpc_client: Option<ScannerClient<Channel>>,
}

impl ValayamState {
    async fn new(cfg: McpConfig) -> Result<Self> {
        // Try to connect to gRPC
        let grpc_client = Self::create_grpc_client(&cfg).await.ok();

        Ok(Self { cfg, grpc_client })
    }

    async fn create_grpc_client(cfg: &McpConfig) -> Result<ScannerClient<Channel>> {
        let mut endpoint = Channel::from_shared(cfg.grpc_endpoint.clone())?;

        if let (Some(cert), Some(key)) = (&cfg.tls_cert_path, &cfg.tls_key_path) {
            let cert_pem = tokio::fs::read(cert).await?;
            let key_pem = tokio::fs::read(key).await?;
            let identity = Identity::from_pem(cert_pem, key_pem);
            let tls = ClientTlsConfig::new().identity(identity);
            if let Some(ca) = &cfg.tls_ca_path {
                let ca_pem = tokio::fs::read(ca).await?;
                let ca_cert = Certificate::from_pem(ca_pem);
                endpoint = endpoint.tls_config(tls.ca_certificate(ca_cert))?;
            } else {
                endpoint = endpoint.tls_config(tls)?;
            }
        }

        let channel = endpoint.connect().await?;
        Ok(ScannerClient::new(channel))
    }

    fn get_or_create_client(&self) -> Result<ScannerClient<Channel>> {
        self.grpc_client.clone().ok_or_else(|| anyhow!("gRPC client not available - check endpoint config"))
    }
}

// =============================================================================
// Tool input types
// =============================================================================

#[derive(Deserialize, Serialize, JsonSchema)]
struct RunScanInput {
    target: String,
    template: Option<String>,
    template_file: Option<String>,
    #[serde(default)]
    plugins: Vec<String>,
    #[serde(default)]
    exclude_plugins: Vec<String>,
    #[serde(default)]
    rate_limit: Option<u32>,
    #[serde(default)]
    output_format: Option<String>, // json, console, sarif
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct ListTemplatesInput {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct GetTemplateInput {
    name: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct GrpcScanInput {
    target_url: String,
    template_yaml: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct GrpcTelemetryInput {
    #[serde(default)]
    event_type: String,
    payload_json: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct ListPluginsInput {}

#[derive(Deserialize, Serialize, JsonSchema)]
struct GenerateReportInput {
    scan_results_path: String,
    format: String, // html, pdf, json
    #[serde(default)]
    output_path: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct ConfigGetInput {
    key: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct ConfigSetInput {
    key: String,
    value: Value,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct ProjectInitInput {
    name: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    template: Option<String>,
}

// =============================================================================
// Server
// =============================================================================

#[derive(Clone)]
struct ValayamMcp {
    state: Arc<ValayamState>,
}

impl ValayamMcp {
    fn new(state: Arc<ValayamState>) -> Self {
        Self { state }
    }

    fn schema<T: JsonSchema>() -> Arc<serde_json::Map<String, Value>> {
        let schema = schemars::schema_for!(T);
        let value = serde_json::to_value(schema).expect("schema serialization");
        Arc::new(value.as_object().expect("schema is object").clone())
    }

    fn tools() -> Vec<Tool> {
        vec![
            Tool::new("run_scan", "Run a security scan via CLI", Self::schema::<RunScanInput>()),
            Tool::new("list_templates", "List available vulnerability templates", Self::schema::<ListTemplatesInput>()),
            Tool::new("get_template", "Get a specific template by name", Self::schema::<GetTemplateInput>()),
            Tool::new("grpc_scan", "Run scan via gRPC API", Self::schema::<GrpcScanInput>()),
            Tool::new("grpc_telemetry", "Send telemetry event via gRPC", Self::schema::<GrpcTelemetryInput>()),
            Tool::new("list_plugins", "List available plugins", Self::schema::<ListPluginsInput>()),
            Tool::new("generate_report", "Generate scan report", Self::schema::<GenerateReportInput>()),
            Tool::new("config_get", "Get configuration value", Self::schema::<ConfigGetInput>()),
            Tool::new("config_set", "Set configuration value", Self::schema::<ConfigSetInput>()),
            Tool::new("project_init", "Initialize a new scan project", Self::schema::<ProjectInitInput>()),
            Tool::new("list_agents", "List eBPF agents", Self::schema::<ListPluginsInput>()),
            Tool::new("health_check", "Check gRPC/API health", Self::schema::<ListPluginsInput>()),
        ]
    }

    // ---- Implementations ----

    async fn run_scan(&self, input: RunScanInput) -> Result<CallToolResult> {
        let mut cmd = TokioCommand::new(&self.state.cfg.cli_binary);
        cmd.arg("scan").arg(&input.target);

        if let Some(t) = &input.template {
            cmd.arg("--template").arg(t);
        }
        if let Some(f) = &input.template_file {
            cmd.arg("--template-file").arg(f);
        }
        for p in &input.plugins {
            cmd.arg("--plugin").arg(p);
        }
        for p in &input.exclude_plugins {
            cmd.arg("--exclude-plugin").arg(p);
        }
        if let Some(r) = input.rate_limit {
            cmd.arg("--rate-limit").arg(r.to_string());
        }
        if let Some(f) = &input.output_format {
            cmd.arg("--output").arg(f);
        }

        cmd.env("VALAYAM_HOME", &self.state.cfg.valayam_home);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = cmd.output().await?;

        Ok(CallToolResult::success(vec![Content::json(json!({
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }))?]))
    }

    async fn list_templates(&self, input: ListTemplatesInput) -> Result<CallToolResult> {
        let template_dir = PathBuf::from(&self.state.cfg.valayam_home).join("templates");
        let mut templates = Vec::new();

        if template_dir.exists() {
            let mut entries = tokio::fs::read_dir(&template_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yaml") ||
                   path.extension().and_then(|s| s.to_str()) == Some("yml") {
                    let content = tokio::fs::read_to_string(&path).await?;
                    if let Ok(template) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        let name = template.get("info").and_then(|i| i.get("name")).and_then(|n| n.as_str()).unwrap_or("unknown");
                        let category = template.get("info").and_then(|i| i.get("category")).and_then(|c| c.as_str());
                        let tags = template.get("info").and_then(|i| i.get("tags")).and_then(|t| t.as_sequence()).map(|s| {
                            s.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()
                        }).unwrap_or_default();

                        if input.category.as_deref() == category || input.category.is_none() {
                            if input.tags.is_empty() || input.tags.iter().any(|t| tags.contains(&t.as_str())) {
                                templates.push(json!({
                                    "name": name,
                                    "file": path.file_name().unwrap().to_string_lossy(),
                                    "category": category,
                                    "tags": tags,
                                }));
                            }
                        }
                    }
                }
            }
        }

        Ok(CallToolResult::success(vec![Content::json(json!({ "templates": templates }))?]))
    }

    async fn get_template(&self, input: GetTemplateInput) -> Result<CallToolResult> {
        let template_dir = PathBuf::from(&self.state.cfg.valayam_home).join("templates");

        for ext in ["yaml", "yml"] {
            let path = template_dir.join(format!("{}.{}", input.name, ext));
            if path.exists() {
                let content = tokio::fs::read_to_string(&path).await?;
                let template: serde_yaml::Value = serde_yaml::from_str(&content)?;
                return Ok(CallToolResult::success(vec![Content::json(json!({
                    "name": input.name,
                    "template": template,
                }))?]));
            }
        }

        Err(anyhow!("template not found: {}", input.name))
    }

    async fn grpc_scan(&self, input: GrpcScanInput) -> Result<CallToolResult> {
        let mut client = self.state.get_or_create_client()?;

        let request = ScanRequest {
            target_url: input.target_url,
            template_yaml: input.template_yaml,
        };

        let response = client.scan(request).await?
            .into_inner();

        Ok(CallToolResult::success(vec![Content::json(json!({
            "findings": response.findings_json,
        }))?]))
    }

    async fn grpc_telemetry(&self, input: GrpcTelemetryInput) -> Result<CallToolResult> {
        let mut client = self.state.get_or_create_client()?;

        let event = TelemetryEvent {
            event_type: input.event_type,
            payload_json: input.payload_json,
        };

        // stream_telemetry expects a stream of TelemetryEvent, not Result<TelemetryEvent, _>
        let stream = tokio_stream::iter(vec![event]);
        let response = client.stream_telemetry(stream).await?
            .into_inner();

        Ok(CallToolResult::success(vec![Content::json(json!({
            "received": response.received,
        }))?]))
    }

    async fn list_plugins(&self, _input: ListPluginsInput) -> Result<CallToolResult> {
        let plugin_dir = PathBuf::from(&self.state.cfg.valayam_home).join("plugins");
        let mut plugins = Vec::new();

        if plugin_dir.exists() {
            let mut entries = tokio::fs::read_dir(&plugin_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                    plugins.push(json!({
                        "name": path.file_stem().unwrap().to_string_lossy(),
                        "type": "wasm",
                        "path": path.to_string_lossy(),
                    }));
                }
            }
        }

        // Also check built-in plugins from engine
        plugins.push(json!({ "name": "http", "type": "builtin" }));
        plugins.push(json!({ "name": "dns", "type": "builtin" }));
        plugins.push(json!({ "name": "tls", "type": "builtin" }));
        plugins.push(json!({ "name": "ssh", "type": "builtin" }));

        Ok(CallToolResult::success(vec![Content::json(json!({ "plugins": plugins }))?]))
    }

    async fn generate_report(&self, input: GenerateReportInput) -> Result<CallToolResult> {
        let content = tokio::fs::read_to_string(&input.scan_results_path).await?;
        let findings: Vec<FindingOwned> = serde_json::from_str(&content)?;

        let output = match input.format.as_str() {
            "json" => serde_json::to_string_pretty(&findings)?,
            "html" => Self::generate_html_report(&findings)?,
            _ => return Err(anyhow!("unsupported format: {}", input.format)),
        };

        if let Some(path) = input.output_path {
            tokio::fs::write(&path, &output).await?;
            Ok(CallToolResult::success(vec![Content::json(json!({
                "written_to": path,
            }))?]))
        } else {
            Ok(CallToolResult::success(vec![Content::json(json!({
                "report": output,
            }))?]))
        }
    }

    fn generate_html_report(findings: &[FindingOwned]) -> Result<String> {
        let mut html = String::from(r#"
<!DOCTYPE html>
<html>
<head><title>Valayam Scan Report</title>
<style>
body { font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; }
.finding { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin: 16px 0; }
.critical { border-left: 4px solid #dc2626; }
.high { border-left: 4px solid #ea580c; }
.medium { border-left: 4px solid #d97706; }
.low { border-left: 4px solid #65a30d; }
.info { border-left: 4px solid #2563eb; }
.severity { font-weight: bold; text-transform: uppercase; }
</style>
</head>
<body>
<h1>Valayam Security Scan Report</h1>
<p>Generated: "#);
        html.push_str(&Utc::now().to_rfc3339());
        html.push_str("</p>\n");

        for f in findings {
            let severity = f.severity.to_string().to_lowercase();
            html.push_str(&format!(r#"
<div class="finding {severity}">
    <h3>{} <span class="severity {severity}">{severity}</span></h3>
    <p><strong>Template:</strong> {} (ID: {})</p>
    <p><strong>Target:</strong> {}</p>
    <p><strong>Location:</strong> {}</p>
    <p><strong>Description:</strong> {}</p>
    <p><strong>Remediation:</strong> {}</p>
</div>"#,
                f.template_name,
                f.template_name,
                f.template_id,
                f.target,
                f.matched_at,
                f.description.as_deref().unwrap_or("N/A"),
                f.solution.as_deref().unwrap_or("N/A"),
            ));
        }

        html.push_str("</body></html>");
        Ok(html)
    }

    async fn config_get(&self, input: ConfigGetInput) -> Result<CallToolResult> {
        let config_path = PathBuf::from(&self.state.cfg.valayam_home).join("config.toml");
        if !config_path.exists() {
            return Ok(CallToolResult::success(vec![Content::json(json!({ "value": null }))?]));
        }
        let content = tokio::fs::read_to_string(&config_path).await?;
        let config: Value = toml::from_str(&content)?;
        let value = config.get(&input.key).cloned().unwrap_or(Value::Null);
        Ok(CallToolResult::success(vec![Content::json(json!({ "key": input.key, "value": value }))?]))
    }

    async fn config_set(&self, input: ConfigSetInput) -> Result<CallToolResult> {
        let config_path = PathBuf::from(&self.state.cfg.valayam_home).join("config.toml");
        let mut config: Value = if config_path.exists() {
            let content = tokio::fs::read_to_string(&config_path).await?;
            toml::from_str(&content)?
        } else {
            json!({})
        };

        if let Value::Object(ref mut map) = config {
            map.insert(input.key, input.value);
        }

        tokio::fs::write(&config_path, toml::to_string(&config)?).await?;
        Ok(CallToolResult::success(vec![Content::json(json!({ "ok": true }))?]))
    }

    async fn project_init(&self, input: ProjectInitInput) -> Result<CallToolResult> {
        let path = input.path.unwrap_or_else(|| format!("./{}", input.name));
        let project_dir = PathBuf::from(&path);
        tokio::fs::create_dir_all(&project_dir).await?;

        // Create basic project structure
        let templates_dir = project_dir.join("templates");
        tokio::fs::create_dir_all(&templates_dir).await?;

        let config_content = format!(r#"
[project]
name = "{}"
version = "0.1.0"

[scan]
default_rate_limit = 100
"#, input.name);
        tokio::fs::write(project_dir.join("valayam.toml"), config_content).await?;

        // If template specified, copy it
        if let Some(template_name) = input.template {
            let src = PathBuf::from(&self.state.cfg.valayam_home).join("templates").join(format!("{}.yaml", template_name));
            if src.exists() {
                let content = tokio::fs::read_to_string(&src).await?;
                tokio::fs::write(templates_dir.join(format!("{}.yaml", template_name)), content).await?;
            }
        }

        Ok(CallToolResult::success(vec![Content::json(json!({
            "project_path": path,
            "created": true,
        }))?]))
    }

    async fn list_agents(&self, _input: ListPluginsInput) -> Result<CallToolResult> {
        // The valayam proto doesn't expose a generic control endpoint for listing agents
        // This would require extending the proto or using a different mechanism
        Ok(CallToolResult::success(vec![Content::json(json!({
            "agents": [],
            "note": "Agent listing not available via gRPC - proto only supports PauseScan/ResumeScan/CancelScan",
        }))?]))
    }

    async fn health_check(&self, _input: ListPluginsInput) -> Result<CallToolResult> {
        let mut checks = serde_json::Map::new();

        // CLI check
        let cli_check = TokioCommand::new(&self.state.cfg.cli_binary)
            .arg("--version")
            .output()
            .await;
        checks.insert("cli".into(), json!({
            "available": cli_check.is_ok(),
            "version": cli_check.ok().and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default(),
        }));

        // gRPC check
        let grpc_ok = self.state.get_or_create_client().is_ok();
        checks.insert("grpc".into(), json!({ "available": grpc_ok }));

        // Template dir
        let tdir = PathBuf::from(&self.state.cfg.valayam_home).join("templates");
        checks.insert("templates".into(), json!({ "available": tdir.exists() }));

        // Plugin dir
        let pdir = PathBuf::from(&self.state.cfg.valayam_home).join("plugins");
        checks.insert("plugins".into(), json!({ "available": pdir.exists() }));

        Ok(CallToolResult::success(vec![Content::json(json!({
            "checks": checks,
            "healthy": checks.values().all(|v| v.get("available").and_then(|b| b.as_bool()).unwrap_or(false)),
        }))?]))
    }
}

impl ServerHandler for ValayamMcp {
    fn get_info(&self) -> InitializeResult {
        InitializeResult {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: rmcp::model::Implementation {
                name: "valayam-mcp".into(),
                version: "0.1.0".into(),
            },
            instructions: Some("Valayam security scanner operator surface - run scans, manage templates, generate reports".into()),
        }
    }

    async fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::Error> {
        Ok(ListToolsResult {
            tools: Self::tools(),
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let args_map = request.arguments.unwrap_or_default();
        let args = Value::Object(args_map);

        let result = match request.name.as_ref() {
            "run_scan" => {
                let input: RunScanInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.run_scan(input).await
            }
            "list_templates" => {
                let input: ListTemplatesInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.list_templates(input).await
            }
            "get_template" => {
                let input: GetTemplateInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.get_template(input).await
            }
            "grpc_scan" => {
                let input: GrpcScanInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.grpc_scan(input).await
            }
            "grpc_telemetry" => {
                let input: GrpcTelemetryInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.grpc_telemetry(input).await
            }
            "list_plugins" => {
                let input: ListPluginsInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.list_plugins(input).await
            }
            "generate_report" => {
                let input: GenerateReportInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.generate_report(input).await
            }
            "config_get" => {
                let input: ConfigGetInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.config_get(input).await
            }
            "config_set" => {
                let input: ConfigSetInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.config_set(input).await
            }
            "project_init" => {
                let input: ProjectInitInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.project_init(input).await
            }
            "list_agents" => {
                let input: ListPluginsInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.list_agents(input).await
            }
            "health_check" => {
                let input: ListPluginsInput = serde_json::from_value(args.clone())
                    .map_err(|e| rmcp::Error::invalid_params(e.to_string(), None))?;
                self.health_check(input).await
            }
            _ => return Err(rmcp::Error::invalid_params(format!("unknown tool: {}", request.name), None)),
        };

        result.map_err(|e| rmcp::Error::internal_error(e.to_string(), None))
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config_str = tokio::fs::read_to_string(&args.config).await
        .context("reading mcp.toml")?;
    let cfg: McpConfig = toml::from_str(&config_str).context("parsing mcp.toml")?;

    let state = Arc::new(ValayamState::new(cfg).await?);
    let server = ValayamMcp::new(state);

    info!("valayam-mcp starting (stdio transport)");
    serve_server(server, stdio()).await?;
    Ok(())
}