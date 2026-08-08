pub mod agent_config;
pub mod cli;
pub mod config;
pub mod notifications;
pub mod orchestrator;
pub mod plugin_cli;
pub mod reporting;
pub mod setup;
pub mod state;
// Telemetry moved to `valayam-telemetry` crate — see init_telemetry() call below.

use clap::Parser;
use colored::*;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use setup::*;
use valayam_engine::rate_limiter::RateLimiter;

/// Prints the branded Valayam ASCII banner to stdout.
fn print_banner() {
    let banner = r#"
 ██╗   ██╗ █████╗ ██╗      █████╗ ██╗   ██╗ █████╗ ███╗   ███╗
 ██║   ██║██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝██╔══██╗████╗ ████║
 ██║   ██║███████║██║     ███████║ ╚████╔╝ ███████║██╔████╔██║
 ╚██╗ ██╔╝██╔══██║██║     ██╔══██║  ╚██╔╝  ██╔══██║██║╚██╔╝██║
  ╚████╔╝ ██║  ██║███████╗██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║
   ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝"#;
    println!("{}", banner.bright_cyan());
    println!(
        "{}",
        "                    Modern Stealth Scanner v0.1.0\n".bright_black()
    );
}

pub async fn run_cli() -> anyhow::Result<()> {
    let mut args = cli::Args::parse();

    // Ensure target has a valid protocol to prevent URL parsing errors
    if !args.target.starts_with("http://") && !args.target.starts_with("https://") {
        args.target = format!("http://{}", args.target);
    }

    let config = config::CliConfig::from_env();
    print_banner();
    // --- Telemetry setup (console + OTLP + optional file) ---
    let console_level_str = config.valayam_log.clone().unwrap_or_else(|| {
        if args.log_level.eq_ignore_ascii_case("info") {
            "error".to_string()
        } else {
            args.log_level.clone()
        }
    });
    let mut otlp_endpoint = config
        .otel_exporter_otlp_endpoint
        .clone()
        .unwrap_or_else(|| "http://localhost:4317".to_string());

    // ── Pre-flight OTLP Connectivity Check ──────────────────────────────
    let mut otlp_active = false;
    if let Ok(url) = reqwest::Url::parse(&otlp_endpoint) {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(4317);
            let addr_str = format!("{}:{}", host, port);
            if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&addr_str) {
                if let Some(addr) = addrs.next() {
                    if std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_millis(500),
                    )
                    .is_ok()
                    {
                        otlp_active = true;
                    }
                }
            }
        }
    }

    if !otlp_active {
        otlp_endpoint = String::new(); // Disable OTLP to prevent spam
    }

    let _telemetry = valayam_telemetry::init_telemetry(
        &console_level_str,
        &otlp_endpoint,
        args.log_file.as_deref().map(Path::new),
    );

    // Handle plugin subcommands — early return
    if let Some(cli::Commands::Plugin { action }) = &args.command {
        return handle_plugin_command(action).await;
    }
    // Handle vuln DB sync — early return
    if let Some(cli::Commands::SyncVulndb { cdn, output }) = &args.command {
        if let Err(e) = crate::orchestrator::sync_vulndb(cdn, output).await {
            tracing::error!("Failed to sync vulnerability database: {}", e);
        }
        return Ok(());
    }
    // Handle control subcommand — early return
    if let Some(cli::Commands::Control {
        action,
        scan_id,
        port,
    }) = &args.command
    {
        return handle_control_command(action, scan_id, port).await;
    }
    // Handle bundle subcommand — early return (air-gapped deployment)
    if let Some(cli::Commands::Bundle { action }) = &args.command {
        return handle_bundle_command(action).await;
    }
    // Handle template subcommand — early return (artifact store management)
    if let Some(cli::Commands::Template { action }) = &args.command {
        return handle_template_command(action).await;
    }
    // ── Template path resolution ──────────────────────────────────────────
    let (template_path, is_nuclei) = resolve_template(&args);
    ensure_demo_template(&template_path);

    // ── Scan state channels ────────────────────────────────────────────────
    let (state_tx, state_rx) =
        tokio::sync::watch::channel(valayam_engine::scan_state::ScanState::Running);
    let cancel_token = CancellationToken::new();

    // ── TLS config + Telemetry server ──────────────────────────────────────
    let tls_config = load_tls_config(
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
        args.tls_ca.as_deref(),
    )?;
    spawn_telemetry_server(
        args.control_port,
        tls_config.clone(),
        state_tx.clone(),
        cancel_token.clone(),
    );

    // ── HTTP client + Proxy ────────────────────────────────────────────────
    let proxy_rotator = init_proxy_rotator(args.proxy_file.as_deref());
    let http_client = init_http_client(&proxy_rotator, args.random_agent, args.allow_internal)?;

    if args.waf_detect {
        println!("  - WAF detection moved to Wasm plugin");
    }
    if let Some(port) = args.mitm_proxy {
        valayam_proxy::mitm::start_proxy(port, Arc::clone(&http_client)).await;
        return Ok(());
    }

    // ── Rate limiter ───────────────────────────────────────────────────────
    let rate_limiter = args.rate_limit.map(|rps| {
        println!(
            "{} Rate limiting enabled: {} requests/second",
            "[+]".green().bold(),
            rps
        );
        Arc::new(RateLimiter::new_simple(rps))
    });

    // ── gRPC worker client ─────────────────────────────────────────────────
    let grpc_client = connect_worker(args.worker.as_deref()).await;

    // ── Template discovery ─────────────────────────────────────────────────
    let template_files = discover_templates(&template_path);
    if template_files.is_empty() {
        println!(
            "{} No valid YAML templates found in {}",
            "[!]".yellow().bold(),
            template_path
        );
        return Ok(());
    }

    // ── Pre-flight OOB DNS Check ───────────────────────────────────────────
    let oob_dns_bind = valayam_oob::server::OobServer::config_from_env().dns_bind;
    let oob_dns_active =
        if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&oob_dns_bind) {
            if let Some(addr) = addrs.next() {
                std::net::UdpSocket::bind(&addr).is_ok()
            } else {
                false
            }
        } else {
            false
        };

    // ── Pre-flight Target Connectivity Check ───────────────────────────────
    let target_online = match reqwest::Client::new()
        .get(&args.target)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(_) => true,
        Err(e) => {
            println!(
                "{} Target connectivity check failed: {}",
                "[-]".red().bold(),
                e
            );
            false
        }
    };

    if !target_online {
        println!(
            "{} Scan aborted because target is unreachable.",
            "[-]".red().bold()
        );
        return Ok(());
    }

    // ── Print scan config ──────────────────────────────────────────────────
    let engine_name = if is_nuclei { "Nuclei" } else { "Native" };
    print_scan_config(
        &args.target,
        template_files.len(),
        engine_name,
        args.concurrency,
        args.rate_limit,
        args.output.as_deref(),
        otlp_active,
        oob_dns_active,
        target_online,
    );

    // ── Crawler ────────────────────────────────────────────────────────────
    let mut targets = vec![args.target.clone()];
    if args.crawl {
        let discovered = run_crawler(
            &args.target,
            http_client.clone(),
            args.crawl_depth,
            rate_limiter.clone(),
            args.crawl_headers.as_deref(),
        )
        .await;
        targets = discovered;
    }

    // ── Execute scan ───────────────────────────────────────────────────────
    orchestrator::run_scan(
        args,
        template_files,
        is_nuclei,
        targets,
        http_client,
        rate_limiter,
        grpc_client,
        Some(state_rx),
        cancel_token,
    )
    .await?;

    // TelemetryGuard is dropped here → flushes + shuts down OTLP tracer provider
    drop(_telemetry);
    Ok(())
}

/// Spawn the telemetry + control gRPC server.
fn spawn_telemetry_server(
    control_port: Option<u16>,
    tls_config: Option<valayam_api::TlsConfig>,
    state_tx: tokio::sync::watch::Sender<valayam_engine::scan_state::ScanState>,
    cancel_token: CancellationToken,
) {
    tokio::spawn(async move {
        let port = control_port.unwrap_or(50051);
        let addr = format!("127.0.0.1:{}", port)
            .parse()
            .expect("valid socket addr");
        if let Some(tls) = tls_config {
            if let Err(e) = valayam_api::start_telemetry_server_tls(
                addr,
                Some(state_tx),
                Some(cancel_token),
                Some(tls),
            )
            .await
            {
                tracing::error!("Telemetry/Control server (TLS) failed: {}", e);
            }
        } else {
            if let Err(e) =
                valayam_api::start_telemetry_server(addr, Some(state_tx), Some(cancel_token)).await
            {
                tracing::error!("Telemetry/Control server failed: {}", e);
            }
        }
    });
}

/// Handle plugin subcommands (package, init, generate-key, install, push, uninstall, list).
async fn handle_plugin_command(action: &cli::PluginCommands) -> anyhow::Result<()> {
    match action {
        cli::PluginCommands::Package { dir, output, sign } => {
            crate::plugin_cli::package_plugin(dir, output.as_deref(), sign.as_deref())
                .map_err(|e| anyhow::anyhow!("Failed to package plugin: {}", e))?;
        }
        cli::PluginCommands::Init {
            name,
            lang,
            runtime,
        } => {
            crate::plugin_cli::init_plugin(name, lang, runtime)
                .map_err(|e| anyhow::anyhow!("Failed to init plugin: {}", e))?;
        }
        cli::PluginCommands::GenerateKey { output } => {
            crate::plugin_cli::generate_key(output)
                .map_err(|e| anyhow::anyhow!("Failed to generate plugin key: {}", e))?;
        }
        cli::PluginCommands::Install { name, url, pubkey } => {
            crate::plugin_cli::install_plugin(name, url, pubkey.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to install plugin: {}", e))?;
        }
        cli::PluginCommands::Push {
            file,
            repo,
            tag,
            signature,
        } => {
            crate::plugin_cli::push_plugin(file, repo, tag, signature.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to push plugin to OCI registry: {}", e))?;
        }
        cli::PluginCommands::Uninstall { name } => {
            crate::plugin_cli::uninstall_plugin(name)
                .map_err(|e| anyhow::anyhow!("Failed to uninstall plugin: {}", e))?;
        }
        cli::PluginCommands::List => {
            crate::plugin_cli::list_plugins()
                .map_err(|e| anyhow::anyhow!("Failed to list plugins: {}", e))?;
        }
    }
    Ok(())
}

/// Handle the control subcommand (pause/resume/cancel).
async fn handle_control_command(
    action: &str,
    scan_id: &Option<String>,
    port: &u16,
) -> anyhow::Result<()> {
    use valayam_engine::rpc::scanner_client::ScannerClient;
    use valayam_engine::rpc::ControlRequest;

    let url = format!("http://127.0.0.1:{}", port);
    let mut client = match ScannerClient::connect(url.clone()).await {
        Ok(c) => c,
        Err(e) => {
            anyhow::bail!("Failed to connect to control plane at {}: {}", url, e);
        }
    };

    let req = tonic::Request::new(ControlRequest {
        scan_id: scan_id.clone().unwrap_or_default(),
    });

    match action {
        "pause" => match client.pause_scan(req).await {
            Ok(resp) => println!("{} {}", "[+]".green().bold(), resp.into_inner().message),
            Err(e) => tracing::error!("Failed to pause scan: {}", e),
        },
        "resume" => match client.resume_scan(req).await {
            Ok(resp) => println!("{} {}", "[+]".green().bold(), resp.into_inner().message),
            Err(e) => tracing::error!("Failed to resume scan: {}", e),
        },
        "cancel" | "stop" => match client.cancel_scan(req).await {
            Ok(resp) => println!("{} {}", "[+]".green().bold(), resp.into_inner().message),
            Err(e) => tracing::error!("Failed to cancel scan: {}", e),
        },
        _ => tracing::error!(
            "Unknown control action '{}'. Valid actions: pause, resume, cancel",
            action
        ),
    }
    Ok(())
}

/// Handle the bundle subcommand (create/verify) for air-gapped deployments.
async fn handle_bundle_command(action: &cli::BundleCommands) -> anyhow::Result<()> {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::fs;

    #[derive(Serialize, Deserialize)]
    struct BundleManifest {
        version: String,
        created: String,
        plugins: Vec<PluginEntry>,
        templates: Vec<TemplateEntry>,
    }

    #[derive(Serialize, Deserialize)]
    struct PluginEntry {
        name: String,
        version: String,
        sha256: String,
    }

    #[derive(Serialize, Deserialize)]
    struct TemplateEntry {
        name: String,
        sha256: String,
    }

    match action {
        cli::BundleCommands::Create {
            plugins,
            templates,
            pubkey,
            output,
        } => {
            tracing::info!(
                "Creating air-gapped bundle from {} + {} → {}",
                plugins,
                templates,
                output
            );

            let out_dir = std::path::Path::new(&output);
            fs::create_dir_all(out_dir.join("plugins"))?;
            fs::create_dir_all(out_dir.join("templates"))?;
            fs::create_dir_all(out_dir.join("wasm_cache"))?;
            fs::create_dir_all(out_dir.join("keys"))?;

            let mut manifest = BundleManifest {
                version: "1".to_string(),
                created: chrono::Utc::now().to_rfc3339(),
                plugins: Vec::new(),
                templates: Vec::new(),
            };

            // Copy plugins (.vpa files)
            let plugins_src = std::path::Path::new(&plugins);
            if plugins_src.exists() {
                for entry in fs::read_dir(plugins_src)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("vpa") {
                        let name = path.file_name().unwrap().to_string_lossy().to_string();
                        let dest = out_dir.join("plugins").join(&name);
                        fs::copy(&path, &dest)?;
                        // Hash the .vpa
                        let bytes = fs::read(&path)?;
                        let hash = hex::encode(Sha256::digest(&bytes));
                        // Extract version from plugin.yaml inside the VPA
                        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
                        let mut version = "unknown".to_string();
                        if let Ok(mut yaml_file) = archive.by_name("plugin.yaml") {
                            let mut yaml_content = String::new();
                            yaml_file.read_to_string(&mut yaml_content)?;
                            if let Ok(m) = serde_yaml::from_str::<valayam_engine::vpa::PluginManifest>(
                                &yaml_content,
                            ) {
                                version = m.version;
                            }
                        }
                        manifest.plugins.push(PluginEntry {
                            name: name.clone(),
                            version,
                            sha256: hash,
                        });
                        println!("  {} plugin: {}", "[+]".green().bold(), name);
                    }
                }
            }

            // Copy templates
            let templates_src = std::path::Path::new(&templates);
            if templates_src.exists() {
                for entry in fs::read_dir(templates_src)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                        let name = path.file_name().unwrap().to_string_lossy().to_string();
                        let dest = out_dir.join("templates").join(&name);
                        fs::copy(&path, &dest)?;
                        let bytes = fs::read(&path)?;
                        let hash = hex::encode(Sha256::digest(&bytes));
                        manifest.templates.push(TemplateEntry {
                            name: name.clone(),
                            sha256: hash,
                        });
                        println!("  {} template: {}", "[+]".green().bold(), name);
                    }
                }
            }

            // Copy public key
            fs::copy(&pubkey, out_dir.join("keys/public.ed25519"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(out_dir.join("keys/public.ed25519"))?.permissions();
                perms.set_mode(0o644);
                fs::set_permissions(out_dir.join("keys/public.ed25519"), perms)?;
            }

            // Write manifest.json
            let manifest_json = serde_json::to_string_pretty(&manifest)?;
            fs::write(out_dir.join("manifest.json"), manifest_json)?;

            println!("{} Bundle created at: {}", "[+]".green().bold(), output);
            println!(
                "  plugins: {}, templates: {}",
                manifest.plugins.len(),
                manifest.templates.len()
            );
        }
        cli::BundleCommands::Verify { bundle } => {
            tracing::info!("Verifying bundle: {}", bundle);

            let bundle_dir = std::path::Path::new(&bundle);
            let manifest_path = bundle_dir.join("manifest.json");
            if !manifest_path.exists() {
                anyhow::bail!("manifest.json not found in bundle directory");
            }

            let manifest_json = fs::read_to_string(&manifest_path)?;
            let manifest: BundleManifest = serde_json::from_str(&manifest_json)?;

            let mut ok = 0;
            let mut failed = 0;

            // Verify plugins
            for p in &manifest.plugins {
                let path = bundle_dir.join("plugins").join(&p.name);
                if path.exists() {
                    let bytes = fs::read(&path)?;
                    let hash = hex::encode(Sha256::digest(&bytes));
                    if hash == p.sha256 {
                        println!(
                            "  {} plugin {} (v{})",
                            "[+]".green().bold(),
                            p.name,
                            p.version
                        );
                        ok += 1;
                    } else {
                        println!(
                            "  {} plugin {} hash mismatch (expected {} got {})",
                            "[✗]".red().bold(),
                            p.name,
                            p.sha256,
                            hash
                        );
                        failed += 1;
                    }
                } else {
                    println!("  {} plugin {} missing", "[✗]".red().bold(), p.name);
                    failed += 1;
                }
            }

            // Verify templates
            for t in &manifest.templates {
                let path = bundle_dir.join("templates").join(&t.name);
                if path.exists() {
                    let bytes = fs::read(&path)?;
                    let hash = hex::encode(Sha256::digest(&bytes));
                    if hash == t.sha256 {
                        println!("  {} template {}", "[+]".green().bold(), t.name);
                        ok += 1;
                    } else {
                        println!("  {} template {} hash mismatch", "[✗]".red().bold(), t.name);
                        failed += 1;
                    }
                } else {
                    println!("  {} template {} missing", "[✗]".red().bold(), t.name);
                    failed += 1;
                }
            }

            // Verify public key exists
            let pubkey_path = bundle_dir.join("keys/public.ed25519");
            if pubkey_path.exists() {
                println!("  {} public key present", "[+]".green().bold());
                ok += 1;
            } else {
                println!("  {} public key missing", "[✗]".red().bold());
                failed += 1;
            }

            println!("\nSummary: {} verified, {} failed", ok, failed);
            if failed > 0 {
                anyhow::bail!(
                    "Bundle verification failed: {} artifact(s) mismatched or missing",
                    failed
                );
            }
        }
    }
    Ok(())
}

/// Handle the template subcommand (push/pull/list) for artifact store management.
async fn handle_template_command(action: &cli::TemplateCommands) -> anyhow::Result<()> {
    use std::fs;
    use std::path::Path;
    use walkdir::WalkDir;

    // Load storage config from env (same contract as platform)
    let storage_config = valayam_common::storage::StorageConfig::from_env()?;

    // Build the template store
    let template_store = storage_config.build_template_store();

    match action {
        cli::TemplateCommands::Push { path, prefix } => {
            tracing::info!(
                "Pushing templates from {} to storage backend (prefix: {})",
                path,
                prefix
            );

            let src_path = Path::new(&path);
            if !src_path.exists() {
                anyhow::bail!("Source path '{}' does not exist", path);
            }

            let mut pushed = 0;
            if src_path.is_file() {
                // Push single file
                let name = src_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
                let norm_prefix = if prefix.is_empty() || prefix.ends_with('/') {
                    prefix.to_string()
                } else {
                    format!("{}/", prefix)
                };
                let key = format!("{}{}", norm_prefix, name);
                let bytes = fs::read(src_path)?;
                template_store.put(&key, &bytes).await?;
                println!("{} Pushed template: {}", "[+]".green().bold(), key);
                pushed += 1;
            } else {
                // Push directory recursively
                let norm_prefix = if prefix.is_empty() || prefix.ends_with('/') {
                    prefix.to_string()
                } else {
                    format!("{}/", prefix)
                };
                for entry in WalkDir::new(src_path).into_iter().filter_map(|e| e.ok()) {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        if let Some(ext) = entry_path.extension().and_then(|s| s.to_str()) {
                            if ext == "yaml" || ext == "yml" {
                                let rel_path = entry_path.strip_prefix(src_path)?;
                                let key = format!(
                                    "{}{}",
                                    norm_prefix,
                                    rel_path.to_string_lossy().replace('\\', "/")
                                );
                                let bytes = fs::read(entry_path)?;
                                template_store.put(&key, &bytes).await?;
                                println!("{} Pushed template: {}", "[+]".green().bold(), key);
                                pushed += 1;
                            }
                        }
                    }
                }
            }
            println!("{} Pushed {} template(s)", "[+]".green().bold(), pushed);
        }
        cli::TemplateCommands::Pull { output, prefix } => {
            tracing::info!(
                "Pulling templates from storage backend (prefix: {}) to {}",
                prefix,
                output
            );

            let out_path = Path::new(&output);
            fs::create_dir_all(out_path)?;

            let keys = template_store.list(&prefix).await?;
            if keys.is_empty() {
                println!("No templates found with prefix '{}'", prefix);
                return Ok(());
            }

            let mut pulled = 0;
            for key in keys {
                let bytes = template_store.get(&key).await?;
                let file_name = key.strip_prefix(&*prefix).unwrap_or(&key);
                let file_path = out_path.join(file_name);
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&file_path, &bytes)?;
                println!("{} Pulled template: {}", "[+]".green().bold(), key);
                pulled += 1;
            }
            println!("{} Pulled {} template(s)", "[+]".green().bold(), pulled);
        }
        cli::TemplateCommands::List { prefix } => {
            tracing::info!(
                "Listing templates from storage backend (prefix: {})",
                prefix
            );

            let keys = template_store.list(&prefix).await?;
            if keys.is_empty() {
                println!("No templates found with prefix '{}'", prefix);
                return Ok(());
            }

            for key in keys {
                // Get metadata (size) for each template
                if let Ok(meta) = template_store.stat(&key).await {
                    println!("{}  {} ({} bytes)", "[•]".blue(), key, meta.size);
                } else {
                    println!("{}  {}", "[•]".blue(), key);
                }
            }
        }
    }
    Ok(())
}

/// Connect to a remote gRPC worker node.
async fn connect_worker(
    worker_url: Option<&str>,
) -> Option<valayam_core::rpc::scanner_client::ScannerClient<tonic::transport::Channel>> {
    use valayam_core::rpc::scanner_client::ScannerClient;
    match worker_url {
        Some(url) => match ScannerClient::connect(url.to_string()).await {
            Ok(client) => {
                println!(
                    "{} Connected to Valayam worker node at {}",
                    "[+]".green().bold(),
                    url
                );
                Some(client)
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to connect to Valayam worker node: {}",
                    "[✗]".red().bold(),
                    e
                );
                None
            }
        },
        None => None,
    }
}
