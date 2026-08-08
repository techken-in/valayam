use crate::cli::Args;
use colored::*;
use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use valayam_core::core::plugins::*;
use valayam_core::core::reporters::{
    composite::CompositeReporter, console::ConsoleReporter, json::JsonReporter,
};
use valayam_engine::executor::ScanExecutor;
use valayam_engine::rate_limiter::RateLimiter;
use valayam_engine::registry::PluginRegistry;
use valayam_engine::traits::{FindingOwned, Reporter};
use valayam_engine::wasm_plugin::PluginConfig;
// Extended plugins moved to Wasm
// NucleiExecutor moved to Wasm
use valayam_core::rpc::scanner_client::ScannerClient;
use valayam_core::template::schema::VulnerabilityTemplate;

/// Detect offline mode and resolve bundle directories for air-gapped deployments.
fn resolve_bundle_dirs() -> Option<(PathBuf, PathBuf, PathBuf)> {
    if std::env::var("VALAYAM_OFFLINE_MODE").is_ok() {
        // Check for bundle directory in standard locations
        let bundle_candidates = vec![
            PathBuf::from("./bundle"),
            PathBuf::from("/bundle"),
            PathBuf::from("/opt/valayam/bundle"),
            dirs::home_dir().unwrap_or_default().join(".valayam/bundle"),
            dirs::cache_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("valayam/bundle"),
        ];

        for bundle in bundle_candidates {
            let plugins_dir = bundle.join("plugins");
            let _templates_dir = bundle.join("templates");
            let wasm_cache_dir = bundle.join("wasm_cache");

            if plugins_dir.exists() && wasm_cache_dir.exists() {
                println!(
                    "{} Air-gapped mode: using bundle at {}",
                    "[+]".green().bold(),
                    bundle.display()
                );
                return Some((bundle, plugins_dir, wasm_cache_dir));
            }
        }
    }
    None
}

/// Tracks severity counts for the scan summary.
#[derive(Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    unknown: usize,
}

impl SeverityCounts {
    fn record(&mut self, severity: valayam_models::finding::Severity) {
        use valayam_models::finding::Severity;
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
            Severity::Unknown => self.unknown += 1,
        }
    }

    fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info + self.unknown
    }
}

/// Prints the final scan summary with severity breakdown and visual bar chart.
fn print_summary(
    duration: Duration,
    template_count: usize,
    target_count: usize,
    counts: &SeverityCounts,
    duplicates_suppressed: usize,
    output_path: Option<&str>,
) {
    let total = counts.total();
    let bar = "─".repeat(54);

    println!();
    println!(
        "  {}",
        format!("┌─ Scan Summary {}┐", "─".repeat(38)).bright_black()
    );

    // Timing
    let secs = duration.as_secs_f64();
    let duration_str = if secs < 1.0 {
        format!("{:.0}ms", duration.as_millis())
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        format!("{}m {:.0}s", (secs / 60.0) as u64, secs % 60.0)
    };
    println!(
        "  {}  {}   {}",
        "│".bright_black(),
        "Duration:".bright_black(),
        duration_str.white().bold()
    );
    println!(
        "  {}  {}  {} executed",
        "│".bright_black(),
        "Templates:".bright_black(),
        format!("{}", template_count).white().bold()
    );
    println!(
        "  {}  {}    {} scanned",
        "│".bright_black(),
        "Targets:".bright_black(),
        format!("{}", target_count).white().bold()
    );

    // Separator
    println!(
        "  {}  {}",
        "│".bright_black(),
        "─".repeat(48).bright_black()
    );

    if total == 0 {
        println!(
            "  {}  {}   {} {}",
            "│".bright_black(),
            "Findings:".bright_black(),
            "0".white().bold(),
            "✅ No vulnerabilities detected".green()
        );
    } else {
        println!(
            "  {}  {}   {} total",
            "│".bright_black(),
            "Findings:".bright_black(),
            format!("{}", total).white().bold()
        );

        // Print each severity level with a mini bar chart
        let severity_lines: Vec<(&str, usize, ColoredString)> = vec![
            (
                "Critical",
                counts.critical,
                "Critical".bright_magenta().bold(),
            ),
            ("High", counts.high, "High".red().bold()),
            ("Medium", counts.medium, "Medium".yellow().bold()),
            ("Low", counts.low, "Low".green().bold()),
            ("Info", counts.info, "Info".blue().bold()),
        ];

        for (_name, count, label) in &severity_lines {
            if *count > 0 {
                let bar_width = if total > 0 {
                    ((*count as f64 / total as f64) * 20.0).ceil() as usize
                } else {
                    0
                };
                let filled = "█".repeat(bar_width);
                let pct = if total > 0 {
                    (*count as f64 / total as f64 * 100.0) as u32
                } else {
                    0
                };
                println!(
                    "  {}    {:>8}: {:>3}   {} {}%",
                    "│".bright_black(),
                    label,
                    format!("{}", count).white().bold(),
                    filled.bright_white(),
                    pct
                );
            }
        }
    }

    if duplicates_suppressed > 0 {
        println!(
            "  {}    {} {} duplicate finding(s) suppressed",
            "│".bright_black(),
            "ℹ".blue(),
            duplicates_suppressed
        );
    }

    if let Some(path) = output_path {
        println!(
            "  {}  {}",
            "│".bright_black(),
            "─".repeat(48).bright_black()
        );
        println!(
            "  {}  {}     {} ({} findings written)",
            "│".bright_black(),
            "Output:".bright_black(),
            path.white().bold(),
            total
        );
    }

    println!("  {}", format!("└{}┘", bar).bright_black());
    println!();
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(http_client, rate_limiter, grpc_client, state_rx, cancel))]
pub async fn run_scan(
    args: Args,
    template_files: Vec<PathBuf>,
    is_nuclei: bool,
    targets: Vec<String>,
    http_client: Arc<valayam_core::network::http::StealthHttpClient>,
    rate_limiter: Option<Arc<RateLimiter>>,
    grpc_client: Option<ScannerClient<tonic::transport::Channel>>,
    state_rx: Option<tokio::sync::watch::Receiver<valayam_engine::scan_state::ScanState>>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    run_scan_with_job_id(
        args,
        template_files,
        is_nuclei,
        targets,
        http_client,
        rate_limiter,
        grpc_client,
        state_rx,
        cancel,
        None,
    )
    .await
}

/// Extended entrypoint that accepts a platform-assigned `job_id`.
/// When provided, it is written into the JSON output envelope so the
/// platform can correlate results with the dispatched job.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(http_client, rate_limiter, grpc_client, state_rx, cancel))]
pub async fn run_scan_with_job_id(
    args: Args,
    template_files: Vec<PathBuf>,
    is_nuclei: bool,
    targets: Vec<String>,
    http_client: Arc<valayam_core::network::http::StealthHttpClient>,
    rate_limiter: Option<Arc<RateLimiter>>,
    grpc_client: Option<ScannerClient<tonic::transport::Channel>>,
    state_rx: Option<tokio::sync::watch::Receiver<valayam_engine::scan_state::ScanState>>,
    cancel: CancellationToken,
    job_id: Option<String>,
) -> anyhow::Result<()> {
    let scan_start = Instant::now();

    // ── Progress bar setup using MultiProgress ──
    let mp = MultiProgress::new();
    let spinner = mp.add(ProgressBar::new_spinner());
    spinner.enable_steady_tick(Duration::from_millis(120));
    if let Ok(style) = ProgressStyle::with_template("{spinner:.cyan} {msg:.bright.black}") {
        spinner.set_style(style.tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]));
    }
    spinner.set_message(format!(
        "Scanning {} target(s) with {} template(s)...",
        targets.len(),
        template_files.len()
    ));

    // ── 1. Create bounded MPSC channel ──
    let (finding_tx, mut finding_rx) = tokio::sync::mpsc::channel::<FindingOwned>(1000);

    let state_rx_to_use = state_rx;
    let cancel_for_handler = cancel.clone();

    // We will still handle ctrl-c to save state
    let db = valayam_state::StateDB::new(".valayam_state").expect("Failed to initialize state DB");
    let state_id = args.resume.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string()
    });

    let mut actual_targets = targets.clone();
    if let Some((pending, _completed)) = db.load_state(&state_id).unwrap_or(None) {
        spinner.suspend(|| {
            println!(
                "{} Resuming scan from state ID: {}. Loaded {} pending targets.",
                "[+]".green().bold(),
                state_id,
                pending.len()
            );
        });
        actual_targets = pending;
    } else {
        spinner.suspend(|| {
            println!(
                "{} Starting new scan with state ID: {}",
                "[+]".green().bold(),
                state_id
            );
        });
    }

    // ── Target Liveness Pre-flight Check ──
    let mut online_targets = Vec::new();
    for target in actual_targets {
        if let Ok(url) = reqwest::Url::parse(&target) {
            if let Some(host) = url.host_str() {
                let port =
                    url.port()
                        .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
                let addr_str = format!("{}:{}", host, port);
                let is_online =
                    if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&addr_str) {
                        if let Some(addr) = addrs.next() {
                            std::net::TcpStream::connect_timeout(
                                &addr,
                                std::time::Duration::from_secs(2),
                            )
                            .is_ok()
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                if is_online {
                    online_targets.push(target.clone());
                } else {
                    tracing::error!("Target {} is offline, skipping scan", target);
                    eprintln!(
                        "{} Target {} is offline, skipping scan",
                        "[-]".red().bold(),
                        target
                    );
                }
            } else {
                online_targets.push(target); // Fallback
            }
        } else {
            online_targets.push(target); // Fallback
        }
    }
    let actual_targets = online_targets;
    if actual_targets.is_empty() {
        tracing::error!("No targets are online. Aborting scan.");
        eprintln!(
            "{} No targets are online. Aborting scan.",
            "[-]".red().bold()
        );
        return Ok(());
    }

    let pending_for_shutdown = actual_targets.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("received Ctrl+C, initiating graceful shutdown...");
            let _ = db.save_state(&state_id, &pending_for_shutdown, &[]);
            cancel_for_handler.cancel();
        }
    });

    // Check for air-gapped bundle mode
    let bundle_dirs = resolve_bundle_dirs();

    // ── 3. Build plugin registry ──
    let (registry, _watcher) = {
        // Resolve trusted public key for plugin signature verification
        let pub_key: Option<[u8; 32]> = if args.require_signed_plugins {
            let pk_hex = std::env::var("VALAYAM_PUBLIC_KEY").unwrap_or_default();
            if pk_hex.is_empty()
                || pk_hex == "0000000000000000000000000000000000000000000000000000000000000000"
            {
                anyhow::bail!("--require-signed-plugins requires VALAYAM_PUBLIC_KEY env var set to a valid 32-byte hex key");
            }
            let decoded = hex::decode(&pk_hex).expect("Invalid VALAYAM_PUBLIC_KEY hex");
            if decoded.len() != 32 {
                anyhow::bail!("VALAYAM_PUBLIC_KEY must be 32 bytes (64 hex characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            Some(arr)
        } else {
            // Optional: still try to use a key if available in env (soft mode)
            std::env::var("VALAYAM_PUBLIC_KEY").ok().and_then(|pk_hex| {
                if pk_hex == "0000000000000000000000000000000000000000000000000000000000000000" {
                    None
                } else {
                    hex::decode(&pk_hex).ok().and_then(|bytes| {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                }
            })
        };
        if pub_key.is_some() {
            println!(
                "{} Plugin signature verification enabled",
                "[+]".green().bold()
            );
        }

        let mut reg = PluginRegistry::with_key(pub_key);

        // Apply WASM plugin sandbox config from CLI args
        let allowed_hosts = if args.plugin_allow_host.is_empty() {
            vec!["*".to_string()]
        } else {
            args.plugin_allow_host.clone()
        };
        let plugin_config = PluginConfig {
            memory_max_pages: (args.plugin_memory_limit as u64 * 1024 * 1024 / 65536) as u32,
            timeout_ms: args.plugin_timeout * 1000,
            allowed_hosts,
        };
        reg.set_plugin_config(plugin_config);

        // In offline mode, set the wasm_cache directory to the bundle's wasm_cache
        if let Some((_, _, ref wasm_cache)) = bundle_dirs {
            reg.set_cache_dir(wasm_cache.clone());
        }

        // Core protocols
        reg.register(HttpScanPlugin::new(http_client.clone()));
        // Scripting and Fuzzer moved to Wasm
        // Cloud & Extended moved to Wasm
        // Batch 8 (Threat Audit) moved to Wasm
        reg.register(SchemaDriftPlugin::new(http_client.clone()));
        reg.register(DnsAuditPlugin);
        reg.register(PortScanPlugin);
        reg.register(ShellsPlugin);

        // Dynamically load WebAssembly and gRPC plugins from disk
        let mut loaded_externals = 0;

        // In offline mode, load from bundle's plugins directory; otherwise use default locations
        let plugin_dirs: Vec<PathBuf> = if let Some((_, ref plugins_dir, _)) = bundle_dirs {
            vec![plugins_dir.clone()]
        } else {
            vec![
                std::path::Path::new("plugins").to_path_buf(),
                std::path::Path::new("plugins-wasm/bin").to_path_buf(),
            ]
        };

        for dir in plugin_dirs {
            if dir.exists() {
                if let Err(e) = reg.load_external_plugins(&dir) {
                    tracing::warn!("Failed to load plugins from {}: {}", dir.display(), e);
                } else {
                    loaded_externals += 1;
                }
            }
        }

        if loaded_externals > 0 {
            spinner.suspend(|| {
                println!(
                    "{} Dynamically loaded external plugins into the engine.",
                    "[+]".green().bold()
                );
            });
        }

        // Initialize ThreatIntelMatcher and register
        let matcher =
            Arc::new(valayam_core::features::threat_intel::ioc_matcher::IocMatcher::new());
        reg.register(ThreatIntelPlugin { matcher });

        // Initialize OOB Server and register
        let oob_server = Arc::new(valayam_oob::server::OobServer::new(
            valayam_oob::server::OobServer::config_from_env(),
        ));
        reg.register(OobPlugin { server: oob_server });
        // DependencyAudit moved to Wasm

        let reg_arc = Arc::new(reg);

        // In offline mode, skip hot-reload watcher (no filesystem changes expected)
        let mut _watcher = None;
        if bundle_dirs.is_none() {
            let plugins_dir = std::path::Path::new("plugins");
            if plugins_dir.exists() {
                match reg_arc.clone().start_hot_reload(plugins_dir.to_path_buf()) {
                    Ok(watcher) => {
                        _watcher = Some(watcher);
                        tracing::info!("Hot-reloading enabled for ./plugins");
                    }
                    Err(e) => tracing::warn!("Failed to start hot-reload for ./plugins: {}", e),
                }
            }
        }

        (reg_arc, _watcher)
    };

    // ── 4. Initialize all plugins (fail-fast on bad config) ──
    registry.init_all().await?;

    // ── 5. Build reporters ──
    let mut reporters: Vec<Box<dyn Reporter>> = vec![Box::new(ConsoleReporter::default())];
    if let Some(ref path) = args.output {
        let scanner_version = env!("CARGO_PKG_VERSION").to_string();
        if path.ends_with(".sarif") {
            let sarif_reporter =
                valayam_reporter::sarif::SarifReporter::new(path.to_string(), scanner_version)?;
            reporters.push(Box::new(sarif_reporter));
        } else {
            let plugins = registry.list_plugins();
            let templates = template_files
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            let scan_id = job_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let start_time = chrono::Utc::now().to_rfc3339();
            let targets: Vec<String> = actual_targets.to_vec();
            let mut json_reporter = JsonReporter::new(
                path.to_string(),
                scan_id,
                start_time,
                plugins,
                templates,
                targets,
                scanner_version,
            )?;
            // Propagate platform job_id into the output envelope
            if let Some(ref jid) = job_id {
                json_reporter.set_job_id(jid.clone());
            }
            reporters.push(Box::new(json_reporter));
        }
    }
    let composite = CompositeReporter::new(reporters);

    // ── 6. Spawn Consumer task with dedup and severity tracking ──
    let severity_counts = Arc::new(Mutex::new(SeverityCounts::default()));
    let dedup_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let severity_for_consumer = severity_counts.clone();
    let dedup_for_consumer = dedup_count.clone();
    let spinner_for_consumer = spinner.clone();

    let consumer_handle = tokio::spawn(async move {
        let mut count = 0usize;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        while let Some(finding) = finding_rx.recv().await {
            // Dedup filter: skip findings with identical (template_id, target, matched_at)
            let key = finding.dedup_key();
            if !seen.insert(key) {
                dedup_for_consumer.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }

            // Track severity counts
            {
                let mut counts = severity_for_consumer.lock().await;
                counts.record(finding.severity);
            }

            // Use suspend to prevent spinner from interleaving with finding output
            spinner_for_consumer.suspend(|| {
                // We need to call process_finding synchronously here since suspend takes FnOnce
                // Instead, we'll just print inline — the ConsoleReporter uses println! internally
            });

            if let Err(e) = composite.process_finding(&finding).await {
                tracing::error!(error = %e, "reporter failed");
            }
            count += 1;

            // Update spinner with progress
            spinner_for_consumer.set_message(format!("Scanning... {} finding(s) so far", count));
        }
        let _ = composite.flush().await;
        count
    });

    // ── 7. Build Executor ──
    let mut executor = ScanExecutor::new(
        finding_tx.clone(),
        registry.clone(),
        rate_limiter.clone(),
        cancel.clone(),
    );
    if let Some(rx) = state_rx_to_use {
        executor = executor.with_state_rx(rx);
    }

    let mut tasks = Vec::new();
    for target in &actual_targets {
        for file_path in &template_files {
            tasks.push((target.clone(), file_path.clone()));
        }
    }

    let concurrency = args.concurrency;
    let grpc_client_arc = grpc_client.map(Arc::new);

    let stream = futures::stream::iter(tasks).map(|(target_url, file_path_clone)| {
        let exec = executor.clone();
        let grpc_client_clone = grpc_client_arc.clone();
        let finding_tx_clone = finding_tx.clone();
        async move {
            let path_str = file_path_clone.to_string_lossy().to_string();

            if is_nuclei {
                tracing::warn!("Nuclei execution moved to Wasm plugin, skipping native execution for {}", path_str);
            } else {
                if let Some(grpc_arc) = grpc_client_clone {
                    let mut client = (*grpc_arc).clone();
                    let yaml_str = match fs::read_to_string(&file_path_clone) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("Failed to read template {}: {}", path_str, e);
                            return;
                        }
                    };

                    let req = tonic::Request::new(valayam_core::rpc::ScanRequest {
                        template_yaml: yaml_str,
                        target_url: target_url.clone(),
                    });

                    match client.scan(req).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            for finding_json in resp.findings_json {
                                if let Ok(scan_res) = serde_json::from_str::<valayam_core::core::result::ScanResult>(&finding_json) {
                                    let finding = valayam_core::core::scan_result_bridge::scan_result_to_finding(scan_res);
                                    let _ = finding_tx_clone.send(finding).await;
                                }
                            }
                        }
                        Err(e) => tracing::error!("gRPC error for template {}: {}", path_str, e),
                    }
                } else {
                    let template = match VulnerabilityTemplate::load(&file_path_clone) {
                        Ok(t) => Arc::new(t),
                        Err(e) => {
                            tracing::error!("Failed to load Native template {}: {}", path_str, e);
                            return;
                        }
                    };

                    let metrics = exec.execute(&target_url, template).await;
                    for m in metrics {
                        tracing::debug!(
                            plugin = %m.plugin_name,
                            outcome = %m.outcome,
                            duration_ms = m.duration.as_millis() as u64,
                            findings = m.finding_count,
                        );
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = stream.buffer_unordered(concurrency).collect::<Vec<()>>() => {
            // normal completion
        }
        _ = cancel.cancelled() => {
            tracing::warn!("Scan execution cancelled, cleaning up...");
        }
    }

    // Drop executor and tx to close the channel, allowing consumer to finish
    drop(executor);
    drop(finding_tx);

    registry.shutdown_all().await;

    let _findings_count = consumer_handle.await.unwrap_or(0);
    spinner.finish_and_clear();

    // Print the rich summary table
    let scan_duration = scan_start.elapsed();
    let counts = severity_counts.lock().await;
    let dupes = dedup_count.load(std::sync::atomic::Ordering::Relaxed);

    print_summary(
        scan_duration,
        template_files.len(),
        actual_targets.len(),
        &counts,
        dupes,
        args.output.as_deref(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_counts_default_zero() {
        let counts = SeverityCounts::default();
        assert_eq!(counts.critical, 0);
        assert_eq!(counts.high, 0);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 0);
        assert_eq!(counts.info, 0);
        assert_eq!(counts.unknown, 0);
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn test_severity_counts_record_critical() {
        let mut counts = SeverityCounts::default();
        counts.record(valayam_models::finding::Severity::from("critical"));
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.total(), 1);
    }

    #[test]
    fn test_severity_counts_record_all_levels() {
        let mut counts = SeverityCounts::default();
        counts.record(valayam_models::finding::Severity::from("critical"));
        counts.record(valayam_models::finding::Severity::from("high"));
        counts.record(valayam_models::finding::Severity::from("medium"));
        counts.record(valayam_models::finding::Severity::from("low"));
        counts.record(valayam_models::finding::Severity::from("info"));
        counts.record(valayam_models::finding::Severity::from("unknown"));
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.info, 1);
        assert_eq!(counts.unknown, 1);
        assert_eq!(counts.total(), 6);
    }

    #[test]
    fn test_severity_counts_case_insensitive() {
        let mut counts = SeverityCounts::default();
        counts.record(valayam_models::finding::Severity::from("Critical"));
        counts.record(valayam_models::finding::Severity::from("HIGH"));
        counts.record(valayam_models::finding::Severity::from("Medium"));
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
    }

    #[test]
    fn test_severity_counts_unknown_severity() {
        let mut counts = SeverityCounts::default();
        counts.record(valayam_models::finding::Severity::from("unknown_severity"));
        counts.record(valayam_models::finding::Severity::from("nope"));
        assert_eq!(counts.unknown, 2);
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn test_severity_counts_multiple_records() {
        let mut counts = SeverityCounts::default();
        for _ in 0..5 {
            counts.record(valayam_models::finding::Severity::from("high"));
        }
        for _ in 0..3 {
            counts.record(valayam_models::finding::Severity::from("critical"));
        }
        assert_eq!(counts.high, 5);
        assert_eq!(counts.critical, 3);
        assert_eq!(counts.total(), 8);
    }
}

#[tracing::instrument]
pub async fn sync_vulndb(cdn: &str, output: &str) -> anyhow::Result<()> {
    use colored::*;
    println!(
        "{} Syncing vulnerability database from {}...",
        "[*]".blue().bold(),
        cdn
    );

    let db_url = format!("{}/vuln-db.sqlite", cdn);
    let sig_url = format!("{}/vuln-db.sqlite.sig", cdn);

    println!("{} Fetching {}...", "[*]".blue().bold(), db_url);
    let db_bytes = reqwest::get(&db_url).await?.bytes().await?;
    println!("{} Fetching {}...", "[*]".blue().bold(), sig_url);
    let sig_hex = reqwest::get(&sig_url).await?.text().await?;

    let config = crate::config::CliConfig::from_env();
    let public_key_hex = config.valayam_public_key;

    println!(
        "{} Verifying Ed25519 signature against public key...",
        "[*]".blue().bold()
    );
    if public_key_hex == "0000000000000000000000000000000000000000000000000000000000000000" {
        println!(
            "{} WARNING: Using zeroed public key (Insecure). Please set VALAYAM_PUBLIC_KEY.",
            "[!]".yellow().bold()
        );
        // Skip verification for the zeroed dummy key
    } else {
        let pk_bytes = hex::decode(public_key_hex.trim())?;
        let mut pk_arr = [0u8; 32];
        if pk_bytes.len() != 32 {
            anyhow::bail!("Invalid public key length");
        }
        pk_arr.copy_from_slice(&pk_bytes);

        let sig_bytes = hex::decode(sig_hex.trim())?;
        let mut sig_arr = [0u8; 64];
        if sig_bytes.len() != 64 {
            anyhow::bail!("Invalid signature length");
        }
        sig_arr.copy_from_slice(&sig_bytes);

        let is_valid = valayam_crypto::PluginCrypto::verify(&pk_arr, &db_bytes, &sig_arr)?;
        if !is_valid {
            anyhow::bail!("Signature verification failed!");
        }
    }

    // Atomic write
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let temp_name = format!("{}.tmp", output);
    std::fs::write(&temp_name, &db_bytes)?;
    std::fs::rename(&temp_name, output)?;

    println!(
        "{} Vulnerability database successfully synced to {}",
        "[+]".green().bold(),
        output
    );
    Ok(())
}
