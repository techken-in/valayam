//! Scan setup and initialization logic extracted from main.rs.
//!
//! Handles template resolution, TLS config, networking, and crawler setup.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cli::Args;
use colored::*;
use walkdir::WalkDir;

use valayam_core::network::http::StealthHttpClient;
use valayam_core::network::ssrf_filter::SsrfConfig;
use valayam_core::rpc::scanner_client::ScannerClient;
use valayam_core::stealth::proxy::ProxyRotator;
use valayam_engine::rate_limiter::RateLimiter;

/// Result of the scan setup phase. Everything needed for `orchestrator::run_scan`.
#[allow(dead_code)]
pub struct ScanSetup {
    /// Resolved template files to scan with.
    pub template_files: Vec<PathBuf>,
    /// Whether templates are in Nuclei format.
    pub is_nuclei: bool,
    /// Resolved targets (after optional crawler expansion).
    pub targets: Vec<String>,
    /// Shared stealth HTTP client.
    pub http_client: Arc<StealthHttpClient>,
    /// Optional rate limiter.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Optional gRPC worker client.
    pub grpc_client: Option<ScannerClient<tonic::transport::Channel>>,
    /// State watcher receiver for scan control.
    pub state_rx: Option<tokio::sync::watch::Receiver<valayam_engine::scan_state::ScanState>>,
    /// Global cancellation token.
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Resolve the template path and determine the engine type.
pub fn resolve_template(args: &Args) -> (String, bool) {
    let default_template = "./templates_repo/demo-template.yaml".to_string();

    if let Some(t) = &args.template {
        (t.clone(), false)
    } else if let Some(n) = &args.nuclei_template {
        (n.clone(), true)
    } else {
        println!(
            "{} No template flag provided. Defaulting to Native engine with demo template (-t {}).",
            "[!]".yellow().bold(),
            default_template
        );
        (default_template, false)
    }
}

/// Auto-generate a demo template if the native template path doesn't exist.
pub fn ensure_demo_template(template_path: &str) {
    if !Path::new(template_path).exists() {
        println!(
            "{} Native template not found at '{}'. Generating demo template...",
            "[!]".yellow().bold(),
            template_path
        );

        if let Some(parent_dir) = Path::new(template_path).parent() {
            let _ = std::fs::create_dir_all(parent_dir);
        }

        let demo_yaml = r#"
id: basic-info-disclosure
info:
  name: "Basic Information Disclosure / SSRF Test"
  severity: "Medium"
  description: "Detects if the target reflects sensitive HTTP headers or payloads."
requests:
  - method: "GET"
    path: "/get?test_param=valayam_engine"
    headers:
      X-Scanner-Test: "true"
    matchers:
      - type: "regex"
        part: "body"
        regex:
          - "valayam_engine"
      - type: "status"
        part: "status"
        status:
          - 200
network:
  - host: "{{Hostname}}"
    ports:
      - "80"
      - "443"
      - "8080"
"#;
        let _ = std::fs::write(template_path, demo_yaml.trim());
        println!(
            "{} Demo template created successfully.\n",
            "[+]".green().bold()
        );
    }
}

/// Collect all YAML template files from a path (file or directory).
pub fn discover_templates(template_path: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let p = Path::new(template_path);
    if p.is_dir() {
        for entry in WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "yaml" || ext == "yml" {
                        files.push(entry.path().to_path_buf());
                    }
                }
            }
        }
    } else if p.is_file() {
        files.push(p.to_path_buf());
    }
    files
}

/// Print the scan configuration table.
pub fn print_scan_config(
    target: &str,
    template_count: usize,
    engine: &str,
    concurrency: usize,
    rate_limit: Option<u32>,
    output: Option<&str>,
    otlp_active: bool,
    oob_dns_active: bool,
    target_online: bool,
) {
    let bar = "─".repeat(54);
    println!(
        "  {}",
        format!("┌─ Scan Configuration {}┐", "─".repeat(32)).bright_black()
    );
    println!(
        "  {}  {}     {}",
        "│".bright_black(),
        "Target:".bright_black(),
        target.cyan().bold()
    );
    println!(
        "  {}  {}  {} {} {}",
        "│".bright_black(),
        "Templates:".bright_black(),
        format!("{}", template_count).white().bold(),
        "loaded".bright_black(),
        format!("({})", engine).bright_black()
    );
    let rate_str = rate_limit.map_or("unlimited".to_string(), |r| format!("{} req/s", r));
    println!(
        "  {}  {}       {} {} {} {}",
        "│".bright_black(),
        "Tuning:".bright_black(),
        "concurrency".bright_black(),
        format!("{}", concurrency).white(),
        "│ rate limit".bright_black(),
        rate_str.white()
    );

    let conn_status = if target_online {
        "Online / Reachable".green().to_string()
    } else {
        "Offline / Unreachable".red().to_string()
    };
    println!(
        "  {}  {}  {}",
        "│".bright_black(),
        "Target Status:".bright_black(),
        conn_status
    );

    let telemetry_status = if otlp_active {
        "OTLP Enabled".green().to_string()
    } else {
        "Offline / Disabled".yellow().to_string()
    };
    println!(
        "  {}  {}  {}",
        "│".bright_black(),
        "Telemetry:".bright_black(),
        telemetry_status
    );

    let oob_status = if oob_dns_active {
        "Active / Listening".green().to_string()
    } else {
        "Offline / Port Occupied".yellow().to_string()
    };
    println!(
        "  {}  {}    {}",
        "│".bright_black(),
        "OOB DNS:".bright_black(),
        oob_status
    );

    if let Some(out) = output {
        println!(
            "  {}  {}     {} {}",
            "│".bright_black(),
            "Output:".bright_black(),
            "console".white(),
            format!("+ {}", out).bright_black()
        );
    } else {
        println!(
            "  {}  {}     {}",
            "│".bright_black(),
            "Output:".bright_black(),
            "console".white()
        );
    }
    println!("  {}", format!("└{}┘", bar).bright_black());
    println!();
}

/// Initialize the proxy rotator from a file path.
pub fn init_proxy_rotator(proxy_file: Option<&str>) -> Option<ProxyRotator> {
    match proxy_file {
        Some(path) => match ProxyRotator::load_from_file(path) {
            Ok(rotator) => {
                println!("{} Loaded proxies from {}", "[+]".green().bold(), path);
                Some(rotator)
            }
            Err(e) => {
                eprintln!("{} Failed to load proxies: {}", "[✗]".red().bold(), e);
                None
            }
        },
        None => None,
    }
}

/// Initialize the stealth HTTP client.
pub fn init_http_client(
    proxy_rotator: &Option<ProxyRotator>,
    random_agent: bool,
    allow_internal: bool,
) -> anyhow::Result<Arc<StealthHttpClient>> {
    Ok(Arc::new(StealthHttpClient::new_with_options(
        proxy_rotator.is_some(),
        random_agent,
        None,
        true,
        None,
        None,
        None,
        Some(SsrfConfig { allow_internal }),
    )?))
}

/// Load TLS configuration from PEM files.
pub fn load_tls_config(
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
) -> anyhow::Result<Option<valayam_api::TlsConfig>> {
    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let ca_pem = match tls_ca {
                Some(ca_path) => Some(std::fs::read(ca_path)?),
                None => None,
            };
            if ca_pem.is_some() {
                println!(
                    "{} TLS mTLS enabled for gRPC control plane (cert: {}, key: {}, ca: {})",
                    "[+]".green().bold(),
                    cert_path,
                    key_path,
                    tls_ca.unwrap()
                );
            } else {
                println!(
                    "{} TLS enabled for gRPC control plane (cert: {}, key: {})",
                    "[+]".green().bold(),
                    cert_path,
                    key_path
                );
            }
            Ok(Some(valayam_api::TlsConfig {
                cert_pem,
                key_pem,
                ca_pem,
            }))
        }
        _ => Ok(None),
    }
}

/// Run the crawler to discover URLs on the target.
pub async fn run_crawler(
    target: &str,
    http_client: Arc<StealthHttpClient>,
    crawl_depth: usize,
    rate_limiter: Option<Arc<RateLimiter>>,
    crawl_headers: Option<&str>,
) -> Vec<String> {
    println!(
        "{} Starting Web Crawler discovery on {}...",
        "[*]".blue().bold(),
        target
    );

    let hdrs = crawl_headers.map(|s| {
        let mut map = std::collections::HashMap::new();
        for kv in s.split(',') {
            let mut parts = kv.splitn(2, ':');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        map
    });

    use valayam_core::features::crawler::Crawler;
    let crawler = Crawler::new(http_client, target, crawl_depth, rate_limiter, hdrs);
    match crawler {
        Ok(c) => {
            let discovered = c.run().await;
            println!(
                "{} Crawler discovered {} page(s) on target domain.",
                "[+]".green().bold(),
                discovered.len()
            );
            if !discovered.is_empty() {
                return discovered.into_iter().collect();
            }
            vec![target.to_string()]
        }
        Err(e) => {
            eprintln!("{} Failed to initialize crawler: {}", "[✗]".red().bold(), e);
            vec![target.to_string()]
        }
    }
}
