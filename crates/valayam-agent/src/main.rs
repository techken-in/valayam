use colored::*;
use hmac::Hmac;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use valayam_config::agent::*;

/// Minimum backoff between polls (when server returns 204)
const MIN_BACKOFF_SECS: u64 = 1;
/// Maximum backoff between polls
const MAX_BACKOFF_SECS: u64 = 60;

use clap::Parser;

#[derive(Parser)]
#[command(name = "valayam-agent", about = "Valayam worker agent")]
pub struct Args {
    #[arg(
        long,
        env = "VALAYAM_PLATFORM_URL",
        default_value = "http://localhost:3000"
    )]
    pub platform_url: String,
    #[arg(long, env = "VALAYAM_WORKER_ID")]
    pub worker_id: Option<String>,
    #[arg(long, env = "VALAYAM_POLL_INTERVAL_SECS", default_value_t = 10)]
    pub poll_interval_secs: u64,
    #[arg(long, env = "VALAYAM_HEARTBEAT_INTERVAL_SECS", default_value_t = 30)]
    pub heartbeat_interval_secs: u64,
    #[arg(long, env = "VALAYAM_CAPABILITIES", default_value = "http,ssl,network")]
    pub capabilities: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let cfg = AgentConfig {
        platform_url: args.platform_url,
        worker_id: args
            .worker_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        poll_interval_secs: args.poll_interval_secs,
        heartbeat_interval_secs: args.heartbeat_interval_secs,
        capabilities: args
            .capabilities
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        job_secret: std::env::var("PLATFORM_JOB_SECRET").unwrap_or_default(),
    };

    let cancel = CancellationToken::new();
    let start_time = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    println!(
        "{} Agent starting — worker_id={}",
        "[+]".green().bold(),
        cfg.worker_id
    );
    println!(
        "{} Platform URL: {}",
        "[+]".green().bold(),
        cfg.platform_url
    );
    println!(
        "{} Poll interval: {}s",
        "[+]".green().bold(),
        cfg.poll_interval_secs
    );

    let mut backoff_secs = MIN_BACKOFF_SECS;
    let current_job_id: Option<String> = None;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                println!("{} Agent received shutdown signal", "[!]".yellow().bold());
                break;
            }
            _ = sleep(Duration::from_secs(1)) => {
                if start_time.elapsed().as_secs() % cfg.heartbeat_interval_secs < 2 {
                    send_heartbeat(&client, &cfg, &current_job_id, start_time).await;
                }

                match poll_job(&client, &cfg).await {
                    Ok(Some(job)) => {
                        println!("{} Received job: {} → {}",
                            "[→]".cyan().bold(), job.job_id, job.target_url);
                        backoff_secs = MIN_BACKOFF_SECS;

                        if let Err(e) = execute_and_report(&client, &cfg, job, start_time, cancel.clone()).await {
                            tracing::error!("Job execution failed: {}", e);
                        }
                    }
                    Ok(None) => {
                        sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                    }
                    Err(e) => {
                        tracing::error!("Poll failed: {} (backoff {}s)", e, backoff_secs);
                        sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                    }
                }
            }
        }
    }

    println!("{} Agent stopped", "[■]".red().bold());
    Ok(())
}

// ── Poll ─────────────────────────────────────────────────────────

async fn poll_job(client: &reqwest::Client, cfg: &AgentConfig) -> anyhow::Result<Option<AgentJob>> {
    let url = format!(
        "{}/api/v1/jobs/poll",
        cfg.platform_url.trim_end_matches('/')
    );

    let resp = client
        .post(&url)
        .header("X-Worker-ID", &cfg.worker_id)
        .json(&serde_json::json!({
            "worker_id": cfg.worker_id,
            "capabilities": cfg.capabilities,
        }))
        .send()
        .await?;

    match resp.status() {
        reqwest::StatusCode::OK => {
            let poll: PollResponse = resp.json().await?;
            Ok(poll.job)
        }
        reqwest::StatusCode::NO_CONTENT => Ok(None),
        code => {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("poll returned {}: {}", code, body);
        }
    }
}

// ── Execute + Report ─────────────────────────────────────────────

async fn execute_and_report(
    client: &reqwest::Client,
    cfg: &AgentConfig,
    job: AgentJob,
    _start_time: Instant,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    if let Some(ref auth) = job.auth {
        if !cfg.job_secret.is_empty() {
            if !verify_job_token(&cfg.job_secret, &job.job_id, &auth.job_token) {
                tracing::error!("Invalid job_token for job {} — rejecting", job.job_id);
                anyhow::bail!("Job token verification failed for job {}", job.job_id);
            }
            tracing::debug!("Job token verified for job {}", job.job_id);
        }
    }

    let job_start = Instant::now();
    let output_path = format!(".valayam_agent_{}.json", job.job_id);
    let started_at = chrono::Utc::now().to_rfc3339();

    let tmp_dir = std::env::temp_dir().join(format!("valayam_{}", job.job_id));
    std::fs::create_dir_all(&tmp_dir)?;

    let _template_paths: Vec<std::path::PathBuf> = job
        .templates
        .iter()
        .map(|t| {
            let p = tmp_dir.join(format!("{}.yaml", t.id));
            std::fs::write(&p, &t.yaml).ok();
            p
        })
        .collect();

    let scan_args = valayam_cli::cli::Args {
        target: job.target_url.clone(),
        template: Some(tmp_dir.to_string_lossy().to_string()),
        nuclei_template: None,
        output: Some(output_path.clone()),
        format: job
            .config
            .output_format
            .clone()
            .unwrap_or_else(|| "json".into()),
        rate_limit: job.config.rate_limit,
        concurrency: job.config.concurrency.unwrap_or(100),
        random_agent: job.config.random_agent.unwrap_or(false),
        proxy_file: None,
        log_level: "error".into(),
        log_file: None,
        worker: None,
        crawl: job.config.crawl.unwrap_or(false),
        crawl_depth: job.config.crawl_depth.unwrap_or(3),
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

    let http_client = valayam_cli::setup::init_http_client(&None, false, false)
        .map_err(|e| anyhow::anyhow!("Failed to init HTTP client: {}", e))?;
    let rate_limiter = scan_args
        .rate_limit
        .map(|rps| Arc::new(valayam_engine::rate_limiter::RateLimiter::new_simple(rps)));
    let template_files = valayam_cli::setup::discover_templates(&tmp_dir.to_string_lossy());

    if template_files.is_empty() {
        anyhow::bail!("No valid templates found for job {}", job.job_id);
    }

    if let Err(e) = valayam_cli::orchestrator::run_scan_with_job_id(
        scan_args,
        template_files,
        false,                        // is_nuclei
        vec![job.target_url.clone()], // targets
        http_client,
        rate_limiter,
        None, // grpc_client
        None, // state_rx
        cancel,
        Some(job.job_id.clone()),
    )
    .await
    {
        tracing::error!("Scan execution error: {}", e);
    }

    let completed_at = chrono::Utc::now().to_rfc3339();
    let duration_secs = job_start.elapsed().as_secs_f64();

    let findings: Vec<serde_json::Value> = match std::fs::read_to_string(&output_path) {
        Ok(content) => content
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect(),
        Err(_) => vec![],
    };

    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let token = job.auth.as_ref().map(|a| a.job_token.clone());

    let result = AgentJobResult {
        job_id: job.job_id.clone(),
        status: "completed".into(),
        started_at,
        completed_at,
        worker_id: cfg.worker_id.clone(),
        metrics: serde_json::json!({
            "duration_secs": duration_secs,
            "findings_count": findings.len(),
            "templates_executed": job.templates.len(),
        }),
        findings,
        errors: vec![],
        job_token: token,
    };

    let url = format!(
        "{}/api/v1/jobs/{}/results",
        cfg.platform_url.trim_end_matches('/'),
        job.job_id
    );

    match client.post(&url).json(&result).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!(
                "{} Results reported for job {}",
                "[✓]".green().bold(),
                job.job_id
            );
        }
        Ok(resp) => {
            tracing::warn!(
                "Result POST returned {} for job {}",
                resp.status(),
                job.job_id
            );
        }
        Err(e) => {
            tracing::error!("Failed to POST results: {}", e);
        }
    }

    Ok(())
}

// ── Heartbeat ────────────────────────────────────────────────────

async fn send_heartbeat(
    client: &reqwest::Client,
    cfg: &AgentConfig,
    current_job_id: &Option<String>,
    start_time: Instant,
) {
    let uptime = start_time.elapsed().as_secs();

    #[cfg(target_os = "linux")]
    let (cpu_pct, mem_pct) = read_proc_stats();
    #[cfg(not(target_os = "linux"))]
    let (cpu_pct, mem_pct) = (0.0, 0.0);

    let heartbeat = AgentHeartbeat {
        worker_id: cfg.worker_id.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: if current_job_id.is_some() {
            "scanning".to_string()
        } else {
            "idle".to_string()
        },
        current_job_id: current_job_id.clone(),
        cpu_usage_pct: cpu_pct,
        memory_usage_pct: mem_pct,
        uptime_secs: uptime,
        plugins_loaded: 0,
        templates_cached: 0,
    };

    let url = format!(
        "{}/api/v1/workers/{}/heartbeat",
        cfg.platform_url.trim_end_matches('/'),
        cfg.worker_id
    );

    if let Err(e) = client.post(&url).json(&heartbeat).send().await {
        tracing::warn!("Heartbeat failed: {}", e);
    }
}

/// Verify a HMAC-SHA256 job token against the shared secret.
fn verify_job_token(secret: &str, job_id: &str, token: &str) -> bool {
    use hmac::Mac;
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(job_id.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    token.len() == expected_hex.len()
        && token
            .as_bytes()
            .iter()
            .zip(expected_hex.as_bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Reads CPU and memory stats from /proc on Linux.
#[cfg(target_os = "linux")]
fn read_proc_stats() -> (f32, f32) {
    let mem_total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                if line.starts_with("MemTotal:") {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<f64>().ok())
                } else {
                    None
                }
            })
        })
        .unwrap_or(1.0);

    let mem_avail = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                if line.starts_with("MemAvailable:") {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<f64>().ok())
                } else {
                    None
                }
            })
        })
        .unwrap_or(0.0);

    let mem_usage = if mem_total > 0.0 {
        ((mem_total - mem_avail) / mem_total * 100.0) as f32
    } else {
        0.0
    };

    (0.0, mem_usage)
}
