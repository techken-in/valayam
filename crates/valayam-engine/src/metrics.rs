//! Prometheus metrics for Valayam engine.
//!
//! All metrics are registered as global `lazy_static` counters, histograms, and
//! gauges.  Call `gather_metrics()` to get the Prometheus exposition-format text
//! for the `/metrics` endpoint.

use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
};

// ── Plugin execution ─────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    /// Execution wall-clock in seconds, bucketed by plugin name + outcome kind.
    static ref PLUGIN_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "valayam_plugin_duration_seconds",
        "Seconds a plugin took to execute",
        &["plugin", "outcome"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("PLUGIN_DURATION_SECONDS");

    /// Counter of plugin executions, labelled by plugin name + outcome kind.
    static ref PLUGIN_OUTCOME_TOTAL: CounterVec = register_counter_vec!(
        "valayam_plugin_outcome_total",
        "Total plugin executions by outcome",
        &["plugin", "outcome"]
    )
    .expect("PLUGIN_OUTCOME_TOTAL");

    /// Counter of findings emitted, labelled by plugin name.
    static ref PLUGIN_FINDING_TOTAL: CounterVec = register_counter_vec!(
        "valayam_plugin_finding_total",
        "Total findings emitted by plugin",
        &["plugin"]
    )
    .expect("PLUGIN_FINDING_TOTAL");

    /// Execution wall-clock in seconds, bucketed by template_id.
    pub static ref SCAN_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "valayam_scan_duration_seconds",
        "Seconds a scan took to execute",
        &["template_id"],
        vec![0.01, 0.1, 1.0, 10.0, 30.0, 60.0, 300.0]
    )
    .expect("SCAN_DURATION_SECONDS");

    /// Counter of findings emitted, labelled by severity and template_id.
    pub static ref FINDINGS_TOTAL: CounterVec = register_counter_vec!(
        "valayam_findings_total",
        "Total findings emitted",
        &["severity", "template_id"]
    )
    .expect("FINDINGS_TOTAL");

    /// Load time of plugins in seconds, labelled by plugin_name.
    pub static ref PLUGIN_LOAD_TIME_SECONDS: HistogramVec = register_histogram_vec!(
        "valayam_plugin_load_time_seconds",
        "Seconds taken to load a plugin",
        &["plugin_name"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )
    .expect("PLUGIN_LOAD_TIME_SECONDS");

    /// Memory used by WASM plugins in bytes, labelled by plugin_name.
    pub static ref WASM_MEMORY_BYTES: GaugeVec = register_gauge_vec!(
        "valayam_wasm_memory_bytes",
        "Memory allocated for a WASM plugin sandbox",
        &["plugin_name"]
    )
    .expect("WASM_MEMORY_BYTES");

    /// Active scans currently running.
    pub static ref ACTIVE_SCANS: Gauge = register_gauge!(
        "valayam_active_scans",
        "Number of active scans running"
    )
    .expect("ACTIVE_SCANS");

    /// Hot reload events, labelled by status (success/failure).
    pub static ref HOT_RELOAD_TOTAL: CounterVec = register_counter_vec!(
        "valayam_hot_reload_total",
        "Total hot reload attempts",
        &["status"]
    )
    .expect("HOT_RELOAD_TOTAL");
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    /// Current number of available rate-limiter permits.
    pub static ref RATE_LIMITER_PERMITS: Gauge = register_gauge!(
        "valayam_rate_limiter_permits_available",
        "Available rate-limiter capacity at last snapshot"
    )
    .expect("RATE_LIMITER_PERMITS");

    /// Time spent waiting for rate limiter permits.
    pub static ref RATE_LIMITER_WAIT_SECONDS: Histogram = register_histogram!(
        "valayam_rate_limiter_wait_seconds",
        "Seconds spent waiting for rate limit permits",
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    )
    .expect("RATE_LIMITER_WAIT_SECONDS");
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Record a single plugin execution outcome.
pub fn record_plugin_outcome(
    plugin: &str,
    outcome_kind: &str,
    duration_secs: f64,
    finding_count: usize,
) {
    PLUGIN_DURATION_SECONDS
        .with_label_values(&[plugin, outcome_kind])
        .observe(duration_secs);
    PLUGIN_OUTCOME_TOTAL
        .with_label_values(&[plugin, outcome_kind])
        .inc();
    if finding_count > 0 {
        PLUGIN_FINDING_TOTAL
            .with_label_values(&[plugin])
            .inc_by(finding_count as f64);
    }
}

/// Return all metrics in Prometheus text format.
pub fn gather_metrics() -> String {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    encoder
        .encode(&prometheus::gather(), &mut buf)
        .expect("metrics encoding should not fail");
    String::from_utf8(buf).unwrap_or_else(|e| format!("# metrics encoding error: {e}"))
}
