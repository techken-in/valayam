//! Prometheus metrics for Valayam engine.
//!
//! All metrics are registered as global `lazy_static` counters, histograms, and
//! gauges.  Call `gather_metrics()` to get the Prometheus exposition-format text
//! for the `/metrics` endpoint.

use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Gauge, HistogramVec,
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
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    /// Current number of available rate-limiter permits.
    pub static ref RATE_LIMITER_PERMITS: Gauge = register_gauge!(
        "valayam_rate_limiter_permits_available",
        "Available rate-limiter capacity at last snapshot"
    )
    .expect("RATE_LIMITER_PERMITS");
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
