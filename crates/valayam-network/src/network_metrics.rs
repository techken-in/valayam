//! HTTP client Prometheus metrics for valayam-network.
//!
//! Counters and histograms for outbound HTTP requests made by `StealthHttpClient`.

use prometheus::{register_counter_vec, register_histogram_vec, CounterVec, HistogramVec};

lazy_static::lazy_static! {
    /// Total HTTP requests, labelled by method, status code, and proxy usage.
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "valayam_http_requests_total",
        "Total outbound HTTP requests",
        &["method", "status", "proxy"]
    )
    .expect("HTTP_REQUESTS_TOTAL");

    /// Request duration seconds bucketed for latency analysis.
    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "valayam_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["method", "status"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .expect("HTTP_REQUEST_DURATION");
}

/// Record a completed HTTP request.
pub fn record_http_request(method: &str, status: u16, proxy: bool, duration_secs: f64) {
    let status_label = status_code_label(status);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, &status_label, if proxy { "1" } else { "0" }])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[method, &status_label])
        .observe(duration_secs);
}

/// Map status code to a label bucket: "2xx", "4xx", "5xx", or the raw code string for others.
fn status_code_label(status: u16) -> String {
    match status {
        200..=299 => "2xx".into(),
        300..=399 => "3xx".into(),
        400..=499 => "4xx".into(),
        500..=599 => "5xx".into(),
        other => other.to_string(),
    }
}
