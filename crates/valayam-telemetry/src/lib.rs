//! Telemetry initialisation: console logging, OTLP export, and file logging.
//!
//! Call `init_telemetry()` once at startup.  The returned `TelemetryGuard` must
//! be kept alive for the lifetime of the application (it holds the
//! non-blocking file writer guard and the OTLP tracer provider).

use opentelemetry_otlp::WithExportConfig;
use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Opaque guard that keeps file-appender and OTLP resources alive.
pub struct TelemetryGuard {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialise the tracing/logging pipeline:
///
/// 1. **Console layer** — human-readable, stderr, level from `console_level_str`.
/// 2. **OTLP layer** — sends spans to the configured OpenTelemetry collector.
/// 3. **File layer** — JSON structured, always DEBUG (only if `log_path` is set).
pub fn init_telemetry(
    console_level_str: &str,
    otlp_endpoint: &str,
    log_path: Option<&Path>,
) -> TelemetryGuard {
    // ── Global Error Handler ───────────────────────────────────────────
    let _ = opentelemetry::global::set_error_handler(|_error| {
        // Silenced: CLI already performs pre-flight check and displays status
    });

    // ── Console layer ──────────────────────────────────────────────────
    let console_level = console_level_str
        .parse::<tracing::Level>()
        .unwrap_or(tracing::Level::ERROR);
    let console_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(console_level.into())
        .parse_lossy(format!(
            "{},extism=off,wasmtime=off,cranelift=off",
            console_level_str
        ));

    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_filter(console_filter);

    // ── OTLP / OpenTelemetry layer ─────────────────────────────────────
    let otel_layer = if !otlp_endpoint.is_empty() {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(otlp_endpoint),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .expect("Failed to initialize OTLP pipeline");

        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    // ── File layer (optional) ─────────────────────────────────────────
    let (file_layer, file_guard) = if let Some(path) = log_path {
        let file = std::fs::File::create(path).expect("Failed to create log file");
        let (non_blocking, guard) = tracing_appender::non_blocking(file);

        let file_filter =
            tracing_subscriber::filter::LevelFilter::from_level(tracing::Level::DEBUG);
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_filter(file_filter);
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    // ── Compose layers ─────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(console_layer)
        .with(otel_layer)
        .with(file_layer)
        .init();

    TelemetryGuard {
        _file_guard: file_guard,
    }
}

/// Drop guard signals shutdown — invoked automatically when the guard is dropped.
impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        opentelemetry::global::shutdown_tracer_provider();
    }
}
