//! Songbird telemetry.
//!
//! - Tracing to stdout through a **non-blocking, lossy** writer: logging never blocks a task; when
//!   the buffer is full, lines are dropped and counted (`songbird_telemetry_log_lines_dropped_total`).
//! - A [`redaction::RedactionLayer`] that refuses callsites with sensitive field names (invariant 6).
//! - Prometheus metrics ([`metrics::Metrics`]) and the admin endpoint ([`admin::serve`]).
#![forbid(unsafe_code)]

pub mod admin;
pub mod metrics;
pub mod redaction;

use songbird_types::config::{LogConfig, LogFormat};
use tracing_appender::non_blocking::{ErrorCounter, NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer};

pub use admin::Health;
pub use metrics::Metrics;
pub use redaction::{RedactionLayer, RedactionMode};

/// Telemetry errors.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The log filter directive is invalid.
    #[error("invalid log filter: {0}")]
    Filter(String),
    /// A global subscriber was already installed.
    #[error("tracing already initialised")]
    AlreadyInitialised,
    /// A metric name matches the redaction rules.
    #[error("metric name `{0}` is sensitive (invariant 6)")]
    SensitiveMetricName(String),
}

/// Keeps the log writer thread alive; drop it last, at the end of `main`, to flush.
#[derive(Debug)]
pub struct TelemetryGuard {
    _worker: WorkerGuard,
    dropped: ErrorCounter,
}

impl TelemetryGuard {
    /// Counter of dropped log lines, for [`Metrics::register_self_metrics`].
    #[must_use]
    pub fn dropped_lines(&self) -> ErrorCounter {
        self.dropped.clone()
    }
}

/// Installs the global tracing subscriber.
///
/// # Errors
/// [`TelemetryError::Filter`] or [`TelemetryError::AlreadyInitialised`].
pub fn init_tracing(
    cfg: &LogConfig,
    mode: RedactionMode,
) -> Result<TelemetryGuard, TelemetryError> {
    let filter =
        EnvFilter::try_new(&cfg.filter).map_err(|e| TelemetryError::Filter(e.to_string()))?;
    let (writer, worker) = NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(cfg.buffered_lines)
        .thread_name("songbird-log")
        .finish(std::io::stdout());
    let dropped = writer.error_counter();

    let fmt = match cfg.format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_writer(writer)
            .boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer().with_writer(writer).boxed(),
    };
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        // Outermost, so its verdict applies to every layer below.
        .with(RedactionLayer::new(mode));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| TelemetryError::AlreadyInitialised)?;
    Ok(TelemetryGuard {
        _worker: worker,
        dropped,
    })
}
