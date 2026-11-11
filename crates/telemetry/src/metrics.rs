//! Prometheus metrics (`OpenMetrics` text exposition via `prometheus-client`).
//!
//! Every metric is registered under the `songbird_` prefix. Metric names are checked against the
//! redaction rules at registration; label *names* in an exposition can be audited with
//! [`audit_exposition`] (used by tests and the CI smoke test). Labels never carry per-device or
//! per-connection values: metrics are aggregates only (invariant 6).

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::{Metric, Registry};
use tracing_appender::non_blocking::ErrorCounter;

use crate::TelemetryError;
use crate::redaction::{is_sensitive, refused_callsites};

/// The metric registry of one process. Build it at startup, register everything, then share it
/// read-only (`Arc<Metrics>`) with the admin endpoint.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
}

impl Metrics {
    /// A registry with `songbird_build_info{service, version}`.
    #[must_use]
    pub fn new(service: &'static str, version: &'static str) -> Self {
        let mut registry = Registry::with_prefix("songbird");
        registry.register(
            "build",
            "Build information",
            Info::new(vec![("service", service), ("version", version)]),
        );
        Self { registry }
    }

    /// Registers a metric.
    ///
    /// # Errors
    /// [`TelemetryError::SensitiveMetricName`] if the name matches the redaction rules.
    pub fn register(
        &mut self,
        name: &str,
        help: &str,
        metric: impl Metric,
    ) -> Result<(), TelemetryError> {
        if is_sensitive(name) {
            return Err(TelemetryError::SensitiveMetricName(name.to_owned()));
        }
        self.registry.register(name, help, metric);
        Ok(())
    }

    /// Registers the telemetry self-metrics (dropped log lines, refused callsites).
    pub fn register_self_metrics(&mut self, dropped: Option<ErrorCounter>) {
        self.registry
            .register_collector(Box::new(SelfMetrics { dropped }));
    }

    /// Encodes the registry in `OpenMetrics` text format.
    ///
    /// # Errors
    /// Only if formatting fails, which `String` never does in practice.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut out = String::with_capacity(4096);
        prometheus_client::encoding::text::encode(&mut out, &self.registry)?;
        Ok(out)
    }
}

#[derive(Debug)]
struct SelfMetrics {
    dropped: Option<ErrorCounter>,
}

impl Collector for SelfMetrics {
    fn encode(&self, mut encoder: DescriptorEncoder<'_>) -> Result<(), std::fmt::Error> {
        let refused = ConstCounter::new(refused_callsites());
        refused.encode(encoder.encode_descriptor(
            "telemetry_refused_callsites",
            "Log or span callsites refused because they carry a sensitive field name",
            None,
            refused.metric_type(),
        )?)?;
        if let Some(dropped) = &self.dropped {
            let c = ConstCounter::new(u64::try_from(dropped.dropped_lines()).unwrap_or(u64::MAX));
            c.encode(encoder.encode_descriptor(
                "telemetry_log_lines_dropped",
                "Log lines dropped because the non-blocking writer's buffer was full",
                None,
                c.metric_type(),
            )?)?;
        }
        Ok(())
    }
}

/// Metric and label names in an `OpenMetrics` exposition that match the redaction rules.
#[must_use]
pub fn audit_exposition(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (name, rest) = line.split_once(['{', ' ']).unwrap_or((line, ""));
        if is_sensitive(name) {
            bad.push(name.to_owned());
        }
        if let Some(labels) = rest.split_once('}').map(|(l, _)| l) {
            for pair in labels.split(',') {
                if let Some((label, _)) = pair.split_once('=') {
                    let label = label.trim();
                    if is_sensitive(label) {
                        bad.push(label.to_owned());
                    }
                }
            }
        }
    }
    bad
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::metrics::counter::Counter;

    #[test]
    fn encodes_build_info_and_self_metrics() {
        let mut m = Metrics::new("test", "0.0.0");
        let c: Counter = Counter::default();
        m.register("frames", "Frames", c.clone()).unwrap();
        c.inc();
        m.register_self_metrics(None);
        let text = m.encode().unwrap();
        assert!(
            text.contains("songbird_build_info{service=\"test\",version=\"0.0.0\"} 1"),
            "{text}"
        );
        assert!(text.contains("songbird_frames_total 1"), "{text}");
        assert!(
            text.contains("songbird_telemetry_refused_callsites_total"),
            "{text}"
        );
        assert!(text.ends_with("# EOF\n"));
        assert_eq!(audit_exposition(&text), Vec::<String>::new());
    }

    #[test]
    fn rejects_sensitive_metric_names() {
        let mut m = Metrics::new("test", "0.0.0");
        assert!(
            m.register("device_id_seen", "x", Counter::<u64>::default())
                .is_err()
        );
    }

    #[test]
    fn audit_finds_sensitive_labels() {
        let text = "songbird_x_total{core=\"1\",device_id=\"ab\"} 1\nsongbird_peer_addr 2\n# EOF\n";
        assert_eq!(audit_exposition(text), ["device_id", "songbird_peer_addr"]);
    }
}
