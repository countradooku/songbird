//! Prometheus metrics (`OpenMetrics` text exposition via `prometheus-client`).
//!
//! Every metric is registered under the `songbird_` prefix. Metric names are checked against the
//! redaction rules at registration; label *names* in an exposition can be audited with
//! [`audit_exposition`] (used by tests and the CI smoke test). Labels never carry per-device or
//! per-connection values: metrics are aggregates only (invariant 6).

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::metrics::gauge::ConstGauge;
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
        // The process's own memory, CPU and descriptors (Linux, read at scrape: nothing on the
        // hot path). Benchmarks derive memory per idle connection and CPU per message from them.
        if let Some(p) = Process::read() {
            let rss = ConstGauge::new(i64::try_from(p.resident_bytes).unwrap_or(i64::MAX));
            rss.encode(encoder.encode_descriptor(
                "process_resident_memory_bytes",
                "Resident memory of this process",
                None,
                rss.metric_type(),
            )?)?;
            let cpu = ConstCounter::new(p.cpu_seconds);
            cpu.encode(encoder.encode_descriptor(
                "process_cpu_seconds",
                "CPU time of this process, user and system, in seconds",
                None,
                cpu.metric_type(),
            )?)?;
            let fds = ConstGauge::new(i64::try_from(p.open_fds).unwrap_or(i64::MAX));
            fds.encode(encoder.encode_descriptor(
                "process_open_fds",
                "Open file descriptors of this process (connections among them)",
                None,
                fds.metric_type(),
            )?)?;
        }
        Ok(())
    }
}

/// What `/proc/self` says about this process (Linux).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Process {
    resident_bytes: u64,
    cpu_seconds: f64,
    open_fds: u64,
}

impl Process {
    #[cfg(target_os = "linux")]
    fn read() -> Option<Self> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let open_fds = std::fs::read_dir("/proc/self/fd").ok()?.count();
        Self::parse(&status, &stat, u64::try_from(open_fds).unwrap_or(u64::MAX))
    }

    #[cfg(not(target_os = "linux"))]
    fn read() -> Option<Self> {
        None
    }

    /// `VmRSS` (kB) from `status`; `utime` + `stime` (fields 14 and 15, in `USER_HZ` = 100 ticks
    /// per second, fixed in Linux's user ABI) from `stat`, read after the command name's closing
    /// parenthesis, which may itself contain spaces.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "tested on every platform"))]
    fn parse(status: &str, stat: &str, open_fds: u64) -> Option<Self> {
        let rss_kb: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        let after = stat.rsplit_once(')')?.1;
        let mut fields = after.split_whitespace();
        // After ")": state is field 3, so utime (14) is the 12th and stime (15) the 13th.
        let utime: u64 = fields.nth(11)?.parse().ok()?;
        let stime: u64 = fields.next()?.parse().ok()?;
        let ticks = utime.saturating_add(stime);
        // Whole seconds and hundredths, each exact in an f64 (u32 seconds: 136 years of CPU).
        let whole = f64::from(u32::try_from(ticks / 100).unwrap_or(u32::MAX));
        let hundredths = f64::from(u32::try_from(ticks % 100).unwrap_or(0));
        let cpu_seconds = whole + hundredths / 100.0;
        Some(Self {
            resident_bytes: rss_kb.saturating_mul(1024),
            cpu_seconds,
            open_fds,
        })
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
    fn reads_process_figures_from_proc_formats() {
        let status = "Name:\tdelivery\nVmPeak:\t  900 kB\nVmRSS:\t  51200 kB\nThreads:\t9\n";
        // A command name with spaces and parentheses must not shift the fields.
        let stat = "4242 (songbird (x) y) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 9";
        let p = Process::parse(status, stat, 17).unwrap();
        assert_eq!(p.resident_bytes, 51_200 * 1024);
        assert!((p.cpu_seconds - 3.0).abs() < 1e-9, "{}", p.cpu_seconds);
        assert_eq!(p.open_fds, 17);
        assert!(Process::parse("VmRSS: x kB", stat, 0).is_none());
        assert!(Process::parse(status, "garbage", 0).is_none());
    }

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
