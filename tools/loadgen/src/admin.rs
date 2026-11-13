//! Reads a delivery node's own figures from its private admin endpoint (`/metrics`): resident
//! memory, CPU seconds and open descriptors (`songbird_process_*`, Linux). The load generator
//! takes them before connecting, once every device is connected, and at the end, for memory per
//! idle connection and CPU per 10,000 messages (master prompt §8).

use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// One scrape, summed over every node given.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Figures {
    pub(crate) resident_bytes: f64,
    pub(crate) cpu_seconds: f64,
    pub(crate) open_fds: f64,
    /// `songbird_delivery_store_seconds`: cumulative counts per bucket bound (`le`), summed over
    /// nodes, in the exposition's order.
    pub(crate) store: [(f64, f64); STORE_BUCKETS],
    /// How many of `store` the exposition had (the last of them is +Inf).
    pub(crate) store_len: usize,
}

/// Buckets of the delivery store histogram (telemetry's `LATENCY_BUCKETS` and +Inf).
pub(crate) const STORE_BUCKETS: usize = 15;

impl Figures {
    /// The store latency quantile `q` between two scrapes, as the upper bound of the bucket that
    /// holds it (seconds; `f64::INFINITY` past the last bound); `None` without observations.
    pub(crate) fn store_quantile(&self, earlier: &Self, q: f64) -> Option<f64> {
        let n = self.store_len.min(earlier.store_len);
        let total = self.store.get(n.checked_sub(1)?)?.1 - earlier.store.get(n - 1)?.1;
        if total <= 0.0 {
            return None;
        }
        let want = q * total;
        self.store
            .iter()
            .zip(&earlier.store)
            .take(n)
            .find(|((_, now), (_, before))| now - before >= want)
            .map(|((le, _), _)| *le)
    }
}

/// Scrapes every `host:port` in `addrs` (comma-separated) and sums them; `None` when no node
/// reports process figures (not Linux).
pub(crate) async fn scrape(addrs: &str) -> anyhow::Result<Option<Figures>> {
    let mut sum = Figures::default();
    let mut any = false;
    for addr in addrs.split(',').filter(|s| !s.is_empty()) {
        let text = get_metrics(addr).await?;
        if let Some(f) = parse(&text) {
            sum.resident_bytes += f.resident_bytes;
            sum.cpu_seconds += f.cpu_seconds;
            sum.open_fds += f.open_fds;
            for (s, b) in sum.store.iter_mut().zip(f.store) {
                *s = (b.0, s.1 + b.1);
            }
            sum.store_len = f.store_len;
            any = true;
        }
    }
    Ok(any.then_some(sum))
}

async fn get_metrics(addr: &str) -> anyhow::Result<String> {
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await?;
        s.write_all(format!("GET /metrics HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await?;
        let mut buf = Vec::with_capacity(64 * 1024);
        s.read_to_end(&mut buf).await?;
        anyhow::Ok(buf)
    };
    let buf = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .context("admin endpoint timed out")??;
    let text = String::from_utf8(buf).context("metrics are not UTF-8")?;
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        bail!("not an HTTP response");
    };
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        bail!(
            "admin endpoint answered {}",
            head.lines().next().unwrap_or_default()
        );
    }
    Ok(body.to_owned())
}

/// The three process samples of an `OpenMetrics` exposition.
fn parse(text: &str) -> Option<Figures> {
    let value = |name: &str| -> Option<f64> {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
    };
    let mut store = [(0.0, 0.0); STORE_BUCKETS];
    let buckets = text.lines().filter_map(|l| {
        let rest = l.strip_prefix("songbird_delivery_store_seconds_bucket{le=\"")?;
        let (le, rest) = rest.split_once("\"}")?;
        let le = if le == "+Inf" {
            f64::INFINITY
        } else {
            le.parse().ok()?
        };
        Some((le, rest.split_whitespace().next()?.parse().ok()?))
    });
    let mut store_len = 0;
    for (slot, b) in store.iter_mut().zip(buckets) {
        *slot = b;
        store_len += 1;
    }
    Some(Figures {
        resident_bytes: value("songbird_process_resident_memory_bytes")?,
        cpu_seconds: value("songbird_process_cpu_seconds_total")?,
        open_fds: value("songbird_process_open_fds")?,
        store,
        store_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_process_samples() {
        let text = "# HELP songbird_process_resident_memory_bytes Resident memory\n\
            songbird_process_resident_memory_bytes 52428800\n\
            songbird_process_cpu_seconds_total 12.5\n\
            songbird_process_open_fds 1007\n\
            songbird_delivery_connections 1000\n";
        let f = parse(text).unwrap();
        assert!((f.resident_bytes - 52_428_800.0).abs() < 1.0);
        assert!((f.cpu_seconds - 12.5).abs() < 1e-9);
        assert!((f.open_fds - 1007.0).abs() < 1e-9);
        assert!(parse("songbird_process_open_fds 3\n").is_none());
    }

    #[test]
    fn store_quantiles_between_scrapes() {
        let with = |counts: [f64; 3]| {
            format!(
                "songbird_process_resident_memory_bytes 1\nsongbird_process_cpu_seconds_total 1\n\
                 songbird_process_open_fds 1\n\
                 songbird_delivery_store_seconds_bucket{{le=\"0.001\"}} {}\n\
                 songbird_delivery_store_seconds_bucket{{le=\"0.002\"}} {}\n\
                 songbird_delivery_store_seconds_bucket{{le=\"+Inf\"}} {}\n",
                counts[0], counts[1], counts[2]
            )
        };
        let before = parse(&with([10.0, 10.0, 10.0])).unwrap();
        // 100 more: 90 within 1 ms, 9 more within 2 ms, 1 beyond.
        let after = parse(&with([100.0, 109.0, 110.0])).unwrap();
        assert_eq!(after.store_quantile(&before, 0.5), Some(0.001));
        assert_eq!(after.store_quantile(&before, 0.99), Some(0.002));
        assert_eq!(after.store_quantile(&before, 0.999), Some(f64::INFINITY));
        assert_eq!(before.store_quantile(&before, 0.5), None);
    }
}
