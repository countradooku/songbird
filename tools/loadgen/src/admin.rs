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
    Some(Figures {
        resident_bytes: value("songbird_process_resident_memory_bytes")?,
        cpu_seconds: value("songbird_process_cpu_seconds_total")?,
        open_fds: value("songbird_process_open_fds")?,
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
}
