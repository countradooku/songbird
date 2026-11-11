//! Latency summaries from raw samples (microseconds). Exact percentiles: runs keep every sample
//! (4 bytes each), which is fine up to tens of millions of messages.

/// Percentile summary.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Summary {
    /// Samples.
    pub(crate) count: usize,
    /// Median, µs.
    pub(crate) p50: u32,
    /// 99th percentile, µs.
    pub(crate) p99: u32,
    /// 99.9th percentile, µs.
    pub(crate) p999: u32,
    /// Largest, µs.
    pub(crate) max: u32,
}

/// Sorts `samples` and summarises them.
#[must_use]
pub(crate) fn summarize(samples: &mut [u32]) -> Summary {
    samples.sort_unstable();
    let at = |q: usize| -> u32 {
        if samples.is_empty() {
            return 0;
        }
        // Nearest-rank percentile with q in per-mille.
        let n = samples.len();
        let rank = (n.saturating_mul(q)).div_ceil(1000).clamp(1, n);
        samples.get(rank - 1).copied().unwrap_or(0)
    };
    Summary {
        count: samples.len(),
        p50: at(500),
        p99: at(990),
        p999: at(999),
        max: samples.last().copied().unwrap_or(0),
    }
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "n={} p50={}us p99={}us p99.9={}us max={}us",
            self.count, self.p50, self.p99, self.p999, self.max
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        let mut v: Vec<u32> = (1..=1000).rev().collect();
        let s = summarize(&mut v);
        assert_eq!((s.p50, s.p99, s.p999, s.max), (500, 990, 999, 1000));
        assert_eq!(summarize(&mut []).p99, 0);
    }
}
