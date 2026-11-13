//! Per-core metrics (master prompt §4: "metrics use per-core counters that are summed only when
//! scraped").
//!
//! A [`ShardedCounter`], [`ShardedGauge`] or [`ShardedHistogram`] keeps one value per core, each on its own cache line,
//! so cores counting the same event never contend for a line; a scrape sums them. A thread says
//! which shard it writes with [`set_core_shard`] (the thread-per-core runtime's workers do this at
//! start); any other thread writes the last shard.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use prometheus_client::encoding::{EncodeMetric, MetricEncoder, NoLabelSet};
use prometheus_client::metrics::{MetricType, TypedMetric};

/// Cores beyond this share the last shard (still correct, only not contention-free).
const MAX_SHARDS: usize = 256;

thread_local! {
    static SHARD: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Makes the calling thread write shard `core` of every sharded metric (call once per worker
/// thread, with its core index).
pub fn set_core_shard(core: usize) {
    SHARD.with(|s| s.set(core));
}

fn shard(len: usize) -> usize {
    let s = SHARD.with(std::cell::Cell::get);
    // Unassigned threads (main, blocking pool) and overflow use the last shard.
    s.min(len.saturating_sub(1))
}

/// Shards for this process: one per CPU it may run on, plus one for other threads.
fn shard_count() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    cpus.saturating_add(1).min(MAX_SHARDS)
}

/// One value on its own cache line pair (128 bytes: adjacent-line prefetch pulls lines in pairs
/// on current x86).
#[derive(Debug, Default)]
#[repr(align(128))]
struct Padded<T>(T);

/// A counter with one shard per core.
#[derive(Debug, Clone)]
pub struct ShardedCounter {
    shards: Arc<[Padded<AtomicU64>]>,
}

impl Default for ShardedCounter {
    fn default() -> Self {
        Self {
            shards: (0..shard_count())
                .map(|_| Padded(AtomicU64::new(0)))
                .collect(),
        }
    }
}

impl ShardedCounter {
    /// Adds one on this thread's shard.
    pub fn inc(&self) {
        self.inc_by(1);
    }

    /// Adds `v` on this thread's shard.
    pub fn inc_by(&self, v: u64) {
        if let Some(s) = self.shards.get(shard(self.shards.len())) {
            s.0.fetch_add(v, Ordering::Relaxed);
        }
    }

    /// The total over all shards.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.0.load(Ordering::Relaxed))
            .fold(0, u64::wrapping_add)
    }
}

impl TypedMetric for ShardedCounter {
    const TYPE: MetricType = MetricType::Counter;
}

impl EncodeMetric for ShardedCounter {
    fn encode(&self, mut encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        encoder.encode_counter::<NoLabelSet, _, u64>(&self.get(), None)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }
}

/// A gauge with one shard per core: each core adds and subtracts on its own shard (a value may
/// be raised on one core and lowered on another; the sum is still right).
#[derive(Debug, Clone)]
pub struct ShardedGauge {
    shards: Arc<[Padded<AtomicI64>]>,
}

impl Default for ShardedGauge {
    fn default() -> Self {
        Self {
            shards: (0..shard_count())
                .map(|_| Padded(AtomicI64::new(0)))
                .collect(),
        }
    }
}

impl ShardedGauge {
    /// Adds one on this thread's shard.
    pub fn inc(&self) {
        if let Some(s) = self.shards.get(shard(self.shards.len())) {
            s.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Subtracts one on this thread's shard.
    pub fn dec(&self) {
        if let Some(s) = self.shards.get(shard(self.shards.len())) {
            s.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// The total over all shards.
    #[must_use]
    pub fn get(&self) -> i64 {
        self.shards
            .iter()
            .map(|s| s.0.load(Ordering::Relaxed))
            .fold(0, i64::wrapping_add)
    }
}

impl TypedMetric for ShardedGauge {
    const TYPE: MetricType = MetricType::Gauge;
}

impl EncodeMetric for ShardedGauge {
    fn encode(&self, mut encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        encoder.encode_gauge(&self.get())
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }
}

/// Bucket upper bounds of [`ShardedHistogram`], in seconds: latencies from 50 µs to 1 s, dense
/// around the 2 ms target (master prompt §8).
pub const LATENCY_BUCKETS: [f64; 14] = [
    0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.002, 0.003, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
    1.0,
];
const BUCKETS: usize = LATENCY_BUCKETS.len() + 1;
/// The bucket bounds in nanoseconds, for the hot path (no float maths per observation).
const BOUNDS_NS: [u64; 14] = [
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_000_000,
    3_000_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    1_000_000_000,
];

/// One core's counts: per bucket (the last is +Inf), then the total in nanoseconds.
#[derive(Debug, Default)]
#[repr(align(128))]
struct HistShard {
    buckets: [AtomicU64; BUCKETS],
    sum_ns: AtomicU64,
}

/// A latency histogram with one shard per core (fixed [`LATENCY_BUCKETS`]): recording is a
/// bucket search over 14 bounds and two relaxed atomic adds on this core's own lines, no lock and
/// no allocation; a scrape sums the shards.
#[derive(Debug, Clone)]
pub struct ShardedHistogram {
    shards: Arc<[HistShard]>,
}

impl Default for ShardedHistogram {
    fn default() -> Self {
        Self {
            shards: (0..shard_count()).map(|_| HistShard::default()).collect(),
        }
    }
}

impl ShardedHistogram {
    /// Records one duration on this thread's shard.
    pub fn observe(&self, d: std::time::Duration) {
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        let i = BOUNDS_NS.partition_point(|&b| b < ns);
        if let Some(s) = self.shards.get(shard(self.shards.len())) {
            if let Some(b) = s.buckets.get(i) {
                b.fetch_add(1, Ordering::Relaxed);
            }
            s.sum_ns.fetch_add(ns, Ordering::Relaxed);
        }
    }

    /// Per-bucket counts (not cumulative; the last is +Inf), the count and the sum in seconds.
    #[must_use]
    pub fn snapshot(&self) -> ([u64; BUCKETS], u64, f64) {
        let mut counts = [0u64; BUCKETS];
        let mut sum_ns = 0u64;
        for s in self.shards.iter() {
            for (c, b) in counts.iter_mut().zip(&s.buckets) {
                *c = c.wrapping_add(b.load(Ordering::Relaxed));
            }
            sum_ns = sum_ns.wrapping_add(s.sum_ns.load(Ordering::Relaxed));
        }
        let count = counts.iter().fold(0u64, |a, &c| a.wrapping_add(c));
        // Whole seconds and the rest, each exact in an f64.
        let secs = f64::from(u32::try_from(sum_ns / 1_000_000_000).unwrap_or(u32::MAX))
            + f64::from(u32::try_from(sum_ns % 1_000_000_000).unwrap_or(0)) / 1e9;
        (counts, count, secs)
    }
}

impl TypedMetric for ShardedHistogram {
    const TYPE: MetricType = MetricType::Histogram;
}

impl EncodeMetric for ShardedHistogram {
    fn encode(&self, mut encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        let (counts, count, sum) = self.snapshot();
        let mut buckets = [(0.0, 0u64); BUCKETS];
        for (i, (b, c)) in buckets.iter_mut().zip(counts).enumerate() {
            *b = (LATENCY_BUCKETS.get(i).copied().unwrap_or(f64::MAX), c);
        }
        encoder.encode_histogram::<NoLabelSet>(sum, count, &buckets, None)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_and_sums_across_shards() {
        let h = ShardedHistogram::default();
        let threads: Vec<_> = (0..3)
            .map(|i| {
                let h = h.clone();
                std::thread::spawn(move || {
                    set_core_shard(i);
                    h.observe(std::time::Duration::from_micros(40)); // <= 50 us
                    h.observe(std::time::Duration::from_micros(1500)); // <= 2 ms
                    h.observe(std::time::Duration::from_secs(3)); // +Inf
                })
            })
            .collect();
        for t in threads {
            assert!(t.join().is_ok());
        }
        // Exactly on a bound goes in that bucket (Prometheus `le`).
        h.observe(std::time::Duration::from_millis(1));
        let (counts, count, sum) = h.snapshot();
        assert_eq!(count, 10);
        assert_eq!(counts[0], 3);
        assert_eq!(counts[4], 1);
        assert_eq!(counts[5], 3);
        assert_eq!(counts[BUCKETS - 1], 3);
        assert!((sum - (3.0 * (0.000_04 + 0.0015 + 3.0) + 0.001)).abs() < 1e-9, "{sum}");
        let mut registry = prometheus_client::registry::Registry::default();
        registry.register("lat", "lat", h);
        let mut out = String::new();
        assert!(prometheus_client::encoding::text::encode(&mut out, &registry).is_ok());
        assert!(out.contains("lat_bucket{le=\"0.002\"} 7"), "{out}");
        assert!(out.contains("lat_count 10"), "{out}");
    }

    #[test]
    fn shards_sum_across_threads() {
        let c = ShardedCounter::default();
        let g = ShardedGauge::default();
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let (c, g) = (c.clone(), g.clone());
                std::thread::spawn(move || {
                    set_core_shard(i);
                    for _ in 0..1000 {
                        c.inc();
                        g.inc();
                    }
                })
            })
            .collect();
        for t in threads {
            assert!(t.join().is_ok());
        }
        // An unassigned thread lowers the gauge on the last shard: the sum is still right.
        for _ in 0..1500 {
            g.dec();
        }
        c.inc_by(5);
        assert_eq!(c.get(), 4005);
        assert_eq!(g.get(), 2500);
    }

    #[test]
    fn encodes_like_the_plain_metrics() {
        let mut registry = prometheus_client::registry::Registry::default();
        let c = ShardedCounter::default();
        c.inc_by(3);
        let g = ShardedGauge::default();
        g.inc();
        registry.register("x", "x", c);
        registry.register("y", "y", g);
        let mut out = String::new();
        assert!(prometheus_client::encoding::text::encode(&mut out, &registry).is_ok());
        assert!(out.contains("x_total 3"), "{out}");
        assert!(out.contains("y 1"), "{out}");
    }
}
