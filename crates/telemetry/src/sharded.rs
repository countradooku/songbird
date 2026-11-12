//! Per-core metrics (master prompt §4: "metrics use per-core counters that are summed only when
//! scraped").
//!
//! A [`ShardedCounter`] or [`ShardedGauge`] keeps one value per core, each on its own cache line,
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

#[cfg(test)]
mod tests {
    use super::*;

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
