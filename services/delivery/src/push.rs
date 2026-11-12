//! Push jobs for offline devices (D-0036).
//!
//! When a stored envelope's device has no session anywhere, the session calls
//! [`Pusher::offline`], which never blocks and never touches Valkey: it puts the device in a
//! bounded channel. One task per process debounces (at most one job per device per window: a
//! burst of messages is one wake-up) and adds the jobs to the queue in pipelined batches. If the
//! buffer is full or the queue is unreachable the wake-up is dropped and counted: the message is
//! safe in the mailbox and the device fetches it at its next connection (runbook "Push jobs
//! dropped").

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use songbird_jobs::{Job, Queue, Work};
use songbird_types::DeviceId;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::DeliveryMetrics;

/// Wake-ups waiting for the batching task.
const BUFFER: usize = 65_536;
/// Most jobs per pipelined batch.
const BATCH: usize = 512;
/// Debounce entries are pruned when the map grows past this.
const PRUNE_ABOVE: usize = 100_000;

/// The sessions' handle. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Pusher {
    tx: Option<mpsc::Sender<DeviceId>>,
    metrics: DeliveryMetrics,
}

impl Pusher {
    /// No push jobs (tests, development without a job queue).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            tx: None,
            metrics: DeliveryMetrics::default(),
        }
    }

    /// A pusher feeding a task started with [`run`].
    #[must_use]
    pub fn new(metrics: DeliveryMetrics) -> (Self, mpsc::Receiver<DeviceId>) {
        let (tx, rx) = mpsc::channel(BUFFER);
        (
            Self {
                tx: Some(tx),
                metrics,
            },
            rx,
        )
    }

    /// A stored envelope's device is offline. Never blocks.
    pub fn offline(&self, device: DeviceId) {
        if let Some(tx) = &self.tx
            && tx.try_send(device).is_err()
        {
            self.metrics.push_dropped.inc();
        }
    }
}

/// Debounces and batches wake-ups into the job queue until `stop`.
pub async fn run(
    queue: Arc<Queue>,
    mut rx: mpsc::Receiver<DeviceId>,
    debounce: Duration,
    metrics: DeliveryMetrics,
    mut stop: watch::Receiver<bool>,
) {
    // Randomly seeded SipHash: keys are device IDs, which clients choose to target.
    let mut last: HashMap<DeviceId, Instant> = HashMap::new();
    let mut batch: Vec<Job> = Vec::with_capacity(BATCH);
    loop {
        let first = tokio::select! {
            d = rx.recv() => d,
            _ = stop.changed() => None,
        };
        let Some(first) = first else { return };
        let now = Instant::now();
        let mut take = |d: DeviceId, batch: &mut Vec<Job>| {
            if last
                .get(&d)
                .is_some_and(|t| now.saturating_duration_since(*t) < debounce)
            {
                return;
            }
            last.insert(d, now);
            if let Ok(job) = Job::new(Work::Push {
                device: d,
                call: false,
            }) {
                batch.push(job);
            }
        };
        take(first, &mut batch);
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(d) => take(d, &mut batch),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            let n = u64::try_from(batch.len()).unwrap_or(u64::MAX);
            match queue.enqueue(&batch).await {
                Ok(()) => metrics.push_jobs.inc_by(n),
                Err(e) => {
                    metrics.push_dropped.inc_by(n);
                    tracing::warn!(error = %e, "push jobs dropped: job queue unavailable");
                    // Let these devices be tried again on their next message.
                    for j in &batch {
                        if let Work::Push { device, .. } = &j.work {
                            last.remove(device);
                        }
                    }
                }
            }
            batch.clear();
        }
        if last.len() > PRUNE_ABOVE {
            last.retain(|_, t| now.saturating_duration_since(*t) < debounce);
        }
    }
}
