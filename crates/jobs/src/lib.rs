//! Background jobs (D-0036): Valkey Streams on `valkey-jobs`, sealed, IDs only.
//!
//! - [`job`]: what a job says ([`Work`]) and how it is sealed before it reaches Valkey.
//! - [`queue`]: streams, consumer groups, retries with backoff, reclaiming stuck jobs, dead
//!   letters.
//! - [`Outbox`] and [`relay`]: jobs that must exist exactly when a database change commits
//!   (account deletion) are written to an outbox table in that change's transaction and moved to
//!   the queue by a relay.
//! - [`consume`]: the consumer loop every service runs.
#![forbid(unsafe_code)]

pub mod job;
pub mod queue;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub use job::{Job, JobError, ObjectKey, Work};
pub use queue::{Delivery, Outcome, Queue, QueueConfig, QueueError, QueueStats, Stream};
use songbird_types::JobId;
use tokio::sync::{Semaphore, watch};

/// Where outbox rows live (SurrealDB in `crates/accounts`).
pub trait Outbox: Send + Sync {
    /// Up to `limit` oldest jobs waiting in the outbox.
    fn take(&self, limit: usize) -> impl Future<Output = Result<Vec<Job>, String>> + Send;
    /// Deletes relayed jobs.
    fn remove(&self, ids: &[JobId]) -> impl Future<Output = Result<(), String>> + Send;
}

/// Moves outbox jobs to the queue until the outbox is empty or a step fails; returns how many
/// moved. A crash between adding and removing repeats jobs; handlers are idempotent.
///
/// # Errors
/// The outbox or the queue failed (the rest waits for the next round).
pub async fn relay<O: Outbox>(outbox: &O, queue: &Queue) -> Result<usize, String> {
    let mut moved = 0;
    loop {
        let jobs = outbox.take(256).await?;
        if jobs.is_empty() {
            return Ok(moved);
        }
        queue.enqueue(&jobs).await.map_err(|e| e.to_string())?;
        let ids: Vec<JobId> = jobs.iter().map(|j| j.id).collect();
        outbox.remove(&ids).await?;
        moved += jobs.len();
    }
}

/// Consumer loop settings.
#[derive(Debug, Clone, Copy)]
pub struct ConsumeConfig {
    /// Jobs read per round.
    pub batch: usize,
    /// Jobs handled at once.
    pub concurrency: usize,
    /// How often due retries are promoted and stuck jobs reclaimed.
    pub housekeeping: Duration,
    /// Pause after a queue error.
    pub error_pause: Duration,
}

impl Default for ConsumeConfig {
    fn default() -> Self {
        Self {
            batch: 64,
            concurrency: 64,
            housekeeping: Duration::from_secs(1),
            error_pause: Duration::from_millis(500),
        }
    }
}

/// Runs `handler` on every job of `stream` until `stop` turns true; finishes the jobs in hand
/// before returning. Handlers must be idempotent: a job can run more than once (reclaimed after
/// a crash, repeated by an outbox relay).
pub async fn consume<H, F>(
    queue: Arc<Queue>,
    stream: Stream,
    cfg: ConsumeConfig,
    handler: H,
    mut stop: watch::Receiver<bool>,
) where
    H: Fn(Job) -> F + Send + Sync + 'static,
    F: Future<Output = Outcome> + Send + 'static,
{
    let handler = Arc::new(handler);
    let permits = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut next_housekeeping = tokio::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    while !*stop.borrow() {
        while tasks.try_join_next().is_some() {}
        let mut batch = Vec::new();
        if tokio::time::Instant::now() >= next_housekeeping {
            next_housekeeping = tokio::time::Instant::now() + cfg.housekeeping;
            if let Err(e) = queue.promote(stream).await {
                tracing::warn!(stream = stream.name(), error = %e, "promoting retries failed");
            }
            match queue.reclaim(stream, cfg.batch).await {
                Ok(d) => batch.extend(d),
                Err(e) => tracing::warn!(stream = stream.name(), error = %e, "reclaim failed"),
            }
        }
        let read = tokio::select! {
            r = queue.read(stream, cfg.batch) => r,
            _ = stop.changed() => break,
        };
        match read {
            Ok(d) => batch.extend(d),
            Err(e) => {
                tracing::warn!(stream = stream.name(), error = %e, "reading jobs failed");
                tokio::select! {
                    () = tokio::time::sleep(cfg.error_pause) => {}
                    _ = stop.changed() => break,
                }
            }
        }
        for d in batch {
            let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                break;
            };
            let (queue, handler) = (Arc::clone(&queue), Arc::clone(&handler));
            tasks.spawn(async move {
                let outcome = handler(d.job.clone()).await;
                if let Err(e) = queue.finish(&d, outcome).await {
                    // Stays pending: reclaimed after the visibility timeout.
                    tracing::warn!(stream = d.stream.name(), error = %e, "finishing a job failed");
                }
                drop(permit);
            });
        }
    }
    while tasks.join_next().await.is_some() {}
}
