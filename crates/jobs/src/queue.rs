//! The queue: Valkey Streams with one consumer group per stream (D-0036).
//!
//! - **Enqueue**: `XADD <stream> * s <sealed>`, many jobs in one pipeline.
//! - **Consume**: `XREADGROUP` on a connection of its own (blocking reads must not hold up
//!   acknowledgements), a short `BLOCK` under the client's response timeout.
//! - **Done**: `XACK` and `XDEL` together, so a finished job leaves memory and the next AOF
//!   rewrite.
//! - **Failed**: the job goes to a sorted set with its due time (exponential backoff, full
//!   jitter), atomically with its `XACK`/`XDEL` (Lua); [`Queue::promote`] moves due jobs back.
//!   Due times come from Valkey's clock (`TIME`), so no node clock matters.
//! - **Stuck** (a consumer died holding it): [`Queue::reclaim`] lists entries idle longer than
//!   the visibility timeout with `XPENDING … IDLE`, which also returns how often each was
//!   delivered, and claims them with `XCLAIM`; one delivered too often (it kills its consumer)
//!   is dead-lettered instead.
//! - **Dead letters**: a capped stream, sealed like everything else, counted for alerting.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use redis::Value;
use songbird_valkey::ValkeyConn;

use crate::job::{Job, Sealer};

/// The job streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stream {
    /// Message wake-ups (consumed by `push`).
    Push,
    /// Call rings (consumed by `push` on a consumer of its own, D-0095).
    Ring,
    /// Attachment and expiry cleanup (consumed by `worker`).
    Cleanup,
    /// Account deletion (consumed by `worker`).
    Deletion,
}

impl Stream {
    /// Every stream.
    pub const ALL: [Self; 4] = [Self::Push, Self::Ring, Self::Cleanup, Self::Deletion];

    /// The Valkey key of the stream.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Push => "j:push",
            Self::Ring => "j:ring",
            Self::Cleanup => "j:cleanup",
            Self::Deletion => "j:deletion",
        }
    }

    /// The stream's place in [`Stream::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Push => 0,
            Self::Ring => 1,
            Self::Cleanup => 2,
            Self::Deletion => 3,
        }
    }

    /// The Valkey key of the stream's delayed (retry) set.
    #[must_use]
    pub const fn delayed_key(self) -> &'static str {
        match self {
            Self::Push => "j:push:later",
            Self::Ring => "j:ring:later",
            Self::Cleanup => "j:cleanup:later",
            Self::Deletion => "j:deletion:later",
        }
    }

    /// Short name, used in the dead-letter stream and in metric labels.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Ring => "ring",
            Self::Cleanup => "cleanup",
            Self::Deletion => "deletion",
        }
    }
}

/// Jobs dead-lettered, process-wide (every stream): aggregates only, no labels (invariant 6).
static DEAD_LETTERED: AtomicU64 = AtomicU64::new(0);
/// Jobs sent back for a retry, process-wide.
static RETRIED: AtomicU64 = AtomicU64::new(0);

/// A process-wide counter a service exports: (name, help, its value at scrape).
pub type CounterSpec = (&'static str, &'static str, fn() -> u64);

/// The job queue's counters for a consuming service to export (`songbird_jobs_*`; alert rules in
/// `deploy/monitoring/rules/songbird.yml`, runbook "Dead letters", D-0097).
pub const METRICS: [CounterSpec; 2] = [
    (
        "jobs_dead_lettered",
        "Jobs moved to the dead-letter stream (any stream)",
        || DEAD_LETTERED.load(Ordering::Relaxed),
    ),
    (
        "jobs_retried",
        "Jobs sent back for a retry after a transient failure",
        || RETRIED.load(Ordering::Relaxed),
    ),
];

/// Key of the dead-letter stream.
pub const DEAD_KEY: &str = "j:dead";
/// Name of every stream's consumer group.
pub const GROUP: &str = "songbird";

/// Queue settings.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// This consumer's name in the groups (unique per process, e.g. `push-<random>`).
    pub consumer: String,
    /// Attempts before a failing job is dead-lettered.
    pub max_attempts: u16,
    /// First retry delay; doubles per attempt (full jitter).
    pub backoff_base: Duration,
    /// Longest retry delay.
    pub backoff_max: Duration,
    /// A delivered job not acknowledged for this long is reclaimed.
    pub visibility: Duration,
    /// Deliveries (including reclaims) before a job is dead-lettered without running again.
    pub max_deliveries: u64,
    /// Dead letters kept (approximate cap).
    pub dead_cap: u64,
}

impl QueueConfig {
    /// Defaults with the given consumer name.
    #[must_use]
    pub fn new(consumer: String) -> Self {
        Self {
            consumer,
            max_attempts: 12,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(600),
            visibility: Duration::from_secs(60),
            max_deliveries: 5,
            dead_cap: 100_000,
        }
    }
}

/// Queue failures. They carry no job content.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// Valkey unreachable or refused.
    #[error("job queue unavailable: {0}")]
    Valkey(String),
    /// A reply this code does not understand.
    #[error("job queue protocol: {0}")]
    Protocol(&'static str),
    /// Sealing failed.
    #[error("job sealing failed")]
    Seal,
}

impl From<redis::RedisError> for QueueError {
    fn from(e: redis::RedisError) -> Self {
        // The kind only: messages may quote arguments.
        Self::Valkey(format!("{:?}", e.kind()))
    }
}

/// Counters, read by the services' metrics.
#[derive(Debug, Default)]
pub struct QueueStats {
    /// Jobs added.
    pub enqueued: AtomicU64,
    /// Jobs handed to a handler.
    pub delivered: AtomicU64,
    /// Jobs finished.
    pub done: AtomicU64,
    /// Jobs scheduled for another attempt.
    pub retried: AtomicU64,
    /// Jobs moved to the dead-letter stream (alert on this).
    pub dead: AtomicU64,
    /// Stuck jobs reclaimed from a consumer that did not finish them.
    pub reclaimed: AtomicU64,
    /// Entries that did not open (wrong key, tampering): dead-lettered as they are.
    pub unopenable: AtomicU64,
}

/// A job handed to a consumer.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// The stream it came from.
    pub stream: Stream,
    /// The stream entry ID (for acknowledging).
    pub entry: String,
    /// The job.
    pub job: Job,
}

/// What a handler decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Done: acknowledge and delete.
    Done,
    /// Try again later (backoff), or after the given delay.
    Retry(Option<Duration>),
    /// Will never succeed: dead-letter now.
    Dead,
}

/// Atomically: schedule the job, acknowledge and delete its entry. Due time from Valkey's clock.
/// KEYS: stream, delayed. ARGV: group, entry, delay ms, sealed.
const RETRY_LUA: &str = r"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZADD', KEYS[2], now + tonumber(ARGV[3]), ARGV[4])
redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
redis.call('XDEL', KEYS[1], ARGV[2])
return 1
";

/// Moves due jobs back to the stream. KEYS: stream, delayed. ARGV: limit.
const PROMOTE_LUA: &str = r"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local due = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now, 'LIMIT', 0, tonumber(ARGV[1]))
for _, m in ipairs(due) do
  redis.call('XADD', KEYS[1], '*', 's', m)
  redis.call('ZREM', KEYS[2], m)
end
return #due
";

/// Atomically: dead-letter an entry, acknowledge and delete it.
/// KEYS: stream, dead. ARGV: group, entry, stream name, sealed, cap.
const DEAD_LUA: &str = r"
redis.call('XADD', KEYS[2], 'MAXLEN', '~', tonumber(ARGV[5]), '*', 'q', ARGV[3], 's', ARGV[4])
redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
redis.call('XDEL', KEYS[1], ARGV[2])
return 1
";

/// A connection to the job queue.
pub struct Queue {
    /// Commands (enqueue, acknowledge, retry, reclaim).
    conn: ValkeyConn,
    /// Blocking reads only: one connection per stream, opened at its first read. Valkey runs a
    /// connection's commands in order, so one shared reader would make every consumer wait out
    /// the others' `BLOCK` on an empty stream (D-0096: it held `j:push` to ~850 jobs/s behind an
    /// idle `j:ring`, and the worker's cleanup behind its deletions).
    readers: [tokio::sync::OnceCell<ValkeyConn>; Stream::ALL.len()],
    client: redis::Client,
    sealer: Sealer,
    cfg: QueueConfig,
    stats: Arc<QueueStats>,
}

impl std::fmt::Debug for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue").finish_non_exhaustive()
    }
}

/// How long one `XREADGROUP` blocks (under redis-rs's 500 ms response timeout).
const READ_BLOCK_MS: u64 = 250;

fn text(v: &Value) -> Option<String> {
    match v {
        Value::BulkString(b) => String::from_utf8(b.clone()).ok(),
        Value::SimpleString(s) => Some(s.clone()),
        _ => None,
    }
}

fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        other => text(other).and_then(|s| s.parse().ok()),
    }
}

/// `[id, [field, value, …]]` entries, as `XREADGROUP`, `XCLAIM` and `XRANGE` return them;
/// yields (entry id, sealed bytes) for entries with an `s` field.
fn entries(v: &Value) -> Vec<(String, Option<Vec<u8>>)> {
    let Value::Array(items) = v else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Array(pair) = item else { continue };
        let (Some(id), fields) = (pair.first().and_then(text), pair.get(1)) else {
            continue;
        };
        let mut sealed = None;
        match fields {
            Some(Value::Array(kv)) => {
                for c in kv.chunks(2) {
                    if let [Value::BulkString(k), Value::BulkString(val)] = c
                        && k.as_slice() == b"s"
                    {
                        sealed = Some(val.clone());
                    }
                }
            }
            Some(Value::Map(kv)) => {
                for (k, val) in kv {
                    if let (Value::BulkString(k), Value::BulkString(val)) = (k, val)
                        && k.as_slice() == b"s"
                    {
                        sealed = Some(val.clone());
                    }
                }
            }
            // A deleted entry still pending shows as nil fields.
            _ => {}
        }
        out.push((id, sealed));
    }
    out
}

/// Full-jitter exponential backoff (AWS architecture blog): uniform in `[0, min(max, base·2ⁿ)]`.
#[must_use]
pub fn backoff(base: Duration, max: Duration, attempt: u16) -> Duration {
    let cap = base
        .checked_mul(1u32 << u32::from(attempt.min(20)))
        .unwrap_or(max)
        .min(max);
    let mut r = [0u8; 8];
    let _ = aws_lc_rs::rand::fill(&mut r);
    let cap_ms = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX).max(1);
    Duration::from_millis(u64::from_be_bytes(r) % cap_ms)
}

impl Queue {
    /// Connects (two connections: commands and blocking reads).
    ///
    /// # Errors
    /// [`QueueError`]: Valkey unreachable, or key derivation failed.
    pub async fn connect(
        client: redis::Client,
        secret: &[u8; 32],
        cfg: QueueConfig,
    ) -> Result<Self, QueueError> {
        let conn = ValkeyConn::connect(client.clone()).await?;
        Ok(Self {
            conn,
            readers: Default::default(),
            client,
            sealer: Sealer::new(secret).map_err(|_| QueueError::Seal)?,
            cfg,
            stats: Arc::new(QueueStats::default()),
        })
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> Arc<QueueStats> {
        Arc::clone(&self.stats)
    }

    /// Creates the consumer group of each stream (and the stream) if missing.
    ///
    /// # Errors
    /// [`QueueError`].
    pub async fn ensure_groups(&self, streams: &[Stream]) -> Result<(), QueueError> {
        for s in streams {
            let r: redis::RedisResult<Value> = self
                .conn
                .query(
                    redis::cmd("XGROUP")
                        .arg("CREATE")
                        .arg(s.key())
                        .arg(GROUP)
                        .arg("0")
                        .arg("MKSTREAM"),
                )
                .await;
            match r {
                Ok(_) => {}
                Err(e) if e.code() == Some("BUSYGROUP") => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Adds jobs, each to its work's stream, in one round trip.
    ///
    /// # Errors
    /// [`QueueError`]; on error some jobs may have been added.
    pub async fn enqueue(&self, jobs: &[Job]) -> Result<(), QueueError> {
        if jobs.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        for j in jobs {
            let stream = j.work.stream();
            let sealed = self
                .sealer
                .seal(stream.key(), j)
                .map_err(|_| QueueError::Seal)?;
            pipe.cmd("XADD")
                .arg(stream.key())
                .arg("*")
                .arg("s")
                .arg(sealed)
                .ignore();
        }
        self.conn.query_pipe::<()>(&pipe).await?;
        self.stats
            .enqueued
            .fetch_add(u64::try_from(jobs.len()).unwrap_or(0), Ordering::Relaxed);
        Ok(())
    }

    /// Up to `count` new jobs from `stream`, waiting briefly when there are none.
    ///
    /// # Errors
    /// [`QueueError`].
    pub async fn read(&self, stream: Stream, count: usize) -> Result<Vec<Delivery>, QueueError> {
        let reader = self
            .readers
            .get(stream.index())
            .ok_or(QueueError::Protocol("stream index"))?
            .get_or_try_init(|| ValkeyConn::connect(self.client.clone()))
            .await?;
        let v: Value = reader
            .query(
                redis::cmd("XREADGROUP")
                    .arg("GROUP")
                    .arg(GROUP)
                    .arg(&self.cfg.consumer)
                    .arg("COUNT")
                    .arg(count.max(1))
                    .arg("BLOCK")
                    .arg(READ_BLOCK_MS)
                    .arg("STREAMS")
                    .arg(stream.key())
                    .arg(">"),
            )
            .await?;
        let list = match &v {
            Value::Nil => return Ok(Vec::new()),
            // RESP2: [[stream, entries]].
            Value::Array(streams) => streams
                .first()
                .and_then(|s| match s {
                    Value::Array(p) => p.get(1).cloned(),
                    _ => None,
                })
                .unwrap_or(Value::Nil),
            // RESP3: {stream: entries}.
            Value::Map(m) => m.first().map_or(Value::Nil, |(_, e)| e.clone()),
            _ => return Err(QueueError::Protocol("XREADGROUP reply")),
        };
        self.open_entries(stream, &list).await
    }

    /// Opens entries; entries that do not open are dead-lettered as they are.
    async fn open_entries(
        &self,
        stream: Stream,
        list: &Value,
    ) -> Result<Vec<Delivery>, QueueError> {
        let mut out = Vec::new();
        for (entry, sealed) in entries(list) {
            let job = sealed
                .as_deref()
                .and_then(|s| self.sealer.open(stream.key(), s).ok());
            if let Some(job) = job {
                out.push(Delivery { stream, entry, job });
            } else {
                self.stats.unopenable.fetch_add(1, Ordering::Relaxed);
                self.dead_raw(stream, &entry, sealed.as_deref().unwrap_or_default())
                    .await?;
            }
        }
        self.stats
            .delivered
            .fetch_add(u64::try_from(out.len()).unwrap_or(0), Ordering::Relaxed);
        Ok(out)
    }

    /// Records a handler's outcome.
    ///
    /// # Errors
    /// [`QueueError`]; the job stays pending and is reclaimed later.
    pub async fn finish(&self, d: &Delivery, outcome: Outcome) -> Result<(), QueueError> {
        match outcome {
            Outcome::Done => {
                let mut pipe = redis::pipe();
                pipe.cmd("XACK")
                    .arg(d.stream.key())
                    .arg(GROUP)
                    .arg(&d.entry)
                    .ignore()
                    .cmd("XDEL")
                    .arg(d.stream.key())
                    .arg(&d.entry)
                    .ignore();
                self.conn.query_pipe::<()>(&pipe).await?;
                self.stats.done.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Outcome::Retry(after) => {
                let next = Job {
                    attempt: d.job.attempt.saturating_add(1),
                    ..d.job.clone()
                };
                if next.attempt >= self.cfg.max_attempts {
                    return self.dead(d).await;
                }
                let delay = after.unwrap_or_else(|| {
                    backoff(self.cfg.backoff_base, self.cfg.backoff_max, d.job.attempt)
                });
                let sealed = self
                    .sealer
                    .seal(d.stream.key(), &next)
                    .map_err(|_| QueueError::Seal)?;
                self.conn
                    .query::<i64>(
                        redis::cmd("EVAL")
                            .arg(RETRY_LUA)
                            .arg(2)
                            .arg(d.stream.key())
                            .arg(d.stream.delayed_key())
                            .arg(GROUP)
                            .arg(&d.entry)
                            .arg(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX))
                            .arg(sealed),
                    )
                    .await?;
                self.stats.retried.fetch_add(1, Ordering::Relaxed);
                RETRIED.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Outcome::Dead => self.dead(d).await,
        }
    }

    async fn dead(&self, d: &Delivery) -> Result<(), QueueError> {
        // Dead letters stay sealed, bound to their original stream.
        let sealed = self
            .sealer
            .seal(d.stream.key(), &d.job)
            .map_err(|_| QueueError::Seal)?;
        self.dead_raw(d.stream, &d.entry, &sealed).await?;
        tracing::warn!(stream = d.stream.name(), "job dead-lettered");
        Ok(())
    }

    async fn dead_raw(&self, stream: Stream, entry: &str, sealed: &[u8]) -> Result<(), QueueError> {
        self.conn
            .query::<i64>(
                redis::cmd("EVAL")
                    .arg(DEAD_LUA)
                    .arg(2)
                    .arg(stream.key())
                    .arg(DEAD_KEY)
                    .arg(GROUP)
                    .arg(entry)
                    .arg(stream.name())
                    .arg(sealed)
                    .arg(self.cfg.dead_cap),
            )
            .await?;
        self.stats.dead.fetch_add(1, Ordering::Relaxed);
        DEAD_LETTERED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Moves due retries back onto `stream`; returns how many.
    ///
    /// # Errors
    /// [`QueueError`].
    pub async fn promote(&self, stream: Stream) -> Result<u64, QueueError> {
        let n: i64 = self
            .conn
            .query(
                redis::cmd("EVAL")
                    .arg(PROMOTE_LUA)
                    .arg(2)
                    .arg(stream.key())
                    .arg(stream.delayed_key())
                    .arg(1000),
            )
            .await?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Claims jobs another consumer took and did not finish within the visibility timeout;
    /// dead-letters those delivered too often.
    ///
    /// # Errors
    /// [`QueueError`].
    pub async fn reclaim(&self, stream: Stream, count: usize) -> Result<Vec<Delivery>, QueueError> {
        let idle = u64::try_from(self.cfg.visibility.as_millis()).unwrap_or(u64::MAX);
        let pending: Value = self
            .conn
            .query(
                redis::cmd("XPENDING")
                    .arg(stream.key())
                    .arg(GROUP)
                    .arg("IDLE")
                    .arg(idle)
                    .arg("-")
                    .arg("+")
                    .arg(count.max(1)),
            )
            .await?;
        let Value::Array(rows) = pending else {
            return Ok(Vec::new());
        };
        let mut claim = Vec::new();
        let mut kill = Vec::new();
        for row in &rows {
            let Value::Array(f) = row else { continue };
            let (Some(id), Some(times)) = (f.first().and_then(text), f.get(3).and_then(int)) else {
                continue;
            };
            if u64::try_from(times).unwrap_or(0) >= self.cfg.max_deliveries {
                kill.push(id);
            } else {
                claim.push(id);
            }
        }
        for id in kill {
            // Dead-letter what the entry holds (it may already be gone).
            let v: Value = self
                .conn
                .query(redis::cmd("XRANGE").arg(stream.key()).arg(&id).arg(&id))
                .await?;
            let sealed = entries(&v)
                .into_iter()
                .next()
                .and_then(|(_, s)| s)
                .unwrap_or_default();
            self.dead_raw(stream, &id, &sealed).await?;
            tracing::warn!(
                stream = stream.name(),
                "job delivered too often, dead-lettered"
            );
        }
        if claim.is_empty() {
            return Ok(Vec::new());
        }
        let mut cmd = redis::cmd("XCLAIM");
        cmd.arg(stream.key())
            .arg(GROUP)
            .arg(&self.cfg.consumer)
            .arg(idle);
        for id in &claim {
            cmd.arg(id);
        }
        let v: Value = self.conn.query(&cmd).await?;
        let out = self.open_entries(stream, &v).await?;
        self.stats
            .reclaimed
            .fetch_add(u64::try_from(out.len()).unwrap_or(0), Ordering::Relaxed);
        Ok(out)
    }

    /// Jobs waiting in `stream` (new, pending and delayed), for metrics and tests.
    ///
    /// # Errors
    /// [`QueueError`].
    pub async fn depth(&self, stream: Stream) -> Result<u64, QueueError> {
        let mut pipe = redis::pipe();
        pipe.cmd("XLEN")
            .arg(stream.key())
            .cmd("ZCARD")
            .arg(stream.delayed_key());
        let (a, b): (u64, u64) = self.conn.query_pipe(&pipe).await?;
        Ok(a + b)
    }

    /// Dead letters kept.
    ///
    /// # Errors
    /// [`QueueError`].
    pub async fn dead_letters(&self) -> Result<u64, QueueError> {
        Ok(self.conn.query(redis::cmd("XLEN").arg(DEAD_KEY)).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_indexes_match_all() {
        for (i, s) in Stream::ALL.iter().enumerate() {
            assert_eq!(s.index(), i);
        }
    }

    #[test]
    fn backoff_stays_under_its_cap() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(5);
        for attempt in 0..40 {
            let cap = base
                .checked_mul(1u32 << u32::from(attempt.min(20)))
                .unwrap_or(max)
                .min(max);
            for _ in 0..50 {
                assert!(backoff(base, max, attempt) < cap.max(Duration::from_millis(1)));
            }
        }
    }

    #[test]
    fn entries_parse_resp2_and_skip_garbage() {
        let v = Value::Array(vec![
            Value::Array(vec![
                Value::BulkString(b"1-0".to_vec()),
                Value::Array(vec![
                    Value::BulkString(b"s".to_vec()),
                    Value::BulkString(vec![1, 2, 3]),
                ]),
            ]),
            Value::Array(vec![Value::BulkString(b"2-0".to_vec()), Value::Nil]),
            Value::Int(4),
        ]);
        let e = entries(&v);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0], ("1-0".to_owned(), Some(vec![1, 2, 3])));
        assert_eq!(e[1], ("2-0".to_owned(), None));
    }
}
