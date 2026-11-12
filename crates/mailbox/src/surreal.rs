//! The SurrealDB mailbox (milestone 2): the durable truth for undelivered envelopes.
//!
//! **Schema** (`SCHEMA`, applied idempotently at connect):
//! - `mailbox:[device, seq]`: one entry per stored envelope, either `env` (per-device ciphertext)
//!   or `body` (a link to a shared body), plus `at`. Keyed by `(device, seq)` so `fetch_after` is
//!   one range scan and `ack_up_to` one range delete.
//! - `seqctr:[device]`: `last`, the last `seq` allocated (never decreases). Written only by stores.
//! - `ackctr:[device]`: `n`, the highest `seq` acknowledged. Written only by ACK batches, so ACKs
//!   and stores never write the same record (no optimistic-transaction conflicts between them).
//! - `body:[id]`: a shared group/channel ciphertext with `refs`, the entries still pointing at it.
//! - `idem:[hmac]`: idempotency record, `stored = [[device, seq], …]` (D-0024).
//! - `mls_group:[group]`: current MLS epoch.
//! - `meta:store`: the store generation.
//!
//! **One writer per process** owns every write: group-commit batches and ACK deletes, so the two
//! never conflict with each other (D-0027).
//!
//! **Group commit** (master prompt §4): the writer collects sends for up to `max_wait` or
//! `max_batch` sends and writes them in one transaction, then answers every waiting sender.
//! SurrealDB 4 syncs every commit (`surrealkv://…?sync=every`), so an answer means durable
//! (invariant 1). `SurrealQL` costs 0.1–1.5 ms *per statement* in 4.0.1 (measured), so a batch is a
//! fixed handful of bulk statements, never a statement or closure per send: the writer caches
//! each device's last `seq`, computes every row and record ID itself, and the counter update
//! only applies where the stored counter still equals the cached one (compare-and-set). Another writer (a
//! second node, milestone 4) makes the guard fail; the writer reloads and retries, so a `seq` is
//! never reused or skipped. One bad send never fails its batch: a reused idempotency key or a
//! stale MLS epoch aborts the transaction, the offending sends are answered, the rest retried.
//!
//! **ACK deletes** are merged per device and written every `ack_interval` in one transaction:
//! a bulk `DELETE` of the explicit entry IDs acknowledged since the last flush, the shared-body
//! reference counts of the entries that went (bodies are deleted at zero), and the counters.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aws_lc_rs::hmac;
use bytes::Bytes;
use songbird_surreal::cbor::{TAG_RECORD_ID, Value};
use songbird_surreal::{Client, Config as RpcConfig, RpcError, StatementError};
use songbird_types::DeviceId;
use tokio::sync::{Mutex, mpsc, oneshot, watch};

use crate::{
    IDEMPOTENCY_RETENTION, Mailbox, MailboxError, Payload, StoreOutcome, StoreRequest, Stored,
    idempotency_tag,
};

/// Settings.
#[derive(Debug, Clone)]
pub struct SurrealConfig {
    /// Connection.
    pub rpc: RpcConfig,
    /// Most sends per group-commit transaction.
    pub max_batch: usize,
    /// Longest a send waits for others to share its transaction.
    pub max_wait: Duration,
    /// How often batched ACK deletes are written.
    pub ack_interval: Duration,
    /// Unacknowledged envelopes kept per device before sends to it are refused (retryable).
    pub max_per_device: u64,
    /// Keys idempotency records (from the secrets; the same on every node).
    pub idempotency_secret: [u8; 32],
}

/// Counters for metrics and benchmarks.
#[derive(Debug, Default)]
pub struct SurrealStats {
    /// Group-commit transactions committed.
    pub commits: AtomicU64,
    /// Sends stored.
    pub sends: AtomicU64,
    /// Envelopes (mailbox entries) stored.
    pub entries: AtomicU64,
    /// Transactions retried (conflicts, partial failures).
    pub retries: AtomicU64,
    /// ACK-delete transactions committed.
    pub ack_commits: AtomicU64,
    /// Failed transactions after retries.
    pub failures: AtomicU64,
}

/// Idempotent schema.
const SCHEMA: &str = "
DEFINE TABLE IF NOT EXISTS mailbox SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS env ON mailbox TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS body ON mailbox TYPE option<record<body>>;
DEFINE FIELD IF NOT EXISTS at ON mailbox TYPE datetime;
DEFINE INDEX IF NOT EXISTS mailbox_at ON mailbox FIELDS at;
DEFINE TABLE IF NOT EXISTS body SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS env ON body TYPE bytes;
DEFINE FIELD IF NOT EXISTS refs ON body TYPE int;
DEFINE FIELD IF NOT EXISTS at ON body TYPE datetime;
DEFINE INDEX IF NOT EXISTS body_at ON body FIELDS at;
DEFINE TABLE IF NOT EXISTS seqctr SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS last ON seqctr TYPE int;
DEFINE FIELD IF NOT EXISTS prev ON seqctr TYPE option<int>;
DEFINE TABLE IF NOT EXISTS ackctr SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS n ON ackctr TYPE int;
DEFINE TABLE IF NOT EXISTS idem SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS stored ON idem TYPE option<array<array<any>>>;
DEFINE FIELD IF NOT EXISTS at ON idem TYPE datetime;
DEFINE INDEX IF NOT EXISTS idem_at ON idem FIELDS at;
DEFINE TABLE IF NOT EXISTS mls_group SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS epoch ON mls_group TYPE int;
DEFINE TABLE IF NOT EXISTS meta SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS generation ON meta TYPE int;
UPSERT meta:store SET generation = generation ?? 1 RETURN NONE;
";

/// Statement fragments of a store transaction (assembled per batch: only what is needed).
const S_BEGIN: &str = "BEGIN TRANSACTION;";
const S_IDEM: &str = "INSERT INTO idem $idems RETURN NONE;";
const S_MLS: &str = "IF ((SELECT VALUE epoch FROM ONLY mls_group:[$g]) ?? 0) != $e { THROW 'stale_epoch' }; UPSERT mls_group:[$g] SET epoch = $e + 1 RETURN NONE;";
const S_CTRS: &str =
    "INSERT INTO seqctr $ctrs ON DUPLICATE KEY UPDATE last = $input.last RETURN NONE;";
const S_BODIES: &str = "INSERT INTO body $bodies RETURN NONE;";
const S_ROWS: &str = "INSERT INTO mailbox $rows RETURN NONE;";
const S_COMMIT: &str = "COMMIT TRANSACTION;";

/// Loads counters for devices the writer has not seen.
const LOAD: &str =
    "SELECT meta::id(id)[0] AS d, last FROM $sids; SELECT meta::id(id)[0] AS d, n FROM $aids;";

/// Most entries deleted by explicit IDs per device and flush; beyond it a range delete is used.
const EXPLICIT_MAX: u64 = 4096;

const FETCH: &str = "SELECT meta::id(id)[1] AS seq, env, body.env AS benv FROM mailbox:[$d, $after]>..[$d, ..] LIMIT $n;";

/// Forgets deleted devices: their entries (shared bodies by reference count) and counters.
const FORGET: &str = "
BEGIN TRANSACTION;
FOR $d IN $ds {
  LET $gone = DELETE mailbox:[$d, 0]>..[$d, ..] RETURN BEFORE;
  FOR $b IN array::filter($gone.body, |$v| $v != NONE) {
    LET $r = UPDATE ONLY $b SET refs -= 1 RETURN VALUE refs;
    IF $r <= 0 { DELETE $b RETURN NONE };
  };
  DELETE seqctr:[$d] RETURN NONE;
  DELETE ackctr:[$d] RETURN NONE;
};
COMMIT TRANSACTION;
";

const EXPIRE: &str = "
BEGIN TRANSACTION;
LET $cut = time::now() - duration::from_secs($age);
LET $gone = DELETE mailbox WHERE at < $cut RETURN BEFORE;
FOR $b IN array::filter($gone.body, |$v| $v != NONE) {
  LET $r = UPDATE ONLY $b SET refs -= 1 RETURN VALUE refs;
  IF $r <= 0 { DELETE $b RETURN NONE };
};
DELETE body WHERE at < $cut RETURN NONE;
DELETE idem WHERE at < time::now() - duration::from_secs($idem_age) RETURN NONE;
RETURN array::len($gone);
COMMIT TRANSACTION;
";

/// Most attempts for one batch before its sends fail as unavailable.
const MAX_ATTEMPTS: u32 = 6;

fn bytes_value(b: &[u8]) -> Value {
    Value::Bytes(Bytes::copy_from_slice(b))
}

fn record(table: &str, key: Value) -> Value {
    record_key(table, vec![key])
}

/// A record ID with an array key, e.g. `mailbox:[device, seq]`.
fn record_key(table: &str, key: Vec<Value>) -> Value {
    Value::Tag(
        TAG_RECORD_ID,
        Box::new(Value::Array(vec![Value::from(table), Value::Array(key)])),
    )
}

/// A SurrealDB datetime (tag 12, `[seconds, nanoseconds]`) for now.
fn now_value() -> Value {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Value::Tag(
        songbird_surreal::cbor::TAG_DATETIME,
        Box::new(Value::Array(vec![
            int(d.as_secs()),
            Value::Int(i64::from(d.subsec_nanos())),
        ])),
    )
}

fn int(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

fn uint(v: &Value) -> Option<u64> {
    v.as_i64().and_then(|i| u64::try_from(i).ok())
}

/// Holds the current connection and reconnects on demand.
struct Conn {
    cfg: RpcConfig,
    current: watch::Sender<Option<Client>>,
    reconnect: Mutex<()>,
}

impl Conn {
    async fn get(&self) -> Result<Client, MailboxError> {
        if let Some(c) = self.current.borrow().as_ref()
            && !c.is_closed()
        {
            return Ok(c.clone());
        }
        // Reconnecting is rare and off the hot path: one task does it, others wait.
        let _g = self.reconnect.lock().await;
        if let Some(c) = self.current.borrow().as_ref()
            && !c.is_closed()
        {
            return Ok(c.clone());
        }
        let c = Client::connect(&self.cfg)
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        self.current.send_replace(Some(c.clone()));
        Ok(c)
    }

    async fn query(
        &self,
        sql: &str,
        vars: Vec<(String, Value)>,
    ) -> Result<Vec<Result<Value, StatementError>>, RpcError> {
        let c = self.get().await.map_err(|_| RpcError::Disconnected)?;
        c.query(sql, vars).await
    }
}

struct Job {
    req: StoreRequest,
    tag: Option<[u8; 32]>,
    reply: oneshot::Sender<Result<StoreOutcome, MailboxError>>,
}

/// A [`Mailbox`] on SurrealDB with group commit and batched ACK deletes.
pub struct SurrealMailbox {
    conn: Arc<Conn>,
    store_tx: mpsc::Sender<Job>,
    ack_tx: mpsc::Sender<(DeviceId, u64)>,
    hmac: hmac::Key,
    stats: Arc<SurrealStats>,
}

impl std::fmt::Debug for SurrealMailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealMailbox")
            .field("rpc", &self.conn.cfg)
            .finish_non_exhaustive()
    }
}

impl SurrealMailbox {
    /// Connects, applies the schema and starts the writer task on the current Tokio runtime.
    ///
    /// # Errors
    /// [`MailboxError::Unavailable`] if SurrealDB cannot be reached or refuses the schema.
    pub async fn connect(cfg: SurrealConfig) -> Result<Self, MailboxError> {
        let conn = Arc::new(Conn {
            cfg: cfg.rpc.clone(),
            current: watch::Sender::new(None),
            reconnect: Mutex::new(()),
        });
        // SurrealDB may still be starting (compose, rollouts): retry for up to ~10 s.
        let mut attempt = 0u32;
        loop {
            match conn.query(SCHEMA, Vec::new()).await {
                Ok(r) if r.iter().all(Result::is_ok) => break,
                _ if attempt < 10 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(100u64 << attempt.min(3))).await;
                }
                _ => return Err(MailboxError::Unavailable),
            }
        }
        let stats = Arc::new(SurrealStats::default());
        let (store_tx, store_rx) = mpsc::channel(64 * 1024);
        let (ack_tx, ack_rx) = mpsc::channel(64 * 1024);
        let writer = Writer {
            conn: Arc::clone(&conn),
            max_batch: cfg.max_batch.max(1),
            max_wait: cfg.max_wait,
            max_per_device: cfg.max_per_device,
            last: HashMap::new(),
            acked: HashMap::new(),
            pending_acks: HashMap::new(),
            stats: Arc::clone(&stats),
        };
        tokio::spawn(writer.run(store_rx, ack_rx, cfg.ack_interval));
        Ok(Self {
            conn,
            store_tx,
            ack_tx,
            hmac: hmac::Key::new(hmac::HMAC_SHA256, &cfg.idempotency_secret),
            stats,
        })
    }

    /// Counters (commits, sends, retries…).
    #[must_use]
    pub fn stats(&self) -> &SurrealStats {
        &self.stats
    }

    /// Runs one statement (tests and tools).
    ///
    /// # Errors
    /// [`MailboxError::Unavailable`].
    pub async fn query_one(
        &self,
        sql: &str,
        vars: Vec<(String, Value)>,
    ) -> Result<Value, MailboxError> {
        let r = self
            .conn
            .query(sql, vars)
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        r.into_iter()
            .next_back()
            .ok_or(MailboxError::Unavailable)?
            .map_err(|_| MailboxError::Unavailable)
    }
}

impl Mailbox for SurrealMailbox {
    fn store(
        &self,
        req: StoreRequest,
    ) -> impl Future<Output = Result<StoreOutcome, MailboxError>> + Send {
        let tag = req.idempotency_key.map(|k| idempotency_tag(&self.hmac, &k));
        let tx = self.store_tx.clone();
        async move {
            let (reply, rx) = oneshot::channel();
            tx.send(Job { req, tag, reply })
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            rx.await.map_err(|_| MailboxError::Unavailable)?
        }
    }

    fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Stored>, MailboxError>> + Send {
        let conn = Arc::clone(&self.conn);
        let vars = vec![
            ("d".to_owned(), bytes_value(device.as_bytes())),
            ("after".to_owned(), int(after_seq)),
            (
                "n".to_owned(),
                int(u64::try_from(limit).unwrap_or(u64::MAX)),
            ),
        ];
        async move {
            let r = conn
                .query(FETCH, vars)
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            let rows = r
                .into_iter()
                .next()
                .ok_or(MailboxError::Unavailable)?
                .map_err(|_| MailboxError::Unavailable)?
                .into_array()
                .ok_or(MailboxError::Unavailable)?;
            rows.iter()
                .map(|row| {
                    let seq = row
                        .get("seq")
                        .and_then(uint)
                        .ok_or(MailboxError::Unavailable)?;
                    let envelope = row
                        .get("env")
                        .and_then(Value::as_bytes)
                        .or_else(|| row.get("benv").and_then(Value::as_bytes))
                        .cloned()
                        .ok_or(MailboxError::Unavailable)?;
                    Ok(Stored { seq, envelope })
                })
                .collect()
        }
    }

    fn ack_up_to(
        &self,
        device: &DeviceId,
        up_to_seq: u64,
    ) -> impl Future<Output = Result<(), MailboxError>> + Send {
        // Never blocks a session: if the queue is full the ACK is dropped; the next ACK or the
        // device's next `Auth.last_acked_seq` repeats it (deletes are idempotent).
        let r = self.ack_tx.try_send((*device, up_to_seq));
        std::future::ready(match r {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(MailboxError::Unavailable),
        })
    }

    fn expire_older_than(
        &self,
        age: Duration,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        let conn = Arc::clone(&self.conn);
        async move {
            let vars = vec![
                ("age".to_owned(), int(age.as_secs())),
                ("idem_age".to_owned(), int(IDEMPOTENCY_RETENTION.as_secs())),
            ];
            let r = conn
                .query(EXPIRE, vars)
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            let n = r.len().checked_sub(2).and_then(|i| r.get(i));
            match n {
                Some(Ok(v)) => uint(v).ok_or(MailboxError::Unavailable),
                _ => Err(MailboxError::Unavailable),
            }
        }
    }

    fn store_generation(&self) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        let conn = Arc::clone(&self.conn);
        async move {
            let r = conn
                .query("SELECT VALUE generation FROM ONLY meta:store;", Vec::new())
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            match r.first() {
                Some(Ok(v)) => uint(v).ok_or(MailboxError::Unavailable),
                _ => Err(MailboxError::Unavailable),
            }
        }
    }

    /// Development backend: the writer's cached counters are not dropped, so a later send to a
    /// forgotten device would continue its `seq`; deployments use Iggy.
    fn forget(&self, devices: &[DeviceId]) -> impl Future<Output = Result<(), MailboxError>> + Send {
        let conn = Arc::clone(&self.conn);
        let ds = Value::Array(devices.iter().map(|d| bytes_value(d.as_bytes())).collect());
        async move {
            let r = conn
                .query(FORGET, vec![("ds".to_owned(), ds)])
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            if r.iter().all(Result::is_ok) {
                Ok(())
            } else {
                Err(MailboxError::Unavailable)
            }
        }
    }

    fn knows(&self, device: &DeviceId) -> impl Future<Output = Result<bool, MailboxError>> + Send {
        let conn = Arc::clone(&self.conn);
        let vars = vec![("d".to_owned(), bytes_value(device.as_bytes()))];
        async move {
            let r = conn
                .query(
                    "RETURN count(SELECT VALUE id FROM mailbox:[$d, 0]>..[$d, ..]) + count(SELECT id FROM seqctr:[$d]) + count(SELECT id FROM ackctr:[$d]);",
                    vars,
                )
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            match r.first() {
                Some(Ok(v)) => uint(v).map(|n| n > 0).ok_or(MailboxError::Unavailable),
                _ => Err(MailboxError::Unavailable),
            }
        }
    }

    fn count_pending(
        &self,
        device: &DeviceId,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        let conn = Arc::clone(&self.conn);
        let vars = vec![("d".to_owned(), bytes_value(device.as_bytes()))];
        async move {
            let r = conn
                .query(
                    "RETURN count(SELECT VALUE id FROM mailbox:[$d, 0]>..[$d, ..]);",
                    vars,
                )
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            match r.first() {
                Some(Ok(v)) => uint(v).ok_or(MailboxError::Unavailable),
                _ => Err(MailboxError::Unavailable),
            }
        }
    }
}

/// Accepted sends with their assigned `seq`s.
type Assigned = Vec<(Job, Vec<u64>)>;

/// What went wrong in a failed transaction.
enum Abort {
    /// Retry everything (conflict, connection, stale counter cache).
    Retry,
    /// The cached counters were stale: reload them, then retry.
    StaleSeq,
    /// An idempotency key exists.
    Replay,
    /// The MLS epoch moved.
    StaleEpoch,
    /// Give up.
    Fatal,
}

fn classify(err: &StatementError) -> Option<Abort> {
    match err.kind.as_str() {
        "Thrown" if err.message.contains("stale_epoch") => Some(Abort::StaleEpoch),
        "Thrown" if err.message.contains("stale_seq") => Some(Abort::StaleSeq),
        "AlreadyExists" => Some(Abort::Replay),
        // Statements skipped because another one failed.
        "Query"
            if err.message.contains("not executed") || err.message.contains("Cannot COMMIT") =>
        {
            None
        }
        _ if err.message.contains("conflict") || err.message.contains("retry") => {
            Some(Abort::Retry)
        }
        _ => Some(Abort::Fatal),
    }
}

/// The single writer: group-commit batches and ACK deletes.
struct Writer {
    conn: Arc<Conn>,
    max_batch: usize,
    max_wait: Duration,
    max_per_device: u64,
    /// Cached `seqctr.last` (0: no record yet).
    last: HashMap<DeviceId, u64>,
    /// Cached `ackctr.n`.
    acked: HashMap<DeviceId, u64>,
    /// ACKs waiting for the next flush.
    pending_acks: HashMap<DeviceId, u64>,
    stats: Arc<SurrealStats>,
}

/// Bound on cached devices; the caches are dropped and reloaded lazily beyond it.
const CACHE_MAX: usize = 1 << 20;

impl Writer {
    async fn run(
        mut self,
        mut store_rx: mpsc::Receiver<Job>,
        mut ack_rx: mpsc::Receiver<(DeviceId, u64)>,
        ack_interval: Duration,
    ) {
        let mut tick = tokio::time::interval(ack_interval.max(Duration::from_millis(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = tick.tick() => {
                    self.take_acks(&mut ack_rx);
                    if !self.pending_acks.is_empty() {
                        self.flush_acks().await;
                    }
                }
                job = store_rx.recv() => {
                    let Some(first) = job else { break };
                    let batch = self.collect(first, &mut store_rx).await;
                    self.store(batch).await;
                    // Steady sends keep this branch ready: take queued ACKs on every wake-up
                    // so they are never starved (and never dropped on a full queue).
                    self.take_acks(&mut ack_rx);
                    if self.pending_acks.len() >= 4096 {
                        self.flush_acks().await;
                    }
                }
                ack = ack_rx.recv() => {
                    let Some((d, up)) = ack else { continue };
                    let e = self.pending_acks.entry(d).or_insert(0);
                    *e = (*e).max(up);
                    self.take_acks(&mut ack_rx);
                    if self.pending_acks.len() >= 4096 {
                        self.flush_acks().await;
                    }
                }
            }
        }
        if !self.pending_acks.is_empty() {
            self.flush_acks().await;
        }
    }

    /// Merges every queued ACK into the pending set.
    fn take_acks(&mut self, rx: &mut mpsc::Receiver<(DeviceId, u64)>) {
        while let Ok((d, up)) = rx.try_recv() {
            let e = self.pending_acks.entry(d).or_insert(0);
            *e = (*e).max(up);
        }
    }

    async fn collect(&self, first: Job, rx: &mut mpsc::Receiver<Job>) -> Vec<Job> {
        let mut batch = vec![first];
        let deadline = tokio::time::Instant::now() + self.max_wait;
        while batch.len() < self.max_batch {
            // Take whatever is already queued; wait for more only until the deadline.
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(mpsc::error::TryRecvError::Disconnected) => break,
                Err(mpsc::error::TryRecvError::Empty) => {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(j)) => batch.push(j),
                        _ => break,
                    }
                }
            }
        }
        batch
    }

    async fn store(&mut self, batch: Vec<Job>) {
        // MLS commits run one per transaction: two commits for one group in a batch would
        // abort each other.
        let (mls, plain): (Vec<Job>, Vec<Job>) =
            batch.into_iter().partition(|j| j.req.mls.is_some());
        if !plain.is_empty() {
            self.commit(plain).await;
        }
        for j in mls {
            self.commit(vec![j]).await;
        }
    }

    /// Loads counters of devices not in the caches (one round trip; only after a restart or
    /// for devices seen for the first time).
    async fn load(&mut self, jobs: &[Job]) -> Result<(), MailboxError> {
        if self.last.len() > CACHE_MAX || self.acked.len() > CACHE_MAX {
            self.last.clear();
            self.acked.clear();
        }
        let mut unknown: Vec<DeviceId> = Vec::new();
        for j in jobs {
            for d in j.req.payload.devices() {
                if !self.last.contains_key(d) && !unknown.contains(d) {
                    unknown.push(*d);
                }
            }
        }
        if unknown.is_empty() {
            return Ok(());
        }
        let sids = unknown
            .iter()
            .map(|d| record("seqctr", bytes_value(d.as_bytes())))
            .collect();
        let aids = unknown
            .iter()
            .map(|d| record("ackctr", bytes_value(d.as_bytes())))
            .collect();
        let r = self
            .conn
            .query(
                LOAD,
                vec![
                    ("sids".to_owned(), Value::Array(sids)),
                    ("aids".to_owned(), Value::Array(aids)),
                ],
            )
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        for d in &unknown {
            self.last.insert(*d, 0);
            self.acked.entry(*d).or_insert(0);
        }
        let mut fill = |rows: Option<&Result<Value, StatementError>>, field: &str, acked: bool| {
            let Some(Ok(Value::Array(rows))) = rows else {
                return;
            };
            for row in rows {
                let (Some(d), Some(v)) = (
                    row.get("d")
                        .and_then(Value::as_bytes)
                        .and_then(|b| DeviceId::from_slice(b).ok()),
                    row.get(field).and_then(uint),
                ) else {
                    continue;
                };
                if acked {
                    self.acked.insert(d, v);
                } else {
                    self.last.insert(d, v);
                }
            }
        };
        fill(r.first(), "last", false);
        fill(r.get(1), "n", true);
        Ok(())
    }

    /// Writes `jobs` in one transaction, retrying around partial failures; answers every job.
    async fn commit(&mut self, mut jobs: Vec<Job>) {
        for attempt in 0..MAX_ATTEMPTS {
            if jobs.is_empty() {
                return;
            }
            if attempt > 0 {
                self.stats.retries.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(1u64 << attempt.min(6))).await;
            }
            if self.load(&jobs).await.is_err() {
                continue;
            }
            let (accepted, next) = self.assign(jobs);
            if accepted.is_empty() {
                return;
            }
            let (sql, vars) = self.build(&accepted, &next);
            let result = self.conn.query(&sql, vars).await;
            // Conflict, disconnect or timeout: the transaction may have committed. Forget the
            // cached counters (the guard tells) and retry: idempotency keys make that safe.
            let statements = match result {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, attempt, "mailbox store request failed");
                    jobs = self.forget(accepted);
                    continue;
                }
            };
            let abort = statements
                .iter()
                .filter_map(|s| s.as_ref().err())
                .find_map(classify);
            match abort {
                None => {
                    self.stats.commits.fetch_add(1, Ordering::Relaxed);
                    self.last.extend(next);
                    for (j, seqs) in accepted {
                        self.stats.sends.fetch_add(1, Ordering::Relaxed);
                        self.stats
                            .entries
                            .fetch_add(u64::try_from(seqs.len()).unwrap_or(0), Ordering::Relaxed);
                        let _ = j.reply.send(Ok(StoreOutcome {
                            seqs,
                            replayed: false,
                        }));
                    }
                    return;
                }
                Some(Abort::Retry | Abort::StaleSeq) => jobs = self.forget(accepted),
                Some(Abort::Fatal) => {
                    let kind = statements
                        .iter()
                        .filter_map(|s| s.as_ref().err())
                        .map(|e| e.kind.as_str())
                        .find(|k| *k != "Query")
                        .unwrap_or("Query");
                    tracing::warn!(kind, "mailbox store transaction failed");
                    jobs = accepted.into_iter().map(|(j, _)| j).collect();
                    break;
                }
                Some(Abort::StaleEpoch) => {
                    // Only MLS commits run alone, so the whole (one-job) batch is stale.
                    for (j, _) in accepted {
                        let _ = j.reply.send(Err(MailboxError::StaleEpoch));
                    }
                    return;
                }
                Some(Abort::Replay) => {
                    let jobs_only = accepted.into_iter().map(|(j, _)| j).collect();
                    jobs = resolve_replays(&self.conn, jobs_only).await;
                }
            }
        }
        self.stats.failures.fetch_add(1, Ordering::Relaxed);
        for j in jobs {
            let _ = j.reply.send(Err(MailboxError::Unavailable));
        }
    }

    /// Drops cached counters of the batch's devices (they will be reloaded).
    fn forget(&mut self, accepted: Assigned) -> Vec<Job> {
        for (j, _) in &accepted {
            for d in j.req.payload.devices() {
                self.last.remove(d);
            }
        }
        accepted.into_iter().map(|(j, _)| j).collect()
    }

    /// Refuses sends to full mailboxes (a soft limit from the cached counters) and assigns
    /// every recipient its `seq`. Returns the accepted sends and each device's new `last`.
    fn assign(&self, jobs: Vec<Job>) -> (Assigned, HashMap<DeviceId, u64>) {
        let mut next: HashMap<DeviceId, u64> = HashMap::new();
        let mut accepted = Vec::with_capacity(jobs.len());
        for j in jobs {
            let full = j.req.payload.devices().any(|d| {
                let last = next
                    .get(d)
                    .copied()
                    .unwrap_or_else(|| self.last.get(d).copied().unwrap_or(0));
                last.saturating_sub(self.acked.get(d).copied().unwrap_or(0)) >= self.max_per_device
            });
            if full {
                let _ = j.reply.send(Err(MailboxError::Full));
                continue;
            }
            let mut seqs = Vec::with_capacity(j.req.payload.len());
            for d in j.req.payload.devices() {
                let base = self.last.get(d).copied().unwrap_or(0);
                let s = next.entry(*d).or_insert(base);
                *s += 1;
                seqs.push(*s);
            }
            accepted.push((j, seqs));
        }
        (accepted, next)
    }

    /// The transaction for a batch: three or four bulk statements whatever its size.
    fn build(
        &self,
        accepted: &[(Job, Vec<u64>)],
        next: &HashMap<DeviceId, u64>,
    ) -> (String, Vec<(String, Value)>) {
        let now = now_value();
        let (mut old_ids, mut old, mut new_ids, mut ctrs) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (d, last) in next {
            let id = record("seqctr", bytes_value(d.as_bytes()));
            match self.last.get(d).copied().unwrap_or(0) {
                0 => new_ids.push(id.clone()),
                prev => {
                    old_ids.push(id.clone());
                    old.push(int(prev));
                }
            }
            ctrs.push(Value::map([("id", id), ("last", int(*last))]));
        }
        let (mut rows, mut bodies, mut idems) = (Vec::new(), Vec::new(), Vec::new());
        let mut mls = None;
        for (j, seqs) in accepted {
            let link = match &j.req.payload {
                Payload::Shared { devices, body } => {
                    let mut id = [0u8; 16];
                    let _ = getrandom::fill(&mut id);
                    let link = record("body", bytes_value(&id));
                    bodies.push(Value::map([
                        ("id", link.clone()),
                        ("env", Value::Bytes(body.clone())),
                        (
                            "refs",
                            int(u64::try_from(devices.len()).unwrap_or(u64::MAX)),
                        ),
                        ("at", now.clone()),
                    ]));
                    Some(link)
                }
                Payload::PerDevice(_) => None,
            };
            let mut stored = Vec::with_capacity(seqs.len());
            for (i, (d, seq)) in j.req.payload.devices().zip(seqs).enumerate() {
                let id = record_key("mailbox", vec![bytes_value(d.as_bytes()), int(*seq)]);
                let content = match &link {
                    Some(l) => ("body", l.clone()),
                    None => (
                        "env",
                        j.req
                            .payload
                            .envelope(i)
                            .cloned()
                            .map_or(Value::Null, Value::Bytes),
                    ),
                };
                rows.push(Value::map([("id", id), content, ("at", now.clone())]));
                stored.push(Value::Array(vec![bytes_value(d.as_bytes()), int(*seq)]));
            }
            if let Some(tag) = j.tag {
                idems.push(Value::map([
                    ("id", record("idem", bytes_value(&tag))),
                    ("stored", Value::Array(stored)),
                    ("at", now.clone()),
                ]));
            }
            if let Some(m) = j.req.mls {
                mls = Some(m);
            }
        }
        let mut sql = String::from(S_BEGIN);
        let mut vars = Vec::with_capacity(10);
        // The idempotency insert comes first: a retried send must replay even when other
        // checks (an MLS epoch) would now fail.
        if !idems.is_empty() {
            sql.push_str(S_IDEM);
            vars.push(("idems".to_owned(), Value::Array(idems)));
        }
        if let Some(m) = mls {
            sql.push_str(S_MLS);
            vars.push(("g".to_owned(), bytes_value(&m.group)));
            vars.push(("e".to_owned(), int(m.epoch)));
        }
        sql.push_str(S_CTRS);
        vars.push(("ctrs".to_owned(), Value::Array(ctrs)));
        if !bodies.is_empty() {
            sql.push_str(S_BODIES);
            vars.push(("bodies".to_owned(), Value::Array(bodies)));
        }
        sql.push_str(S_ROWS);
        vars.push(("rows".to_owned(), Value::Array(rows)));
        sql.push_str(S_COMMIT);
        (sql, vars)
    }

    /// Deletes everything acknowledged since the last flush: explicit entry IDs (or a range for a
    /// device whose previous ACK is unknown), the acknowledged counters, then shared bodies whose
    /// last entry went.
    async fn flush_acks(&mut self) {
        let mut ids = Vec::new();
        let mut ranges = Vec::new();
        let mut counters = Vec::new();
        let mut done: Vec<(DeviceId, u64)> = Vec::new();
        for (d, up) in &self.pending_acks {
            let prev = self.acked.get(d).copied();
            if prev.is_some_and(|p| *up <= p) {
                continue;
            }
            match prev {
                Some(p) if up - p <= EXPLICIT_MAX => {
                    for s in p + 1..=*up {
                        ids.push(record_key(
                            "mailbox",
                            vec![bytes_value(d.as_bytes()), int(s)],
                        ));
                    }
                }
                _ => ranges.push((*d, *up)),
            }
            counters.push(Value::map([
                ("id", record("ackctr", bytes_value(d.as_bytes()))),
                ("n", int(*up)),
            ]));
            done.push((*d, *up));
        }
        self.pending_acks.clear();
        if done.is_empty() {
            return;
        }
        // One transaction: delete the entries, record the counters, and decrement (deleting at
        // zero) every shared body whose entries went, so entries and body references never
        // disagree.
        let mut sql = String::from(S_BEGIN);
        let mut vars = Vec::new();
        let mut gone = Vec::new();
        if !ids.is_empty() {
            sql.push_str("LET $g_ids = DELETE $ids RETURN VALUE $before.body;");
            vars.push(("ids".to_owned(), Value::Array(ids)));
            gone.push("$g_ids".to_owned());
        }
        for (i, (d, up)) in ranges.iter().enumerate() {
            let _ = write!(
                sql,
                "LET $g{i} = DELETE mailbox:[$rd{i}, 0]..=[$rd{i}, $ru{i}] RETURN VALUE $before.body;"
            );
            vars.push((format!("rd{i}"), bytes_value(d.as_bytes())));
            vars.push((format!("ru{i}"), int(*up)));
            gone.push(format!("$g{i}"));
        }
        let _ = write!(
            sql,
            "LET $gone = array::filter(array::flatten([{}]), |$v| $v != NONE);\
             FOR $b IN array::distinct($gone) {{\
               UPDATE $b SET refs -= array::len(array::filter($gone, |$v| $v = $b)) RETURN NONE;\
               DELETE $b WHERE refs <= 0 RETURN NONE;\
             }};",
            gone.join(", ")
        );
        sql.push_str("INSERT INTO ackctr $acks ON DUPLICATE KEY UPDATE n = math::max([n, $input.n]) RETURN NONE;");
        vars.push(("acks".to_owned(), Value::Array(counters)));
        sql.push_str(S_COMMIT);
        let ok = match self.conn.query(&sql, vars).await {
            Ok(results) => match results.iter().find_map(|r| r.as_ref().err()) {
                None => true,
                Some(e) => {
                    // The kind only: messages can quote record IDs (invariant 6).
                    tracing::warn!(kind = %e.kind, "mailbox ack flush failed");
                    false
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "mailbox ack flush failed");
                false
            }
        };
        if ok {
            self.stats.ack_commits.fetch_add(1, Ordering::Relaxed);
            self.acked.extend(done);
        } else {
            // Keep them for the next flush; the transaction is all or nothing.
            self.stats.retries.fetch_add(1, Ordering::Relaxed);
            self.pending_acks.extend(done);
        }
    }
}

/// Answers sends whose idempotency record exists (replay or conflict); returns the others.
async fn resolve_replays(conn: &Conn, jobs: Vec<Job>) -> Vec<Job> {
    let ids: Vec<Value> = jobs
        .iter()
        .filter_map(|j| j.tag.map(|t| record("idem", bytes_value(&t))))
        .collect();
    let r = conn
        .query(
            "SELECT meta::id(id)[0] AS h, stored FROM $ids;",
            vec![("ids".to_owned(), Value::Array(ids))],
        )
        .await;
    let rows = match r {
        Ok(mut s) if !s.is_empty() => match s.swap_remove(0) {
            Ok(Value::Array(rows)) => rows,
            _ => return jobs,
        },
        _ => return jobs,
    };
    let mut found: HashMap<Bytes, Vec<(Bytes, u64)>> = HashMap::new();
    for row in &rows {
        let (Some(h), Some(stored)) = (
            row.get("h").and_then(Value::as_bytes),
            row.get("stored").and_then(Value::as_array),
        ) else {
            continue;
        };
        let pairs = stored
            .iter()
            .filter_map(|p| {
                let a = p.as_array()?;
                Some((a.first()?.as_bytes()?.clone(), uint(a.get(1)?)?))
            })
            .collect();
        found.insert(h.clone(), pairs);
    }
    let mut rest = Vec::with_capacity(jobs.len());
    for j in jobs {
        let Some(stored) = j.tag.and_then(|t| found.get(t.as_slice())) else {
            rest.push(j);
            continue;
        };
        let same = stored.len() == j.req.payload.len()
            && stored
                .iter()
                .zip(j.req.payload.devices())
                .all(|((d, _), dev)| d.as_ref() == dev.as_bytes());
        let reply = if same {
            Ok(StoreOutcome {
                seqs: stored.iter().map(|(_, s)| *s).collect(),
                replayed: true,
            })
        } else {
            Err(MailboxError::IdempotencyConflict)
        };
        let _ = j.reply.send(reply);
    }
    rest
}
