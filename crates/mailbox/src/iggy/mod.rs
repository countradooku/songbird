//! Mailbox on Apache Iggy (D-0029): an append-only log is the durable truth.
//!
//! - **Partitions and writers.** A topic with `partitions` partitions; each device belongs to one
//!   (a hash of its ID). One writer task per partition, in this process, owns that partition's
//!   state: every device's `seq` counter and acknowledged `seq`, the index of pending entries
//!   (offsets into the log, not ciphertext), idempotency tags and MLS epochs. It batches the
//!   requests that queue while it commits (natural group commit) into one append.
//! - **Durability.** The topic's `durability` is `persisted`: Iggy fsyncs before it confirms, and
//!   a send is acknowledged only after that (invariant 1).
//! - **One writer per partition.** Each writer is an idempotent Iggy producer with a fixed id and a
//!   new epoch at every start (recorded in the log). Iggy refuses batches of an older epoch
//!   (`ProducerEpochFenced`), so a second process cannot corrupt `seq`s, and a batch whose outcome
//!   is unknown is resent with the same sequence and written once.
//! - **Multi-partition sends.** A send has a home partition (the MLS group's, else the one with
//!   most recipients, so most sends are one append). The home record holds the home devices'
//!   entries and the parts for other partitions; those parts are then stored on their partitions
//!   under the same idempotency tag, and a re-driver completes any that failed, also after a
//!   restart. A send is either refused with nothing stored or recorded and eventually stored for
//!   every recipient.
//! - **Start-up.** Each partition is replayed from its low-water offset to rebuild the state.
//! - **Idempotency.** A tag is stored with a fingerprint of the send's whole recipient set; a
//!   reused key is a retry only when both match, else it is refused.
//! - **Compaction.** Off the write path (a compactor task reads old records on its own
//!   connection): pending entries older than `relocate_after` are copied forward, a counter
//!   snapshot is written, and the low-water offset (stored as an Iggy consumer offset, which also
//!   stops Iggy deleting segments past it) moves up. Iggy deletes sealed segments below it once
//!   older than the topic's `message_expiry`. Entries older than 30 days are dropped (invariant 3).
//!
//! Acknowledged ciphertext leaves the index at once and the disk when its segment is deleted
//! (`segment_expiry` after the low-water offset passes it).

mod record;
mod state;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use bytes::Bytes;
use iggy::prelude::{
    BatchProducer, Consumer, ConsumerOffsetClient as _, Durability, Identifier, IggyClient,
    IggyDuration, IggyError, IggyExpiry, IggyMessage, MessageClient as _, PollOptions,
    PollingStrategy, StreamClient as _, StreamCreateOptions, TopicClient as _, TopicCreateOptions,
};
use songbird_types::DeviceId;
use tokio::sync::{mpsc, oneshot};

pub use self::config::{IggyConfig, IggyConnection};

/// Why the Iggy mailbox could not start.
#[derive(Debug, thiserror::Error)]
pub enum IggyMailboxError {
    /// Iggy refused or failed a request.
    #[error("iggy error {}", .0.as_code())]
    Iggy(#[from] IggyError),
    /// The log holds a record this version cannot read. Replaying past it would lose counters
    /// and reuse `seq`s, so the mailbox does not start (runbook: "Mailbox log unreadable").
    #[error(
        "mailbox log unreadable: partition {partition}, offset {offset}, record version {version}"
    )]
    Unreadable {
        /// Partition.
        partition: u32,
        /// Offset of the record.
        offset: u64,
        /// Its version byte (this build writes and reads [`RECORD_VERSION`]).
        version: u8,
    },
}

/// The record format version this build reads and writes.
pub const RECORD_VERSION: u8 = record::VERSION;
use self::record::{Local, Record, Remote};
use self::state::{Entry, State};
use crate::{
    IDEMPOTENCY_RETENTION, MAX_ENVELOPE_AGE, Mailbox, MailboxError, MlsCommit, Payload,
    StoreOutcome, StoreRequest, Stored, idempotency_tag,
};

mod config;

/// Consumer whose stored offset is each partition's low-water mark.
const LOW_WATER_CONSUMER: &str = "songbird-mailbox-low-water";
/// Records fetched per poll during replay.
const REPLAY_POLL: u32 = 1000;
/// Largest relocate or snapshot record written by compaction (bytes, approximate).
const COMPACTION_RECORD_BYTES: usize = 1 << 20;
/// How long a remote part may stay incomplete before the re-driver takes it over.
const REDRIVE_AFTER: Duration = Duration::from_secs(2);
/// Offsets read with one poll when they are this close.
const READ_SPAN: u64 = 512;
/// Most entries one compaction pass copies forward (the rest wait for the next pass).
const RELOCATE_PER_PASS: usize = 100_000;

/// Counters for metrics and benchmarks.
#[derive(Debug, Default)]
pub struct IggyStats {
    /// Appends that carried sends.
    pub commits: AtomicU64,
    /// Sends (or parts) stored.
    pub sends: AtomicU64,
    /// Entries stored.
    pub entries: AtomicU64,
    /// Appends resent after an uncertain outcome.
    pub resends: AtomicU64,
    /// ACK checkpoint appends.
    pub ack_commits: AtomicU64,
    /// Entries copied forward by compaction.
    pub relocated: AtomicU64,
    /// Remote parts completed by the re-driver.
    pub redriven: AtomicU64,
    /// Polls that read records back from the log (cache misses).
    pub reads: AtomicU64,
    /// Compaction passes completed (the low-water offset considered).
    pub compactions: AtomicU64,
}

fn n64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn idx(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn hash16(b: &[u8]) -> u64 {
    let mut p = [0u8; 8];
    p.copy_from_slice(b.get(..8).unwrap_or(&[0; 8]));
    // Fibonacci hashing spreads random and sequential IDs alike.
    u64::from_le_bytes(p).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// First 16 bytes of SHA-256 over the sorted recipient device IDs.
fn recipients_fingerprint(devices: &[DeviceId]) -> [u8; 16] {
    let mut sorted: Vec<&DeviceId> = devices.iter().collect();
    sorted.sort_unstable();
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for d in sorted {
        ctx.update(d.as_bytes());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(ctx.finish().as_ref().get(..16).unwrap_or(&[0; 16]));
    out
}

fn partition_of(d: &DeviceId, n: u32) -> u32 {
    u32::try_from(hash16(d.as_bytes()) % u64::from(n.max(1))).unwrap_or(0)
}

/// What a writer stores for its own partition.
#[derive(Clone)]
enum LocalReq {
    PerDevice(Vec<(DeviceId, Bytes)>),
    Shared { devices: Vec<DeviceId>, body: Bytes },
}

impl LocalReq {
    fn devices(&self) -> Vec<DeviceId> {
        match self {
            Self::PerDevice(v) => v.iter().map(|(d, _)| *d).collect(),
            Self::Shared { devices, .. } => devices.clone(),
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            Self::PerDevice(v) => v.is_empty(),
            Self::Shared { devices, .. } => devices.is_empty(),
        }
    }
}

/// A writer's answer: (device, seq) of its part, and whether it was a replay.
type PartResult = Result<(Vec<(DeviceId, u64)>, bool), MailboxError>;
type Reply = oneshot::Receiver<PartResult>;

/// A store request for one writer.
struct StoreJob {
    /// Idempotency tag and the fingerprint of the send's whole recipient set.
    tag: Option<([u8; 32], [u8; 16])>,
    mls: Option<MlsCommit>,
    local: LocalReq,
    remote: Vec<Remote>,
    reply: oneshot::Sender<PartResult>,
}

enum Job {
    Store(StoreJob),
    Ack(DeviceId, u64),
    Expire(u64, oneshot::Sender<u64>),
    /// A remote part of the send with this tag is stored on this partition.
    PartDone([u8; 32], u32),
    /// Entries read by the compactor, to copy forward; `last` ends the pass.
    Relocated {
        items: Vec<(DeviceId, u64, u64, Bytes)>,
        last: bool,
    },
}

/// Read access to a partition, shared by the writer and readers.
struct Shared {
    partition: u32,
    state: Mutex<State>,
    /// Record payloads by offset (recently written or read), bounded by `cache_bytes`.
    cache: Mutex<(BTreeMap<u64, Bytes>, usize)>,
    cache_bytes: usize,
    reader: IggyClient,
    /// Connection of the compactor (old records are read off the write and drain paths).
    compactor: IggyClient,
    /// A compaction pass is running.
    compacting: AtomicBool,
    stream: Identifier,
    topic: Identifier,
    healthy: AtomicBool,
    stats: Arc<IggyStats>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cache_put(&self, offset: u64, payload: Bytes) {
        let mut c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = payload.len();
        if c.0.insert(offset, payload).is_none() {
            c.1 += len;
        }
        while c.1 > self.cache_bytes {
            match c.0.pop_first() {
                Some((_, b)) => c.1 = c.1.saturating_sub(b.len()),
                None => break,
            }
        }
    }

    fn cache_get(&self, offset: u64) -> Option<Bytes> {
        let c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.0.get(&offset).cloned()
    }

    /// The records at `offsets` (cache, else the log): nearby offsets are read with one poll.
    async fn records(
        &self,
        client: &IggyClient,
        offsets: &[u64],
    ) -> Result<HashMap<u64, Record>, MailboxError> {
        let mut wanted: Vec<u64> = offsets.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut out = HashMap::with_capacity(wanted.len());
        let mut missing = Vec::new();
        for o in wanted {
            match self.cache_get(o) {
                Some(p) => {
                    out.insert(
                        o,
                        Record::decode(&p).map_err(|_| MailboxError::Unavailable)?,
                    );
                }
                None => missing.push(o),
            }
        }
        let consumer = Consumer::new(
            Identifier::named(LOW_WATER_CONSUMER).map_err(|_| MailboxError::Unavailable)?,
        );
        let mut i = 0;
        while let Some(&start) = missing.get(i) {
            // One poll covers every missing offset within READ_SPAN of the first.
            let mut end = start;
            let mut j = i;
            while let Some(&o) = missing.get(j) {
                if o - start >= READ_SPAN {
                    break;
                }
                end = o;
                j += 1;
            }
            self.stats.reads.fetch_add(1, Ordering::Relaxed);
            let count = u32::try_from(end - start + 1).unwrap_or(u32::MAX);
            let polled = client
                .poll_messages(
                    &self.stream,
                    &self.topic,
                    self.partition,
                    &consumer,
                    &PollingStrategy::offset(start),
                    PollOptions {
                        count,
                        ..PollOptions::default()
                    },
                )
                .await
                .map_err(|e| unavailable("mailbox read failed", &e))?;
            let want = missing.get(i..j).unwrap_or_default();
            for m in polled.messages {
                if want.binary_search(&m.header.offset).is_ok() {
                    let rec = Record::decode(&m.payload).map_err(|_| MailboxError::Unavailable)?;
                    out.insert(m.header.offset, rec);
                }
            }
            if want.iter().any(|o| !out.contains_key(o)) {
                return Err(MailboxError::Unavailable);
            }
            i = j;
        }
        Ok(out)
    }

    /// The record at `offset` (cache, else the log).
    async fn record(&self, offset: u64) -> Result<Record, MailboxError> {
        let payload = if let Some(p) = self.cache_get(offset) {
            p
        } else {
            {
                self.stats.reads.fetch_add(1, Ordering::Relaxed);
                let polled = self
                    .reader
                    .poll_messages(
                        &self.stream,
                        &self.topic,
                        self.partition,
                        &Consumer::new(
                            Identifier::named(LOW_WATER_CONSUMER)
                                .map_err(|_| MailboxError::Unavailable)?,
                        ),
                        &PollingStrategy::offset(offset),
                        PollOptions {
                            count: 1,
                            ..PollOptions::default()
                        },
                    )
                    .await
                    .map_err(|e| unavailable("mailbox read failed", &e))?;
                let msg = polled
                    .messages
                    .into_iter()
                    .find(|m| m.header.offset == offset)
                    .ok_or(MailboxError::Unavailable)?;
                msg.payload
            }
        };
        Record::decode(&payload).map_err(|_| MailboxError::Unavailable)
    }
}

fn unavailable(what: &str, e: &IggyError) -> MailboxError {
    tracing::warn!(code = e.as_code(), "{what}");
    MailboxError::Unavailable
}

struct Part {
    tx: mpsc::Sender<Job>,
    shared: Arc<Shared>,
}

/// The Iggy mailbox.
pub struct IggyMailbox {
    parts: Arc<Vec<Part>>,
    idem: hmac::Key,
    timeout: Duration,
    generation: u64,
    fault_skip_remote_parts: bool,
    max_per_device: u64,
    stats: Arc<IggyStats>,
}

impl std::fmt::Debug for IggyMailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IggyMailbox")
            .field("partitions", &self.parts.len())
            .finish_non_exhaustive()
    }
}

/// Fuzzing entry point: decodes one log record; anything accepted re-encodes to the same bytes.
/// Not part of the API.
#[doc(hidden)]
pub fn fuzz_record(data: &[u8]) {
    let src = Bytes::copy_from_slice(data);
    if let Ok(rec) = Record::decode(&src) {
        let again = rec.encode();
        assert_eq!(
            Record::decode(&again).ok(),
            Some(rec),
            "re-encoding decodes to the same record"
        );
        assert_eq!(again, src, "the encoding is canonical");
    }
}

impl IggyMailbox {
    /// Connects, creates the stream and topic if missing, replays every partition, starts the
    /// writers and completes remote parts left incomplete before the last stop.
    ///
    /// # Errors
    /// The connection, the topic set-up or the replay failed, or another writer holds a newer
    /// producer epoch.
    pub async fn connect(cfg: IggyConfig) -> Result<Self, IggyMailboxError> {
        let admin = cfg.connection.client().await?;
        let stream = Identifier::named(&cfg.stream)?;
        let topic = Identifier::named(&cfg.topic)?;
        if admin.get_stream(&stream).await?.is_none() {
            admin
                .create_stream(&cfg.stream, &StreamCreateOptions::default())
                .await?;
        }
        if admin.get_topic(&stream, &topic).await?.is_none() {
            let opts = TopicCreateOptions {
                partitions_count: Some(cfg.partitions),
                durability: Durability::Persisted,
                consumer_offset_durability: Durability::Persisted,
                message_expiry: Some(IggyExpiry::ExpireDuration(IggyDuration::from(
                    cfg.segment_expiry,
                ))),
                ..TopicCreateOptions::default()
            };
            admin.create_topic(&stream, &cfg.topic, &opts).await?;
        }
        let stats = Arc::new(IggyStats::default());
        let senders: Arc<OnceLock<Vec<mpsc::Sender<Job>>>> = Arc::new(OnceLock::new());
        let mut parts = Vec::new();
        let mut incomplete = Vec::new();
        for p in 0..cfg.partitions {
            let shared = Arc::new(Shared {
                partition: p,
                state: Mutex::new(State::default()),
                cache: Mutex::new((BTreeMap::new(), 0)),
                cache_bytes: cfg.cache_bytes,
                reader: cfg.connection.client().await?,
                compactor: cfg.connection.client().await?,
                compacting: AtomicBool::new(false),
                stream: stream.clone(),
                topic: topic.clone(),
                healthy: AtomicBool::new(true),
                stats: stats.clone(),
            });
            let homes = replay(&shared).await?;
            let writer_client = cfg.connection.client().await?;
            let (tx, rx) = mpsc::channel(cfg.queue);
            let mut w = Writer::new(shared.clone(), writer_client, &cfg, senders.clone());
            w.start_epoch().await?;
            incomplete.push(homes);
            tokio::spawn(w.run(rx));
            parts.push(Part { tx, shared });
        }
        let _ = senders.set(parts.iter().map(|p| p.tx.clone()).collect());
        let mailbox = Self {
            parts: Arc::new(parts),
            idem: hmac::Key::new(hmac::HMAC_SHA256, &cfg.idempotency_secret),
            timeout: cfg.timeout,
            generation: cfg.store_generation,
            fault_skip_remote_parts: cfg.fault_skip_remote_parts,
            max_per_device: cfg.max_per_device,
            stats,
        };
        // Remote parts of recent home records that their partitions do not hold (checked in
        // the replayed tag indexes; an 8-byte prefix match counts as held): the re-driver stores
        // them, one home partition at a time.
        let all: Vec<mpsc::Sender<Job>> = mailbox.parts.iter().map(|p| p.tx.clone()).collect();
        for (home, homes) in incomplete.into_iter().enumerate() {
            let Some(h) = mailbox.parts.get(home) else {
                continue;
            };
            let missing: Vec<u64> = homes
                .into_iter()
                .filter(|(_, tag, parts)| {
                    parts.iter().any(|p| {
                        mailbox
                            .parts
                            .get(idx(*p))
                            .is_some_and(|x| x.shared.lock().tag_candidates(tag).is_empty())
                    })
                })
                .map(|(o, _, _)| o)
                .collect();
            if missing.is_empty() {
                continue;
            }
            let shared = h.shared.clone();
            let all = all.clone();
            tokio::spawn(async move {
                for offset in missing {
                    redrive_with(&shared, &all, offset).await;
                }
            });
        }
        Ok(mailbox)
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> Arc<IggyStats> {
        self.stats.clone()
    }

    /// Whether every writer is running (false after a fatal error such as a fenced epoch).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.parts
            .iter()
            .all(|p| p.shared.healthy.load(Ordering::Relaxed))
    }

    fn partitions(&self) -> u32 {
        u32::try_from(self.parts.len()).unwrap_or(1)
    }

    async fn submit(&self, p: u32, job: StoreJob) -> Result<(), MailboxError> {
        let part = self.parts.get(idx(p)).ok_or(MailboxError::Unavailable)?;
        part.tx
            .send(Job::Store(job))
            .await
            .map_err(|_| MailboxError::Unavailable)
    }

    async fn wait(&self, rx: Reply) -> PartResult {
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => r,
            _ => Err(MailboxError::Unavailable),
        }
    }
}

/// A recent home record: its offset, tag and the partitions of its remote parts.
type Home = (u64, [u8; 32], Vec<u32>);

/// Replays a partition; returns the recent home records whose remote parts may be incomplete.
async fn replay(shared: &Shared) -> Result<Vec<Home>, IggyMailboxError> {
    let consumer = Consumer::new(Identifier::named(LOW_WATER_CONSUMER)?);
    let start = shared
        .reader
        .get_consumer_offset(
            &consumer,
            &shared.stream,
            &shared.topic,
            Some(shared.partition),
        )
        .await?
        .map_or(0, |o| o.stored_offset.saturating_add(1));
    let now = now_ms();
    let window = u64::try_from(IDEMPOTENCY_RETENTION.as_millis()).unwrap_or(u64::MAX);
    let mut offset = start;
    let mut homes = Vec::new();
    let mut st = State {
        next_offset: start,
        ..State::default()
    };
    loop {
        let polled = shared
            .reader
            .poll_messages(
                &shared.stream,
                &shared.topic,
                shared.partition,
                &consumer,
                &PollingStrategy::offset(offset),
                PollOptions {
                    count: REPLAY_POLL,
                    ..PollOptions::default()
                },
            )
            .await?;
        if polled.messages.is_empty() {
            break;
        }
        for m in &polled.messages {
            let o = m.header.offset;
            if o < offset {
                continue;
            }
            let Ok(rec) = Record::decode(&m.payload) else {
                return Err(IggyMailboxError::Unreadable {
                    partition: shared.partition,
                    offset: o,
                    version: m.payload.first().copied().unwrap_or(0),
                });
            };
            {
                if let Record::Store {
                    remote,
                    at_ms,
                    tag: Some(tag),
                    ..
                } = &rec
                    && !remote.is_empty()
                    && at_ms.saturating_add(window) >= now
                {
                    homes.push((o, tag.0, remote.iter().map(|r| r.partition).collect()));
                }
                st.apply(o, &rec, window, now);
            }
            offset = o + 1;
        }
    }
    *shared.lock() = st;
    Ok(homes)
}

struct Writer {
    shared: Arc<Shared>,
    client: IggyClient,
    producer_id: u64,
    producer: Option<BatchProducer>,
    max_batch: usize,
    max_per_device: u64,
    ack_interval: Duration,
    compaction_interval: Duration,
    relocate_after: Duration,
    pending_acks: HashMap<DeviceId, u64>,
    /// Tag of a multi-partition send -> (home record offset, accepted at, remote partitions not
    /// yet confirmed).
    incomplete: HashMap<[u8; 32], (u64, tokio::time::Instant, Vec<u32>)>,
    senders: Arc<OnceLock<Vec<mpsc::Sender<Job>>>>,
    tag_window_ms: u64,
}

/// Outcome of a store job before the append.
enum Plan {
    Done(PartResult),
    Append(Vec<(DeviceId, u64)>),
}

impl Writer {
    fn new(
        shared: Arc<Shared>,
        client: IggyClient,
        cfg: &IggyConfig,
        senders: Arc<OnceLock<Vec<mpsc::Sender<Job>>>>,
    ) -> Self {
        Self {
            producer_id: cfg.producer_base + u64::from(shared.partition),
            shared,
            client,
            producer: None,
            max_batch: cfg.max_batch,
            max_per_device: cfg.max_per_device,
            ack_interval: cfg.ack_interval,
            compaction_interval: cfg.compaction_interval,
            relocate_after: cfg.relocate_after,
            pending_acks: HashMap::new(),
            incomplete: HashMap::new(),
            senders,
            tag_window_ms: u64::try_from(IDEMPOTENCY_RETENTION.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Takes over the partition with a producer epoch above every recorded one.
    async fn start_epoch(&mut self) -> Result<(), IggyError> {
        let epoch = self
            .shared
            .lock()
            .owner_epoch
            .checked_add(1)
            .ok_or(IggyError::InvalidCommand)?;
        let p = BatchProducer::new(self.producer_id, epoch, 0).ok_or(IggyError::InvalidCommand)?;
        self.producer = Some(p);
        let rec = Record::Owner { epoch };
        let base = self.append_once(vec![rec.encode()]).await?;
        let mut st = self.shared.lock();
        st.owner_epoch = epoch;
        st.next_offset = base + 1;
        Ok(())
    }

    /// Appends payloads once with the current producer; returns the base offset.
    async fn append_once(&mut self, payloads: Vec<Bytes>) -> Result<u64, IggyError> {
        let producer = self.producer.ok_or(IggyError::InvalidCommand)?;
        let count = u32::try_from(payloads.len()).unwrap_or(u32::MAX);
        let mut msgs = Vec::with_capacity(payloads.len());
        for p in payloads {
            msgs.push(IggyMessage::builder().payload(p).build()?);
        }
        let resp = self
            .client
            .send_producer_messages(
                &self.shared.stream,
                &self.shared.topic,
                self.shared.partition,
                producer,
                &mut msgs,
            )
            .await?;
        self.producer = Some(producer.next(count));
        let expected = self.shared.lock().next_offset;
        Ok(resp
            .confirmations
            .first()
            .map_or(expected, |c| c.base_offset))
    }

    /// Appends until Iggy confirms (same producer sequence on every attempt, so written once).
    /// `None` after a fatal error: the writer stops.
    async fn append(&mut self, payloads: Vec<Bytes>) -> Option<u64> {
        let mut backoff = Duration::from_millis(20);
        loop {
            match self.append_once(payloads.clone()).await {
                Ok(base) => return Some(base),
                Err(
                    e @ (IggyError::ProducerEpochFenced | IggyError::ProducerSequenceOutOfOrder),
                ) => {
                    tracing::error!(
                        code = e.as_code(),
                        "mailbox writer fenced by another writer; stopping"
                    );
                    self.shared.healthy.store(false, Ordering::Relaxed);
                    return None;
                }
                Err(e) => {
                    self.shared.stats.resends.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(code = e.as_code(), "mailbox append failed; resending");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                }
            }
        }
    }

    async fn run(mut self, mut rx: mpsc::Receiver<Job>) {
        let mut ack_tick = tokio::time::interval(self.ack_interval);
        let mut compact_tick = tokio::time::interval(self.compaction_interval);
        let mut redrive_tick = tokio::time::interval(REDRIVE_AFTER);
        compact_tick.tick().await;
        let mut batch: Vec<StoreJob> = Vec::with_capacity(self.max_batch);
        loop {
            if !self.shared.healthy.load(Ordering::Relaxed) {
                // Fenced: refuse everything from now on.
                while let Some(job) = rx.recv().await {
                    if let Job::Store(j) = job {
                        let _ = j.reply.send(Err(MailboxError::Unavailable));
                    }
                }
                return;
            }
            tokio::select! {
                biased;
                _ = ack_tick.tick() => self.flush_acks().await,
                _ = compact_tick.tick() => { self.start_compaction(None); }
                _ = redrive_tick.tick() => self.redrive_stale(),
                job = rx.recv() => {
                    let Some(job) = job else { return };
                    self.take(job, &mut batch).await;
                    while batch.len() < self.max_batch {
                        match rx.try_recv() {
                            Ok(j) => self.take(j, &mut batch).await,
                            Err(_) => break,
                        }
                    }
                    if !batch.is_empty() {
                        self.commit(&mut batch).await;
                    }
                }
            }
        }
    }

    async fn take(&mut self, job: Job, batch: &mut Vec<StoreJob>) {
        match job {
            Job::Store(j) => batch.push(j),
            Job::Ack(d, s) => {
                let e = self.pending_acks.entry(d).or_default();
                *e = (*e).max(s);
            }
            Job::Expire(age_ms, reply) => {
                let n = self.start_compaction(Some(age_ms));
                let _ = reply.send(n);
            }
            Job::Relocated { items, last } => {
                if !items.is_empty() {
                    self.relocate(items, now_ms()).await;
                }
                if last {
                    self.finish_compaction().await;
                    self.shared.compacting.store(false, Ordering::Release);
                    self.shared
                        .stats
                        .compactions
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Job::PartDone(tag, p) => {
                if let Some((_, _, rest)) = self.incomplete.get_mut(&tag) {
                    rest.retain(|x| *x != p);
                    if rest.is_empty() {
                        self.incomplete.remove(&tag);
                    }
                }
            }
        }
    }

    fn redrive_stale(&mut self) {
        let now = tokio::time::Instant::now();
        let stale: Vec<([u8; 32], u64)> = self
            .incomplete
            .iter()
            .filter(|(_, (_, at, _))| now.duration_since(*at) >= REDRIVE_AFTER)
            .map(|(t, (o, _, _))| (*t, *o))
            .collect();
        for (tag, offset) in stale {
            self.incomplete.remove(&tag);
            let shared = self.shared.clone();
            let senders = self.senders.clone();
            tokio::spawn(async move {
                if let Some(s) = senders.get() {
                    redrive_with(&shared, s, offset).await;
                }
            });
        }
    }

    /// Looks up a tag: the record that carries it, if any (prefix hits are verified).
    async fn find_tag(&self, tag: &[u8; 32]) -> Result<Option<(u64, Record)>, MailboxError> {
        let candidates = self.shared.lock().tag_candidates(tag);
        for offset in candidates {
            let rec = self.shared.record(offset).await?;
            if let Record::Store { tag: Some(t), .. } = &rec
                && t.0 == *tag
            {
                return Ok(Some((offset, rec)));
            }
        }
        Ok(None)
    }

    async fn commit(&mut self, batch: &mut Vec<StoreJob>) {
        let now = now_ms();
        let mut plans: Vec<Plan> = Vec::with_capacity(batch.len());
        let mut records: Vec<Record> = Vec::new();
        let mut provisional: HashMap<DeviceId, u64> = HashMap::new();
        let mut epochs: HashMap<[u8; 16], u64> = HashMap::new();
        let mut batch_tags: Vec<[u8; 32]> = Vec::new();
        for job in batch.iter() {
            plans.push(
                self.plan(
                    job,
                    now,
                    &mut records,
                    &mut provisional,
                    &mut epochs,
                    &mut batch_tags,
                )
                .await,
            );
        }
        let payloads: Vec<Bytes> = records.iter().map(Record::encode).collect();
        let base = if payloads.is_empty() {
            Some(self.shared.lock().next_offset)
        } else {
            self.append(payloads.clone()).await
        };
        let Some(base) = base else {
            for job in batch.drain(..) {
                let _ = job.reply.send(Err(MailboxError::Unavailable));
            }
            return;
        };
        if !payloads.is_empty() {
            self.shared.stats.commits.fetch_add(1, Ordering::Relaxed);
            let mut st = self.shared.lock();
            st.note_batch(base, now);
            for (i, rec) in records.iter().enumerate() {
                let offset = base + n64(i);
                st.apply(offset, rec, self.tag_window_ms, now);
                if let Record::Store {
                    remote,
                    tag: Some(tag),
                    ..
                } = rec
                    && !remote.is_empty()
                {
                    let parts = remote.iter().map(|r| r.partition).collect();
                    self.incomplete
                        .insert(tag.0, (offset, tokio::time::Instant::now(), parts));
                }
            }
            st.next_offset = base + n64(payloads.len());
            drop(st);
            for (i, p) in payloads.into_iter().enumerate() {
                self.shared.cache_put(base + n64(i), p);
            }
        }
        for (job, plan) in batch.drain(..).zip(plans) {
            let r = match plan {
                Plan::Done(r) => r,
                Plan::Append(seqs) => {
                    self.shared.stats.sends.fetch_add(1, Ordering::Relaxed);
                    self.shared
                        .stats
                        .entries
                        .fetch_add(n64(seqs.len()), Ordering::Relaxed);
                    Ok((seqs, false))
                }
            };
            let _ = job.reply.send(r);
        }
    }

    #[allow(clippy::too_many_arguments, reason = "one batch's scratch state")]
    async fn plan(
        &self,
        job: &StoreJob,
        now: u64,
        records: &mut Vec<Record>,
        provisional: &mut HashMap<DeviceId, u64>,
        epochs: &mut HashMap<[u8; 16], u64>,
        batch_tags: &mut Vec<[u8; 32]>,
    ) -> Plan {
        let devices = job.local.devices();
        if let Some((tag, fp)) = &job.tag {
            if batch_tags.contains(tag) {
                // The same send twice in one batch: the client retried while the first was queued.
                return Plan::Done(Err(MailboxError::Unavailable));
            }
            match self.find_tag(tag).await {
                Err(e) => return Plan::Done(Err(e)),
                Ok(Some((
                    _,
                    Record::Store {
                        local,
                        tag: Some((_, stored_fp)),
                        ..
                    },
                ))) => {
                    // The same key for the same recipient set is a retry; for another set it is
                    // refused (reason 7), whichever part of the earlier send this partition holds.
                    return Plan::Done(if stored_fp == *fp {
                        Ok((state::local_seqs(&local), true))
                    } else {
                        Err(MailboxError::IdempotencyConflict)
                    });
                }
                Ok(_) => {}
            }
        }
        let mut mls = None;
        {
            let st = self.shared.lock();
            if let Some(m) = &job.mls {
                let cur = epochs
                    .get(&m.group)
                    .copied()
                    .or_else(|| st.epochs.get(&m.group).copied())
                    .unwrap_or(0);
                if cur != m.epoch {
                    return Plan::Done(Err(MailboxError::StaleEpoch));
                }
                mls = Some((m.group, m.epoch + 1));
            }
            for d in &devices {
                if st.devices.get(d).map_or(0, |s| n64(s.pending.len())) >= self.max_per_device {
                    return Plan::Done(Err(MailboxError::Full));
                }
            }
        }
        if let Some((g, e)) = mls {
            epochs.insert(g, e);
        }
        let mut seqs = Vec::with_capacity(devices.len());
        {
            let st = self.shared.lock();
            for d in &devices {
                let last = provisional
                    .get(d)
                    .copied()
                    .or_else(|| st.devices.get(d).map(|s| s.last))
                    .unwrap_or(0);
                provisional.insert(*d, last + 1);
                seqs.push((*d, last + 1));
            }
        }
        let local = match &job.local {
            LocalReq::PerDevice(items) => Local::PerDevice(
                items
                    .iter()
                    .zip(&seqs)
                    .map(|((d, env), (_, s))| (*d, *s, env.clone()))
                    .collect(),
            ),
            LocalReq::Shared { body, .. } => Local::Shared {
                entries: seqs.clone(),
                body: body.clone(),
            },
        };
        if let Some((t, _)) = job.tag {
            batch_tags.push(t);
        }
        records.push(Record::Store {
            tag: job.tag,
            at_ms: now,
            mls,
            local,
            remote: job.remote.clone(),
        });
        Plan::Append(seqs)
    }

    async fn flush_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }
        let items: Vec<(DeviceId, u64)> = self.pending_acks.drain().collect();
        let rec = Record::Ack(items.clone());
        if let Some(base) = self.append(vec![rec.encode()]).await {
            self.shared
                .stats
                .ack_commits
                .fetch_add(1, Ordering::Relaxed);
            let mut st = self.shared.lock();
            st.next_offset = base + 1;
            for (d, s) in &items {
                st.ack(d, *s);
            }
        }
    }

    /// Starts a compaction pass (also from `expire_older_than` with an age): drops expired
    /// entries from the index at once; the compactor task reads the pending entries older than
    /// `relocate_after` off the write path and hands them back to be copied forward
    /// ([`Job::Relocated`]). Returns how many entries expired.
    fn start_compaction(&mut self, age_ms: Option<u64>) -> u64 {
        let now = now_ms();
        let max_age = age_ms
            .unwrap_or_else(|| u64::try_from(MAX_ENVELOPE_AGE.as_millis()).unwrap_or(u64::MAX));
        let relocate_ms = u64::try_from(self.relocate_after.as_millis()).unwrap_or(u64::MAX);
        let (expired, mut moves) = {
            let mut st = self.shared.lock();
            let expired = st.expire(now.saturating_sub(max_age));
            let cut = st.offset_at(now.saturating_sub(relocate_ms));
            (expired, st.entries_before(cut))
        };
        if self.shared.compacting.swap(true, Ordering::AcqRel) {
            return expired;
        }
        let me = self
            .senders
            .get()
            .and_then(|s| s.get(idx(self.shared.partition)))
            .cloned();
        let Some(me) = me else {
            self.shared.compacting.store(false, Ordering::Release);
            return expired;
        };
        moves.truncate(RELOCATE_PER_PASS);
        tokio::spawn(compactor(self.shared.clone(), moves, me));
        expired
    }

    /// Ends a pass: snapshots the counters and moves the low-water offset up to the oldest
    /// record still needed (pending entries, the idempotency window, incomplete parts).
    async fn finish_compaction(&mut self) {
        let now = now_ms();
        let relocate_ms = u64::try_from(self.relocate_after.as_millis()).unwrap_or(u64::MAX);
        let (cut, tag_cut, min_live, current_low) = {
            let st = self.shared.lock();
            (
                st.offset_at(now.saturating_sub(relocate_ms)),
                st.offset_at(now.saturating_sub(self.tag_window_ms)),
                st.min_live(),
                st.times.front().map_or(st.next_offset, |(o, _)| *o),
            )
        };
        let mut low = cut.min(tag_cut);
        if let Some(m) = min_live {
            low = low.min(m);
        }
        if let Some(m) = self.incomplete.values().map(|(o, _, _)| *o).min() {
            low = low.min(m);
        }
        if low <= current_low {
            return;
        }
        // Snapshot the counters so the records below `low` are no longer needed, then move it.
        let Some(snap) = self.snapshot(now).await else {
            return;
        };
        let low = low.min(snap);
        let Ok(name) = Identifier::named(LOW_WATER_CONSUMER) else {
            return;
        };
        if self
            .client
            .store_consumer_offset(
                &Consumer::new(name),
                &self.shared.stream,
                &self.shared.topic,
                Some(self.shared.partition),
                low.saturating_sub(1),
            )
            .await
            .is_ok()
        {
            let mut st = self.shared.lock();
            st.prune_times(low);
            st.prune_tags(tag_cut.min(low));
        }
    }

    async fn relocate(&mut self, items: Vec<(DeviceId, u64, u64, Bytes)>, now: u64) -> bool {
        let rec = Record::Relocate(items);
        let payload = rec.encode();
        let Some(base) = self.append(vec![payload.clone()]).await else {
            return false;
        };
        if let Record::Relocate(items) = &rec {
            self.shared
                .stats
                .relocated
                .fetch_add(n64(items.len()), Ordering::Relaxed);
        }
        let mut st = self.shared.lock();
        st.apply(base, &rec, 0, now);
        st.note_batch(base, now);
        drop(st);
        self.shared.cache_put(base, payload);
        true
    }

    /// Writes the counter snapshot; returns the offset of its first record.
    async fn snapshot(&mut self, now: u64) -> Option<u64> {
        let (owner, devices, groups) = {
            let st = self.shared.lock();
            let owner = st.owner_epoch;
            let d: Vec<(DeviceId, u64, u64)> = st
                .devices
                .iter()
                .map(|(d, s)| (*d, s.last, s.acked))
                .collect();
            let g: Vec<([u8; 16], u64)> = st.epochs.iter().map(|(g, e)| (*g, *e)).collect();
            (owner, d, g)
        };
        let per = (COMPACTION_RECORD_BYTES / 32).max(1);
        let mut records = Vec::new();
        let mut chunks = devices.chunks(per).peekable();
        if chunks.peek().is_none() {
            records.push(Record::Snapshot {
                owner,
                devices: vec![],
                groups: groups.clone(),
            });
        }
        let mut first = true;
        for c in chunks {
            records.push(Record::Snapshot {
                owner,
                devices: c.to_vec(),
                groups: if first { groups.clone() } else { vec![] },
            });
            first = false;
        }
        let payloads: Vec<Bytes> = records.iter().map(Record::encode).collect();
        let n = n64(payloads.len());
        let base = self.append(payloads).await?;
        let mut st = self.shared.lock();
        st.next_offset = base + n;
        st.note_batch(base, now);
        Some(base)
    }
}

/// Reads the entries a compaction pass copies forward (on its own connection, many records per
/// poll) and hands them to the writer in records of about `COMPACTION_RECORD_BYTES`.
async fn compactor(shared: Arc<Shared>, moves: Vec<(DeviceId, Entry)>, writer: mpsc::Sender<Job>) {
    let mut items = Vec::new();
    let mut bytes = 0usize;
    for chunk in moves.chunks(4096) {
        let offsets: Vec<u64> = chunk.iter().map(|(_, e)| e.offset).collect();
        let Ok(recs) = shared.records(&shared.compactor, &offsets).await else {
            // Unread entries stay where they are; the low-water offset cannot pass them.
            break;
        };
        for (d, e) in chunk {
            let env = match recs.get(&e.offset) {
                Some(Record::Store { local, .. }) => local.envelope(idx(e.slot)),
                Some(Record::Relocate(items)) => items.get(idx(e.slot)).map(|i| i.3.clone()),
                _ => None,
            };
            let Some(env) = env else { continue };
            bytes += env.len() + 40;
            items.push((*d, e.seq, e.at_ms, env));
            if bytes >= COMPACTION_RECORD_BYTES {
                let full = std::mem::take(&mut items);
                bytes = 0;
                if writer
                    .send(Job::Relocated {
                        items: full,
                        last: false,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = writer.send(Job::Relocated { items, last: true }).await;
}

/// The re-driver, started from a writer.
async fn redrive_with(shared: &Shared, senders: &[mpsc::Sender<Job>], offset: u64) {
    let mut backoff = Duration::from_millis(100);
    loop {
        if let Ok(Record::Store { tag, remote, .. }) = shared.record(offset).await {
            let mut all = true;
            for r in remote {
                let Some(tx) = senders.get(idx(r.partition)) else {
                    continue;
                };
                let local = match r.shared {
                    Some(body) => LocalReq::Shared {
                        devices: r.items.iter().map(|(d, _)| *d).collect(),
                        body,
                    },
                    None => LocalReq::PerDevice(r.items),
                };
                let (rtx, rrx) = oneshot::channel();
                let job = StoreJob {
                    tag,
                    mls: None,
                    local,
                    remote: vec![],
                    reply: rtx,
                };
                let ok = tx.send(Job::Store(job)).await.is_ok()
                    && matches!(
                        tokio::time::timeout(Duration::from_secs(30), rrx).await,
                        Ok(Ok(Ok(_)))
                    );
                if ok {
                    shared.stats.redriven.fetch_add(1, Ordering::Relaxed);
                } else {
                    all = false;
                }
            }
            if all {
                return;
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

impl Mailbox for IggyMailbox {
    #[allow(
        clippy::too_many_lines,
        reason = "routing of one send across partitions, kept in one place"
    )]
    async fn store(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        let n = self.partitions();
        let devices: Vec<DeviceId> = req.payload.devices().copied().collect();
        let multi = devices
            .iter()
            .any(|d| partition_of(d, n) != devices.first().map_or(0, |f| partition_of(f, n)));
        // A multi-partition send always carries a tag, so its parts are stored exactly once
        // (by this call or by the re-driver).
        let key = match req.idempotency_key {
            Some(k) => Some(idempotency_tag(&self.idem, &k)),
            None if multi => {
                let mut t = [0u8; 32];
                getrandom::fill(&mut t).map_err(|_| MailboxError::Unavailable)?;
                Some(t)
            }
            None => None,
        };
        let tag = key.map(|t| (t, recipients_fingerprint(&devices)));
        // Split by partition.
        let mut by_part: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (i, d) in devices.iter().enumerate() {
            by_part.entry(partition_of(d, n)).or_default().push(i);
        }
        // Home: the MLS group's partition (its epoch lives there); otherwise the partition with
        // most recipients (the first recipient's on a tie), so that most sends are one append.
        // Deterministic for a retried request.
        let home = if let Some(m) = &req.mls {
            u32::try_from(hash16(&m.group) % u64::from(n)).unwrap_or(0)
        } else {
            let first = devices.first().map_or(0, |d| partition_of(d, n));
            by_part
                .iter()
                .max_by_key(|(p, idx)| (idx.len(), **p == first))
                .map_or(first, |(p, _)| *p)
        };
        let part_req = |idx: &[usize]| -> LocalReq {
            match &req.payload {
                Payload::PerDevice(items) => LocalReq::PerDevice(
                    idx.iter()
                        .filter_map(|i| items.get(*i))
                        .map(|e| (e.device, e.envelope.clone()))
                        .collect(),
                ),
                Payload::Shared { devices, body } => LocalReq::Shared {
                    devices: idx
                        .iter()
                        .filter_map(|i| devices.get(*i))
                        .copied()
                        .collect(),
                    body: body.clone(),
                },
            }
        };
        let local = by_part
            .get(&home)
            .map_or_else(|| part_req(&[]), |idx| part_req(idx));
        let remote: Vec<Remote> = by_part
            .iter()
            .filter(|(p, _)| **p != home)
            .map(|(p, idx)| match part_req(idx) {
                LocalReq::PerDevice(items) => Remote {
                    partition: *p,
                    items,
                    shared: None,
                },
                LocalReq::Shared { devices, body } => Remote {
                    partition: *p,
                    items: devices.into_iter().map(|d| (d, Bytes::new())).collect(),
                    shared: Some(body),
                },
            })
            .collect();
        if local.is_empty() && remote.is_empty() {
            return Ok(StoreOutcome {
                seqs: vec![],
                replayed: false,
            });
        }
        // Capacity check across partitions before anything is written (soft limit).
        for d in &devices {
            let p = self
                .parts
                .get(idx(partition_of(d, n)))
                .ok_or(MailboxError::Unavailable)?;
            if p.shared
                .lock()
                .devices
                .get(d)
                .map_or(0, |s| n64(s.pending.len()))
                >= self.max_per_device
            {
                return Err(MailboxError::Full);
            }
        }
        let mut seq_of: HashMap<DeviceId, u64> = HashMap::with_capacity(devices.len());
        let (tx, rx) = oneshot::channel();
        let job = StoreJob {
            tag,
            mls: req.mls,
            local,
            remote: remote.clone(),
            reply: tx,
        };
        self.submit(home, job).await?;
        let (home_seqs, mut replayed) = self.wait(rx).await?;
        for (d, s) in home_seqs {
            seq_of.insert(d, s);
        }
        if self.fault_skip_remote_parts && !remote.is_empty() {
            return Err(MailboxError::Unavailable);
        }
        // Remote parts (idempotent under the tag; completed by the re-driver if this fails).
        let mut waits = Vec::new();
        for r in remote {
            let (tx, rx) = oneshot::channel();
            let local = match r.shared {
                Some(body) => LocalReq::Shared {
                    devices: r.items.iter().map(|(d, _)| *d).collect(),
                    body,
                },
                None => LocalReq::PerDevice(r.items),
            };
            let job = StoreJob {
                tag,
                mls: None,
                local,
                remote: vec![],
                reply: tx,
            };
            self.submit(r.partition, job).await?;
            waits.push((r.partition, rx));
        }
        let home_tx = self.parts.get(idx(home)).map(|p| p.tx.clone());
        for (p, w) in waits {
            let (part_seqs, part_replayed) = self.wait(w).await?;
            replayed &= part_replayed;
            for (d, s) in part_seqs {
                seq_of.insert(d, s);
            }
            if let (Some(t), Some(h)) = (tag, &home_tx) {
                let _ = h.send(Job::PartDone(t.0, p)).await;
            }
        }
        let seqs = devices
            .iter()
            .map(|d| seq_of.get(d).copied().ok_or(MailboxError::Unavailable))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StoreOutcome { seqs, replayed })
    }

    async fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        let part = self
            .parts
            .get(
                partition_of(device, self.partitions())
                    .try_into()
                    .unwrap_or(usize::MAX),
            )
            .ok_or(MailboxError::Unavailable)?;
        let entries: Vec<Entry> = {
            let st = part.shared.lock();
            st.devices
                .get(device)
                .map(|s| {
                    s.pending
                        .iter()
                        .filter(|e| e.seq > after_seq)
                        .take(limit)
                        .copied()
                        .collect()
                })
                .unwrap_or_default()
        };
        let offsets: Vec<u64> = entries.iter().map(|e| e.offset).collect();
        let recs = part.shared.records(&part.shared.reader, &offsets).await?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let env = match recs.get(&e.offset) {
                Some(Record::Store { local, .. }) => local.envelope(idx(e.slot)),
                Some(Record::Relocate(items)) => items.get(idx(e.slot)).map(|i| i.3.clone()),
                _ => None,
            };
            out.push(Stored {
                seq: e.seq,
                envelope: env.ok_or(MailboxError::Unavailable)?,
            });
        }
        Ok(out)
    }

    async fn ack_up_to(&self, device: &DeviceId, up_to_seq: u64) -> Result<(), MailboxError> {
        let part = self
            .parts
            .get(
                partition_of(device, self.partitions())
                    .try_into()
                    .unwrap_or(usize::MAX),
            )
            .ok_or(MailboxError::Unavailable)?;
        part.tx
            .send(Job::Ack(*device, up_to_seq))
            .await
            .map_err(|_| MailboxError::Unavailable)
    }

    async fn expire_older_than(&self, age: Duration) -> Result<u64, MailboxError> {
        let age_ms = u64::try_from(age.as_millis()).unwrap_or(u64::MAX);
        let mut total = 0;
        for p in self.parts.iter() {
            let (tx, rx) = oneshot::channel();
            p.tx.send(Job::Expire(age_ms, tx))
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            total += rx.await.map_err(|_| MailboxError::Unavailable)?;
        }
        Ok(total)
    }

    fn store_generation(&self) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        std::future::ready(Ok(self.generation))
    }

    fn count_pending(
        &self,
        device: &DeviceId,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        std::future::ready(self.pending_of(device))
    }
}

impl IggyMailbox {
    fn pending_of(&self, device: &DeviceId) -> Result<u64, MailboxError> {
        let part = self
            .parts
            .get(
                partition_of(device, self.partitions())
                    .try_into()
                    .unwrap_or(usize::MAX),
            )
            .ok_or(MailboxError::Unavailable)?;
        let st = part.shared.lock();
        Ok(st.devices.get(device).map_or(0, |s| n64(s.pending.len())))
    }
}
