//! Mailbox on Apache Iggy (D-0029), with deletion on acknowledgement by key destruction
//! (D-0031): an append-only log is the durable truth, and every record in it is sealed.
//!
//! - **Partitions and writers.** A topic with `partitions` partitions; each device belongs to one
//!   (a hash of its ID). One writer task per partition, in this process, owns that partition's
//!   state: every device's `seq` counter and acknowledged `seq`, the index of pending entries
//!   (where their sealed slots are, not ciphertext), idempotency tags, MLS epochs and the key
//!   ring. It batches the requests that queue while it commits (natural group commit).
//! - **Durability.** The topic's `durability` is `persisted`: Iggy fsyncs before it confirms, and
//!   a send is acknowledged only after that (invariant 1). A key window is in the key file before
//!   any record sealed with it is appended.
//! - **Deletion on acknowledgement.** Each entry (envelope, device, `seq`) is sealed under its own
//!   leaf key of a puncturable key tree; an ACK punctures the leaf, and the punctured key state is
//!   written with the ACK checkpoint: the entry cannot be decrypted again, from the log or from any
//!   later key state ([`keys`]). A window's metadata key is destroyed once all its records are below
//!   the low-water offset.
//! - **One writer per partition.** Each writer is an idempotent Iggy producer with a fixed id and a
//!   new epoch at every start (recorded in the log). Iggy refuses batches of an older epoch
//!   (`ProducerEpochFenced`); a batch whose outcome is unknown is resent with the same sequence.
//! - **Multi-partition sends.** A send's home partition is its MLS group's, else the one with most
//!   recipients. The home record holds the home devices' entries and the parts for other
//!   partitions (each in its own slot, punctured once stored there); a re-driver completes any
//!   part that failed, also after a restart.
//! - **Idempotency.** A tag is stored with a fingerprint of the send's whole recipient set; a
//!   reused key is a retry only when both match, else it is refused. A retry after delivery gets
//!   `seq` 0 for entries already acknowledged (nothing left to route).
//! - **Start-up.** The key file is loaded and each partition replayed from its low-water offset; a
//!   record that does not open stops the start.
//! - **Compaction** (off the write path): expired entries are acknowledged, pending entries older
//!   than `relocate_after` are re-sealed forward, a counter snapshot is written, the low-water
//!   offset (an Iggy consumer offset) moves up and windows below it are destroyed. Iggy deletes
//!   sealed segments below it after the topic's `message_expiry`.

mod keys;
mod record;
mod sealed;
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
use self::keys::KeyFile;
use self::record::{Local, Record, Remote};
use self::sealed::{Meta, OpenError, Sealed};
use self::state::{Entry, Fact, Idem, State};
use crate::{
    IDEMPOTENCY_RETENTION, MAX_ENVELOPE_AGE, Mailbox, MailboxError, MlsCommit, Payload,
    StoreOutcome, StoreRequest, Stored, idempotency_tag,
};

mod config;

/// Why the Iggy mailbox could not start.
#[derive(Debug, thiserror::Error)]
pub enum IggyMailboxError {
    /// Iggy refused or failed a request.
    #[error("iggy error {}", .0.as_code())]
    Iggy(#[from] IggyError),
    /// The log holds a record this build cannot open (another version, missing keys, or
    /// tampering). Replaying past it would lose counters and reuse `seq`s, so the mailbox does
    /// not start (runbook: "Mailbox log unreadable").
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
    /// A key file is unreadable (wrong master key, corruption) or cannot be written.
    #[error("mailbox key file of partition {partition} unusable")]
    Keys {
        /// Partition.
        partition: u32,
    },
}

/// The record format version this build reads and writes.
pub const RECORD_VERSION: u8 = sealed::VERSION;

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
/// Idempotency entries are written to their topic this often. Until then their store records
/// hold the low-water offset back, so a crash loses none (replay rebuilds them from the log).
const IDEM_FLUSH: Duration = Duration::from_secs(1);
/// The idempotency topic keeps its records this long (the idempotency window and a margin).
const IDEM_EXPIRY: Duration = Duration::from_hours(7);

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
    /// Key windows destroyed.
    pub windows_destroyed: AtomicU64,
    /// Key file writes.
    pub key_writes: AtomicU64,
}

fn n64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn idx(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
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

/// First 16 bytes of HMAC-SHA256 (server key) over the sorted recipient device IDs: keyed, so
/// whoever holds the log cannot test guessed recipient sets against it.
fn recipients_fingerprint(key: &hmac::Key, devices: &[DeviceId]) -> [u8; 16] {
    let mut sorted: Vec<&DeviceId> = devices.iter().collect();
    sorted.sort_unstable();
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(b"songbird-recipients-v1");
    for d in sorted {
        ctx.update(d.as_bytes());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(ctx.sign().as_ref().get(..16).unwrap_or(&[0; 16]));
    out
}

/// Idempotency topic records: (tag, keyed fingerprint, `at_ms`, store record offset)*.
fn encode_idem(items: &[([u8; 32], Idem)]) -> Bytes {
    let mut b = Vec::with_capacity(5 + items.len() * 64);
    b.push(1u8);
    b.extend_from_slice(&u32::try_from(items.len()).unwrap_or(u32::MAX).to_be_bytes());
    for (t, i) in items {
        b.extend_from_slice(t);
        b.extend_from_slice(&i.fp);
        b.extend_from_slice(&i.at_ms.to_be_bytes());
        b.extend_from_slice(&i.offset.to_be_bytes());
    }
    Bytes::from(b)
}

fn decode_idem(b: &[u8]) -> Option<Vec<([u8; 32], Idem)>> {
    let (head, rest) = b.split_at_checked(5)?;
    if head.first() != Some(&1) {
        return None;
    }
    let n = usize::try_from(u32::from_be_bytes(head.get(1..5)?.try_into().ok()?)).ok()?;
    if rest.len() != n.checked_mul(64)? {
        return None;
    }
    rest.as_chunks::<64>()
        .0
        .iter()
        .map(|c| {
            Some((
                c.get(..32)?.try_into().ok()?,
                Idem {
                    fp: c.get(32..48)?.try_into().ok()?,
                    at_ms: u64::from_be_bytes(c.get(48..56)?.try_into().ok()?),
                    offset: u64::from_be_bytes(c.get(56..64)?.try_into().ok()?),
                },
            ))
        })
        .collect()
}

fn partition_of(d: &DeviceId, n: u32) -> u32 {
    u32::try_from(hash16(d.as_bytes()) % u64::from(n.max(1))).unwrap_or(0)
}

/// Slots a record seals.
fn slots_of(rec: &Record) -> u32 {
    let n = match rec {
        Record::Store { local, remote, .. } => {
            local.len() + usize::from(matches!(local, Local::Shared { .. })) + remote.len()
        }
        Record::Relocate(items) => items.len(),
        _ => 0,
    };
    u32::try_from(n).unwrap_or(u32::MAX)
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
    fn from_remote(r: Remote) -> Self {
        match r.shared {
            Some(body) => Self::Shared {
                devices: r.items.iter().map(|(d, _)| *d).collect(),
                body,
            },
            None => Self::PerDevice(r.items),
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
    /// A part slot of a home record to puncture (its part is stored).
    Puncture(u64, u32),
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
    keys: Arc<KeyFile>,
    /// Sealed record payloads by offset (recently written or read), bounded by `cache_bytes`.
    cache: Mutex<(BTreeMap<u64, Bytes>, usize)>,
    cache_bytes: usize,
    reader: IggyClient,
    /// Connection of the compactor (old records are read off the write and drain paths).
    compactor: IggyClient,
    /// A compaction pass is running.
    compacting: AtomicBool,
    stream: Identifier,
    topic: Identifier,
    /// The idempotency topic (keyed hashes only, D-0031).
    idem_topic: Identifier,
    /// Idempotency entries waiting for the idempotency topic, and those being written: the
    /// low-water offset cannot pass their store records until they are durable there.
    idem_queue: Mutex<Vec<([u8; 32], Idem)>>,
    idem_inflight: Mutex<Vec<([u8; 32], Idem)>>,
    healthy: AtomicBool,
    stats: Arc<IggyStats>,
}

fn unavailable(what: &str, e: &IggyError) -> MailboxError {
    tracing::warn!(code = e.as_code(), "{what}");
    MailboxError::Unavailable
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

    /// The sealed records at `offsets` (cache, else the log): nearby offsets are read with one
    /// poll.
    async fn sealed(
        &self,
        client: &IggyClient,
        offsets: &[u64],
    ) -> Result<HashMap<u64, Sealed>, MailboxError> {
        let mut wanted: Vec<u64> = offsets.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut out = HashMap::with_capacity(wanted.len());
        let mut missing = Vec::new();
        for o in wanted {
            match self.cache_get(o) {
                Some(p) => {
                    out.insert(o, Sealed::parse(&p).map_err(|_| MailboxError::Unavailable)?);
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
                    let s = Sealed::parse(&m.payload).map_err(|_| MailboxError::Unavailable)?;
                    out.insert(m.header.offset, s);
                }
            }
            if want.iter().any(|o| !out.contains_key(o)) {
                return Err(MailboxError::Unavailable);
            }
            i = j;
        }
        Ok(out)
    }

    /// One sealed record.
    async fn one(&self, offset: u64) -> Result<Sealed, MailboxError> {
        self.sealed(&self.reader, &[offset])
            .await?
            .remove(&offset)
            .ok_or(MailboxError::Unavailable)
    }

    /// Opens a record's metadata.
    fn meta(&self, s: &Sealed) -> Result<Meta, MailboxError> {
        s.meta(&self.lock().ring, self.partition)
            .map_err(|_| MailboxError::Unavailable)
    }

    /// Opens slot `i` (`None`: punctured).
    fn slot(&self, s: &Sealed, i: u32) -> Result<Option<Vec<u8>>, MailboxError> {
        s.slot(&self.lock().ring, self.partition, i)
            .map_err(|_| MailboxError::Unavailable)
    }

    /// The envelope of a pending entry.
    #[allow(clippy::many_single_char_names, reason = "short-lived locals")]
    fn envelope(&self, s: &Sealed, e: &Entry) -> Result<Bytes, MailboxError> {
        let i = e
            .leaf
            .checked_sub(s.first_leaf)
            .ok_or(MailboxError::Unavailable)?;
        match self.meta(s)? {
            Meta::Store(m) => {
                if m.shared {
                    let b = self.slot(s, m.n_local)?.ok_or(MailboxError::Unavailable)?;
                    Ok(Bytes::from(b))
                } else {
                    let plain = self.slot(s, i)?.ok_or(MailboxError::Unavailable)?;
                    sealed::decode_entry(&plain, false)
                        .ok()
                        .and_then(|e| e.envelope)
                        .ok_or(MailboxError::Unavailable)
                }
            }
            Meta::Relocate { .. } => {
                let plain = self.slot(s, i)?.ok_or(MailboxError::Unavailable)?;
                sealed::decode_relocated(&plain)
                    .ok()
                    .and_then(|e| e.envelope)
                    .ok_or(MailboxError::Unavailable)
            }
            Meta::Plain(_) => Err(MailboxError::Unavailable),
        }
    }

    /// Writes the key file if anything changed (punctures, windows). Blocking I/O off the
    /// async threads.
    async fn persist_keys(&self) -> Result<(), MailboxError> {
        let sealed = {
            let mut st = self.lock();
            // Slots written since the last write get individual keys and leave the tree, so the
            // file stays proportional to the pending entries.
            if st.ring.advance().is_err() {
                return Err(MailboxError::Unavailable);
            }
            if !st.ring.dirty {
                return Ok(());
            }
            st.ring.dirty = false;
            self.keys.seal(&st.ring)
        };
        let ok = match sealed {
            Ok(bytes) => {
                let file = self.keys.clone();
                match tokio::task::spawn_blocking(move || file.write(&bytes)).await {
                    Ok(Ok(())) => true,
                    Ok(Err(keys::KeyError::Fenced)) => {
                        tracing::error!("mailbox key file owned by a newer writer; stopping");
                        self.healthy.store(false, Ordering::Relaxed);
                        false
                    }
                    _ => false,
                }
            }
            Err(_) => false,
        };
        if ok {
            self.stats.key_writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.lock().ring.dirty = true;
            tracing::warn!("mailbox key file write failed");
            Err(MailboxError::Unavailable)
        }
    }
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

/// Fuzzing entry point: the sealed-record parser and the inner record decoder never panic, and
/// what the inner decoder accepts re-encodes canonically. Not part of the API.
#[doc(hidden)]
pub fn fuzz_record(data: &[u8]) {
    let src = Bytes::copy_from_slice(data);
    let _ = Sealed::parse(&src);
    let _ = sealed::decode_entry(data, false);
    let _ = sealed::decode_relocated(data);
    let _ = sealed::decode_remote(data, 0);
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

/// What an attacker holding the Iggy data, the key directory and the master key could read:
/// every record still in the log of every partition is opened with the key files as they are on
/// disk now. Returns (records whose raw bytes contain `marker`, opened plaintexts containing
/// `marker`). Tests only; not part of the API.
///
/// # Errors
/// Iggy or a key file failed.
#[doc(hidden)]
pub async fn forensic_scan(
    cfg: &IggyConfig,
    marker: &[u8],
) -> Result<(usize, usize), IggyMailboxError> {
    let client = cfg.connection.client().await?;
    let stream = Identifier::named(&cfg.stream)?;
    let topic = Identifier::named(&cfg.topic)?;
    let consumer = Consumer::new(Identifier::named("songbird-forensic")?);
    let contains = |hay: &[u8]| hay.windows(marker.len()).any(|w| w == marker);
    let (mut raw_hits, mut open_hits) = (0, 0);
    for p in 0..cfg.partitions {
        let ring = KeyFile::new(&cfg.key_dir, &cfg.stream, &cfg.topic, p, cfg.master_key)
            .load()
            .map_err(|_| IggyMailboxError::Keys { partition: p })?;
        let mut offset = 0;
        loop {
            let polled = client
                .poll_messages(
                    &stream,
                    &topic,
                    p,
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
                offset = offset.max(m.header.offset + 1);
                if contains(&m.payload) {
                    raw_hits += 1;
                }
                let Ok(s) = Sealed::parse(&m.payload) else {
                    continue;
                };
                for i in 0..s.slots() {
                    if let Ok(Some(plain)) = s.slot(&ring, p, i)
                        && contains(&plain)
                    {
                        open_hits += 1;
                    }
                }
            }
        }
    }
    Ok((raw_hits, open_hits))
}

/// A recent home record's remote parts still to confirm: (offset, tag, [(partition, slot)]).
type Home = (u64, [u8; 32], Vec<(u32, u32)>);

impl IggyMailbox {
    /// Connects, creates the stream and topic if missing, loads the key files, replays every
    /// partition, starts the writers and completes remote parts left incomplete before the last
    /// stop.
    ///
    /// # Errors
    /// The connection, the topic set-up, a key file or the replay failed, or another writer
    /// holds a newer producer epoch.
    pub async fn connect(cfg: IggyConfig) -> Result<Self, IggyMailboxError> {
        // Set-up is retried while Iggy answers that it is busy (start-up under load).
        let mut backoff = Duration::from_millis(50);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match Self::connect_once(cfg.clone()).await {
                Err(IggyMailboxError::Iggy(
                    e @ (IggyError::TransientNotAccepted
                    | IggyError::NotPrimary
                    | IggyError::DeferredPollCapacityExceeded),
                )) if tokio::time::Instant::now() < deadline => {
                    tracing::warn!(code = e.as_code(), "mailbox set-up busy; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(2));
                }
                other => return other,
            }
        }
    }

    /// Creates the stream, the mailbox topic and the idempotency topic if missing.
    async fn ensure_topics(
        cfg: &IggyConfig,
    ) -> Result<(Identifier, Identifier, Identifier), IggyMailboxError> {
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
                segment_size: Some(iggy::prelude::IggyByteSize::from(cfg.segment_bytes)),
                ..TopicCreateOptions::default()
            };
            admin.create_topic(&stream, &cfg.topic, &opts).await?;
        }
        let idem_name = format!("{}-idem", cfg.topic);
        let idem_topic = Identifier::named(&idem_name)?;
        if admin.get_topic(&stream, &idem_topic).await?.is_none() {
            let opts = TopicCreateOptions {
                partitions_count: Some(cfg.partitions),
                durability: Durability::Persisted,
                consumer_offset_durability: Durability::Persisted,
                message_expiry: Some(IggyExpiry::ExpireDuration(IggyDuration::from(IDEM_EXPIRY))),
                ..TopicCreateOptions::default()
            };
            admin.create_topic(&stream, &idem_name, &opts).await?;
        }
        Ok((stream, topic, idem_topic))
    }

    async fn connect_once(cfg: IggyConfig) -> Result<Self, IggyMailboxError> {
        let (stream, topic, idem_topic) = Self::ensure_topics(&cfg).await?;
        std::fs::create_dir_all(&cfg.key_dir)
            .map_err(|_| IggyMailboxError::Keys { partition: 0 })?;
        let stats = Arc::new(IggyStats::default());
        let senders: Arc<OnceLock<Vec<mpsc::Sender<Job>>>> = Arc::new(OnceLock::new());
        let mut parts = Vec::new();
        let mut incomplete = Vec::new();
        for p in 0..cfg.partitions {
            let keys = Arc::new(KeyFile::new(
                &cfg.key_dir,
                &cfg.stream,
                &cfg.topic,
                p,
                cfg.master_key,
            ));
            let ring = keys
                .load()
                .map_err(|_| IggyMailboxError::Keys { partition: p })?;
            let shared = Arc::new(Shared {
                partition: p,
                state: Mutex::new(State::with_ring(ring)),
                keys,
                cache: Mutex::new((BTreeMap::new(), 0)),
                cache_bytes: cfg.cache_bytes,
                reader: cfg.connection.client().await?,
                compactor: cfg.connection.client().await?,
                compacting: AtomicBool::new(false),
                stream: stream.clone(),
                topic: topic.clone(),
                idem_topic: idem_topic.clone(),
                idem_queue: Mutex::new(Vec::new()),
                idem_inflight: Mutex::new(Vec::new()),
                healthy: AtomicBool::new(true),
                stats: stats.clone(),
            });
            replay_idem(&shared).await?;
            let homes = replay(&shared).await?;
            shared
                .persist_keys()
                .await
                .map_err(|_| IggyMailboxError::Keys { partition: p })?;
            let writer_client = cfg.connection.client().await?;
            let (tx, rx) = mpsc::channel(cfg.queue);
            let mut w = Writer::new(shared.clone(), writer_client, &cfg, senders.clone());
            w.start_epoch().await?;
            incomplete.push(homes);
            tokio::spawn(w.run(rx));
            tokio::spawn(key_persister(shared.clone(), cfg.ack_interval));
            tokio::spawn(idem_flusher(
                shared.clone(),
                cfg.connection.client().await?,
                IDEM_FLUSH,
            ));
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
        mailbox.resume_parts(incomplete).await;
        Ok(mailbox)
    }

    /// Remote parts of recent home records: those their partitions hold (checked in the
    /// replayed tag indexes; an 8-byte prefix match counts as held) have their slots punctured;
    /// the others are re-driven, one home partition at a time.
    async fn resume_parts(&self, incomplete: Vec<Vec<Home>>) {
        let all: Vec<mpsc::Sender<Job>> = self.parts.iter().map(|p| p.tx.clone()).collect();
        for (home, homes) in incomplete.into_iter().enumerate() {
            let Some(h) = self.parts.get(home) else {
                continue;
            };
            let mut missing = Vec::new();
            for (offset, tag, parts) in homes {
                let mut redrive = false;
                for (p, slot) in parts {
                    let held = self
                        .parts
                        .get(idx(p))
                        .is_some_and(|x| x.shared.lock().idem.contains_key(&tag));
                    if held {
                        let _ = h.tx.send(Job::Puncture(offset, slot)).await;
                    } else {
                        redrive = true;
                    }
                }
                if redrive {
                    missing.push(offset);
                }
            }
            if missing.is_empty() {
                continue;
            }
            let shared = h.shared.clone();
            let all = all.clone();
            let home_tx = h.tx.clone();
            tokio::spawn(async move {
                for offset in missing {
                    redrive_with(&shared, &all, &home_tx, offset).await;
                }
            });
        }
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

    fn part_of(&self, device: &DeviceId) -> Result<&Part, MailboxError> {
        self.parts
            .get(idx(partition_of(device, self.partitions())))
            .ok_or(MailboxError::Unavailable)
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

    fn pending_of(&self, device: &DeviceId) -> Result<u64, MailboxError> {
        let part = self.part_of(device)?;
        let st = part.shared.lock();
        Ok(st.devices.get(device).map_or(0, |s| n64(s.pending.len())))
    }
}

/// What a sealed record means for the state, opening what is still openable. Punctured entries
/// are left out. Also returns, for a recent home record, its remote parts still to confirm.
fn open_fact(
    shared: &Shared,
    s: &Sealed,
    offset: u64,
    window_ms: u64,
    now: u64,
) -> Result<(Fact, Option<Home>), OpenError> {
    let st = shared.lock();
    let ring = &st.ring;
    let p = shared.partition;
    let meta = s.meta(ring, p)?;
    Ok(match meta {
        Meta::Store(m) => {
            let mut entries = Vec::new();
            for i in 0..m.n_local {
                if let Some(plain) = s.slot(ring, p, i)? {
                    let e = sealed::decode_entry(&plain, m.shared)?;
                    entries.push((e.device, e.seq, s.first_leaf + i));
                }
            }
            let body_leaf = match m.body_slot() {
                Some(b)
                    if ring
                        .leaf(s.window, s.first_leaf + b)
                        .ok()
                        .flatten()
                        .is_some() =>
                {
                    Some(s.first_leaf + b)
                }
                _ => None,
            };
            let mut pending_parts = Vec::new();
            for (i, part) in m.remotes.iter().enumerate() {
                let slot = m.remote_slot(i);
                if ring
                    .leaf(s.window, s.first_leaf + slot)
                    .ok()
                    .flatten()
                    .is_some()
                {
                    pending_parts.push((*part, slot));
                }
            }
            let home = match (&m.tag, pending_parts.is_empty()) {
                (Some((t, _)), false) if m.at_ms.saturating_add(window_ms) >= now => {
                    Some((offset, *t, pending_parts))
                }
                _ => None,
            };
            (
                Fact::Store {
                    at_ms: m.at_ms,
                    tag: m.tag,
                    mls: m.mls,
                    entries,
                    body_leaf,
                },
                home,
            )
        }
        Meta::Relocate { n } => {
            let mut entries = Vec::new();
            for i in 0..n {
                if let Some(plain) = s.slot(ring, p, i)? {
                    let e = sealed::decode_relocated(&plain)?;
                    entries.push((e.device, e.seq, e.at_ms.unwrap_or(0), s.first_leaf + i));
                }
            }
            (Fact::Relocate { entries }, None)
        }
        Meta::Plain(rec) => (fact_of_plain(rec), None),
    })
}

fn fact_of_plain(rec: Record) -> Fact {
    match rec {
        Record::Ack(items) => Fact::Ack(items),
        Record::Owner { epoch } => Fact::Owner(epoch),
        Record::Snapshot {
            owner,
            devices,
            groups,
        } => Fact::Snapshot {
            owner,
            devices,
            groups,
        },
        // Store and Relocate are never plain.
        Record::Store { .. } | Record::Relocate(_) => Fact::Ack(Vec::new()),
    }
}

/// The fact of a record this writer just sealed (no decryption needed).
fn fact_of(rec: &Record, first_leaf: u32) -> Fact {
    match rec {
        Record::Store {
            tag,
            at_ms,
            mls,
            local,
            ..
        } => {
            let n = u32::try_from(local.len()).unwrap_or(u32::MAX);
            let entries = (0..local.len())
                .filter_map(|i| local.entry(i))
                .zip(first_leaf..)
                .map(|((d, s), leaf)| (d, s, leaf))
                .collect();
            Fact::Store {
                at_ms: *at_ms,
                tag: *tag,
                mls: *mls,
                entries,
                body_leaf: matches!(local, Local::Shared { .. }).then_some(first_leaf + n),
            }
        }
        Record::Relocate(items) => Fact::Relocate {
            entries: items
                .iter()
                .zip(first_leaf..)
                .map(|((d, s, at, _), leaf)| (*d, *s, *at, leaf))
                .collect(),
        },
        other => fact_of_plain(other.clone()),
    }
}

/// Loads the idempotency entries of the window from the idempotency topic.
async fn replay_idem(shared: &Shared) -> Result<(), IggyMailboxError> {
    let consumer = Consumer::new(Identifier::named(LOW_WATER_CONSUMER)?);
    let cutoff = now_ms().saturating_sub(ms(IDEMPOTENCY_RETENTION));
    let mut offset = 0;
    loop {
        let polled = shared
            .reader
            .poll_messages(
                &shared.stream,
                &shared.idem_topic,
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
            return Ok(());
        }
        let mut st = shared.lock();
        for m in &polled.messages {
            offset = offset.max(m.header.offset + 1);
            let items = decode_idem(&m.payload).ok_or(IggyMailboxError::Unreadable {
                partition: shared.partition,
                offset: m.header.offset,
                version: m.payload.first().copied().unwrap_or(0),
            })?;
            for (t, i) in items {
                if i.at_ms >= cutoff {
                    st.add_idem(t, i);
                }
            }
        }
    }
}

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
    let window = ms(IDEMPOTENCY_RETENTION);
    let mut offset = start;
    let mut homes = Vec::new();
    shared.lock().next_offset = start;
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
            let unreadable = || IggyMailboxError::Unreadable {
                partition: shared.partition,
                offset: o,
                version: m.payload.first().copied().unwrap_or(0),
            };
            let s = Sealed::parse(&m.payload).map_err(|_| unreadable())?;
            let (fact, home) = open_fact(shared, &s, o, window, now).map_err(|_| unreadable())?;
            if let Some(h) = home {
                homes.push(h);
            }
            shared.lock().apply(o, s.window, &fact, window, now);
            offset = o + 1;
        }
    }
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
    key_window_ms: u64,
    pending_acks: HashMap<DeviceId, u64>,
    /// Tag of a multi-partition send -> (home record offset, accepted at, remote partitions not
    /// yet confirmed with their part slots).
    incomplete: HashMap<[u8; 32], Incomplete>,
    senders: Arc<OnceLock<Vec<mpsc::Sender<Job>>>>,
    tag_window_ms: u64,
}

/// A multi-partition send's home record offset, when it was accepted, and the remote
/// partitions not yet confirmed with their part slots.
type Incomplete = (u64, tokio::time::Instant, Vec<(u32, u32)>);

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
            key_window_ms: ms(cfg.key_window),
            pending_acks: HashMap::new(),
            incomplete: HashMap::new(),
            senders,
            tag_window_ms: ms(IDEMPOTENCY_RETENTION),
        }
    }

    /// The window to seal `needed` slots in: the current one, or a new one written to the key
    /// file first (a record must never be appended under keys that are not on disk).
    async fn window(&self, needed: u32) -> Option<u64> {
        let now = now_ms();
        let opened = {
            let mut st = self.shared.lock();
            if let Some(w) = st.ring.current(now, self.key_window_ms, needed) {
                return Some(w);
            }
            st.ring.open_window(now).ok()?
        };
        self.shared.persist_keys().await.ok()?;
        Some(opened)
    }

    /// Seals records into `window`; returns the payloads and each record's first leaf.
    fn seal_all(&self, records: &[Record], window: u64) -> Option<(Vec<Bytes>, Vec<u32>)> {
        let mut st = self.shared.lock();
        let sealed =
            sealed::seal_batch(records, &mut st.ring, window, self.shared.partition).ok()?;
        Some(sealed.into_iter().unzip())
    }

    /// Seals, appends and applies records written by the writer itself (no store replies).
    /// Returns the base offset.
    async fn write_records(&mut self, records: Vec<Record>) -> Option<u64> {
        let needed = records.iter().map(slots_of).sum();
        let window = self.window(needed).await?;
        let (payloads, leaves) = self.seal_all(&records, window)?;
        let base = self.append(payloads.clone()).await?;
        let now = now_ms();
        let mut st = self.shared.lock();
        for (i, (rec, first)) in records.iter().zip(&leaves).enumerate() {
            st.apply(
                base + n64(i),
                window,
                &fact_of(rec, *first),
                self.tag_window_ms,
                now,
            );
        }
        st.next_offset = base + n64(payloads.len());
        drop(st);
        for (i, p) in payloads.into_iter().enumerate() {
            self.shared.cache_put(base + n64(i), p);
        }
        Some(base)
    }

    /// Takes over the partition with a producer epoch above every recorded one.
    async fn start_epoch(&mut self) -> Result<(), IggyMailboxError> {
        let partition = self.shared.partition;
        let epoch = self
            .shared
            .lock()
            .owner_epoch
            .checked_add(1)
            .ok_or(IggyError::InvalidCommand)?;
        let p = BatchProducer::new(self.producer_id, epoch, 0).ok_or(IggyError::InvalidCommand)?;
        self.producer = Some(p);
        self.shared.keys.set_epoch(epoch);
        self.shared.lock().ring.dirty = true;
        let window = self
            .window(0)
            .await
            .ok_or(IggyMailboxError::Keys { partition })?;
        let (payloads, _) = self
            .seal_all(&[Record::Owner { epoch }], window)
            .ok_or(IggyMailboxError::Keys { partition })?;
        let base = self.append_once(payloads).await?;
        let now = now_ms();
        let mut st = self.shared.lock();
        st.apply(base, window, &Fact::Owner(epoch), self.tag_window_ms, now);
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
                // ACK checkpoints ride with store batches; this writes them when no send does.
                _ = ack_tick.tick() => self.flush_acks().await,
                _ = compact_tick.tick() => { self.start_compaction(None).await; }
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
                let n = self.start_compaction(Some(age_ms)).await;
                let _ = reply.send(n);
            }
            Job::Relocated { items, last } => {
                if !items.is_empty() {
                    self.relocate(items).await;
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
                if let Some((offset, _, rest)) = self.incomplete.get_mut(&tag) {
                    let offset = *offset;
                    let mut done = Vec::new();
                    rest.retain(|(part, slot)| {
                        let keep = *part != p;
                        if !keep {
                            done.push(*slot);
                        }
                        keep
                    });
                    if rest.is_empty() {
                        self.incomplete.remove(&tag);
                    }
                    for slot in done {
                        self.puncture_slot(offset, slot).await;
                    }
                }
            }
            Job::Puncture(offset, slot) => self.puncture_slot(offset, slot).await,
        }
    }

    /// Punctures slot `slot` of the record at `offset` (a confirmed remote part).
    async fn puncture_slot(&self, offset: u64, slot: u32) {
        if let Ok(s) = self.shared.one(offset).await {
            let _ = self
                .shared
                .lock()
                .ring
                .puncture(s.window, s.first_leaf + slot);
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
        let home = self
            .senders
            .get()
            .and_then(|s| s.get(idx(self.shared.partition)))
            .cloned();
        for (tag, offset) in stale {
            self.incomplete.remove(&tag);
            let shared = self.shared.clone();
            let senders = self.senders.clone();
            let Some(home) = home.clone() else { continue };
            tokio::spawn(async move {
                if let Some(s) = senders.get() {
                    redrive_with(&shared, s, &home, offset).await;
                }
            });
        }
    }

    /// The current `seq`s of a replayed send's entries that are still pending (acknowledged
    /// ones are unreadable now and left out: they answer 0).
    async fn replay_seqs(&self, offset: u64) -> Vec<(DeviceId, u64)> {
        let Ok(s) = self.shared.one(offset).await else {
            // Below the low-water offset: everything in it was delivered or moved.
            return Vec::new();
        };
        let Ok(Meta::Store(m)) = self.shared.meta(&s) else {
            return Vec::new();
        };
        let mut seqs = Vec::new();
        for i in 0..m.n_local {
            if let Ok(Some(plain)) = self.shared.slot(&s, i)
                && let Ok(e) = sealed::decode_entry(&plain, m.shared)
            {
                seqs.push((e.device, e.seq));
            }
        }
        seqs
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
        // Pending ACKs ride in the same append (one fsync for both).
        let acks: Vec<(DeviceId, u64)> = self.pending_acks.drain().collect();
        if !acks.is_empty() {
            records.push(Record::Ack(acks.clone()));
        }
        let ok = records.is_empty() || self.commit_records(&records, now).await;
        if !ok {
            for (d, s) in acks {
                let e = self.pending_acks.entry(d).or_default();
                *e = (*e).max(s);
            }
        }
        for (job, plan) in batch.drain(..).zip(plans) {
            let r = match plan {
                Plan::Done(r) => r,
                Plan::Append(seqs) if ok => {
                    self.shared.stats.sends.fetch_add(1, Ordering::Relaxed);
                    self.shared
                        .stats
                        .entries
                        .fetch_add(n64(seqs.len()), Ordering::Relaxed);
                    Ok((seqs, false))
                }
                Plan::Append(_) => Err(MailboxError::Unavailable),
            };
            let _ = job.reply.send(r);
        }
    }

    /// Seals and appends a batch's store records, then applies them.
    async fn commit_records(&mut self, records: &[Record], now: u64) -> bool {
        let needed = records.iter().map(slots_of).sum();
        let Some(window) = self.window(needed).await else {
            return false;
        };
        let Some((payloads, leaves)) = self.seal_all(records, window) else {
            return false;
        };
        let Some(base) = self.append(payloads.clone()).await else {
            return false;
        };
        self.shared.stats.commits.fetch_add(1, Ordering::Relaxed);
        let mut st = self.shared.lock();
        st.note_batch(base, now);
        for (i, (rec, first)) in records.iter().zip(&leaves).enumerate() {
            let offset = base + n64(i);
            st.apply(
                offset,
                window,
                &fact_of(rec, *first),
                self.tag_window_ms,
                now,
            );
            if let Record::Store {
                tag: Some((t, fp)),
                at_ms,
                ..
            } = rec
            {
                self.shared
                    .idem_queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((
                        *t,
                        Idem {
                            fp: *fp,
                            at_ms: *at_ms,
                            offset,
                        },
                    ));
            }
            if let Record::Store {
                remote,
                tag: Some(tag),
                local,
                ..
            } = rec
                && !remote.is_empty()
            {
                let base_slot = u32::try_from(local.len()).unwrap_or(0)
                    + u32::from(matches!(local, Local::Shared { .. }));
                let parts = remote
                    .iter()
                    .zip(base_slot..)
                    .map(|(r, slot)| (r.partition, slot))
                    .collect();
                self.incomplete
                    .insert(tag.0, (offset, tokio::time::Instant::now(), parts));
            }
        }
        st.next_offset = base + n64(payloads.len());
        drop(st);
        for (i, p) in payloads.into_iter().enumerate() {
            self.shared.cache_put(base + n64(i), p);
        }
        true
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
            let known = self.shared.lock().idem.get(tag).copied();
            if let Some(i) = known {
                // The same key for the same recipient set is a retry; for another set it is
                // refused (reason 7), whichever part of the earlier send this partition holds.
                if i.fp != *fp {
                    return Plan::Done(Err(MailboxError::IdempotencyConflict));
                }
                return Plan::Done(Ok((self.replay_seqs(i.offset).await, true)));
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

    /// Writes the ACK checkpoint, then removes the entries and punctures their leaves.
    async fn flush_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }
        let items: Vec<(DeviceId, u64)> = self.pending_acks.drain().collect();
        if self
            .write_records(vec![Record::Ack(items.clone())])
            .await
            .is_some()
        {
            self.shared
                .stats
                .ack_commits
                .fetch_add(1, Ordering::Relaxed);
        } else {
            // Kept for the next checkpoint.
            for (d, s) in items {
                let e = self.pending_acks.entry(d).or_default();
                *e = (*e).max(s);
            }
        }
    }

    /// Starts a compaction pass (also from `expire_older_than` with an age): expired entries are
    /// acknowledged (written, then their leaves punctured); the compactor task reads the pending
    /// entries older than `relocate_after` off the write path and hands them back to be re-sealed
    /// forward ([`Job::Relocated`]). Returns how many entries expired.
    async fn start_compaction(&mut self, age_ms: Option<u64>) -> u64 {
        let now = now_ms();
        let max_age = age_ms.unwrap_or_else(|| ms(MAX_ENVELOPE_AGE));
        let cutoff = now.saturating_sub(max_age);
        let (expired, count) = {
            let st = self.shared.lock();
            let e = st.expired(cutoff);
            let n: u64 = e
                .iter()
                .map(|(d, up)| {
                    st.devices.get(d).map_or(0, |s| {
                        n64(s.pending.iter().take_while(|x| x.seq <= *up).count())
                    })
                })
                .sum();
            (e, n)
        };
        if !expired.is_empty()
            && self
                .write_records(vec![Record::Ack(expired)])
                .await
                .is_none()
        {
            return 0;
        }
        let mut moves = {
            let st = self.shared.lock();
            let cut = st.offset_at(now.saturating_sub(ms(self.relocate_after)));
            st.entries_before(cut)
        };
        if self.shared.compacting.swap(true, Ordering::AcqRel) {
            return count;
        }
        let me = self
            .senders
            .get()
            .and_then(|s| s.get(idx(self.shared.partition)))
            .cloned();
        let Some(me) = me else {
            self.shared.compacting.store(false, Ordering::Release);
            return count;
        };
        moves.truncate(RELOCATE_PER_PASS);
        tokio::spawn(compactor(self.shared.clone(), moves, me));
        count
    }

    /// Ends a pass: snapshots the counters, moves the low-water offset up to the oldest record
    /// still needed (pending entries, the idempotency window, incomplete parts) and destroys the
    /// key windows below it.
    async fn finish_compaction(&mut self) {
        let now = now_ms();
        let (cut, min_live, current_low) = {
            let mut st = self.shared.lock();
            st.prune_idem(now.saturating_sub(self.tag_window_ms));
            (
                st.offset_at(now.saturating_sub(ms(self.relocate_after))),
                st.min_live(),
                st.times.front().map_or(st.next_offset, |(o, _)| *o),
            )
        };
        // Idempotency lives in its own topic: only pending entries, incomplete parts and
        // idempotency entries not yet written there hold the low-water offset back.
        let mut low = cut;
        let idem_floor = [&self.shared.idem_queue, &self.shared.idem_inflight]
            .iter()
            .filter_map(|m| {
                m.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .iter()
                    .map(|(_, i)| i.offset)
                    .min()
            })
            .min();
        if let Some(m) = idem_floor {
            low = low.min(m);
        }
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
        let Some(snap) = self.snapshot().await else {
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
            let destroyed = {
                let mut st = self.shared.lock();
                st.prune_times(low);
                let current = st.ring.windows.keys().next_back().copied();
                st.destroy_windows_below(low, current)
            };
            self.shared
                .stats
                .windows_destroyed
                .fetch_add(n64(destroyed), Ordering::Relaxed);
        }
    }

    async fn relocate(&mut self, items: Vec<(DeviceId, u64, u64, Bytes)>) -> bool {
        let n = n64(items.len());
        if self
            .write_records(vec![Record::Relocate(items)])
            .await
            .is_none()
        {
            return false;
        }
        self.shared.stats.relocated.fetch_add(n, Ordering::Relaxed);
        // The old copies' leaves were punctured on apply (written by the key persister).
        true
    }

    /// Writes the counter snapshot; returns the offset of its first record.
    async fn snapshot(&mut self) -> Option<u64> {
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
        let base = self.write_records(records).await?;
        let now = now_ms();
        self.shared.lock().note_batch(base, now);
        Some(base)
    }
}

/// Writes the key file when punctures or windows changed it, off the writer's path. The
/// deletion guarantee holds: an acknowledged entry's key leaves the disk within one interval.
async fn key_persister(shared: Arc<Shared>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        if !shared.healthy.load(Ordering::Relaxed) {
            return;
        }
        let _ = shared.persist_keys().await;
    }
}

/// Writes idempotency entries to the idempotency topic, off the writer's path.
async fn idem_flusher(shared: Arc<Shared>, client: IggyClient, every: Duration) {
    let mut tick = tokio::time::interval(every);
    let lock = |m: &Mutex<Vec<([u8; 32], Idem)>>| {
        std::mem::take(&mut *m.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    };
    loop {
        tick.tick().await;
        if !shared.healthy.load(Ordering::Relaxed) {
            return;
        }
        let batch = {
            let mut q = shared
                .idem_queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut f = shared
                .idem_inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f.append(&mut q);
            f.clone()
        };
        if batch.is_empty() {
            continue;
        }
        let Ok(msg) = IggyMessage::builder().payload(encode_idem(&batch)).build() else {
            continue;
        };
        let mut msgs = vec![msg];
        if client
            .send_messages(
                &shared.stream,
                &shared.idem_topic,
                &iggy::prelude::Partitioning::partition_id(shared.partition),
                &mut msgs,
            )
            .await
            .is_ok()
        {
            let _ = lock(&shared.idem_inflight);
        }
    }
}

/// Reads the entries a compaction pass copies forward (on its own connection, many records per
/// poll, decrypting their slots) and hands them to the writer in records of about
/// `COMPACTION_RECORD_BYTES`.
async fn compactor(shared: Arc<Shared>, moves: Vec<(DeviceId, Entry)>, writer: mpsc::Sender<Job>) {
    let mut items = Vec::new();
    let mut bytes = 0usize;
    for chunk in moves.chunks(4096) {
        let offsets: Vec<u64> = chunk.iter().map(|(_, e)| e.offset).collect();
        let Ok(recs) = shared.sealed(&shared.compactor, &offsets).await else {
            // Unread entries stay where they are; the low-water offset cannot pass them.
            break;
        };
        for (d, e) in chunk {
            let Some(s) = recs.get(&e.offset) else {
                continue;
            };
            let Ok(env) = shared.envelope(s, e) else {
                continue;
            };
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

/// The re-driver: stores the remote parts of the home record at `offset` that are still
/// readable, and tells the home writer to puncture each one stored.
async fn redrive_with(
    shared: &Shared,
    senders: &[mpsc::Sender<Job>],
    home: &mpsc::Sender<Job>,
    offset: u64,
) {
    let mut backoff = Duration::from_millis(100);
    loop {
        let mut all = true;
        let opened = shared.one(offset).await.and_then(|s| {
            let Meta::Store(m) = shared.meta(&s)? else {
                return Err(MailboxError::Unavailable);
            };
            let mut parts = Vec::new();
            for (i, p) in m.remotes.iter().enumerate() {
                let slot = m.remote_slot(i);
                if let Some(plain) = shared.slot(&s, slot)? {
                    let r =
                        sealed::decode_remote(&plain, *p).map_err(|_| MailboxError::Unavailable)?;
                    parts.push((slot, r));
                }
            }
            Ok((m.tag, parts))
        });
        match opened {
            Ok((tag, parts)) => {
                for (slot, r) in parts {
                    let Some(tx) = senders.get(idx(r.partition)) else {
                        continue;
                    };
                    let (rtx, rrx) = oneshot::channel();
                    let job = StoreJob {
                        tag,
                        mls: None,
                        local: LocalReq::from_remote(r),
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
                        let _ = home.send(Job::Puncture(offset, slot)).await;
                    } else {
                        all = false;
                    }
                }
            }
            Err(_) => all = false,
        }
        if all {
            return;
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
        let tag = key.map(|t| (t, recipients_fingerprint(&self.idem, &devices)));
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
            let p = self.part_of(d)?;
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
            let p = r.partition;
            let job = StoreJob {
                tag,
                mls: None,
                local: LocalReq::from_remote(r),
                remote: vec![],
                reply: tx,
            };
            self.submit(p, job).await?;
            waits.push((p, rx));
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
        // A replay answers 0 for entries already acknowledged (unreadable now: nothing to route).
        let seqs = devices
            .iter()
            .map(|d| match seq_of.get(d) {
                Some(s) => Ok(*s),
                None if replayed => Ok(0),
                None => Err(MailboxError::Unavailable),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StoreOutcome { seqs, replayed })
    }

    async fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        let part = self.part_of(device)?;
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
        let recs = part.shared.sealed(&part.shared.reader, &offsets).await?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let s = recs.get(&e.offset).ok_or(MailboxError::Unavailable)?;
            out.push(Stored {
                seq: e.seq,
                envelope: part.shared.envelope(s, &e)?,
            });
        }
        Ok(out)
    }

    async fn ack_up_to(&self, device: &DeviceId, up_to_seq: u64) -> Result<(), MailboxError> {
        self.part_of(device)?
            .tx
            .send(Job::Ack(*device, up_to_seq))
            .await
            .map_err(|_| MailboxError::Unavailable)
    }

    async fn expire_older_than(&self, age: Duration) -> Result<u64, MailboxError> {
        let age_ms = ms(age);
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
