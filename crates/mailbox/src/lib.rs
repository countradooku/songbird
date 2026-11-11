//! Per-device mailboxes: the only durable truth for undelivered envelopes (invariants 1–3).
//!
//! A mailbox holds, per device, the envelopes not yet acknowledged, each with a per-device
//! sequence number: strictly increasing, gap-free at allocation, never reused. Operations:
//!
//! - [`Mailbox::store`]: store one send (an envelope per recipient device, or one shared body for
//!   many devices) and return each recipient's `seq`. All or nothing. The caller acknowledges the
//!   sender only after this returns (invariant 1). An MLS commit is stored only if the group's
//!   epoch matches, and advances it, in the same transaction.
//! - [`Mailbox::fetch_after`]: the oldest envelopes after a `seq`, in order (a range scan).
//! - [`Mailbox::ack_up_to`]: hard-delete everything up to and including a `seq` (invariant 3);
//!   implementations may batch the deletes for a few tens of milliseconds.
//! - [`Mailbox::expire_older_than`]: delete what has waited too long (30 days, invariant 3).
//!
//! Implementations: [`memory::MemoryMailbox`] (tests and development),
//! [`surreal::SurrealMailbox`] (SurrealDB with group commit, milestone 2's first design) and
//! [`iggy::IggyMailbox`] (Apache Iggy log, deployments, D-0029).
#![forbid(unsafe_code)]

use std::future::Future;
use std::time::Duration;

use aws_lc_rs::hmac;
use bytes::Bytes;
use songbird_types::DeviceId;

pub mod iggy;
pub mod memory;
pub mod surreal;

/// An envelope to store for one device.
#[derive(Clone)]
pub struct NewEnvelope {
    /// Recipient device.
    pub device: DeviceId,
    /// Opaque ciphertext.
    pub envelope: Bytes,
}

impl std::fmt::Debug for NewEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewEnvelope")
            .field("device", &self.device)
            .field("len", &self.envelope.len())
            .finish()
    }
}

/// A stored envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct Stored {
    /// Its per-device sequence number.
    pub seq: u64,
    /// Opaque ciphertext.
    pub envelope: Bytes,
}

impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stored")
            .field("seq", &self.seq)
            .field("len", &self.envelope.len())
            .finish()
    }
}

/// What a send stores.
#[derive(Clone)]
pub enum Payload {
    /// One ciphertext per recipient device (pairwise sessions).
    PerDevice(Vec<NewEnvelope>),
    /// One ciphertext for every listed device (group or channel message): stored once, with a
    /// small index entry per device; deleted when the last device acknowledges or after 30 days.
    Shared {
        /// Recipient devices, each at most once.
        devices: Vec<DeviceId>,
        /// The ciphertext.
        body: Bytes,
    },
}

impl Payload {
    /// The recipient devices, in order.
    pub fn devices(&self) -> impl Iterator<Item = &DeviceId> {
        let (a, b) = match self {
            Self::PerDevice(items) => (Some(items.iter().map(|i| &i.device)), None),
            Self::Shared { devices, .. } => (None, Some(devices.iter())),
        };
        a.into_iter().flatten().chain(b.into_iter().flatten())
    }

    /// The number of recipient devices.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::PerDevice(items) => items.len(),
            Self::Shared { devices, .. } => devices.len(),
        }
    }

    /// Whether there are no recipients.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The ciphertext for recipient `i`.
    #[must_use]
    pub fn envelope(&self, i: usize) -> Option<&Bytes> {
        match self {
            Self::PerDevice(items) => items.get(i).map(|n| &n.envelope),
            Self::Shared { devices, body } => (i < devices.len()).then_some(body),
        }
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerDevice(items) => f.debug_tuple("PerDevice").field(&items.len()).finish(),
            Self::Shared { devices, body } => f
                .debug_struct("Shared")
                .field("devices", &devices.len())
                .field("len", &body.len())
                .finish(),
        }
    }
}

/// An MLS commit: stored only if the group is at `epoch`, which then becomes `epoch + 1`, in the
/// same transaction (exactly one of several concurrent commits wins).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlsCommit {
    /// The group (opaque 16 bytes chosen by clients).
    pub group: [u8; 16],
    /// The epoch the commit was made from.
    pub epoch: u64,
}

impl std::fmt::Debug for MlsCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsCommit")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// One send to store.
#[derive(Debug, Clone)]
pub struct StoreRequest {
    /// Random per logical message; a retry reuses it (see [`Mailbox::store`]).
    pub idempotency_key: Option<[u8; 16]>,
    /// Set for an MLS commit.
    pub mls: Option<MlsCommit>,
    /// What to store.
    pub payload: Payload,
}

/// Result of [`Mailbox::store`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOutcome {
    /// The `seq` of each recipient, in input order.
    pub seqs: Vec<u64>,
    /// The idempotency key was seen before: nothing new was stored and `seqs` are the original
    /// ones.
    pub replayed: bool,
}

/// Longest an undelivered envelope is kept (invariant 3).
pub const MAX_ENVELOPE_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long an idempotency key is remembered: the client's retry horizon (D-0021). A send retried
/// later is stored again and the recipient app drops it by the message ID inside the envelope.
pub const IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(6 * 3600);

/// Mailbox failures. All are retryable from the client's point of view.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailboxError {
    /// A device's mailbox is at its configured capacity; nothing was stored.
    #[error("mailbox full")]
    Full,
    /// The store is unreachable or failed; nothing was stored.
    #[error("mailbox unavailable")]
    Unavailable,
    /// The idempotency key was already used for a send to other recipient devices; nothing was
    /// stored. Not retryable: the client must use a fresh key.
    #[error("idempotency key reused for other recipients")]
    IdempotencyConflict,
    /// An MLS commit from an epoch the group has already left; nothing was stored. The client
    /// processes the winning commit and retries from the new epoch.
    #[error("stale MLS epoch")]
    StaleEpoch,
}

/// A mailbox store. Implementations are shared by every session of a process.
pub trait Mailbox: Send + Sync + 'static {
    /// Stores one send, allocating each recipient device's next `seq`; returns the `seq` of each
    /// recipient in input order. All or nothing: on error nothing is stored. Returns only once the
    /// write is durable (SurrealDB: committed with sync on commit).
    ///
    /// A send's `idempotency_key` is remembered, as a keyed hash (HMAC-SHA256 with a server
    /// secret), with the recipient devices and `seq`s for [`IDEMPOTENCY_RETENTION`]. A retry with
    /// the same key and the same recipient devices stores nothing and returns the original
    /// result with `replayed` set; the same key for other recipients is refused with
    /// [`MailboxError::IdempotencyConflict`]. The record is not linked to the sender (minimal
    /// metadata).
    fn store(
        &self,
        req: StoreRequest,
    ) -> impl Future<Output = Result<StoreOutcome, MailboxError>> + Send;

    /// Up to `limit` envelopes of `device` with `seq > after_seq`, ascending.
    fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Stored>, MailboxError>> + Send;

    /// Deletes every envelope of `device` with `seq <= up_to_seq`. May be applied in a batch
    /// shortly after it returns (a lost ACK is repeated by the next one or by
    /// `Auth.last_acked_seq`).
    fn ack_up_to(
        &self,
        device: &DeviceId,
        up_to_seq: u64,
    ) -> impl Future<Output = Result<(), MailboxError>> + Send;

    /// Deletes every envelope stored more than `age` ago; returns how many.
    fn expire_older_than(
        &self,
        age: Duration,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send;

    /// The store generation: incremented by every restore from backup (`PROTOCOL.md` §3.6).
    fn store_generation(&self) -> impl Future<Output = Result<u64, MailboxError>> + Send;

    /// Unacknowledged envelopes of `device` (diagnostics and tests; a range count).
    fn count_pending(
        &self,
        device: &DeviceId,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send;
}

/// The record ID of an idempotency key: HMAC-SHA256 under a server secret, so stores never hold
/// a client's key (D-0024).
pub(crate) fn idempotency_tag(key: &hmac::Key, k: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let tag = hmac::sign(key, k);
    if let Some(t) = tag.as_ref().get(..32) {
        out.copy_from_slice(t);
    }
    out
}

/// Either backend, chosen at startup from configuration.
#[derive(Debug)]
pub enum AnyMailbox {
    /// In memory (development, tests).
    Memory(memory::MemoryMailbox),
    /// SurrealDB (M2 first design; development).
    Surreal(surreal::SurrealMailbox),
    /// Apache Iggy (deployments, D-0029).
    Iggy(iggy::IggyMailbox),
}

impl Mailbox for AnyMailbox {
    async fn store(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        match self {
            Self::Memory(m) => m.store(req).await,
            Self::Surreal(m) => m.store(req).await,
            Self::Iggy(m) => m.store(req).await,
        }
    }

    async fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        match self {
            Self::Memory(m) => m.fetch_after(device, after_seq, limit).await,
            Self::Surreal(m) => m.fetch_after(device, after_seq, limit).await,
            Self::Iggy(m) => m.fetch_after(device, after_seq, limit).await,
        }
    }

    async fn ack_up_to(&self, device: &DeviceId, up_to_seq: u64) -> Result<(), MailboxError> {
        match self {
            Self::Memory(m) => m.ack_up_to(device, up_to_seq).await,
            Self::Surreal(m) => m.ack_up_to(device, up_to_seq).await,
            Self::Iggy(m) => m.ack_up_to(device, up_to_seq).await,
        }
    }

    async fn expire_older_than(&self, age: Duration) -> Result<u64, MailboxError> {
        match self {
            Self::Memory(m) => m.expire_older_than(age).await,
            Self::Surreal(m) => m.expire_older_than(age).await,
            Self::Iggy(m) => m.expire_older_than(age).await,
        }
    }

    async fn store_generation(&self) -> Result<u64, MailboxError> {
        match self {
            Self::Memory(m) => m.store_generation().await,
            Self::Surreal(m) => m.store_generation().await,
            Self::Iggy(m) => m.store_generation().await,
        }
    }

    async fn count_pending(&self, device: &DeviceId) -> Result<u64, MailboxError> {
        match self {
            Self::Memory(m) => m.count_pending(device).await,
            Self::Surreal(m) => m.count_pending(device).await,
            Self::Iggy(m) => m.count_pending(device).await,
        }
    }
}
