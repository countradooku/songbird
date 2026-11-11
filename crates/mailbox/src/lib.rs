//! Per-device mailboxes: the only durable truth for undelivered envelopes (invariants 1–3).
//!
//! A mailbox holds, per device, the envelopes not yet acknowledged, each with a per-device
//! sequence number: strictly increasing, gap-free at allocation, never reused. Operations:
//!
//! - [`Mailbox::store_batch`]: store envelopes for many devices at once and return their `seq`.
//!   All or nothing. The caller acknowledges the sender only after this returns (invariant 1).
//! - [`Mailbox::fetch_after`]: the oldest envelopes after a `seq`, in order (a range scan).
//! - [`Mailbox::ack_up_to`]: hard-delete everything up to and including a `seq` (invariant 3).
//! - [`Mailbox::expire_older_than`]: delete what has waited too long (30 days, invariant 3).
//!
//! Milestone 1 ships [`memory::MemoryMailbox`] so the session algorithm can be built and tested;
//! milestone 2 adds the SurrealDB store with group commit behind the same trait.
#![forbid(unsafe_code)]

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use songbird_types::DeviceId;

pub mod memory;

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

/// Result of [`Mailbox::store_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOutcome {
    /// The `seq` of each item, in input order.
    pub seqs: Vec<u64>,
    /// The idempotency key was seen before: nothing new was stored and `seqs` are the original
    /// ones. The caller must not route again.
    pub replayed: bool,
}

/// Longest an undelivered envelope is kept (invariant 3).
pub const MAX_ENVELOPE_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long an idempotency key is remembered.
pub const IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(24 * 3600);

/// Mailbox failures. All are retryable from the client's point of view.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailboxError {
    /// A device's mailbox is at its configured capacity; nothing was stored.
    #[error("mailbox full")]
    Full,
    /// The store is unreachable or failed; nothing was stored.
    #[error("mailbox unavailable")]
    Unavailable,
}

/// A mailbox store. Implementations are shared by every session of a process.
pub trait Mailbox: Send + Sync + 'static {
    /// Stores every item, allocating each device's next `seq`; returns the `seq` of each item in
    /// input order. All or nothing: on error nothing is stored. Returns only once the write is
    /// as durable as the store gets.
    ///
    /// A send's `idempotency_key` is remembered with the result for
    /// [`IDEMPOTENCY_RETENTION`]; a retry with the same key stores nothing and returns the
    /// original result with `replayed` set. The key is not linked to the sender (minimal
    /// metadata): it is 128 random bits only the sender and the server ever see.
    fn store_batch(
        &self,
        idempotency_key: Option<[u8; 16]>,
        items: &[NewEnvelope],
    ) -> impl Future<Output = Result<StoreOutcome, MailboxError>> + Send;

    /// Up to `limit` envelopes of `device` with `seq > after_seq`, ascending.
    fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Stored>, MailboxError>> + Send;

    /// Deletes every envelope of `device` with `seq <= up_to_seq`; returns how many.
    fn ack_up_to(
        &self,
        device: &DeviceId,
        up_to_seq: u64,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send;

    /// Deletes every envelope stored more than `age` ago; returns how many.
    fn expire_older_than(
        &self,
        age: Duration,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send;

    /// The store generation: incremented by every restore from backup (`PROTOCOL.md` §3.6).
    fn store_generation(&self) -> impl Future<Output = Result<u64, MailboxError>> + Send;
}
