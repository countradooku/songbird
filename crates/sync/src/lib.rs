//! Songbird's account record store, client side (Prompt 9; `docs/PROTOCOL.md` §10; D-0102).
//!
//! Settings, chat preferences, contacts and lists sync across an account's devices as
//! encrypted records the server stores opaque ([`record`]). Each device keeps a [`Replica`]:
//! per logical key, the record with the greatest hybrid-logical-clock stamp ([`hlc`]) wins,
//! wherever and whenever it was written, so devices converge whatever order they sync in. An
//! encrypted manifest written with every change lets a device detect a server that withholds,
//! replays or rolls back records.
//!
//! The crate does no I/O. [`sync`] runs one sync against anything that implements [`Remote`]:
//! the app's HTTP client, or [`memory::MemoryServer`], the reference server the property tests
//! (`tests/convergence.rs`) and the app's offline mode use.
#![forbid(unsafe_code)]

pub mod hlc;
pub mod keys;
pub mod memory;
pub mod record;
pub mod replica;

use std::future::Future;

pub use hlc::{Clock, Hlc};
pub use record::{RecordPlain, StorageKey};
pub use replica::{Prepared, Replica};
use songbird_proto::storage::{Head, ID_LEN, Ids, MAX_READ, Record, Write};

/// Tombstones are collected, and a device's own unwritten edits dropped, after 90 days.
pub const HORIZON_MS: u64 = 90 * 24 * 3_600_000;
/// Rounds of read, merge and write before a sync gives up (each lost round means another device
/// wrote in between).
pub const MAX_ROUNDS: usize = 8;

/// Why a sync failed. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// The server offered a version below one this device already saw.
    #[error("the store was rolled back")]
    Rollback,
    /// A record or the manifest does not open, or the manifest does not match the records.
    #[error("the store was tampered with")]
    Tampered,
    /// The manifest was written under another storage key: the account rotated it.
    #[error("the storage key changed")]
    KeyChanged,
    /// The store moved on between two reads: read again.
    #[error("the store moved on")]
    Stale,
    /// A record, key or value outside the format's bounds.
    #[error("malformed record")]
    Malformed,
    /// No randomness.
    #[error("no randomness")]
    Random,
    /// A cryptographic primitive failed.
    #[error("crypto failure")]
    Crypto,
    /// The store is full (the server's caps).
    #[error("the store is full")]
    Full,
    /// Other devices kept writing for [`MAX_ROUNDS`] rounds.
    #[error("too many concurrent writers")]
    Busy,
    /// The server could not be reached or refused the request.
    #[error("server unavailable")]
    Remote,
}

/// What a write answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Applied: the new version.
    Applied(u64),
    /// Another write moved the store on (409): its version.
    Conflict(u64),
    /// A cap was reached.
    Full,
}

/// The server's record store, as a device sees it.
pub trait Remote {
    /// `GET /v1/storage`.
    fn head(&self) -> impl Future<Output = Result<Head, SyncError>>;
    /// `GET /v1/storage/ids`.
    fn ids(&self) -> impl Future<Output = Result<Ids, SyncError>>;
    /// `POST /v1/storage/read` (at most [`MAX_READ`] IDs).
    fn read(&self, ids: &[[u8; ID_LEN]]) -> impl Future<Output = Result<Vec<Record>, SyncError>>;
    /// `PUT /v1/storage`.
    fn write(&self, w: &Write) -> impl Future<Output = Result<WriteOutcome, SyncError>>;
}

/// One sync: read what changed, merge, write local edits; repeated while other devices win the
/// race, at most [`MAX_ROUNDS`] times. Returns the keys whose value changed on this device.
///
/// # Errors
/// [`SyncError`].
pub async fn sync<R: Remote>(
    replica: &mut Replica,
    remote: &R,
    phys_ms: u64,
) -> Result<Vec<String>, SyncError> {
    let mut changed = Vec::new();
    for _ in 0..MAX_ROUNDS {
        let head = remote.head().await?;
        if replica.check_head(&head)? {
            let ids = remote.ids().await?;
            let missing = replica.missing(&ids);
            let mut records = Vec::with_capacity(missing.len());
            for chunk in missing.chunks(MAX_READ) {
                records.extend(remote.read(chunk).await?);
            }
            // The head read first may be older than the IDs: verify against the newest pair.
            let head = if ids.version == head.version {
                head
            } else {
                remote.head().await?
            };
            match replica.apply(&head, &ids, &records, phys_ms) {
                Ok(c) => changed.extend(c),
                Err(SyncError::Stale) => continue,
                Err(e) => return Err(e),
            }
        }
        replica.expire(phys_ms);
        let Some(p) = replica.prepare()? else {
            changed.sort();
            changed.dedup();
            return Ok(changed);
        };
        match remote.write(&p.write).await? {
            WriteOutcome::Applied(v) => replica.committed(p, v),
            WriteOutcome::Conflict(_) => {}
            WriteOutcome::Full => return Err(SyncError::Full),
        }
    }
    Err(SyncError::Busy)
}

/// Rotates the storage key: rewrites every record under `new_key` in one write. The caller then
/// sends `new_key` to the account's other devices (end-to-end encrypted sync message).
///
/// # Errors
/// [`SyncError`].
pub async fn rotate<R: Remote>(
    replica: &mut Replica,
    remote: &R,
    new_key: StorageKey,
    phys_ms: u64,
) -> Result<(), SyncError> {
    for _ in 0..MAX_ROUNDS {
        sync(replica, remote, phys_ms).await?;
        let p = replica.prepare_rotation(new_key.clone())?;
        match remote.write(&p.write).await? {
            WriteOutcome::Applied(v) => {
                replica.committed(p, v);
                return Ok(());
            }
            WriteOutcome::Conflict(_) => {}
            WriteOutcome::Full => return Err(SyncError::Full),
        }
    }
    Err(SyncError::Busy)
}
