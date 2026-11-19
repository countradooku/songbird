//! The one interface every store implements (PROTOCOL §11.8).

use async_trait::async_trait;
use songbird_backup_format::ChunkName;

/// What a store can answer. Never carries a name, a key, a token or content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// No such object (or no vault: one answer for both).
    #[error("not found")]
    NotFound,
    /// The manifest moved on: the store's current generation.
    #[error("the backup moved on (generation {current})")]
    Conflict {
        /// The current generation.
        current: u64,
    },
    /// The store's quota would be passed.
    #[error("the backup space is full")]
    Full,
    /// The credentials were refused (a signed-out account, an expired token, a wrong secret).
    #[error("not allowed")]
    Unauthorized,
    /// The store asked to wait.
    #[error("too many requests (retry in {retry_after_ms} ms)")]
    Throttled {
        /// How long to wait.
        retry_after_ms: u64,
    },
    /// The store could not be reached or failed (its HTTP status, if any).
    #[error("store unavailable ({status})")]
    Unavailable {
        /// The HTTP status (0: no answer).
        status: u16,
    },
    /// The store answered something outside its protocol.
    #[error("unexpected answer: {0}")]
    Protocol(&'static str),
    /// A local file failed.
    #[error("file: {0}")]
    Io(#[from] std::io::Error),
}

/// The common shape of a status code into an error.
#[must_use]
pub fn status_error(status: u16) -> StoreError {
    match status {
        401 | 403 => StoreError::Unauthorized,
        404 | 410 => StoreError::NotFound,
        429 => StoreError::Throttled {
            retry_after_ms: 1_000,
        },
        507 => StoreError::Full,
        s => StoreError::Unavailable { status: s },
    }
}

/// A place a backup lives: opaque chunk objects under their names, and one manifest object
/// replaced only by compare-and-swap on its generation.
///
/// Rules every adapter keeps (checked by [`crate::conformance`]):
/// - `put` of a name already stored succeeds and may keep either object (same name, same
///   plaintext);
/// - `get` returns exactly the bytes stored, or [`StoreError::NotFound`];
/// - `list` returns every stored chunk name, each once, whatever their number;
/// - `delete` of names not stored succeeds;
/// - `swap_manifest(expected, object)` stores `object` only if the current manifest's
///   generation is `expected` (0: none) and the object's own generation is `expected + 1`;
///   otherwise [`StoreError::Conflict`] with the current generation; of racing writers exactly
///   one wins each generation;
/// - `destroy` removes everything, after which the store is empty.
#[async_trait]
pub trait BackupStore: Send + Sync {
    /// A short, fixed name for logs and the app ("vault", "s3", ...).
    fn kind(&self) -> &'static str;

    /// Prepares the store (creates the vault or the app folder); harmless when it exists.
    async fn open(&self) -> Result<(), StoreError>;

    /// Stores one chunk object.
    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError>;

    /// Reads one chunk object.
    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError>;

    /// Every stored chunk name.
    async fn list(&self) -> Result<Vec<ChunkName>, StoreError>;

    /// Deletes chunks.
    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError>;

    /// The current manifest object, if any.
    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError>;

    /// Replaces the manifest if the current one's generation is `expected`.
    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError>;

    /// Deletes the whole backup.
    async fn destroy(&self) -> Result<(), StoreError>;
}

/// The generation in a manifest object's header, for adapters checking a swap.
///
/// # Errors
/// [`StoreError::Protocol`] for an object that is not a manifest.
pub fn generation_of(object: &[u8]) -> Result<u64, StoreError> {
    songbird_backup_format::object::manifest_generation(object)
        .map_err(|_| StoreError::Protocol("not a manifest"))
}

/// Checks a swap's arguments: the object is the next generation after `expected`.
///
/// # Errors
/// [`StoreError::Protocol`].
pub fn check_next(expected: u64, object: &[u8]) -> Result<u64, StoreError> {
    let g = generation_of(object)?;
    if Some(g) == expected.checked_add(1) {
        Ok(g)
    } else {
        Err(StoreError::Protocol("generation"))
    }
}
