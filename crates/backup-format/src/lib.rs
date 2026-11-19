//! Songbird's backup format (Prompt 10; D-0119, D-0120; PROTOCOL §11).
//!
//! A backup is an encrypted **manifest** and a set of encrypted **chunks**, every key derived
//! from a 64-character [`RecoveryKey`]:
//!
//! - the content (account, profile, settings, contacts, groups, chats, messages, media) is
//!   written as byte **streams** ([`schema::StreamKind`]), cut by a keyed content-defined
//!   [`chunker`] into chunks of 1 to 8 MiB;
//! - a chunk is named by `HMAC-SHA256(chunk-name key, plaintext)` and sealed with
//!   XChaCha20-Poly1305 after Padmé padding ([`object`]); equal content gets the same name, so a
//!   later backup uploads only chunks the store does not hold yet;
//! - the manifest lists every stream's chunks, its length and SHA-256, and the hash of the
//!   previous manifest; its generation is the only clear field, for the store's
//!   compare-and-swap.
//!
//! Restoring is two-phase ([`reader`]): every chunk is fetched and checked (tag, name, length,
//! padding, each stream's length and SHA-256, every record decodes) before the caller writes
//! anything. A damaged, truncated, renamed, missing or foreign chunk fails loudly.
//!
//! Sans-IO: chunks go to a [`writer::ChunkSink`] and come from a [`reader::ChunkSource`], which
//! `songbird-backup-storage` implements for every store.
#![forbid(unsafe_code)]

pub mod chunker;
pub mod key;
pub mod object;
pub mod reader;
pub mod schema;
pub mod synth;
pub mod writer;

pub use key::{BackupKeys, RecoveryKey};
pub use object::ChunkName;

/// The format version this crate writes.
pub const FORMAT_VERSION: u32 = 1;
/// The newest `min_reader_version` this crate reads.
pub const READER_VERSION: u32 = 1;

/// What went wrong. Never carries content, keys or names.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A recovery key holds a character outside the alphabet.
    #[error("the recovery key has a character that is not in it")]
    KeyCharacter,
    /// A recovery key is not 64 characters.
    #[error("the recovery key is not 64 characters")]
    KeyLength,
    /// A recovery key's check does not match: a typo.
    #[error("the recovery key does not check out (a typo?)")]
    KeyCheck,
    /// The random source failed.
    #[error("no randomness")]
    Random,
    /// A cryptographic primitive refused its input (never for valid lengths).
    #[error("cryptography failed")]
    Crypto,
    /// An object is not in the format (bad magic, version, lengths or padding).
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// An object's tag does not verify: damaged, truncated, or from another backup.
    #[error("a {0} is damaged or belongs to another backup")]
    Damaged(&'static str),
    /// A chunk's content does not match its name.
    #[error("a chunk does not match its name")]
    WrongName,
    /// A stream's length or SHA-256 does not match the manifest.
    #[error("a stream does not match the manifest")]
    StreamMismatch,
    /// A chunk the manifest names is missing from the store.
    #[error("a chunk is missing")]
    Missing,
    /// The backup needs a newer reader.
    #[error("this backup needs a newer version of Songbird")]
    TooNew,
    /// The store served a manifest older than one this device has seen.
    #[error("the store served an older backup than one already seen")]
    Rollback,
    /// The store served a manifest that does not follow the one this device has seen.
    #[error("the store served a backup that does not follow the one already seen")]
    Fork,
    /// An input exceeds a bound of the format.
    #[error("{0} too large")]
    TooLarge(&'static str),
    /// The store failed (the adapter's error, already redacted).
    #[error("store: {0}")]
    Store(Box<dyn std::error::Error + Send + Sync>),
    /// Reading a media file the caller passed failed.
    #[error("reading a file failed")]
    Io(#[from] std::io::Error),
}

/// A source of randomness. Backups use [`OsRng`]; vectors use a fixed one.
pub trait Rng {
    /// Fills `b` with random bytes.
    ///
    /// # Errors
    /// [`Error::Random`].
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error>;
}

/// The operating system's random source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(b).map_err(|_| Error::Random)
    }
}

/// A deterministic random source for vectors and tests: SHA-256 of a seed and a counter.
/// **Never** for real backups.
#[derive(Debug, Clone)]
pub struct FixedRng {
    seed: [u8; 32],
    counter: u64,
}

impl FixedRng {
    /// A source that always yields the same bytes for the same seed.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

impl Rng for FixedRng {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        for part in b.chunks_mut(32) {
            let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
            ctx.update(&self.seed);
            ctx.update(&self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
            let d = ctx.finish();
            part.copy_from_slice(d.as_ref().split_at(part.len()).0);
        }
        Ok(())
    }
}
