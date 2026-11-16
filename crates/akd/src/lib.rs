//! Key transparency on Meta's `akd` (Prompt 3, D-0057; the owner's decision of 2026-11-16).
//!
//! `akd` is a verifiable key directory: a VRF hides labels, and lookup, history and
//! append-only (audit) proofs let clients and auditors check the directory without trusting the
//! server. Songbird supplies its storage ([`store::SurrealStore`] on SurrealDB), the VRF key from
//! the secrets store ([`SecretVrf`]), and its labels:
//!
//! - **Label** = `kind u8 || subject [32]`, where `subject = HMAC-SHA256(salt,
//!   "songbird.v1/kt-subject\0" || account)` ([`subject`]) with a random per-account salt:
//!   deleting the salt with the account leaves its entries unlinkable, which matters because
//!   `akd` 0.13 cannot tombstone.
//! - **Value** = SHA-256 of the identity key or of the signed device list, or the username hash
//!   (32 zero bytes once released).
//!
//! One writer (the worker) publishes an epoch per batch of changes; `api` nodes read with
//! [`akd::directory::ReadOnlyDirectory`].
#![forbid(unsafe_code)]

pub mod head;
pub mod proofs;
pub mod store;

use akd::directory::{Directory, ReadOnlyDirectory};
use akd::ecvrf::{VRFKeyStorage, VrfError};
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue, AzksParallelismConfig};

pub use akd::WhatsAppV1Configuration as Config;
pub use head::SignedHead;
pub use store::SurrealStore;

/// The writer's directory.
pub type Writer = Directory<Config, SurrealStore, SecretVrf>;
/// A reader's directory.
pub type Reader = ReadOnlyDirectory<Config, SurrealStore, SecretVrf>;

/// The VRF private key (an Ed25519 seed) from the secrets store.
#[derive(Clone)]
pub struct SecretVrf(std::sync::Arc<[u8; 32]>);

impl std::fmt::Debug for SecretVrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretVrf(..)")
    }
}

impl SecretVrf {
    /// From the 32-byte seed.
    #[must_use]
    pub fn new(seed: &[u8; 32]) -> Self {
        Self(std::sync::Arc::new(*seed))
    }
}

#[async_trait::async_trait]
impl VRFKeyStorage for SecretVrf {
    async fn retrieve(&self) -> Result<Vec<u8>, VrfError> {
        Ok(self.0.to_vec())
    }
}

/// What a label is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The account identity key.
    Identity = 1,
    /// The signed device list.
    DeviceList = 2,
    /// The username hash.
    Username = 3,
}

impl Kind {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Identity => 1,
            Self::DeviceList => 2,
            Self::Username => 3,
        }
    }
}

/// The label for one kind of an account's entries.
#[must_use]
pub fn label(kind: Kind, subject: &[u8; 32]) -> AkdLabel {
    let mut l = Vec::with_capacity(33);
    l.push(kind.code());
    l.extend_from_slice(subject);
    AkdLabel(l)
}

/// A value: 32 bytes.
#[must_use]
pub fn value(v: &[u8; 32]) -> AkdValue {
    AkdValue(v.to_vec())
}

/// Opens (or creates) the writer's directory.
///
/// # Errors
/// The storage or the directory refused.
pub async fn writer(store: SurrealStore, vrf: SecretVrf) -> Result<Writer, akd::errors::AkdError> {
    Directory::new(
        StorageManager::new_no_cache(store),
        vrf,
        AzksParallelismConfig::disabled(),
    )
    .await
}

/// Opens a reader's directory (the writer must have created it).
///
/// # Errors
/// The storage refused, or no directory exists yet.
pub async fn reader(store: SurrealStore, vrf: SecretVrf) -> Result<Reader, akd::errors::AkdError> {
    ReadOnlyDirectory::new(
        StorageManager::new_no_cache(store),
        vrf,
        AzksParallelismConfig::disabled(),
    )
    .await
}

/// The subject naming an account: `HMAC-SHA256(salt, "songbird.v1/kt-subject\0" || account)`.
#[must_use]
pub fn subject(salt: &[u8; 32], account: &[u8; 16]) -> [u8; 32] {
    use aws_lc_rs::hmac;
    let k = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(b"songbird.v1/kt-subject\0");
    ctx.update(account);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

fn kind_of(k: songbird_accounts::kt::KtKind) -> Kind {
    match k {
        songbird_accounts::kt::KtKind::Identity => Kind::Identity,
        songbird_accounts::kt::KtKind::DeviceList => Kind::DeviceList,
        songbird_accounts::kt::KtKind::Username => Kind::Username,
    }
}

/// Publishes what changed (the worker's pass): one epoch for up to `limit` accounts, then marks
/// them published. Returns the entries published (0: no epoch).
///
/// # Errors
/// The registry or `akd` refused; nothing is marked, so the next pass retries.
pub async fn publish_pending(
    registry: &songbird_accounts::Registry,
    writer: &Writer,
    limit: usize,
) -> Result<usize, PublishError> {
    let pending = registry
        .kt_pending(limit)
        .await
        .map_err(PublishError::Registry)?;
    let updates: Vec<(AkdLabel, AkdValue)> = pending
        .iter()
        .flat_map(|p| {
            let s = subject(&p.salt, p.account.as_bytes());
            p.changes
                .iter()
                .map(move |(k, v)| (label(kind_of(*k), &s), value(v)))
        })
        .collect();
    let n = updates.len();
    if n > 0 {
        writer.publish(updates).await.map_err(PublishError::Akd)?;
    }
    for p in &pending {
        registry
            .kt_logged(p)
            .await
            .map_err(PublishError::Registry)?;
    }
    Ok(n)
}

/// The writer's directory, for the service that owns it (the worker).
pub struct Publisher(pub Writer);

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Publisher(..)")
    }
}

impl Publisher {
    /// Opens (or creates) the directory.
    ///
    /// # Errors
    /// The storage or the directory refused.
    pub async fn open(store: SurrealStore, vrf: SecretVrf) -> Result<Self, akd::errors::AkdError> {
        Ok(Self(writer(store, vrf).await?))
    }

    /// [`publish_pending`].
    ///
    /// # Errors
    /// [`PublishError`].
    pub async fn publish_pending(
        &self,
        registry: &songbird_accounts::Registry,
        limit: usize,
    ) -> Result<usize, PublishError> {
        publish_pending(registry, &self.0, limit).await
    }
}

/// Publishing failed.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The registry.
    #[error("registry: {0}")]
    Registry(songbird_accounts::RegistryError),
    /// `akd`.
    #[error("akd: {0}")]
    Akd(akd::errors::AkdError),
}
