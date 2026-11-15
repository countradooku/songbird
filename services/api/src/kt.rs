//! Key transparency (Prompt 3, M6, D-0055; `docs/PROTOCOL.md` §4.9): signed tree heads,
//! an account's entries with inclusion proofs, and consistency proofs.
//!
//! | Method and path | What |
//! | --- | --- |
//! | `GET /v1/kt/head` | The current signed tree head |
//! | `POST /v1/kt/account` | `{"account"}` → the account's salt, the head, its entries with proofs |
//! | `POST /v1/kt/consistency` | `{"from", "to"}` → the consistency proof between two sizes |

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use aws_lc_rs::{hkdf, hmac};
use songbird_accounts::Registry;
use songbird_kt::TreeHead;
use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;

use crate::config::KtSettings;
use crate::registration::Registration;

/// Most entries an account answer carries (the newest).
pub const MAX_ENTRIES: usize = 256;

/// What a transparency endpoint answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 200 with JSON.
    Json(serde_json::Value),
    /// 200 with bytes.
    Blob(bytes::Bytes),
    /// 400.
    Malformed(&'static str),
    /// 404.
    NotFound,
    /// 429 (microseconds).
    Throttled(u64),
    /// 503.
    Unavailable,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountBody {
    account: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsistencyBody {
    from: u64,
    to: u64,
}

/// Transparency state.
pub struct Transparency {
    /// Settings.
    pub settings: KtSettings,
    key: Ed25519KeyPair,
    record_key: hmac::Key,
}

impl std::fmt::Debug for Transparency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transparency").finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Signs a tree head.
#[must_use]
pub fn sign_head(key: &Ed25519KeyPair, size: u64, root: [u8; 32], time_ms: u64) -> TreeHead {
    let mut h = TreeHead {
        size,
        root,
        time_ms,
        signature: [0; 64],
    };
    let sig = key.sign(&h.signed_bytes());
    h.signature.copy_from_slice(sig.as_ref());
    h
}

impl Transparency {
    /// Loads the log key; derives the throttle key.
    ///
    /// # Errors
    /// A malformed key, HKDF (never).
    pub fn new(
        settings: KtSettings,
        secret: &[u8; 32],
        log_seed: &[u8; 32],
    ) -> Result<Self, &'static str> {
        let key = Ed25519KeyPair::from_seed_unchecked(log_seed).map_err(|_| "log key")?;
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-kt-v1")
            .extract(secret)
            .expand(&[b"kt-records"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut k))
            .map_err(|_| "hkdf")?;
        Ok(Self {
            settings,
            key,
            record_key: hmac::Key::new(hmac::HMAC_SHA256, &k),
        })
    }

    /// The log's public key (clients pin it).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key().as_ref().try_into().unwrap_or([0; 32])
    }

    async fn throttle(&self, hot: &ValkeyConn, requester: &AccountId) -> Result<(), Outcome> {
        let mut ctx = hmac::Context::with_key(&self.record_key);
        ctx.update(b"f\0");
        ctx.update(requester.as_bytes());
        let record = format!(
            "kt:f:{}",
            hex::encode(ctx.sign().as_ref().get(..16).unwrap_or_default())
        );
        match Registration::gcra(
            hot,
            &record,
            self.settings.fetches_per_hour,
            self.settings.fetch_burst,
            false,
        )
        .await
        {
            Ok(0) => Ok(()),
            Ok(w) => Err(Outcome::Throttled(w)),
            Err(()) => Err(Outcome::Unavailable),
        }
    }

    async fn head_at(&self, registry: &Registry, size: u64) -> Result<TreeHead, Outcome> {
        let root = registry
            .kt_root(size)
            .await
            .map_err(|_| Outcome::Unavailable)?;
        Ok(sign_head(&self.key, size, root, now_ms()))
    }

    /// `GET /v1/kt/head`.
    pub async fn head(&self, registry: &Registry) -> Outcome {
        let Ok(size) = registry.kt_size().await else {
            return Outcome::Unavailable;
        };
        match self.head_at(registry, size).await {
            Ok(h) => Outcome::Blob(bytes::Bytes::from(h.encode())),
            Err(o) => o,
        }
    }

    /// `POST /v1/kt/account`.
    pub async fn account(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        requester: &AccountId,
        body: &[u8],
    ) -> Outcome {
        if let Err(o) = self.throttle(hot, requester).await {
            return o;
        }
        let Some(account) = serde_json::from_slice::<AccountBody>(body)
            .ok()
            .and_then(|b| {
                let mut a = [0u8; 16];
                hex::decode_to_slice(b.account, &mut a).ok().map(|()| a)
            })
            .map(AccountId::from_bytes)
        else {
            return Outcome::Malformed("request");
        };
        let Ok(size) = registry.kt_size().await else {
            return Outcome::Unavailable;
        };
        let head = match self.head_at(registry, size).await {
            Ok(h) => h,
            Err(o) => return o,
        };
        match registry.kt_account(&account, size, MAX_ENTRIES).await {
            Ok(Some((salt, entries))) => Outcome::Json(serde_json::json!({
                "salt": hex::encode(salt),
                "head": hex::encode(head.encode()),
                "entries": entries.iter().map(|e| serde_json::json!({
                    "index": e.index,
                    "leaf": hex::encode(e.leaf.encode()),
                    "proof": e.proof.iter().map(hex::encode).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })),
            Ok(None) => Outcome::NotFound,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/kt/consistency`.
    pub async fn consistency(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        requester: &AccountId,
        body: &[u8],
    ) -> Outcome {
        if let Err(o) = self.throttle(hot, requester).await {
            return o;
        }
        let Ok(b) = serde_json::from_slice::<ConsistencyBody>(body) else {
            return Outcome::Malformed("request");
        };
        let Ok(size) = registry.kt_size().await else {
            return Outcome::Unavailable;
        };
        if b.from == 0 || b.from > b.to || b.to > size {
            return Outcome::Malformed("sizes");
        }
        match registry.kt_consistency(b.from, b.to).await {
            Ok(p) => Outcome::Json(serde_json::json!({
                "proof": p.iter().map(hex::encode).collect::<Vec<_>>(),
            })),
            Err(_) => Outcome::Unavailable,
        }
    }
}
