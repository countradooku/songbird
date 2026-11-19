//! Plans in `api` (Prompt 11, M1; `docs/PROTOCOL.md` §12; D-0127).
//!
//! | Request | What |
//! | --- | --- |
//! | `GET /v1/entitlements` | Signed by a listed device: the account's level, its last day, the catalogue version, and the limits and flags in force |
//! | `POST /v1/entitlements/redeem` | Signed by a listed device: one anonymous plan token (`songbird_tokens::token::Redemption`); the account holds its level through the token's month and [`GRACE_DAYS`] |
//! | `GET /v1/tokens/keys` | No account: the token public keys apps pin |
//!
//! # Redemption (D-0128)
//!
//! A plan token was issued by billing for a month and a level, on a nonce `api` has never seen
//! (it was blinded). Redeeming it: the account's budget first (keyed record), then the token's
//! metadata (a paid level this build knows, the current or the next month), then the PRF under
//! that metadata (constant time), then, in one transaction, its nullifier is burnt and the
//! entitlement extended. A token spent twice is 409 `spent` and changes nothing. Nothing about
//! the token is kept but its nullifier, until its month is over.
//!
//! Every limit `api` enforces reads the account's level here: the device limit (linking), the
//! largest file and the daily upload bytes (grants), the vault's space and chunks, new packs per
//! 30 days. A downgrade never deletes: what is over the limit stays and keeps working, and only
//! additions are refused until the account is back under it (D-0126 finding 5).

use std::sync::Arc;

use aws_lc_rs::{hkdf, hmac};
use songbird_accounts::{Registry, RegistryError};
use songbird_entitlements::{Catalog, Level, Limits, Live};
use songbird_tokens::token::{self, Keys, Kind, Redemption};
use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;

use crate::config::TokenSettings;
use crate::profiles::Outcome;

/// Days a plan token's level is held past the end of its month: a renewal that fails at the
/// store's first attempt is retried for a few days before the plan lapses.
pub const GRACE_DAYS: u32 = 3;

/// The catalogue and the live snapshot.
#[derive(Debug, Default, Clone)]
pub struct Plans {
    /// Every level's limits and flags (`[api.plans]`).
    pub catalog: Catalog,
    /// The accounts not on the default plan, followed from the registry.
    pub live: Arc<Live>,
    /// Token redemption (`[api.tokens]`; absent: 503).
    pub redeemer: Option<Arc<Redeemer>>,
}

/// The token keys and the redemption budget.
pub struct Redeemer {
    keys: Keys,
    record_key: hmac::Key,
    settings: TokenSettings,
}

impl std::fmt::Debug for Redeemer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redeemer")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl Redeemer {
    /// Derives the token keys and the budget records' key from the token secret.
    ///
    /// # Errors
    /// A bad key list, or HKDF (never for 32 bytes).
    pub fn new(settings: TokenSettings, secret: &[u8; 32]) -> Result<Self, &'static str> {
        let keys = Keys::derive(secret, &settings.keys).map_err(|_| "token keys")?;
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-tokens-v1")
            .extract(secret)
            .expand(&[b"redeem-records"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut k))
            .map_err(|_| "hkdf")?;
        Ok(Self {
            keys,
            record_key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            settings,
        })
    }

    /// The token keys (tests issue with them).
    #[must_use]
    pub const fn keys(&self) -> &Keys {
        &self.keys
    }

    fn record(&self, account: &AccountId) -> String {
        let tag = hmac::sign(&self.record_key, account.as_bytes());
        format!(
            "tk:r:{}",
            hex::encode(tag.as_ref().get(..16).unwrap_or_default())
        )
    }

    /// `GET /v1/tokens/keys`.
    #[must_use]
    pub fn public_keys(&self) -> serde_json::Value {
        serde_json::json!({
            "current": self.keys.current(),
            "keys": self.keys.public().iter().map(|(id, pk)| serde_json::json!({
                "id": id,
                "public": hex::encode(pk),
            })).collect::<Vec<_>>(),
        })
    }

    /// `POST /v1/entitlements/redeem` for `account` (a listed device's).
    pub async fn redeem(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        body: &[u8],
        today: u32,
    ) -> Outcome {
        match crate::registration::Registration::gcra(
            hot,
            &self.record(account),
            self.settings.redeems_per_hour,
            self.settings.redeem_burst,
            false,
        )
        .await
        {
            Ok(0) => {}
            Ok(wait) => return Outcome::Throttled(wait),
            Err(()) => return Outcome::Unavailable,
        }
        let Ok(r) = serde_json::from_slice::<Redemption>(body) else {
            return Outcome::Malformed("token");
        };
        let Some(level) = Level::from_u8(r.level).filter(|l| *l != Level::Free) else {
            return Outcome::Malformed("level");
        };
        if r.kind != Kind::Plan.as_u8() {
            return Outcome::Malformed("kind");
        }
        let month = token::month_of(today);
        if r.period < month || r.period > month.saturating_add(1) {
            return Outcome::Conflict("period");
        }
        let nullifier = match self.keys.redeem(&r) {
            Ok((_, n)) => n,
            Err(token::TokenError::Invalid) => return Outcome::Conflict("invalid"),
            Err(_) => return Outcome::Malformed("token"),
        };
        let end = token::last_day(r.period);
        match registry
            .redeem_plan_token(
                &nullifier,
                end.saturating_add(1),
                account,
                level.as_u8(),
                end.saturating_add(GRACE_DAYS),
                today,
            )
            .await
        {
            Ok(row) => Outcome::Json(serde_json::json!({
                "level": Level::from_u8(row.level).map_or("free", Level::name),
                "last_day": row.last_day,
            })),
            Err(RegistryError::Spent) => Outcome::Conflict("spent"),
            Err(RegistryError::NotFound) => Outcome::Unauthorized,
            Err(_) => Outcome::Unavailable,
        }
    }
}

impl Plans {
    /// The account's level today.
    #[must_use]
    pub fn level(&self, account: &AccountId) -> Level {
        self.live.level(account)
    }

    /// The account's limits today.
    #[must_use]
    pub fn limits(&self, account: &AccountId) -> &Limits {
        self.catalog.limits(self.level(account))
    }

    /// The account's device limit (the primary included) under a deployment ceiling.
    #[must_use]
    pub fn devices(&self, account: &AccountId, ceiling: u32) -> u32 {
        self.limits(account).devices().min(ceiling)
    }

    /// `GET /v1/entitlements`.
    #[must_use]
    pub fn describe(&self, account: &AccountId) -> serde_json::Value {
        let entry = self.live.entry(account);
        let level = entry.map_or(Level::Free, |e| e.level);
        let plan = self.catalog.plan(level);
        let l = &plan.limits;
        let f = &plan.flags;
        serde_json::json!({
            "level": level.name(),
            "last_day": entry.map(|e| e.last_day),
            "catalog": self.catalog.version,
            "limits": {
                "linked_devices": l.linked_devices,
                "file_bytes": l.file_bytes,
                "upload_bytes_per_day": l.upload_bytes_per_day,
                "vault_bytes": l.vault_bytes,
                "vault_chunks": l.vault_chunks,
                "packs_per_month": l.packs_per_month,
            },
            "flags": {
                "app_icons": f.app_icons,
                "chat_themes": f.chat_themes,
                "priority_support": f.priority_support,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use songbird_accounts::entitlements::{EntRow, Source};
    use songbird_entitlements::{Snapshot, today};

    use super::*;

    #[test]
    fn limits_follow_the_level_and_expire_by_date() {
        let a = AccountId::from_bytes([1; 16]);
        let b = AccountId::from_bytes([2; 16]);
        let plans = Plans::default();
        plans.live.store(Snapshot::from_rows(
            2,
            &[
                EntRow {
                    account: a,
                    level: 1,
                    last_day: today(),
                    source: Source::Grant,
                },
                EntRow {
                    account: b,
                    level: 1,
                    last_day: today() - 1,
                    source: Source::Token,
                },
            ],
        ));
        assert_eq!(plans.level(&a), Level::Plus);
        assert_eq!(plans.devices(&a, 16), 11);
        assert_eq!(plans.devices(&a, 2), 2, "a deployment ceiling wins");
        assert_eq!(plans.limits(&a).file_bytes, 4 << 30);
        // Expired yesterday: Free, whatever the snapshot still lists.
        assert_eq!(plans.level(&b), Level::Free);
        assert_eq!(plans.devices(&b, 16), 6);
        let d = plans.describe(&a);
        assert_eq!(d["level"], "plus");
        assert_eq!(d["last_day"], today());
        assert_eq!(d["limits"]["linked_devices"], 10);
        assert_eq!(d["flags"]["chat_themes"], true);
        let d = plans.describe(&b);
        assert_eq!(d["level"], "free");
        assert!(d["last_day"].is_null());
        assert_eq!(d["flags"]["app_icons"], false);
    }
}
