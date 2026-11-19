//! Plans in `api` (Prompt 11, M1; `docs/PROTOCOL.md` §12; D-0127).
//!
//! | Request | What |
//! | --- | --- |
//! | `GET /v1/entitlements` | Signed by a listed device: the account's level, its last day, the catalogue version, and the limits and flags in force |
//!
//! Every limit `api` enforces reads the account's level here: the device limit (linking), the
//! largest file and the daily upload bytes (grants), the vault's space and chunks, new packs per
//! 30 days. A downgrade never deletes: what is over the limit stays and keeps working, and only
//! additions are refused until the account is back under it (D-0126 finding 5).

use std::sync::Arc;

use songbird_entitlements::{Catalog, Level, Limits, Live};
use songbird_types::AccountId;

/// The catalogue and the live snapshot.
#[derive(Debug, Default, Clone)]
pub struct Plans {
    /// Every level's limits and flags (`[api.plans]`).
    pub catalog: Catalog,
    /// The accounts not on the default plan, followed from the registry.
    pub live: Arc<Live>,
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
