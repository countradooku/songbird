//! Blocks and the message-request policy (Prompt 4, M4; `docs/PROTOCOL.md` §5.10–5.11, D-0062).
//!
//! | Request | Body | Who |
//! | --- | --- | --- |
//! | `PUT /v1/blocks` | `{"account": hex}` | any listed device (tightening) |
//! | `DELETE /v1/blocks` | `{"account": hex}` | the primary only (loosening) |
//! | `GET /v1/account/requests` | none | any device: `{"from": "everyone" \| "nobody"}` |
//! | `PUT /v1/account/requests` | `{"from": "nobody"}` | any listed device (tightening) |
//! | `PUT /v1/account/requests` | `{"from": "everyone"}` | the primary only (loosening) |
//!
//! The owner's rule (D-0058): a linked device may make the account safer, only the primary may
//! make it less safe, so a stolen linked device cannot unblock a stalker or open the account to
//! strangers. A pending device changes nothing. The server stores a block as a keyed hash of the
//! pair ([`songbird_send::GateKeys`]); the list itself syncs between the user's devices in
//! encrypted content.

use serde::Deserialize;
use songbird_accounts::{DeviceRow, Registry, RegistryError};
use songbird_send::GateKeys;
use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_types::AccountId;

use crate::devices::Outcome;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct RequestsMetrics {
    /// Blocks added.
    pub blocks: Counter,
    /// Blocks removed.
    pub unblocks: Counter,
}

impl RequestsMetrics {
    /// Registers the counters.
    ///
    /// # Errors
    /// A name is refused.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        m.register("api_blocks_added", "Blocks added", self.blocks.clone())?;
        m.register(
            "api_blocks_removed",
            "Blocks removed",
            self.unblocks.clone(),
        )
    }
}

/// The blocks and request-policy endpoints.
#[derive(Debug, Clone)]
pub struct Requests {
    keys: GateKeys,
    metrics: RequestsMetrics,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockBody {
    account: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBody {
    from: String,
}

impl Requests {
    /// Whether `blocker` blocked `target` (a call to an open account, Prompt 7).
    ///
    /// # Errors
    /// The registry failed.
    pub(crate) async fn blocked(
        &self,
        registry: &Registry,
        blocker: &AccountId,
        target: &AccountId,
    ) -> Result<bool, ()> {
        registry
            .is_blocked(&self.keys.pair(blocker, target))
            .await
            .map_err(|_| ())
    }
}

fn account_of(body: &[u8]) -> Option<AccountId> {
    let b: BlockBody = serde_json::from_slice(body).ok()?;
    AccountId::parse_hex(&b.account).ok()
}

impl Requests {
    /// The endpoints over the gate's keys (the same secret as every delivery node's gate).
    #[must_use]
    pub const fn new(keys: GateKeys, metrics: RequestsMetrics) -> Self {
        Self { keys, metrics }
    }

    /// `PUT /v1/blocks`: a listed device blocks an account.
    pub async fn block(&self, registry: &Registry, row: &DeviceRow, body: &[u8]) -> Outcome {
        if row.pending {
            return Outcome::Forbidden("pending");
        }
        let Some(blocked) = account_of(body).filter(|a| *a != row.account) else {
            return Outcome::Malformed("account");
        };
        let owner = self.keys.owner(&row.account);
        match registry
            .add_block(&owner, &self.keys.pair(&row.account, &blocked))
            .await
        {
            Ok(()) => {
                self.metrics.blocks.inc();
                Outcome::Done
            }
            Err(RegistryError::Full) => Outcome::Conflict("limit"),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `DELETE /v1/blocks`: the primary unblocks an account.
    pub async fn unblock(&self, registry: &Registry, row: &DeviceRow, body: &[u8]) -> Outcome {
        if !row.primary {
            return Outcome::Forbidden("primary");
        }
        let Some(blocked) = account_of(body) else {
            return Outcome::Malformed("account");
        };
        match registry
            .remove_block(
                &self.keys.owner(&row.account),
                &self.keys.pair(&row.account, &blocked),
            )
            .await
        {
            Ok(()) => {
                self.metrics.unblocks.inc();
                Outcome::Done
            }
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `GET /v1/account/requests`.
    pub async fn policy(registry: &Registry, row: &DeviceRow) -> Outcome {
        match registry.requests_off(&row.account).await {
            Ok(off) => Outcome::Json(serde_json::json!({
                "from": if off { "nobody" } else { "everyone" }
            })),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `PUT /v1/account/requests`: refusing requests from any listed device, accepting them again
    /// from the primary only.
    pub async fn set_policy(registry: &Registry, row: &DeviceRow, body: &[u8]) -> Outcome {
        let Ok(p) = serde_json::from_slice::<PolicyBody>(body) else {
            return Outcome::Malformed("from");
        };
        let off = match p.from.as_str() {
            "nobody" => true,
            "everyone" => false,
            _ => return Outcome::Malformed("from"),
        };
        if row.pending {
            return Outcome::Forbidden("pending");
        }
        if !off && !row.primary {
            return Outcome::Forbidden("primary");
        }
        match registry.set_requests_off(&row.account, off).await {
            Ok(()) => Outcome::Done,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// The owner tag of an account's block rows (export and deletion).
    #[must_use]
    pub fn owner(&self, account: &AccountId) -> [u8; 16] {
        self.keys.owner(account)
    }
}
