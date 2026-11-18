//! Server-enforced settings (Prompt 9, M2, D-0103; `docs/THREAT_MODEL.md` §4; PROTOCOL §10.3).
//!
//! | Method and path | Who | What |
//! | --- | --- | --- |
//! | `GET /v1/account/settings` | any device of the account | `{"discoverable", "groups", "requests", "inactivity_months"}` |
//! | `PUT /v1/account/discoverable` | `{"on": bool}`: off from any listed device, on from the primary | Found by username lookups |
//! | `PUT /v1/account/groups` | `{"from": "everyone" \| "contacts"}`: contacts from any listed device, everyone from the primary | Who may add the account to groups |
//!
//! Tightening is any listed device's; loosening is the primary's (D-0058): a stolen linked
//! device cannot open the account up.

use serde::Deserialize;
use songbird_accounts::{DeviceRow, Registry, RegistryError};

use crate::devices::Outcome;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OnBody {
    on: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FromBody {
    from: String,
}

/// `GET /v1/account/settings`.
pub async fn get(registry: &Registry, row: &DeviceRow) -> Outcome {
    match registry.server_settings(&row.account).await {
        Ok(s) => Outcome::Json(serde_json::json!({
            "discoverable": s.discoverable,
            "groups": if s.groups_contacts { "contacts" } else { "everyone" },
            "requests": if s.requests_off { "nobody" } else { "everyone" },
            "inactivity_months": s.inactivity_months,
        })),
        Err(RegistryError::NotFound) => Outcome::NotFound,
        Err(_) => Outcome::Unavailable,
    }
}

fn written(r: &Result<(), RegistryError>) -> Outcome {
    match r {
        Ok(()) => Outcome::Done,
        Err(RegistryError::NotPrimary) => Outcome::Forbidden("primary"),
        Err(RegistryError::NotFound) => Outcome::NotFound,
        Err(_) => Outcome::Unavailable,
    }
}

/// `PUT /v1/account/discoverable`.
pub async fn set_discoverable(registry: &Registry, row: &DeviceRow, body: &[u8]) -> Outcome {
    let Ok(b) = serde_json::from_slice::<OnBody>(body) else {
        return Outcome::Malformed("on");
    };
    if row.pending {
        return Outcome::Forbidden("pending");
    }
    written(
        &registry
            .set_discoverable(&row.account, b.on, row.primary)
            .await,
    )
}

/// `PUT /v1/account/groups`.
pub async fn set_groups(registry: &Registry, row: &DeviceRow, body: &[u8]) -> Outcome {
    let Ok(b) = serde_json::from_slice::<FromBody>(body) else {
        return Outcome::Malformed("from");
    };
    let contacts = match b.from.as_str() {
        "contacts" => true,
        "everyone" => false,
        _ => return Outcome::Malformed("from"),
    };
    if row.pending {
        return Outcome::Forbidden("pending");
    }
    written(
        &registry
            .set_groups_contacts(&row.account, contacts, row.primary)
            .await,
    )
}
