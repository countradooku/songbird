//! Server-enforced settings (Prompt 9, M2, D-0103; `docs/THREAT_MODEL.md` §4; PROTOCOL §10.3).
//!
//! | Method and path | Who | What |
//! | --- | --- | --- |
//! | `GET /v1/account/settings` | any device of the account | `{"discoverable", "groups", "requests", "inactivity_months"}` |
//! | `PUT /v1/account/discoverable` | `{"on": bool}`: off from any listed device, on from the primary | Found by username lookups |
//! | `PUT /v1/account/groups` | `{"from": "everyone" \| "contacts"}`: contacts from any listed device, everyone from the primary | Who may add the account to groups |
//! | `PUT /v1/supervision` | a signed policy (PROTOCOL §10.6): the first from the child's primary, later ones from any device, authorized by the parent's signature | Parental supervision (Prompt 9, M4) |
//! | `GET /v1/supervision` | the child's devices | The policy in force, as signed (404 when none) |
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
            "supervised": s.supervised,
        })),
        Err(RegistryError::NotFound) => Outcome::NotFound,
        Err(_) => Outcome::Unavailable,
    }
}

fn written(r: &Result<(), RegistryError>) -> Outcome {
    match r {
        Ok(()) => Outcome::Done,
        Err(RegistryError::NotPrimary) => Outcome::Forbidden("primary"),
        Err(RegistryError::Supervised) => Outcome::Forbidden("supervised"),
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

/// `PUT /v1/supervision` (Prompt 9, M4, D-0105; D-0108), signed by one of the child's own
/// devices: the first policy from the child's primary (the child consents in person; the
/// parent's signature proves the parent does), or a later one the child's device carries. A
/// policy for another account is refused with one answer whether or not that account is
/// supervised, so the endpoint tells nobody which accounts are children's. A parent's device
/// sends later policies unsigned ([`update_supervision`]), so the server never learns which
/// account the parent is.
pub async fn put_supervision(registry: &Registry, row: &DeviceRow, body: &[u8]) -> Outcome {
    use songbird_proto::supervision::Policy;
    let Ok(p) = Policy::decode(body) else {
        return Outcome::Malformed("policy");
    };
    if row.pending {
        return Outcome::Forbidden("pending");
    }
    if p.child != row.account {
        return Outcome::Forbidden("account");
    }
    let Ok(current) = registry.supervision(&p.child).await else {
        return Outcome::Unavailable;
    };
    let first = current.is_none();
    if first && !row.primary {
        return Outcome::Forbidden("primary");
    }
    let key = current.as_ref().map_or(p.policy_key, |c| c.key);
    if !songbird_keys::ed25519_verify(&key, &p.signed_bytes(), &p.signature) {
        return Outcome::Forbidden("signature");
    }
    store_policy(registry, &p, body, first).await
}

/// `PUT /v1/supervision/update`, unsigned (D-0108): a later policy from the parent's device,
/// authorized by the parent's signature against the key in force alone. No device or account
/// is named, as for sealed sends; the caller throttles it per IP range. One answer, 403
/// `signature`, for a bad signature and for an account with no policy in force, after the same
/// work, so it reveals nothing about who is supervised. A first policy never comes this way.
pub async fn update_supervision(registry: &Registry, body: &[u8]) -> Outcome {
    use songbird_proto::supervision::Policy;
    let Ok(p) = Policy::decode(body) else {
        return Outcome::Malformed("policy");
    };
    let Ok(current) = registry.supervision(&p.child).await else {
        return Outcome::Unavailable;
    };
    // With none in force, verify against the policy's own key anyway (the same work), then refuse.
    let key = current.as_ref().map_or(p.policy_key, |c| c.key);
    let signed = songbird_keys::ed25519_verify(&key, &p.signed_bytes(), &p.signature);
    if current.is_none() || !signed {
        return Outcome::Forbidden("signature");
    }
    store_policy(registry, &p, body, false).await
}

async fn store_policy(
    registry: &Registry,
    p: &songbird_proto::supervision::Policy,
    body: &[u8],
    first: bool,
) -> Outcome {
    match registry.put_supervision(p, body, first).await {
        Ok(()) => Outcome::Done,
        Err(RegistryError::Exists) => Outcome::Conflict("exists"),
        Err(RegistryError::Rollback) => Outcome::Conflict("version"),
        Err(RegistryError::Later) => Outcome::Conflict("date"),
        // The policy went between the read and the write (the date, an unlink).
        Err(RegistryError::NotFound) => Outcome::Forbidden("signature"),
        Err(_) => Outcome::Unavailable,
    }
}

/// `GET /v1/supervision`: the child's own policy, as signed, so its app shows every rule in
/// force and checks the parent's signature itself.
pub async fn get_supervision(registry: &Registry, row: &DeviceRow) -> Outcome {
    match registry.supervision(&row.account).await {
        Ok(Some(s)) => Outcome::Blob(s.policy),
        Ok(None) => Outcome::NotFound,
        Err(_) => Outcome::Unavailable,
    }
}
