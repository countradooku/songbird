//! Communities (Prompt 5, M4; D-0072): a container of groups around an announcement group.
//!
//! The server keeps opaque links (community → announcement group, community → groups) and an
//! encrypted info blob; names, descriptions and pictures are ciphertext. The community's admins
//! are the announcement group's: its roles, which every member's client verifies in the MLS group
//! context (D-0070), decide who may change the community.
//!
//! - `POST /v1/communities`: `version | community [16] | announcement [16]`. For an admin of an
//!   announcement-only group (its policy lets only admins send) that is in no community. 204;
//!   409 `exists`; 400 `announcement`.
//! - `POST /v1/communities/groups/add`: `version | community | group [16]`. For a device that is
//!   an admin of both the announcement group and the group. 204; 409 `exists` (the group is in a
//!   community), `full` (100 groups).
//! - `POST /v1/communities/groups/remove`: `version | community | group`. For an admin of the
//!   announcement group or of the group (a group may leave). 204.
//! - `POST /v1/communities/meta`: `version | community | expected u64 | blob` (≤ 16 KiB), for
//!   the announcement group's admins. 200 `{"version": n}`; 409 `stale`.
//! - `POST /v1/communities/state`: `version | community`, for the announcement group's members
//!   (and their accounts' other devices): `announcement [16] | meta_v u64 | meta_len u32 | meta |
//!   n u16 | n × group [16]`. 404 for everyone else, as for no community.
//! - `POST /v1/communities/delete`: `version | community`, for the announcement group's owners.
//!   204. The groups stay.
//!
//! Every endpoint answers 404 when the device is not in a group it must be in, as for no group.

use bytes::Bytes;
use songbird_accounts::RegistryError;
use songbird_accounts::communities::MAX_COMMUNITY_META;
use songbird_groups::roles::Role;
use songbird_types::DeviceId;

use crate::devices::Outcome;
use crate::groups::{Groups, put_meta, roster_of, split};
use crate::messages::Messages;

/// The policy byte for "send" (`songbird_groups::roles::Policy::to_bytes`).
const POLICY_SEND: usize = 0;

/// The device's role in `group` and the group's policy; 404 if the group is unknown or the
/// device is not in it.
async fn role_in(
    registry: &songbird_accounts::Registry,
    group: &[u8; 16],
    device: &DeviceId,
) -> Result<(u8, [u8; 7]), Outcome> {
    let (_, roster) = match registry.group_roster(group).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(Outcome::NotFound),
        Err(_) => return Err(Outcome::Unavailable),
    };
    let roster = roster_of(&roster).ok_or(Outcome::Unavailable)?;
    let role = roster.role(device).ok_or(Outcome::NotFound)?;
    Ok((role, roster.policy))
}

/// The community's announcement group; 404 if there is no such community.
async fn announcement_of(
    registry: &songbird_accounts::Registry,
    community: &[u8; 16],
) -> Result<songbird_accounts::communities::CommunityRow, Outcome> {
    match registry.community(community).await {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err(Outcome::NotFound),
        Err(_) => Err(Outcome::Unavailable),
    }
}

/// At least `need` in the community's announcement group.
async fn require_community_role(
    registry: &songbird_accounts::Registry,
    community: &[u8; 16],
    device: &DeviceId,
    need: Role,
) -> Result<songbird_accounts::communities::CommunityRow, Outcome> {
    let c = announcement_of(registry, community).await?;
    let (role, _) = role_in(registry, &c.announcement, device).await?;
    if role < need.as_u8() {
        return Err(Outcome::Forbidden("role"));
    }
    Ok(c)
}

fn id(rest: &[u8]) -> Option<[u8; 16]> {
    <[u8; 16]>::try_from(rest).ok()
}

impl Groups {
    /// `POST /v1/communities`.
    pub(crate) async fn create_community(
        &self,
        registry: &songbird_accounts::Registry,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((community, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        let Some(announcement) = id(rest) else {
            return Outcome::Malformed("request");
        };
        let (role, policy) = match role_in(registry, &announcement, &device).await {
            Ok(v) => v,
            Err(o) => return o,
        };
        if role < Role::Admin.as_u8() {
            return Outcome::Forbidden("role");
        }
        // An announcement group is one where only admins speak.
        if policy[POLICY_SEND] < Role::Admin.as_u8() {
            return Outcome::Malformed("announcement");
        }
        match registry.create_community(&community, &announcement).await {
            Ok(()) => Outcome::Done,
            Err(RegistryError::Exists) => Outcome::Conflict("exists"),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/communities/groups/add`.
    pub(crate) async fn add_community_group(
        &self,
        registry: &songbird_accounts::Registry,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((community, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        let Some(group) = id(rest) else {
            return Outcome::Malformed("request");
        };
        if let Err(o) = require_community_role(registry, &community, &device, Role::Admin).await {
            return o;
        }
        // The group's own admins consent: a community admin cannot claim someone else's group.
        match role_in(registry, &group, &device).await {
            Ok((role, _)) if role >= Role::Admin.as_u8() => {}
            Ok(_) => return Outcome::Forbidden("role"),
            Err(o) => return o,
        }
        match registry.add_community_group(&community, &group).await {
            Ok(()) => Outcome::Done,
            Err(RegistryError::Exists) => Outcome::Conflict("exists"),
            Err(RegistryError::Full) => Outcome::Conflict("full"),
            Err(RegistryError::NotFound) => Outcome::NotFound,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/communities/groups/remove`.
    pub(crate) async fn remove_community_group(
        &self,
        registry: &songbird_accounts::Registry,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((community, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        let Some(group) = id(rest) else {
            return Outcome::Malformed("request");
        };
        let c = match announcement_of(registry, &community).await {
            Ok(c) => c,
            Err(o) => return o,
        };
        let admin_of = |r: Result<(u8, [u8; 7]), Outcome>| {
            r.is_ok_and(|(role, _)| role >= Role::Admin.as_u8())
        };
        let community_admin = admin_of(role_in(registry, &c.announcement, &device).await);
        if !community_admin && !admin_of(role_in(registry, &group, &device).await) {
            return Outcome::Forbidden("role");
        }
        match registry.remove_community_group(&community, &group).await {
            Ok(()) => Outcome::Done,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/communities/meta`.
    pub(crate) async fn community_meta(
        &self,
        registry: &songbird_accounts::Registry,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((community, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        let Some((expected, blob)) = rest.split_at_checked(8) else {
            return Outcome::Malformed("request");
        };
        let expected = u64::from_be_bytes(expected.try_into().unwrap_or([0; 8]));
        if blob.is_empty() || blob.len() > MAX_COMMUNITY_META {
            return Outcome::Malformed("size");
        }
        let c = match require_community_role(registry, &community, &device, Role::Admin).await {
            Ok(c) => c,
            Err(o) => return o,
        };
        match registry
            .put_community_meta(&community, expected, blob)
            .await
        {
            Ok(v) => Outcome::Json(serde_json::json!({ "version": v })),
            Err(RegistryError::StaleEpoch) => Outcome::Stale(c.meta_v),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/communities/state`.
    pub(crate) async fn community_state(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((community, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        if !rest.is_empty() {
            return Outcome::Malformed("request");
        }
        let c = match announcement_of(registry, &community).await {
            Ok(c) => c,
            Err(o) => return o,
        };
        let roster = match registry.group_roster(&c.announcement).await {
            Ok(Some((_, r))) => r,
            Ok(None) => return Outcome::NotFound,
            Err(_) => return Outcome::Unavailable,
        };
        if !Self::may_read(m, &roster, &device) {
            return Outcome::NotFound;
        }
        let mut out = Vec::with_capacity(16 + 12 + c.meta.len() + 2 + c.groups.len() * 16);
        out.extend_from_slice(&c.announcement);
        put_meta(&mut out, c.meta_v, &c.meta);
        out.extend_from_slice(
            &u16::try_from(c.groups.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for g in &c.groups {
            out.extend_from_slice(g);
        }
        Outcome::Blob(Bytes::from(out))
    }

    /// `POST /v1/communities/delete`.
    pub(crate) async fn delete_community(
        &self,
        registry: &songbird_accounts::Registry,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((community, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        if !rest.is_empty() {
            return Outcome::Malformed("request");
        }
        if let Err(o) = require_community_role(registry, &community, &device, Role::Owner).await {
            return o;
        }
        match registry.delete_community(&community).await {
            Ok(()) => Outcome::Done,
            Err(_) => Outcome::Unavailable,
        }
    }
}
