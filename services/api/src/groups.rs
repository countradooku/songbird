//! MLS groups (Prompt 5, M1; D-0066, D-0067): the delivery service's HTTP side.
//!
//! - `POST /v1/groups`: a device creates a group: `version u8 (1) | group [16] | info_len u32 |
//!   GroupInfo | tree_len u32 | ratchet tree`. 204; 409 `exists`; 400 with the reason.
//! - `POST /v1/groups/commit`: a member commits: `version u8 (1) | group [16] | bundle`
//!   (`songbird_groups::wire::Bundle`). 200 `{"epoch": n}` once every recipient's mailbox holds
//!   the commit (and the added devices' the Welcome); 409 `{"error": "stale", "epoch": n}` if
//!   another commit won; 404 for an unknown group; 400 with the reason; 503 to retry (a retried
//!   commit that already won is answered 200 again, and its fan-out finished).
//! - `POST /v1/groups/state`: `version u8 (1) | group [16]`. 200 `epoch u64 | info_len u32 |
//!   GroupInfo | tree_len u32 | ratchet tree` for a device in the group, or a listed device of an
//!   account in it (to rejoin by external commit); 404 otherwise, the same as for no group.
//!
//! Commits and Welcomes reach devices as ordinary mailbox envelopes: the `MLSMessage` bytes as
//! they were uploaded. The fan-out is recorded with the commit in one transaction
//! (`grp_fanout`), stored under keys only the servers can derive (a member cannot pre-empt them
//! with a send of its own), then forgotten; [`redrive`] finishes any a crash interrupted.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::{digest, hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::RegistryError;
use songbird_groups::wire::Bundle;
use songbird_groups::{Group, GroupError, Limits, Record};
use songbird_types::{AccountId, DeviceId};

use crate::devices::Outcome;
use crate::messages::Messages;

/// Request format version.
const VERSION: u8 = 1;
/// Longest `POST /v1/groups` or `/v1/groups/commit` body (the bundle limit plus framing).
pub const MAX_BODY: usize = (4 << 20) + 64;
/// Fan-outs older than this are re-driven.
const REDRIVE_AFTER_SECS: u64 = 10;

/// The groups feature.
pub struct Groups {
    /// Keys the fan-out idempotency keys and the rate records.
    key: hmac::Key,
    /// Group size and bundle limits.
    pub limits: Limits,
    /// Commits (and creations) per second per device.
    pub commits_per_sec: u32,
    /// Their burst.
    pub commit_burst: u32,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Groups {
    /// Derives the groups key from the cluster secret (every `api` node derives the same);
    /// `None` if key derivation failed.
    #[must_use]
    pub fn new(cluster_secret: &[u8; 32], limits: Limits) -> Option<Self> {
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1/groups")
            .extract(cluster_secret)
            .expand(&[b"group-fanout"], hkdf::HKDF_SHA256)
            .ok()?
            .fill(&mut k)
            .ok()?;
        Some(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            limits,
            commits_per_sec: 2,
            commit_burst: 10,
        })
    }

    fn idempotency(&self, kind: &[u8], group: &[u8; 16], epoch: u64) -> [u8; 16] {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(&[u8::try_from(kind.len()).unwrap_or(u8::MAX)]);
        ctx.update(kind);
        ctx.update(group);
        ctx.update(&epoch.to_be_bytes());
        let tag = ctx.sign();
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref().get(..16).unwrap_or(&[0; 16]));
        out
    }

    /// The `valkey-hot` record of a device's commit budget (a keyed hash, no device ID).
    pub(crate) fn rate_record(&self, device: &DeviceId) -> String {
        let tag = hmac::sign(&self.key, device.as_bytes());
        format!(
            "gc:{}",
            hex::encode(tag.as_ref().get(..16).unwrap_or_default())
        )
    }
}

/// The directory the delivery-service core checks devices against: listed devices only.
struct Listed(Arc<songbird_send::Directory>);

impl songbird_groups::Directory for Listed {
    fn account_of(&self, device: &DeviceId) -> Option<AccountId> {
        self.0.listed_account(device)
    }
}

/// A recorded fan-out (postcard): the commit to the members, the Welcome to the added devices.
#[derive(serde::Serialize, serde::Deserialize)]
struct Plan {
    commit: Vec<u8>,
    members: Vec<[u8; 16]>,
    welcome: Option<Vec<u8>>,
    added: Vec<[u8; 16]>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, b);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn devices_of(roster: &[u8]) -> Vec<DeviceId> {
    roster
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| DeviceId::from_bytes(*c))
        .collect()
}

fn reason(e: &GroupError) -> &'static str {
    match e {
        GroupError::Wire(_) | GroupError::Malformed => "malformed",
        GroupError::Kind => "kind",
        GroupError::OtherGroup => "group",
        GroupError::StaleEpoch { .. } => "stale",
        GroupError::Ciphersuite => "ciphersuite",
        GroupError::Sender => "sender",
        GroupError::Credential => "credential",
        GroupError::Proposal => "proposal",
        GroupError::External => "external",
        GroupError::Duplicate => "duplicate",
        GroupError::TooLarge { .. } => "size",
        GroupError::Welcome => "welcome",
        GroupError::GroupInfo => "group_info",
        GroupError::Invalid => "invalid",
        GroupError::State(_) => "state",
    }
}

/// `version | group [16] | rest`.
fn split(body: &[u8]) -> Option<([u8; 16], &[u8])> {
    let (&v, rest) = body.split_first()?;
    if v != VERSION || rest.len() < 16 {
        return None;
    }
    let (g, rest) = rest.split_at(16);
    Some((g.try_into().ok()?, rest))
}

/// `len u32 | bytes`, twice, exactly.
fn part(b: &[u8]) -> Option<(&[u8], usize)> {
    let n = usize::try_from(u32::from_be_bytes(b.get(..4)?.try_into().ok()?)).ok()?;
    let end = n.checked_add(4)?;
    Some((b.get(4..end)?, end))
}

fn two_parts(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (a, used) = part(b)?;
    let (c, used2) = part(b.get(used..)?)?;
    (used + used2 == b.len() && !a.is_empty() && !c.is_empty()).then_some((a, c))
}

impl Groups {
    /// `POST /v1/groups`.
    pub(crate) async fn create(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((group, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        let Some((info, tree)) = two_parts(rest) else {
            return Outcome::Malformed("request");
        };
        let dir = Listed(m.path.directory());
        let (info, tree) = (info.to_vec(), tree.to_vec());
        let made = tokio::task::spawn_blocking(move || {
            let g = Group::create(group, &device, &info, &tree, &dir)?;
            let roster: Vec<DeviceId> = g.roster().devices().collect();
            Ok::<_, GroupError>((
                g.record().encode()?,
                songbird_send::Roster::to_bytes(&roster),
            ))
        })
        .await;
        let (state, roster) = match made {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Outcome::Malformed(reason(&e)),
            Err(_) => return Outcome::Unavailable,
        };
        match registry.create_group(&group, &state, &roster).await {
            Ok(()) => Outcome::Done,
            Err(RegistryError::Exists) => Outcome::Conflict("exists"),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/groups/commit`.
    pub(crate) async fn commit(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((group, bundle)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        let Ok(parts) = Bundle::parse(bundle, self.limits.max_bundle) else {
            return Outcome::Malformed("malformed");
        };
        let hash = sha256(parts.commit);
        let row = match registry.group(&group).await {
            Ok(Some(r)) => r,
            Ok(None) => return Outcome::NotFound,
            Err(_) => return Outcome::Unavailable,
        };
        let Ok(record) = Record::decode(&row.state) else {
            return Outcome::Unavailable;
        };
        let dir = Listed(m.path.directory());
        let limits = self.limits;
        let bundle_owned = bundle.to_vec();
        let applied = tokio::task::spawn_blocking(move || {
            let g = Group::load(record)?;
            let (g, a) = g.apply_commit(&device, &bundle_owned, &dir, &limits)?;
            let roster: Vec<DeviceId> = g.roster().devices().collect();
            Ok::<_, GroupError>((g.record().encode()?, roster, a))
        })
        .await;
        let (state, roster, applied) = match applied {
            Ok(Ok(v)) => v,
            // The same commit again (an answer that was lost): it won; finish its fan-out.
            Ok(Err(GroupError::StaleEpoch { current })) if row.last.as_ref() == hash => {
                return self
                    .finish(registry, m, &group, current.saturating_sub(1), current)
                    .await;
            }
            Ok(Err(GroupError::StaleEpoch { current })) => {
                return Outcome::Stale(current);
            }
            Ok(Err(e)) => return Outcome::Malformed(reason(&e)),
            Err(_) => return Outcome::Unavailable,
        };

        // Who hears what: the commit goes to every device in the group before or after it
        // (removed devices learn they were removed) except the committer and the added devices,
        // which get the Welcome instead.
        let old = devices_of(&row.roster);
        let mut members: Vec<DeviceId> = old.iter().chain(roster.iter()).copied().collect();
        members.sort_unstable();
        members.dedup();
        members.retain(|d| *d != device && !applied.added.contains(d));
        let plan = Plan {
            commit: parts.commit.to_vec(),
            members: members.iter().map(|d| *d.as_bytes()).collect(),
            welcome: parts.welcome.map(<[u8]>::to_vec),
            added: applied.added.iter().map(|d| *d.as_bytes()).collect(),
        };
        let Ok(plan_bytes) = postcard::to_stdvec(&plan) else {
            return Outcome::Unavailable;
        };
        let roster_bytes = songbird_send::Roster::to_bytes(&roster);
        let from = applied.from_epoch;
        match registry
            .commit_group(&group, from, &state, &roster_bytes, &hash, &plan_bytes)
            .await
        {
            Ok(()) => {}
            // Another node stored a commit from this epoch first.
            Err(RegistryError::StaleEpoch) => {
                let current = registry
                    .group(&group)
                    .await
                    .ok()
                    .flatten()
                    .map_or(from + 1, |r| r.epoch);
                return Outcome::Stale(current);
            }
            Err(_) => return Outcome::Unavailable,
        }
        self.finish(registry, m, &group, from, from + 1).await
    }

    /// Delivers the recorded fan-out of the commit from `from` (if still pending), forgets it,
    /// and answers with the group's epoch.
    async fn finish(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        group: &[u8; 16],
        from: u64,
        epoch: u64,
    ) -> Outcome {
        match self.deliver(registry, m, group, from).await {
            Ok(()) => Outcome::Json(serde_json::json!({ "epoch": epoch })),
            Err(()) => Outcome::Unavailable,
        }
    }

    /// Stores a recorded fan-out in every recipient's mailbox (idempotent), then deletes it.
    async fn deliver(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        group: &[u8; 16],
        from: u64,
    ) -> Result<(), ()> {
        let Some(bytes) = registry.group_fanout(group, from).await.map_err(|_| ())? else {
            return Ok(());
        };
        let plan: Plan = postcard::from_bytes(&bytes).map_err(|_| ())?;
        let members: Vec<DeviceId> = plan
            .members
            .iter()
            .map(|d| DeviceId::from_bytes(*d))
            .collect();
        m.path
            .shared(
                &members,
                Bytes::from(plan.commit),
                self.idempotency(b"commit", group, from),
            )
            .await
            .map_err(|_| ())?;
        if let Some(w) = plan.welcome {
            let added: Vec<DeviceId> = plan
                .added
                .iter()
                .map(|d| DeviceId::from_bytes(*d))
                .collect();
            m.path
                .shared(
                    &added,
                    Bytes::from(w),
                    self.idempotency(b"welcome", group, from),
                )
                .await
                .map_err(|_| ())?;
        }
        registry
            .group_fanout_done(group, from)
            .await
            .map_err(|_| ())
    }

    /// `POST /v1/groups/state`.
    pub(crate) async fn state(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        device: DeviceId,
        body: Bytes,
    ) -> Outcome {
        let Some((group, rest)) = split(&body) else {
            return Outcome::Malformed("request");
        };
        if !rest.is_empty() {
            return Outcome::Malformed("request");
        }
        let row = match registry.group(&group).await {
            Ok(Some(r)) => r,
            Ok(None) => return Outcome::NotFound,
            Err(_) => return Outcome::Unavailable,
        };
        let dir = m.path.directory();
        let roster = devices_of(&row.roster);
        let allowed = roster.binary_search(&device).is_ok()
            || dir
                .listed_account(&device)
                .is_some_and(|a| roster.iter().any(|d| dir.listed_account(d) == Some(a)));
        if !allowed {
            return Outcome::NotFound;
        }
        let Ok(record) = Record::decode(&row.state) else {
            return Outcome::Unavailable;
        };
        let built = tokio::task::spawn_blocking(move || {
            let g = Group::load(record)?;
            let tree = g.ratchet_tree()?;
            let info = g.group_info().to_vec();
            let mut out = Vec::with_capacity(16 + info.len() + tree.len());
            out.extend_from_slice(&g.epoch().to_be_bytes());
            for part in [&info, &tree] {
                out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
                out.extend_from_slice(part);
            }
            Ok::<_, GroupError>(out)
        })
        .await;
        match built {
            Ok(Ok(b)) => Outcome::Blob(Bytes::from(b)),
            _ => Outcome::Unavailable,
        }
    }
}

/// Finishes fan-outs a crash interrupted (every few seconds, on every `api` node; delivery is
/// idempotent, so two nodes re-driving one fan-out store it once).
pub async fn redrive(
    registry: Arc<songbird_accounts::Registry>,
    app: Arc<crate::App>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let Some(m) = app.messages.as_ref() else {
            return;
        };
        let Some(g) = m.groups.as_ref() else { return };
        g.redrive_once(&registry, m, REDRIVE_AFTER_SECS).await;
    }
}

impl Groups {
    /// One re-drive pass over fan-outs older than `age_secs`; returns how many it finished.
    pub async fn redrive_once(
        &self,
        registry: &songbird_accounts::Registry,
        m: &Messages,
        age_secs: u64,
    ) -> usize {
        let Ok(stale) = registry.stale_group_fanouts(age_secs, 64).await else {
            return 0;
        };
        let mut done = 0;
        for (group, from, _) in stale {
            if self.deliver(registry, m, &group, from).await.is_ok() {
                done += 1;
            } else {
                tracing::warn!("a group fan-out could not be re-driven yet");
            }
        }
        done
    }
}
