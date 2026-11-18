//! Calls (Prompt 7, M2; PROTOCOL §8.6; D-0085, D-0087): rooms, tokens and wake-ups. The rooms and
//! tokens themselves are `songbird_calls`; this module decides who may have one.
//!
//! - `POST /v1/calls` `{"callee": hex, "media": "audio"|"video", "access_key": hex?, "ring": bool}`:
//!   a 1:1 call. The callee must be another account that is open or whose access key the caller
//!   presents (a contact, §5.10). 200 [`songbird_calls::Ticket`].
//! - `POST /v1/calls/group` `{"group": hex, "media": …, "ring": bool}`: starts the group's call
//!   (a member whose role is at least the policy's `call`), or joins the one already live (any
//!   member). 200 ticket.
//! - `POST /v1/calls/join` `{"call": hex, "group": hex?}`: a ticket for a live call: a 1:1 call
//!   admits only the two accounts' listed devices; a group call only the group's current roster.
//!
//! - `POST /v1/calls/links`, `/links/join`, `/links/lobby`, `/links/admit`, `/links/revoke`:
//!   call links (M3, §8.7): hashed link IDs, an admin token, expiry, an optional lobby.
//!
//! Every refusal that would tell a stranger something answers 404, as for no such call. A call to
//! an open account that blocked the caller is answered like any other and wakes no one (§5.11).
//! Nothing here logs an account, a device, a room or a group (invariant 6).

use std::sync::Arc;

use serde::Deserialize;
use songbird_accounts::Registry;
use songbird_calls::{Call, Calls, GroupCall, Kind, Media, Publish, RoomId, now_ms};
use songbird_jobs::{Job, Queue, Work};
use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_types::{AccountId, DeviceId};
use songbird_valkey::ValkeyConn;

use crate::devices::Outcome;
use crate::messages::Messages;
use crate::registration::Registration;

/// The policy byte for "start a group call" (`songbird_groups::roles::Policy::to_bytes`).
const POLICY_CALL: usize = 4;
/// Role 1, a member: may publish in a group call; role 0 (read-only, a channel's default) listens.
const ROLE_MEMBER: u8 = 1;
/// Wake-ups one caller may cause one receiver per hour, and their burst (D-0091).
const WAKES_PER_PAIR_HOUR: u32 = 20;
const WAKE_PAIR_BURST: u32 = 6;
/// How long a call ring may still be sent (D-0095).
const RING_LIFE_MS: u64 = 30_000;
/// A group's call pointer younger than this is live without asking LiveKit: its starter may
/// still be creating the room (D-0091).
const YOUNG_CALL_MS: u64 = 15_000;
/// Attempts at disconnecting removed members after a commit.
const RECONCILE_ATTEMPTS: u32 = 3;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct CallMetrics {
    /// Calls created (1:1 and group).
    pub created: Counter,
    /// Tickets issued (joins included).
    pub tickets: Counter,
    /// Call wake-ups queued.
    pub wakes: Counter,
    /// Participants removed after a roster change.
    pub removed: Counter,
    /// Refused: not a contact, not a member, no such call.
    pub refused: Counter,
    /// Commits after which removed members could not be disconnected (LiveKit unreachable).
    pub reconcile_failed: Counter,
}

impl CallMetrics {
    /// Registers them.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            ("api_calls_created", "Calls created", &self.created),
            ("api_call_tickets", "Call tickets issued", &self.tickets),
            ("api_call_wakes", "Call wake-ups queued", &self.wakes),
            (
                "api_call_participants_removed",
                "Call participants removed after a roster change",
                &self.removed,
            ),
            ("api_calls_refused", "Call requests refused", &self.refused),
            (
                "api_call_reconcile_failed",
                "Commits after which removed call members could not be disconnected",
                &self.reconcile_failed,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// The calls feature in `api`.
pub struct CallsApi {
    /// Rooms, tokens, records.
    pub calls: Arc<Calls>,
    /// Counters.
    pub metrics: CallMetrics,
}

impl std::fmt::Debug for CallsApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallsApi").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum MediaBody {
    Audio,
    Video,
}

impl From<MediaBody> for Media {
    fn from(m: MediaBody) -> Self {
        match m {
            MediaBody::Audio => Self::Audio,
            MediaBody::Video => Self::Video,
        }
    }
}

/// `POST /v1/calls`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OneToOneBody {
    callee: String,
    media: MediaBody,
    #[serde(default)]
    access_key: Option<String>,
    #[serde(default)]
    ring: bool,
}

/// `POST /v1/calls/group`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupBody {
    group: String,
    media: MediaBody,
    #[serde(default)]
    ring: bool,
}

/// `POST /v1/calls/join`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinBody {
    call: String,
    #[serde(default)]
    group: Option<String>,
}

fn hex16(s: &str) -> Option<[u8; 16]> {
    let mut b = [0u8; 16];
    (s.len() == 32 && !s.bytes().any(|c| c.is_ascii_uppercase()))
        .then(|| hex::decode_to_slice(s, &mut b).ok())
        .flatten()
        .map(|()| b)
}

/// Who is asking: the device and its account (from the registry row).
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    /// The device.
    pub device: DeviceId,
    /// Its account.
    pub account: AccountId,
}

/// Where a group call's roster comes from.
struct GroupView {
    roster: songbird_send::Roster,
}

impl GroupView {
    async fn load(registry: &Registry, group: &[u8; 16]) -> Result<Option<Self>, ()> {
        let Some(row) = registry.group(group).await.map_err(|_| ())? else {
            return Ok(None);
        };
        Ok(crate::groups::roster_of(&row.roster).map(|roster| Self { roster }))
    }

    const fn publish(role: u8, media: Media) -> Publish {
        match (role >= ROLE_MEMBER, media) {
            (false, _) => Publish::Nothing,
            (true, Media::Audio) => Publish::Audio,
            (true, Media::Video) => Publish::Everything,
        }
    }
}

impl CallsApi {
    async fn budget(
        &self,
        hot: &ValkeyConn,
        kind: &str,
        subject: &[u8],
        per_hour: u32,
        burst: u32,
    ) -> Result<(), Outcome> {
        let record = self.calls.keys.budget_record(kind, subject);
        match Registration::gcra(hot, &record, per_hour, burst, false).await {
            Ok(0) => Ok(()),
            Ok(wait) => Err(Outcome::Throttled(wait)),
            Err(()) => Err(Outcome::Unavailable),
        }
    }

    fn ticket(&self, room: &RoomId, device: &DeviceId, publish: Publish) -> Outcome {
        match self.calls.ticket(room, device, publish) {
            Ok(t) => {
                self.metrics.tickets.inc();
                serde_json::to_value(t).map_or(Outcome::Unavailable, Outcome::Json)
            }
            Err(_) => Outcome::Unavailable,
        }
    }

    /// Queues `VoIP` / high-priority wake-ups for `devices`, within the receiving account's wake
    /// budget and the (caller, receiver) pair's, so one caller cannot spend everyone else's
    /// (D-0091). A budget spent is silently skipped: the stored offer still arrives.
    async fn wake(
        &self,
        hot: &ValkeyConn,
        queue: &Queue,
        caller: &AccountId,
        account: &AccountId,
        devices: &[DeviceId],
    ) {
        let l = &self.calls.limits;
        let pair = [caller.as_bytes().as_slice(), account.as_bytes().as_slice()].concat();
        if devices.is_empty()
            || self
                .budget(hot, "wp", &pair, WAKES_PER_PAIR_HOUR, WAKE_PAIR_BURST)
                .await
                .is_err()
            || self
                .budget(hot, "w", account.as_bytes(), l.wakes_per_hour, l.wake_burst)
                .await
                .is_err()
        {
            return;
        }
        // A ring is worth sending for 30 s (D-0095): the offer expires after 60 s, and a ring
        // that arrives later than this would ring for a call already given up.
        let until_ms = now_ms().saturating_add(RING_LIFE_MS);
        let jobs: Vec<Job> = devices
            .iter()
            .filter_map(|d| {
                Job::new(Work::Ring {
                    device: *d,
                    until_ms,
                })
                .ok()
            })
            .collect();
        let n = u64::try_from(jobs.len()).unwrap_or(u64::MAX);
        if queue.enqueue(&jobs).await.is_ok() {
            self.metrics.wakes.inc_by(n);
        } else {
            tracing::warn!("call wake-ups dropped: job queue unavailable");
        }
    }

    /// `POST /v1/calls`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the request's context, passed explicitly"
    )]
    pub(crate) async fn one_to_one(
        &self,
        hot: &ValkeyConn,
        queue: &Queue,
        m: &Messages,
        caller: Caller,
        body: &[u8],
    ) -> Outcome {
        let Ok(b) = serde_json::from_slice::<OneToOneBody>(body) else {
            return Outcome::Malformed("request");
        };
        let Some(peer) = hex16(&b.callee).map(AccountId::from_bytes) else {
            return Outcome::Malformed("callee");
        };
        let presented = match b.access_key.as_deref().map(hex16) {
            None => None,
            Some(Some(k)) => Some(k),
            Some(None) => return Outcome::Malformed("access_key"),
        };
        let l = &self.calls.limits;
        if let Err(o) = self
            .budget(
                hot,
                "c",
                caller.account.as_bytes(),
                l.calls_per_hour,
                l.call_burst,
            )
            .await
        {
            return o;
        }
        if peer == caller.account {
            return Outcome::Malformed("callee");
        }
        // The contact proof, from the directory snapshot (§5.10): open, or its access key.
        let directory = m.path.directory();
        let access = directory.access(&peer);
        let contact = access.key.zip(presented).is_some_and(|(k, p)| {
            aws_lc_rs::constant_time::verify_slices_are_equal(&k, &p).is_ok()
        });
        let peer_devices: Vec<DeviceId> = directory.listed_devices(&peer).collect();
        if peer_devices.is_empty() || !(contact || access.open) {
            self.metrics.refused.inc();
            return Outcome::NotFound;
        }
        let media = Media::from(b.media);
        let Some(room) = RoomId::random() else {
            return Outcome::Unavailable;
        };
        if self.calls.open_room(&room, media).await.is_err() {
            return Outcome::Unavailable;
        }
        let call = Call {
            kind: Kind::OneToOne {
                caller: caller.account,
                callee: peer,
            },
            media,
            created_ms: now_ms(),
        };
        if self.calls.records(hot).put(&room, &call).await.is_err() {
            return Outcome::Unavailable;
        }
        self.metrics.created.inc();
        // Only a contact's call wakes anyone: on iOS a VoIP push rings. A stranger's call to an
        // open account rings nobody; its offer arrives as a message (§8.5, D-0091).
        if b.ring && contact {
            self.wake(hot, queue, &caller.account, &peer, &peer_devices)
                .await;
        }
        self.ticket(&room, &caller.device, Publish::Everything)
    }

    /// `POST /v1/calls/group`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the request's context, passed explicitly"
    )]
    pub(crate) async fn group(
        &self,
        hot: &ValkeyConn,
        queue: &Queue,
        m: &Messages,
        registry: &Registry,
        caller: Caller,
        body: &[u8],
    ) -> Outcome {
        let Ok(b) = serde_json::from_slice::<GroupBody>(body) else {
            return Outcome::Malformed("request");
        };
        let Some(group) = hex16(&b.group) else {
            return Outcome::Malformed("group");
        };
        let l = &self.calls.limits;
        if let Err(o) = self
            .budget(
                hot,
                "j",
                caller.device.as_bytes(),
                l.joins_per_hour,
                l.join_burst,
            )
            .await
        {
            return o;
        }
        let view = match GroupView::load(registry, &group).await {
            Ok(Some(v)) => v,
            Ok(None) => return Outcome::NotFound,
            Err(()) => return Outcome::Unavailable,
        };
        let Some(role) = view.roster.role(&caller.device) else {
            self.metrics.refused.inc();
            return Outcome::NotFound;
        };
        let records = self.calls.records(hot);
        // A live call: join it, whatever the media asked.
        match self.live(&records, &group).await {
            Ok(Some(live)) => {
                return self.ticket(
                    &live.room,
                    &caller.device,
                    GroupView::publish(role, live.media),
                );
            }
            Ok(None) => {}
            Err(o) => return o,
        }
        if role < view.roster.policy[POLICY_CALL] {
            self.metrics.refused.inc();
            return Outcome::Forbidden("role");
        }
        if let Err(o) = self
            .budget(
                hot,
                "c",
                caller.account.as_bytes(),
                l.calls_per_hour,
                l.call_burst,
            )
            .await
        {
            return o;
        }
        let media = Media::from(b.media);
        let Some(room) = RoomId::random() else {
            return Outcome::Unavailable;
        };
        let candidate = GroupCall {
            room,
            media,
            created_ms: now_ms(),
        };
        // The call's record first, so a pointer never names a room without one.
        let call = Call {
            kind: Kind::Group(self.calls.keys.group_tag(&group)),
            media,
            created_ms: candidate.created_ms,
        };
        if records.put(&room, &call).await.is_err() {
            return Outcome::Unavailable;
        }
        // Two members starting at once: one room wins, both join it.
        let Ok(live) = records.claim_group(&group, &candidate).await else {
            let _ = records.forget(&room).await;
            return Outcome::Unavailable;
        };
        if live.room == room {
            if self.calls.open_room(&room, media).await.is_err() {
                let _ = records
                    .release_group_tag(&self.calls.keys.group_tag(&group), &room)
                    .await;
                let _ = records.forget(&room).await;
                return Outcome::Unavailable;
            }
            self.metrics.created.inc();
            if b.ring {
                self.ring_group(hot, queue, m, &view, &caller.account).await;
            }
        } else {
            let _ = records.forget(&room).await;
        }
        self.ticket(
            &live.room,
            &caller.device,
            GroupView::publish(role, live.media),
        )
    }

    /// The group's live call. A pointer younger than [`YOUNG_CALL_MS`] is live (its starter may
    /// still be creating the room); an older one whose room LiveKit no longer has (its webhook
    /// was lost) is forgotten. A live call's records are kept for another lifetime.
    async fn live(
        &self,
        records: &songbird_calls::Records<'_>,
        group: &[u8; 16],
    ) -> Result<Option<GroupCall>, Outcome> {
        let Some(live) = records
            .group(group)
            .await
            .map_err(|_| Outcome::Unavailable)?
        else {
            return Ok(None);
        };
        let young = now_ms().saturating_sub(live.created_ms) < YOUNG_CALL_MS;
        let alive = young
            || self
                .calls
                .rooms
                .exists(&live.room)
                .await
                .map_err(|_| Outcome::Unavailable)?;
        if alive {
            records
                .touch(&live.room, Some(group))
                .await
                .map_err(|_| Outcome::Unavailable)?;
            return Ok(Some(live));
        }
        let tag = self.calls.keys.group_tag(group);
        if records.forget(&live.room).await.is_err()
            || records.release_group_tag(&tag, &live.room).await.is_err()
        {
            return Err(Outcome::Unavailable);
        }
        Ok(None)
    }

    /// Wakes the other members' devices, if the group is small enough to ring.
    async fn ring_group(
        &self,
        hot: &ValkeyConn,
        queue: &Queue,
        m: &Messages,
        view: &GroupView,
        caller: &AccountId,
    ) {
        let directory = m.path.directory();
        let mut by_account: std::collections::BTreeMap<AccountId, Vec<DeviceId>> =
            std::collections::BTreeMap::new();
        for d in view.roster.devices() {
            if let Some(a) = directory.listed_account(d) {
                by_account.entry(a).or_default().push(*d);
            }
        }
        let limit = usize::try_from(self.calls.limits.ring_max_accounts).unwrap_or(usize::MAX);
        if by_account.len() > limit {
            return;
        }
        for (account, devices) in by_account.iter().filter(|(a, _)| *a != caller) {
            self.wake(hot, queue, caller, account, devices).await;
        }
    }

    /// `POST /v1/calls/join`.
    pub(crate) async fn join(
        &self,
        hot: &ValkeyConn,
        registry: &Registry,
        caller: Caller,
        body: &[u8],
    ) -> Outcome {
        let Ok(b) = serde_json::from_slice::<JoinBody>(body) else {
            return Outcome::Malformed("request");
        };
        let Some(room) = hex16(&b.call).map(RoomId::from_bytes) else {
            return Outcome::Malformed("call");
        };
        let group = match b.group.as_deref().map(hex16) {
            None => None,
            Some(Some(g)) => Some(g),
            Some(None) => return Outcome::Malformed("group"),
        };
        let l = &self.calls.limits;
        if let Err(o) = self
            .budget(
                hot,
                "j",
                caller.device.as_bytes(),
                l.joins_per_hour,
                l.join_burst,
            )
            .await
        {
            return o;
        }
        let call = match self.calls.records(hot).get(&room).await {
            Ok(Some(c)) => c,
            Ok(None) => return self.refuse(),
            Err(_) => return Outcome::Unavailable,
        };
        match call.kind {
            Kind::OneToOne {
                caller: a,
                callee: b,
            } => {
                if caller.account != a && caller.account != b {
                    return self.refuse();
                }
                self.ticket(&room, &caller.device, Publish::Everything)
            }
            Kind::Group(tag) => {
                let Some(group) = group.filter(|g| {
                    aws_lc_rs::constant_time::verify_slices_are_equal(
                        &self.calls.keys.group_tag(g),
                        &tag,
                    )
                    .is_ok()
                }) else {
                    return self.refuse();
                };
                let view = match GroupView::load(registry, &group).await {
                    Ok(Some(v)) => v,
                    Ok(None) => return self.refuse(),
                    Err(()) => return Outcome::Unavailable,
                };
                let Some(role) = view.roster.role(&caller.device) else {
                    return self.refuse();
                };
                self.ticket(&room, &caller.device, GroupView::publish(role, call.media))
            }
            // Link calls join through `/v1/calls/links/join` (M3).
            Kind::Link(_) => self.refuse(),
        }
    }

    fn refuse(&self) -> Outcome {
        self.metrics.refused.inc();
        Outcome::NotFound
    }

    /// After a commit to `group`: disconnects from its live call every participant no longer in
    /// its roster (a removed member mid-call, §8.6). Their next join is refused by the roster.
    pub async fn reconcile_group(&self, hot: &ValkeyConn, registry: &Registry, group: &[u8; 16]) {
        let Ok(Some(live)) = self.calls.records(hot).group(group).await else {
            return;
        };
        let devices: Vec<DeviceId> = match GroupView::load(registry, group).await {
            Ok(Some(v)) => v.roster.devices().copied().collect(),
            // The group is gone: nobody stays.
            Ok(None) => Vec::new(),
            Err(()) => return,
        };
        let records = self.calls.records(hot);
        for attempt in 1..=RECONCILE_ATTEMPTS {
            match self
                .calls
                .reconcile(&records, &live.room, devices.iter().copied())
                .await
            {
                Ok(n) => {
                    self.metrics
                        .removed
                        .inc_by(u64::try_from(n).unwrap_or(u64::MAX));
                    return;
                }
                Err(_) if attempt < RECONCILE_ATTEMPTS => {
                    tokio::time::sleep(std::time::Duration::from_millis(200 * u64::from(attempt)))
                        .await;
                }
                Err(_) => {}
            }
        }
        // Degraded (runbook calls.md): the removed devices hold no key to the new epoch, and the
        // next commit, or their next join's webhook, disconnects them.
        self.metrics.reconcile_failed.inc();
        tracing::warn!("a group call's participants could not be reconciled");
    }
}

// --- Call links (M3, PROTOCOL §8.7, D-0088) ----------------------------------------------------

/// Domain separation of the stored hash of a link ID (as `songbird_content::call::link_id_hash`).
const LINK_HASH_CONTEXT: &[u8] = b"songbird.v1/call-link-hash\0";
/// Domain separation of the stored hash of a link's admin token.
const ADMIN_HASH_CONTEXT: &[u8] = b"songbird.v1/call-link-admin\0";
/// A link lives a day unless its creator asks for less or more (at most 30 days).
const DEFAULT_LINK_TTL_SECS: u64 = 86_400;
/// Lobby polls per device: a joiner asks every few seconds while it waits.
const POLLS_PER_HOUR: u32 = 1_800;
const POLL_BURST: u32 = 120;
/// The smallest sealed card: version, nonce and tag (PROTOCOL §8.4).
const MIN_CARD: usize = 1 + 12 + 16;

fn sha256_with(ctx: &[u8], v: &[u8; 32]) -> [u8; 32] {
    let mut d = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    d.update(ctx);
    d.update(v);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.finish().as_ref());
    out
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut b = [0u8; 32];
    (s.len() == 64 && !s.bytes().any(|c| c.is_ascii_uppercase()))
        .then(|| hex::decode_to_slice(s, &mut b).ok())
        .flatten()
        .map(|()| b)
}

/// `POST /v1/calls/links`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkCreateBody {
    link: String,
    admin: String,
    media: MediaBody,
    #[serde(default)]
    lobby: bool,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// `POST /v1/calls/links/join`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkJoinBody {
    link: String,
    #[serde(default)]
    admin: Option<String>,
    #[serde(default)]
    lobby: Option<String>,
    #[serde(default)]
    card: Option<String>,
}

/// `POST /v1/calls/links/lobby`, `/admit`, `/revoke`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkAdminBody {
    link: String,
    admin: String,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    admit: Option<bool>,
}

/// A link found and, if asked, its admin token checked.
struct Link {
    hash: [u8; 32],
    row: songbird_accounts::call_links::CallLinkRow,
}

impl CallsApi {
    async fn link(
        registry: &Registry,
        link: &str,
        admin: Option<&str>,
    ) -> Result<(Link, bool), Outcome> {
        let id = hex32(link).ok_or(Outcome::Malformed("link"))?;
        let admin = match admin.map(hex32) {
            None => None,
            Some(Some(a)) => Some(a),
            Some(None) => return Err(Outcome::Malformed("admin")),
        };
        let hash = sha256_with(LINK_HASH_CONTEXT, &id);
        let row = match registry.call_link(&hash).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err(Outcome::NotFound),
            Err(_) => return Err(Outcome::Unavailable),
        };
        let is_admin = admin.is_some_and(|a| {
            aws_lc_rs::constant_time::verify_slices_are_equal(
                &sha256_with(ADMIN_HASH_CONTEXT, &a),
                &row.admin,
            )
            .is_ok()
        });
        Ok((Link { hash, row }, is_admin))
    }

    /// Opens the link's room (idempotent), records it, and issues a ticket. Spends the join
    /// budget. A link revoked while its room was being opened gets its room closed again.
    async fn link_ticket(
        &self,
        hot: &ValkeyConn,
        registry: &Registry,
        link: &Link,
        device: &DeviceId,
    ) -> Outcome {
        let l = &self.calls.limits;
        if let Err(o) = self
            .budget(hot, "j", device.as_bytes(), l.joins_per_hour, l.join_burst)
            .await
        {
            return o;
        }
        let room = RoomId::from_bytes(link.row.room);
        let media = Media::from_byte(link.row.media).unwrap_or(Media::Video);
        if self.calls.open_room(&room, media).await.is_err() {
            return Outcome::Unavailable;
        }
        match registry.call_link(&link.hash).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.calls.rooms.delete_room(&room).await;
                return self.refuse();
            }
            Err(_) => return Outcome::Unavailable,
        }
        let call = Call {
            kind: Kind::Link(self.calls.keys.link_tag(&link.hash)),
            media,
            created_ms: now_ms(),
        };
        if self.calls.records(hot).put(&room, &call).await.is_err() {
            return Outcome::Unavailable;
        }
        let publish = match media {
            Media::Audio => Publish::Audio,
            Media::Video => Publish::Everything,
        };
        self.ticket(&room, device, publish)
    }

    /// `POST /v1/calls/links`: a new link. Its creator keeps the admin token; no account is
    /// stored with it.
    pub(crate) async fn create_link(
        &self,
        hot: &ValkeyConn,
        registry: &Registry,
        caller: Caller,
        body: &[u8],
    ) -> Outcome {
        let Ok(b) = serde_json::from_slice::<LinkCreateBody>(body) else {
            return Outcome::Malformed("request");
        };
        let (Some(id), Some(admin)) = (hex32(&b.link), hex32(&b.admin)) else {
            return Outcome::Malformed("link");
        };
        let l = &self.calls.limits;
        if let Err(o) = self
            .budget(
                hot,
                "c",
                caller.account.as_bytes(),
                l.calls_per_hour,
                l.call_burst,
            )
            .await
        {
            return o;
        }
        let Some(room) = RoomId::random() else {
            return Outcome::Unavailable;
        };
        let row = songbird_accounts::call_links::CallLinkRow {
            room: *room.as_bytes(),
            admin: sha256_with(ADMIN_HASH_CONTEXT, &admin),
            media: Media::from(b.media).byte(),
            lobby: b.lobby,
        };
        let ttl = b.ttl_secs.unwrap_or(DEFAULT_LINK_TTL_SECS);
        match registry
            .create_call_link(&sha256_with(LINK_HASH_CONTEXT, &id), &row, ttl)
            .await
        {
            Ok(()) => {
                self.metrics.created.inc();
                Outcome::Done
            }
            Err(songbird_accounts::RegistryError::Exists) => Outcome::Conflict("exists"),
            Err(songbird_accounts::RegistryError::Shape) => Outcome::Malformed("ttl_secs"),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/calls/links/join`: a ticket, or a place in the lobby (202 with its handle), or,
    /// polling with that handle, 202 until an admin decides.
    pub(crate) async fn join_link(
        &self,
        hot: &ValkeyConn,
        registry: &Registry,
        caller: Caller,
        body: &[u8],
    ) -> Outcome {
        let Ok(b) = serde_json::from_slice::<LinkJoinBody>(body) else {
            return Outcome::Malformed("request");
        };
        // Every request spends the poll budget; a ticket also spends the join budget
        // (`link_ticket`), whatever the request claims to be (D-0091).
        if let Err(o) = self
            .budget(
                hot,
                "p",
                caller.device.as_bytes(),
                POLLS_PER_HOUR,
                POLL_BURST,
            )
            .await
        {
            return o;
        }
        let (link, is_admin) = match Self::link(registry, &b.link, b.admin.as_deref()).await {
            Ok(v) => v,
            Err(Outcome::NotFound) => return self.refuse(),
            Err(o) => return o,
        };
        if b.admin.is_some() && !is_admin {
            return self.refuse();
        }
        if is_admin || !link.row.lobby {
            return self.link_ticket(hot, registry, &link, &caller.device).await;
        }
        let tag = self.calls.keys.link_tag(&link.hash);
        let records = self.calls.records(hot);
        let me = self.calls.keys.device_tag(&caller.device);
        if let Some(handle) = b.lobby {
            let Some(handle) = hex16(&handle) else {
                return Outcome::Malformed("lobby");
            };
            let entry = match records.lobby_get(&tag, &handle).await {
                Ok(Some(e)) if e.device == me => e,
                Ok(_) => return self.refuse(),
                Err(_) => return Outcome::Unavailable,
            };
            return match entry.state {
                songbird_calls::records::Waiting::Waiting => {
                    Outcome::Accepted(serde_json::json!({ "lobby": hex::encode(handle) }))
                }
                songbird_calls::records::Waiting::Admitted => {
                    if records.lobby_remove(&tag, &handle, &me).await.is_err() {
                        return Outcome::Unavailable;
                    }
                    self.link_ticket(hot, registry, &link, &caller.device).await
                }
            };
        }
        let Some(card) = b
            .card
            .filter(|c| c.len() <= 2 * songbird_calls::records::MAX_CARD)
            .and_then(|c| hex::decode(c).ok())
            .filter(|c| c.len() >= MIN_CARD)
        else {
            return Outcome::Malformed("card");
        };
        match records.lobby_add(&tag, me, card).await {
            Ok(handle) => Outcome::Accepted(serde_json::json!({ "lobby": hex::encode(handle) })),
            Err(songbird_calls::records::LobbyError::Full) => Outcome::Conflict("full"),
            Err(songbird_calls::records::LobbyError::Store) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/calls/links/lobby`, `/admit`, `/revoke`: the admin's side. A wrong token is 404,
    /// like no link.
    pub(crate) async fn admin_link(
        &self,
        hot: &ValkeyConn,
        registry: &Registry,
        caller: Caller,
        action: &str,
        body: &[u8],
    ) -> Outcome {
        let Ok(b) = serde_json::from_slice::<LinkAdminBody>(body) else {
            return Outcome::Malformed("request");
        };
        if let Err(o) = self
            .budget(
                hot,
                "p",
                caller.device.as_bytes(),
                POLLS_PER_HOUR,
                POLL_BURST,
            )
            .await
        {
            return o;
        }
        let (link, is_admin) = match Self::link(registry, &b.link, Some(&b.admin)).await {
            Ok(v) => v,
            Err(Outcome::NotFound) => return self.refuse(),
            Err(o) => return o,
        };
        if !is_admin {
            return self.refuse();
        }
        let tag = self.calls.keys.link_tag(&link.hash);
        let records = self.calls.records(hot);
        match action {
            "lobby" => match records.lobby_waiting(&tag).await {
                Ok(w) => Outcome::Json(serde_json::json!({
                    "waiting": w.iter().map(|(h, c)| serde_json::json!({
                        "handle": hex::encode(h), "card": hex::encode(c),
                    })).collect::<Vec<_>>(),
                })),
                Err(_) => Outcome::Unavailable,
            },
            "admit" => {
                let (Some(handle), Some(admit)) = (b.handle.as_deref().and_then(hex16), b.admit)
                else {
                    return Outcome::Malformed("handle");
                };
                match records.lobby_decide(&tag, &handle, admit).await {
                    Ok(true) => Outcome::Done,
                    Ok(false) => Outcome::NotFound,
                    Err(_) => Outcome::Unavailable,
                }
            }
            _ => {
                // Revoke: the link goes, its lobby goes, and its call ends for everyone.
                let room = RoomId::from_bytes(link.row.room);
                if registry.delete_call_link(&link.hash).await.is_err()
                    || records.lobby_clear(&tag).await.is_err()
                    || records.forget(&room).await.is_err()
                {
                    return Outcome::Unavailable;
                }
                match self.calls.rooms.delete_room(&room).await {
                    Ok(()) | Err(songbird_calls::TwirpError::NotFound) => Outcome::Done,
                    Err(_) => Outcome::Unavailable,
                }
            }
        }
    }
}
