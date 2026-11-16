//! The send path as a library (D-0037): every service that sends — `delivery` for the WebSocket
//! `Send` frame, `api` for `PUT /v1/messages`, later `calls` and `worker` — links this crate and
//! takes the same tested path, with no internal network Send API and no extra hop.
//!
//! ```text
//! check (reserved prefix, duplicates, device list) ─▶ store (idempotent, durable) ─▶ acknowledge
//!                                                   ─▶ route (per device) ─▶ push if offline
//! ```
//!
//! - **Device-list check** (master prompt §5, `send`): every addressed device exists, and a send
//!   that addresses an account addresses all of its devices (except the sender's own). On a
//!   mismatch nothing is stored; the client re-encrypts for the corrected list.
//! - **Store before acknowledge** (invariant 1): [`SendPath::store`] returns only once the mailbox
//!   (Iggy, D-0029) holds the send durably; the caller acknowledges after it and only then calls
//!   [`SendPath::route`]. Idempotency is the mailbox's (keyed tag plus recipient fingerprint), so
//!   a retry over another transport (WebSocket, then HTTP) is stored once.
//! - **Routing never blocks on a recipient**, and a device with no session anywhere gets a
//!   debounced push wake-up ([`Pusher`]); the message waits in the mailbox either way.
//! - **System frames are never user messages** ([`system`]): user envelopes that begin with the
//!   prefix reserved for what the server writes are refused, and server notices are signed.
//! - **Franking** ([`franking`], Prompt 4): a franked send's envelopes for other accounts are
//!   stored behind a stamp the server MACs, so a recipient can later report them.
//! - **The disappearing hint** (Prompt 4): a send's deadline goes to the mailbox, which never
//!   delivers its envelopes after it and deletes them then.
//!
//! The hot path (one delivery core) allocates nothing here that it did not allocate before the
//! extraction: [`SendPath`] is a set of borrows built per send, the recipient scratch list is the
//! caller's and reused, and the two allocations of a send (the store request's recipient list and
//! the route list) are the ones the M3 gate budgets (`tests/e2e/tests/allocations.rs`).
#![forbid(unsafe_code)]

pub mod config;
pub mod directory;
pub mod franking;
pub mod gate;
pub mod groups;
pub mod push;
pub mod system;

use std::time::{Duration, Instant};

use bytes::Bytes;
use songbird_mailbox::{MailboxError, NewEnvelope, Payload, StoreOutcome, StoreRequest, StoreSend};
use songbird_proto::control;
use songbird_proto::frame::{RejectReason, SendFrame, SendPayload, SendStatus};
use songbird_router::{Live, Routed, Router};
use songbird_service::telemetry::sharded::{ShardedCounter as Counter, ShardedHistogram};
use songbird_service::telemetry::{Metrics, TelemetryError};
use songbird_types::{AccountId, DeviceId};
use std::sync::Arc;

pub use config::LimitsConfig;
pub use directory::{Directory, LiveDirectory, Mismatch};
pub use franking::{Franker, Frankers};
pub use gate::{Admit, Gate, GateKeys, MemoryGate, RegistryGate, RequestLimits};
pub use groups::{MemoryRosters, RegistryRosters, Roster, Rosters};
pub use push::{PushMetrics, Pusher};

/// The device a sealed send (`PUT /v1/messages/sealed`, D-0054) passes as its sender: no real
/// device has this ID, and the sealed endpoint has already checked the recipients' access keys.
pub const SEALED_SENDER: DeviceId = DeviceId::from_bytes([0; 16]);

/// What the send path enforces beyond limits and the device list (Prompt 4). One per service,
/// borrowed by every send.
pub struct Policy {
    /// Stamps franked sends. Without it a franked send is refused as unavailable (a deployment
    /// must configure it; configuration validation requires it outside development).
    pub franking: Option<Franker>,
    /// The cluster-wide checks of requests and broadcasts. Without it those sends are refused as
    /// unavailable (only a registry directory has closed accounts, and deployments configure
    /// it).
    pub gate: Option<Arc<dyn Gate>>,
    /// Most other accounts one broadcast may address.
    pub max_broadcast_accounts: u32,
    /// Group rosters (Prompt 5). Without them a group message is refused as unavailable.
    pub rosters: Option<Arc<dyn Rosters>>,
    /// The channel rate class (D-0072): posts per channel on this node.
    pub channels: Arc<groups::ChannelBudget>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            franking: None,
            gate: None,
            max_broadcast_accounts: RequestLimits::default().max_broadcast_accounts,
            rosters: None,
            channels: Arc::default(),
        }
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("franking", &self.franking)
            .field("gate", &self.gate.is_some())
            .field("max_broadcast_accounts", &self.max_broadcast_accounts)
            .field("rosters", &self.rosters.is_some())
            .field("channels", &self.channels)
            .finish()
    }
}

/// What the gate decided for a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admitted {
    /// Store it as it is.
    Store,
    /// Drop this account's part silently.
    Drop(AccountId),
}

/// What kind of conversation a send belongs to (Prompt 4, D-0062), from what the server can see:
/// the addressed accounts, the frame's flags and the directory snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Only the sender's own other devices (sync messages).
    Sync,
    /// One other account, a contact: its access key is in the send.
    Direct,
    /// One other account that is open (anyone may send): no key needed, but its blocks apply.
    Open(AccountId),
    /// Several other accounts, each a contact or open: a broadcast list.
    Broadcast(u32),
    /// A shared body: a group or channel. Until Prompt 5 authorizes membership, every closed
    /// account it reaches needs its access key in the combined key.
    Group,
    /// A message request to one closed account.
    Request(AccountId),
    /// A sealed send: the sealed endpoint checked the access keys.
    Sealed,
}

/// Retry hint (milliseconds) for a send refused because the store is unavailable.
pub const RETRY_MS: u32 = 1_000;

/// Counters of the send path. Clones share their counts: `delivery` hands in its own counters
/// (metric names unchanged), `api` registers a set under its own prefix.
#[derive(Debug, Clone, Default)]
pub struct SendMetrics {
    /// Sends accepted (stored now).
    pub sends_accepted: Counter,
    /// Sends answered from the idempotency record (a retry).
    pub sends_replayed: Counter,
    /// Sends the path refused (check or store); a caller counts its own refusals (rate limits).
    pub sends_rejected: Counter,
    /// Envelopes stored (one per recipient device).
    pub envelopes_stored: Counter,
    /// Notifications dropped because a session's inbox was full.
    pub routes_lagged: Counter,
    /// Envelopes stored for devices with no session anywhere (a push wake-up follows).
    pub routes_offline: Counter,
    /// Stores that failed (mailbox full or unavailable).
    pub mailbox_errors: Counter,
    /// Message requests stored.
    pub requests: Counter,
    /// Message requests accepted and dropped (blocked, or requests refused).
    pub requests_dropped: Counter,
    /// Broadcast sends stored.
    pub broadcasts: Counter,
    /// From the request read to the send durably stored, group commit included.
    pub store_seconds: ShardedHistogram,
}

impl SendMetrics {
    /// Registers every counter as `<prefix>_<name>` (aggregate only, invariant 6).
    ///
    /// # Errors
    /// [`TelemetryError`] if a name is refused.
    pub fn register(&self, m: &mut Metrics, prefix: &str) -> Result<(), TelemetryError> {
        for (name, help, c) in [
            ("sends_accepted", "Sends accepted", &self.sends_accepted),
            (
                "sends_replayed",
                "Retried sends answered from the idempotency record",
                &self.sends_replayed,
            ),
            ("sends_rejected", "Sends rejected", &self.sends_rejected),
            (
                "envelopes_stored",
                "Envelopes stored",
                &self.envelopes_stored,
            ),
            (
                "routes_lagged",
                "Notifications dropped on a full inbox",
                &self.routes_lagged,
            ),
            (
                "routes_offline",
                "Envelopes for devices without a session",
                &self.routes_offline,
            ),
            (
                "send_mailbox_errors",
                "Sends that failed in the mailbox",
                &self.mailbox_errors,
            ),
            ("requests", "Message requests stored", &self.requests),
            (
                "requests_dropped",
                "Message requests dropped silently (blocked or refused)",
                &self.requests_dropped,
            ),
            ("broadcasts", "Broadcast sends stored", &self.broadcasts),
        ] {
            m.register(&format!("{prefix}_{name}"), help, c.clone())?;
        }
        m.register(
            &format!("{prefix}_store_seconds"),
            "From a send read to it durably stored, group commit included",
            self.store_seconds.clone(),
        )
    }
}

/// One send's view of what it needs: borrows only, built per send for free.
pub struct SendPath<'a, M, R> {
    /// Devices and accounts (the device-list check reads its current snapshot, lock-free).
    pub directory: &'a LiveDirectory,
    /// The mailbox (or, on a node that only sends, its store operation).
    pub mailbox: &'a M,
    /// The router.
    pub router: &'a R,
    /// Push wake-ups for offline devices.
    pub push: &'a Pusher,
    /// Counters.
    pub metrics: &'a SendMetrics,
    /// Franking and (M4) the contact gate.
    pub policy: &'a Policy,
}

impl<M, R> std::fmt::Debug for SendPath<'_, M, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendPath").finish_non_exhaustive()
    }
}

impl<M, R> Clone for SendPath<'_, M, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M, R> Copy for SendPath<'_, M, R> {}

const fn reject(reason: RejectReason, retry_after_ms: u32) -> SendStatus {
    SendStatus::Rejected {
        reason,
        retry_after_ms,
    }
}

impl<M: StoreSend, R: Router> SendPath<'_, M, R> {
    /// Check, then store durably. `Ok` means the send is in the mailbox (invariant 1): the
    /// caller acknowledges it, then calls [`route`](Self::route) with the frame's payload and the
    /// returned `seq`s. `Err` is the status to answer; nothing was stored.
    ///
    /// A franked send's payload is replaced, in `s`, by the stamped envelopes that were stored, so
    /// the caller routes exactly what the mailbox holds.
    ///
    /// `received` is when the request was read (the store latency metric starts there).
    /// `scratch` is the caller's reusable recipient list (no allocation per send).
    ///
    /// # Errors
    /// The `SendResult` status for the client: reserved envelope, duplicate recipient, device
    /// mismatch, idempotency conflict, stale MLS epoch, or unavailable with a retry hint.
    pub async fn store(
        &self,
        sender: &DeviceId,
        s: &mut SendFrame,
        received: Instant,
        scratch: &mut Vec<DeviceId>,
    ) -> Result<StoreOutcome, SendStatus> {
        let m = self.metrics;
        let lane = if let Some(group) = s.hints.group {
            // A group message (Prompt 5): membership is the authorization and the roster the
            // recipients; the device-list and contact checks do not apply.
            if let Err(status) = self.group_recipients(sender, &group, s).await {
                m.sends_rejected.inc();
                return Err(status);
            }
            if s.payload.is_empty() {
                // The sender is the group's only device: nothing to store.
                return Ok(StoreOutcome {
                    seqs: Vec::new(),
                    replayed: false,
                });
            }
            Lane::Group
        } else {
            if let Err(status) = self.check(sender, &s.payload, scratch) {
                m.sends_rejected.inc();
                return Err(status);
            }
            match self.lane(sender, s) {
                Ok(l) => l,
                Err(status) => {
                    m.sends_rejected.inc();
                    return Err(status);
                }
            }
        };
        match self.admit(sender, lane).await {
            Ok(Admitted::Store) => {}
            // Dropped silently: answered as accepted (see `drop_part`).
            Ok(Admitted::Drop(r)) => match self.drop_part(s, r).await {
                Ok(true) => {
                    return Ok(StoreOutcome {
                        seqs: Vec::new(),
                        replayed: false,
                    });
                }
                Ok(false) => {}
                Err(status) => {
                    m.sends_rejected.inc();
                    return Err(status);
                }
            },
            Err(status) => {
                m.sends_rejected.inc();
                return Err(status);
            }
        }
        if let Some(c) = s.hints.commitment {
            let Some(f) = &self.policy.franking else {
                m.sends_rejected.inc();
                return Err(reject(RejectReason::Unavailable, RETRY_MS));
            };
            self.stamp(f, sender, &c, &mut s.payload);
        }
        let req = store_request(s);
        let recipients = req.payload.len();
        let outcome = match self.mailbox.store_send(req).await {
            Ok(o) => o,
            Err(e) => {
                m.sends_rejected.inc();
                return Err(match e {
                    MailboxError::IdempotencyConflict => {
                        reject(RejectReason::IdempotencyConflict, 0)
                    }
                    MailboxError::StaleEpoch => reject(RejectReason::StaleEpoch, 0),
                    MailboxError::Full | MailboxError::Unavailable => {
                        m.mailbox_errors.inc();
                        reject(RejectReason::Unavailable, RETRY_MS)
                    }
                });
            }
        };
        // The server's store latency, from the request read (no allocation).
        m.store_seconds.observe(received.elapsed());
        if outcome.replayed {
            m.sends_replayed.inc();
        } else {
            m.sends_accepted.inc();
            m.envelopes_stored
                .inc_by(u64::try_from(recipients).unwrap_or(u64::MAX));
        }
        Ok(outcome)
    }

    /// A group message's recipients (D-0067): the body is an application `PrivateMessage` of
    /// the frame's group at the roster's epoch (or the one before), from a device in the roster;
    /// the recipients become the roster minus the sender.
    ///
    /// # Errors
    /// Invalid group message, not a member (also for a group that does not exist), stale epoch,
    /// or unavailable when no roster store is configured or it is unreachable.
    pub async fn group_recipients(
        &self,
        sender: &DeviceId,
        group: &[u8; 16],
        s: &mut SendFrame,
    ) -> Result<(), SendStatus> {
        let invalid = || reject(RejectReason::InvalidGroupMessage, 0);
        let SendPayload::Shared { devices, body } = &mut s.payload else {
            return Err(invalid());
        };
        let p = songbird_proto::mls::private_prefix(body).map_err(|_| invalid())?;
        if p.group != *group || p.content_type != songbird_proto::mls::CONTENT_APPLICATION {
            return Err(invalid());
        }
        let Some(rosters) = &self.policy.rosters else {
            return Err(reject(RejectReason::Unavailable, RETRY_MS));
        };
        let roster = rosters
            .roster(group, p.epoch)
            .await
            .map_err(|()| reject(RejectReason::Unavailable, RETRY_MS))?
            .ok_or_else(|| reject(RejectReason::NotMember, 0))?;
        let Some(role) = roster.role(sender) else {
            return Err(reject(RejectReason::NotMember, 0));
        };
        // "Only admins can send", a channel's subscribers (D-0070).
        if role < roster.send_min {
            return Err(reject(RejectReason::NotAllowed, 0));
        }
        if p.epoch != roster.epoch && p.epoch.checked_add(1) != Some(roster.epoch) {
            return Err(reject(RejectReason::StaleEpoch, 0));
        }
        // The channel rate class (D-0072): a post reaches every subscriber.
        if roster.is_channel()
            && let Err(wait) = self.policy.channels.take(group, Instant::now())
        {
            let ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX).max(1);
            return Err(reject(RejectReason::RateLimited, ms));
        }
        devices.clear();
        devices.extend(roster.devices().filter(|d| *d != sender).copied());
        Ok(())
    }

    /// The checks that need no store: no envelope in the reserved system-frame format, no device
    /// twice, and the device list (master prompt §5). Nothing is allocated unless the send is
    /// refused with a device list.
    ///
    /// # Errors
    /// The refusal status.
    pub fn check(
        &self,
        sender: &DeviceId,
        payload: &SendPayload,
        scratch: &mut Vec<DeviceId>,
    ) -> Result<(), SendStatus> {
        // System frames are the server's alone (D-0037): a user envelope that looks like one is
        // refused, so a client never even has to drop a forged notice.
        if reserved(payload) {
            return Err(reject(RejectReason::ReservedEnvelope, 0));
        }
        // Bounded by max_recipients (checked by the decoder).
        scratch.clear();
        scratch.extend(payload.devices().copied());
        if has_duplicate_device(scratch) {
            return Err(reject(RejectReason::DuplicateRecipient, 0));
        }
        // Device lists: every device of each addressed account, no device that does not exist.
        if let Err(mm) = self.directory.load().check_devices(sender, scratch) {
            let ids = |v: Vec<DeviceId>| v.iter().map(|d| d.as_bytes().to_vec()).collect();
            return Err(SendStatus::DeviceMismatch(control::DeviceMismatch {
                missing: ids(mm.missing),
                extra: ids(mm.extra),
                stale: Vec::new(),
            }));
        }
        Ok(())
    }

    /// The send's lane (D-0062), from the directory snapshot alone: no store round trip, and no
    /// allocation unless the send addresses several other accounts of which one is closed.
    ///
    /// # Errors
    /// Access required (no key, a wrong one, or an account without a profile), an invalid
    /// request, too many accounts for a broadcast, or unavailable when the sender's account is not
    /// in the snapshot yet (never stamped as sealed).
    pub fn lane(&self, sender: &DeviceId, s: &SendFrame) -> Result<Lane, SendStatus> {
        if *sender == SEALED_SENDER {
            return Ok(Lane::Sealed);
        }
        let dir = self.directory.load();
        let Some(from) = dir.account_of(sender) else {
            return Err(reject(RejectReason::Unavailable, RETRY_MS));
        };
        let (mut first, mut several, mut closed) = (None, false, false);
        for d in s.payload.devices() {
            let Some(a) = dir.account_of(d) else { continue };
            if a == from {
                continue;
            }
            closed |= !dir.access(&a).open;
            match first {
                None => first = Some(a),
                Some(f) if f != a => several = true,
                Some(_) => {}
            }
        }
        let Some(first) = first else {
            return Ok(Lane::Sync);
        };
        let h = &s.hints;
        let shared = matches!(s.payload, SendPayload::Shared { .. });
        if !several && !shared {
            let acc = dir.access(&first);
            if h.access
                .is_some_and(|k| acc.key.is_some_and(|key| ct_eq(&key, &k)))
            {
                return Ok(Lane::Direct);
            }
            if acc.open {
                return Ok(Lane::Open(first));
            }
            if h.access.is_some() {
                return Err(reject(RejectReason::AccessRequired, 0));
            }
            if h.request {
                if h.commitment.is_none() {
                    return Err(reject(RejectReason::InvalidRequest, 0));
                }
                return Ok(Lane::Request(first));
            }
            return Err(reject(RejectReason::AccessRequired, 0));
        }
        // Several accounts (a broadcast), or a shared body (a group): every other account a
        // contact (one combined key) or open. Until Prompt 5 authorizes group membership, a group's
        // members prove they are contacts the same way (groups share their members' profile keys).
        if h.request {
            return Err(reject(RejectReason::InvalidRequest, 0));
        }
        let mut accounts: Vec<AccountId> = Vec::new();
        if closed || !shared {
            accounts = s
                .payload
                .devices()
                .filter_map(|d| dir.account_of(d))
                .filter(|a| *a != from)
                .collect();
            accounts.sort_unstable();
            accounts.dedup();
        }
        let n = u32::try_from(accounts.len()).unwrap_or(u32::MAX);
        if !shared && n > self.policy.max_broadcast_accounts {
            return Err(reject(RejectReason::TooManyRecipients, 0));
        }
        if closed {
            let mut combined = [0u8; 16];
            for a in &accounts {
                let acc = dir.access(a);
                if acc.open {
                    continue;
                }
                let Some(key) = acc.key else {
                    return Err(reject(RejectReason::AccessRequired, 0));
                };
                combined.iter_mut().zip(key).for_each(|(c, k)| *c ^= k);
            }
            if !h.access.is_some_and(|k| ct_eq(&combined, &k)) {
                return Err(reject(RejectReason::AccessRequired, 0));
            }
        }
        Ok(if shared {
            Lane::Group
        } else {
            Lane::Broadcast(n)
        })
    }

    /// The cluster-wide part of a request, a send to an open account or a broadcast ([`gate`]).
    async fn admit(&self, sender: &DeviceId, lane: Lane) -> Result<Admitted, SendStatus> {
        let (Lane::Request(_) | Lane::Broadcast(_) | Lane::Open(_)) = lane else {
            return Ok(Admitted::Store);
        };
        let Some(gate) = &self.policy.gate else {
            // Without a gate there are no blocks to apply (a static development directory, where
            // every account is open); requests and broadcasts cannot be held to budgets.
            return match lane {
                Lane::Open(_) => Ok(Admitted::Store),
                _ => Err(reject(RejectReason::Unavailable, RETRY_MS)),
            };
        };
        let (from, refused) = {
            let dir = self.directory.load();
            let from = dir
                .account_of(sender)
                .ok_or(reject(RejectReason::Unavailable, RETRY_MS))?;
            let refused = match lane {
                Lane::Request(r) => dir.access(&r).requests_off,
                _ => false,
            };
            (from, refused)
        };
        let admit = match lane {
            Lane::Request(r) => gate.request(&from, &r, refused).await,
            Lane::Broadcast(n) => gate.broadcast(&from, n).await,
            Lane::Open(r) => gate.blocked(&from, &r).await,
            _ => Admit::Allow,
        };
        match (admit, lane) {
            (Admit::Allow, Lane::Request(_)) => {
                self.metrics.requests.inc();
                Ok(Admitted::Store)
            }
            (Admit::Allow, Lane::Broadcast(_)) => {
                self.metrics.broadcasts.inc();
                Ok(Admitted::Store)
            }
            (Admit::Drop, Lane::Request(r) | Lane::Open(r)) => {
                self.metrics.requests_dropped.inc();
                Ok(Admitted::Drop(r))
            }
            // A broadcast is never dropped (the gate only drops requests and open accounts).
            (Admit::Allow | Admit::Drop, _) => Ok(Admitted::Store),
            (Admit::Limited(ms), _) => Err(reject(RejectReason::RateLimited, ms)),
            (Admit::Unavailable, _) => Err(reject(RejectReason::Unavailable, RETRY_MS)),
        }
    }

    /// A dropped send (blocked, or requests refused), so that nothing the sender sees differs from
    /// a delivered one:
    ///
    /// - the whole send, every envelope of it, is stored under its own idempotency key with a
    ///   deadline that has already passed: never fetched or routed, deleted by the next sweep. The
    ///   idempotency record therefore names exactly the devices an undropped send's would, and the
    ///   store's answer (a conflict for a reused key, a replay, unavailable) is the send's answer;
    /// - the sender's own envelopes (its sync transcript) are then stored live under a key derived
    ///   from it, so its other devices still see what it sent.
    ///
    /// Returns `Ok(true)` if nothing is left to store.
    async fn drop_part(&self, s: &mut SendFrame, recipient: AccountId) -> Result<bool, SendStatus> {
        let SendPayload::PerDevice(rs) = &mut s.payload else {
            return Ok(false);
        };
        let all: Vec<NewEnvelope> = rs
            .iter()
            .map(|r| NewEnvelope {
                device: r.device,
                envelope: r.envelope.clone(),
            })
            .collect();
        {
            let dir = self.directory.load();
            rs.retain(|x| dir.account_of(&x.device) != Some(recipient));
        }
        let expired = StoreRequest {
            idempotency_key: Some(s.idempotency_key),
            mls: None,
            expires_after: Some(Duration::ZERO),
            payload: Payload::PerDevice(all),
        };
        match self.mailbox.store_send(expired).await {
            Ok(_) => {}
            Err(MailboxError::IdempotencyConflict) => {
                return Err(reject(RejectReason::IdempotencyConflict, 0));
            }
            Err(MailboxError::StaleEpoch) => return Err(reject(RejectReason::StaleEpoch, 0)),
            Err(MailboxError::Full | MailboxError::Unavailable) => {
                self.metrics.mailbox_errors.inc();
                return Err(reject(RejectReason::Unavailable, RETRY_MS));
            }
        }
        for (i, b) in s.idempotency_key.iter_mut().enumerate() {
            *b ^= 0xA5 ^ u8::try_from(i).unwrap_or(0);
        }
        Ok(rs.is_empty())
    }

    /// Stamps every envelope for another account (a shared body once, for no one in particular);
    /// the sender's own devices get their envelopes as sent. The sender is all zeros for a sealed
    /// send (no device of it is in the directory). One allocation per stamped envelope.
    fn stamp(
        &self,
        f: &Franker,
        sender: &DeviceId,
        commitment: &[u8; 32],
        payload: &mut SendPayload,
    ) {
        let dir = self.directory.load();
        let from = dir.account_of(sender);
        let sender_account = from.map_or([0; 16], |a| *a.as_bytes());
        let now = now_ms();
        match payload {
            SendPayload::PerDevice(rs) => {
                for r in rs.iter_mut() {
                    let to = dir.account_of(&r.device);
                    if to.is_none() || to == from {
                        continue;
                    }
                    let recipient = to.map_or([0; 16], |a| *a.as_bytes());
                    let st = f.stamp(commitment, now, &sender_account, &recipient);
                    r.envelope = st.prepend(&r.envelope);
                }
            }
            SendPayload::Shared { body, .. } => {
                let st = f.stamp(commitment, now, &sender_account, &[0; 16]);
                *body = st.prepend(body);
            }
        }
    }

    /// Routes a stored send to its recipients' sessions, wherever they are; a device with no
    /// session gets a push wake-up (debounced, never blocking the caller).
    pub async fn route(&self, payload: SendPayload, seqs: Vec<u64>) {
        let m = self.metrics;
        // Route even a replayed send: if the original route was lost (crash between store and
        // route), this retry delivers it now instead of at the next safety sweep; a duplicate
        // is dropped by the recipient session's cursor.
        let routes: Vec<(DeviceId, Bytes)> = match payload {
            SendPayload::PerDevice(rs) => rs.into_iter().map(|r| (r.device, r.envelope)).collect(),
            // One buffer for every recipient: `Bytes` clones share it (no copy per device).
            SendPayload::Shared { devices, body } => {
                devices.into_iter().map(|d| (d, body.clone())).collect()
            }
        };
        for ((device, envelope), seq) in routes.into_iter().zip(seqs) {
            // `seq` 0: a replayed send already acknowledged by this device (the mailbox can no
            // longer read it, D-0031); nothing to route.
            if seq == 0 {
                continue;
            }
            match self.router.route(&device, Live { seq, envelope }).await {
                Routed::Queued => {}
                Routed::Lagged => m.routes_lagged.inc(),
                Routed::Offline => {
                    m.routes_offline.inc();
                    self.push.offline(device);
                }
            }
        }
    }

    /// [`store`](Self::store), then [`route`](Self::route): for callers with nothing to write
    /// between the two (`api`). Returns the `SendResult` status.
    pub async fn send(
        &self,
        sender: &DeviceId,
        mut s: SendFrame,
        received: Instant,
        scratch: &mut Vec<DeviceId>,
    ) -> SendStatus {
        match self.store(sender, &mut s, received, scratch).await {
            Ok(outcome) => {
                self.route(s.payload, outcome.seqs).await;
                SendStatus::Accepted
            }
            Err(status) => status,
        }
    }
}

/// Whether any envelope begins with the prefix reserved for what the server writes (system
/// frames, franking stamps).
fn reserved(payload: &SendPayload) -> bool {
    use songbird_proto::envelope::is_reserved;
    match payload {
        SendPayload::PerDevice(rs) => rs.iter().any(|r| is_reserved(&r.envelope)),
        SendPayload::Shared { body, .. } => is_reserved(body),
    }
}

/// Constant-time comparison of two access keys.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The mailbox request for a decoded `Send` (payload bytes are shared, not copied).
#[must_use]
pub fn store_request(s: &SendFrame) -> StoreRequest {
    let payload = match &s.payload {
        SendPayload::PerDevice(rs) => Payload::PerDevice(
            rs.iter()
                .map(|r| NewEnvelope {
                    device: r.device,
                    envelope: r.envelope.clone(),
                })
                .collect(),
        ),
        SendPayload::Shared { devices, body } => Payload::Shared {
            devices: devices.clone(),
            body: body.clone(),
        },
    };
    StoreRequest {
        expires_after: s
            .hints
            .expire_after_s
            .map(|t| Duration::from_secs(u64::from(t))),
        idempotency_key: Some(s.idempotency_key),
        // Commits no longer come through the send path (PROTOCOL §6.3; the frame's MLS flag is
        // retired), so nothing here asks the mailbox to order an epoch.
        mls: None,
        payload,
    }
}

/// Whether a device appears twice. Pairwise for the common small sends (no allocation; a
/// per-send `HashSet` was 8 % of user CPU in the M1 flamegraph), sorting above that.
#[must_use]
pub fn has_duplicate_device(devices: &[DeviceId]) -> bool {
    const PAIRWISE_MAX: usize = 32;
    if devices.len() <= PAIRWISE_MAX {
        return devices.iter().enumerate().any(|(i, d)| {
            devices
                .get(i + 1..)
                .unwrap_or_default()
                .iter()
                .any(|o| o == d)
        });
    }
    // Bounded by max_recipients (checked by the decoder).
    let mut ids: Vec<&[u8; 16]> = devices.iter().map(DeviceId::as_bytes).collect();
    ids.sort_unstable();
    ids.windows(2).any(|w| w.first() == w.get(1))
}

#[cfg(test)]
mod tests;
