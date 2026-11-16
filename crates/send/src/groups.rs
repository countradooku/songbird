//! Group application messages on the send path (Prompt 5, M1; D-0067).
//!
//! A `Send` with the `GROUP` flag carries one MLS `PrivateMessage` and lists no devices. Before
//! anything is stored the send path reads the message's plaintext prefix (no decryption, no
//! OpenMLS, no allocation) and checks it against the group's roster:
//!
//! - the prefix is an application message of the frame's group;
//! - the sending device is in the roster;
//! - the message's epoch is the roster's, or the one before (a message sent just before a commit
//!   landed); anything else is a stale epoch.
//!
//! The recipients are then the roster minus the sender, so a removed device never receives a
//! byte, and membership replaces the contact keys of D-0064's interim rule.
//!
//! Rosters come from the registry (`grp:[group]`, written by `api` with every commit) through a
//! per-node cache: an entry is refreshed after [`ROSTER_TTL`], or at once when a message names a
//! newer epoch than the cached one. A device removed by a commit can therefore still post at the
//! old epoch for at most that long on a node that has not refreshed (threat model §6).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use songbird_types::DeviceId;

/// Longest a cached roster is used without asking the registry again.
pub const ROSTER_TTL: Duration = Duration::from_secs(1);

/// The registry's roster format with roles (D-0070, written by `crates/groups`).
pub const ROSTER_V2: u8 = 2;
/// The role a member needs at least to be a full member (`songbird_groups::roles::Role`).
pub const ROLE_MEMBER: u8 = 1;
/// The policy flag of a channel (`songbird_groups::roles::FLAG_CHANNEL`).
pub const FLAG_CHANNEL: u8 = 0x01;

/// A group's roster at an epoch: member devices (sorted) with their roles, and the least role
/// that may send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    pub epoch: u64,
    /// `(device, role)`, devices ascending.
    pub members: Vec<(DeviceId, u8)>,
    /// The least role that may send (the policy's first byte).
    pub send_min: u8,
    /// The policy's seven bytes (`songbird_groups::roles::Policy`).
    pub policy: [u8; 7],
}

impl Roster {
    /// A private channel (the policy's channel flag, `songbird_groups::roles::FLAG_CHANNEL`):
    /// its posts take the channel rate class (D-0072).
    #[must_use]
    pub const fn is_channel(&self) -> bool {
        self.policy[6] & FLAG_CHANNEL != 0
    }

    /// Parses the registry's roster: `version u8 (2) | policy [7] | n × (device [16] |
    /// role u8)`, devices strictly ascending, roles 0 to 4.
    #[must_use]
    pub fn from_bytes(epoch: u64, bytes: &[u8]) -> Option<Self> {
        let (&version, rest) = bytes.split_first()?;
        if version != ROSTER_V2 {
            return None;
        }
        let (policy, rest) = rest.split_at_checked(7)?;
        let policy: [u8; 7] = policy.try_into().ok()?;
        let (chunks, tail) = rest.as_chunks::<17>();
        if !tail.is_empty() {
            return None;
        }
        let mut members = Vec::with_capacity(chunks.len());
        for c in chunks {
            let (d, r) = c.split_at(16);
            let role = *r.first()?;
            if role > 4 {
                return None;
            }
            members.push((DeviceId::from_slice(d).ok()?, role));
        }
        if !members.windows(2).all(|w| matches!(w, [a, b] if a.0 < b.0)) {
            return None;
        }
        Some(Self {
            epoch,
            members,
            send_min: policy[0],
            policy,
        })
    }

    /// Encodes a roster (tests and development; `crates/groups` writes the real one).
    #[must_use]
    pub fn encode(policy: [u8; 7], members: &[(DeviceId, u8)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + members.len() * 17);
        out.push(ROSTER_V2);
        out.extend_from_slice(&policy);
        for (d, r) in members {
            out.extend_from_slice(d.as_bytes());
            out.push(*r);
        }
        out
    }

    /// The device's role, if it is a member.
    #[must_use]
    pub fn role(&self, device: &DeviceId) -> Option<u8> {
        self.members
            .binary_search_by(|(d, _)| d.cmp(device))
            .ok()
            .and_then(|i| self.members.get(i))
            .map(|(_, r)| *r)
    }

    #[must_use]
    pub fn contains(&self, device: &DeviceId) -> bool {
        self.role(device).is_some()
    }

    /// Every member device.
    pub fn devices(&self) -> impl Iterator<Item = &DeviceId> {
        self.members.iter().map(|(d, _)| d)
    }
}

/// What a roster lookup may answer.
pub type RosterFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Arc<Roster>>, ()>> + Send + 'a>>;

/// Where the send path finds rosters.
pub trait Rosters: Send + Sync + 'static {
    /// The group's roster, at least as new as `epoch` if the store has it; `None` if no such
    /// group; `Err` if the store is unreachable.
    fn roster<'a>(&'a self, group: &'a [u8; 16], epoch: u64) -> RosterFuture<'a>;
}

/// Rosters from the registry, cached per node.
pub struct RegistryRosters {
    registry: Arc<songbird_accounts::Registry>,
    cache: papaya::HashMap<[u8; 16], (Arc<Roster>, Instant)>,
    ttl: Duration,
}

impl std::fmt::Debug for RegistryRosters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryRosters")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl RegistryRosters {
    #[must_use]
    pub fn new(registry: Arc<songbird_accounts::Registry>, ttl: Duration) -> Self {
        Self {
            registry,
            cache: papaya::HashMap::new(),
            ttl,
        }
    }
}

impl Rosters for RegistryRosters {
    fn roster<'a>(&'a self, group: &'a [u8; 16], epoch: u64) -> RosterFuture<'a> {
        Box::pin(async move {
            let cached = self.cache.pin().get(group).cloned();
            if let Some((r, at)) = &cached
                && r.epoch >= epoch
                && at.elapsed() < self.ttl
            {
                return Ok(Some(Arc::clone(r)));
            }
            let Some((e, bytes)) = self.registry.group_roster(group).await.map_err(|_| ())? else {
                self.cache.pin().remove(group);
                return Ok(None);
            };
            let r = Arc::new(Roster::from_bytes(e, &bytes).ok_or(())?);
            self.cache
                .pin()
                .insert(*group, (Arc::clone(&r), Instant::now()));
            Ok(Some(r))
        })
    }
}

/// Fixed rosters (tests and development).
#[derive(Debug, Default)]
pub struct MemoryRosters {
    groups: papaya::HashMap<[u8; 16], Arc<Roster>>,
}

impl MemoryRosters {
    /// Sets a group's roster (devices are sorted here).
    pub fn set(&self, group: [u8; 16], epoch: u64, devices: Vec<DeviceId>) {
        let members = devices.into_iter().map(|d| (d, ROLE_MEMBER)).collect();
        self.set_roles(group, epoch, [ROLE_MEMBER, 1, 1, 3, 1, 1, 0], members);
    }

    /// Sets a group's roster with roles and policy (devices are sorted here).
    pub fn set_roles(
        &self,
        group: [u8; 16],
        epoch: u64,
        policy: [u8; 7],
        mut members: Vec<(DeviceId, u8)>,
    ) {
        members.sort_unstable();
        members.dedup_by_key(|(d, _)| *d);
        self.groups.pin().insert(
            group,
            Arc::new(Roster {
                epoch,
                members,
                send_min: policy[0],
                policy,
            }),
        );
    }
}

impl Rosters for MemoryRosters {
    fn roster<'a>(&'a self, group: &'a [u8; 16], _epoch: u64) -> RosterFuture<'a> {
        Box::pin(async move { Ok(self.groups.pin().get(group).cloned()) })
    }
}

/// The channel rate class (D-0072): posts per channel, across its admins, on this node. A post
/// to a channel is stored for up to `max_channel_members` devices, so channels get a budget of
/// their own, on top of each sender's device budget. GCRA: `per_sec` steady, `burst` at once.
#[derive(Debug)]
pub struct ChannelBudget {
    interval: Duration,
    tolerance: Duration,
    /// Each channel's theoretical arrival time.
    tat: std::sync::Mutex<std::collections::HashMap<[u8; 16], Instant>>,
}

/// Channels tracked before idle ones are forgotten.
const CHANNEL_BUDGET_ENTRIES: usize = 4_096;

impl ChannelBudget {
    /// A budget of `per_sec` posts a second per channel, bursting to `burst`.
    #[must_use]
    pub fn new(per_sec: u32, burst: u32) -> Self {
        let interval = Duration::from_secs(1) / per_sec.max(1);
        Self {
            interval,
            tolerance: interval * burst.max(1).saturating_sub(1),
            tat: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Takes one post for `channel` at `now`; `Err(wait)` if the channel is over budget.
    ///
    /// # Errors
    /// How long until the channel may post again.
    pub fn take(&self, channel: &[u8; 16], now: Instant) -> Result<(), Duration> {
        let mut map = self
            .tat
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= CHANNEL_BUDGET_ENTRIES && !map.contains_key(channel) {
            // Channels whose budget is full again need no entry.
            map.retain(|_, tat| *tat > now);
        }
        let tat = map.get(channel).copied().unwrap_or(now).max(now);
        let ahead = tat.saturating_duration_since(now);
        if ahead > self.tolerance {
            return Err(ahead.saturating_sub(self.tolerance));
        }
        map.insert(*channel, tat + self.interval);
        Ok(())
    }
}

impl Default for ChannelBudget {
    /// One post a second per channel, bursting to ten.
    fn default() -> Self {
        Self::new(1, 10)
    }
}
