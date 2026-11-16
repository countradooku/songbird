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

/// A group's roster at an epoch: member devices, sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    pub epoch: u64,
    pub devices: Vec<DeviceId>,
}

impl Roster {
    /// Parses the registry's roster bytes (16 bytes per device, sorted, no repeats).
    #[must_use]
    pub fn from_bytes(epoch: u64, bytes: &[u8]) -> Option<Self> {
        let (chunks, rest) = bytes.as_chunks::<16>();
        if !rest.is_empty() {
            return None;
        }
        let devices: Vec<DeviceId> = chunks.iter().map(|c| DeviceId::from_bytes(*c)).collect();
        devices
            .windows(2)
            .all(|w| matches!(w, [a, b] if a < b))
            .then_some(Self { epoch, devices })
    }

    /// The registry's roster bytes.
    #[must_use]
    pub fn to_bytes(devices: &[DeviceId]) -> Vec<u8> {
        devices.iter().flat_map(|d| *d.as_bytes()).collect()
    }

    #[must_use]
    pub fn contains(&self, device: &DeviceId) -> bool {
        self.devices.binary_search(device).is_ok()
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
    pub fn set(&self, group: [u8; 16], epoch: u64, mut devices: Vec<DeviceId>) {
        devices.sort_unstable();
        devices.dedup();
        self.groups
            .pin()
            .insert(group, Arc::new(Roster { epoch, devices }));
    }
}

impl Rosters for MemoryRosters {
    fn roster<'a>(&'a self, group: &'a [u8; 16], _epoch: u64) -> RosterFuture<'a> {
        Box::pin(async move { Ok(self.groups.pin().get(group).cloned()) })
    }
}
