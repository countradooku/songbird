//! Plans and entitlements (Prompt 11, M1; `docs/PROTOCOL.md` §12; D-0126, D-0127).
//!
//! One source of truth for what each plan allows, read by every service:
//!
//! - [`Catalog`]: the limits and flags of each [`Level`], from configuration, with a version the
//!   apps see. Validated so that a higher level never allows less than a lower one.
//! - [`Snapshot`]: the accounts that are **not** on the default plan, with the last day they hold
//!   their level. Only exceptions, so it stays small; everyone else is Free.
//! - [`Live`]: the snapshot every request reads lock-free (`arc-swap`), replaced whole when the
//!   registry's `entver` row changes ([`follow`]).
//!
//! Rules every reader keeps (D-0126 finding 5):
//!
//! - **An entitlement expires by date at the reader.** Each entry carries its last day; a reader
//!   compares it with the clock. A stale snapshot, a failed reload or a stopped worker can never
//!   extend one.
//! - **Security is never in the catalogue.** Encryption, verification, app lock, the PIN and
//!   passkeys, backups and restore, privacy settings, calls, groups, reporting, blocking, export
//!   and deletion are the same on every plan; there is nothing here to gate them with.
//! - **A downgrade never deletes.** Over a limit means nothing new is added until the account is
//!   back under it; what exists keeps working.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use songbird_accounts::Registry;
use songbird_accounts::entitlements::EntRow;
use songbird_types::AccountId;

/// A plan level. Family members and owners hold [`Level::Plus`]: the server cannot tell a
/// family seat from a Plus subscription (D-0126 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Level {
    /// The default plan; never stored.
    #[default]
    Free = 0,
    /// Plus (and every Family seat).
    Plus = 1,
}

impl Level {
    /// Every level, lowest first.
    pub const ALL: [Self; 2] = [Self::Free, Self::Plus];

    /// The stored and wire number.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Free => 0,
            Self::Plus => 1,
        }
    }

    /// The level stored as `n`, if it is one this build knows.
    #[must_use]
    pub const fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::Free),
            1 => Some(Self::Plus),
            _ => None,
        }
    }

    /// Its name on the wire and in the tools.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Plus => "plus",
        }
    }

    /// The level named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.name() == s)
    }
}

/// What a plan allows, in numbers. Every one is enforced by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Linked devices besides the primary.
    pub linked_devices: u32,
    /// Largest attachment ciphertext (bytes).
    pub file_bytes: u64,
    /// Upload bytes granted per 24 hours.
    pub upload_bytes_per_day: u64,
    /// Songbird backup vault space (bytes).
    pub vault_bytes: u64,
    /// Songbird backup vault chunks.
    pub vault_chunks: u64,
    /// New packs (stickers, scenes, sounds, emoticons) per 30 days.
    pub packs_per_month: u32,
}

impl Limits {
    /// Devices in all: the primary and the linked ones.
    #[must_use]
    pub const fn devices(&self) -> u32 {
        self.linked_devices.saturating_add(1)
    }

    fn le(&self, o: &Self) -> bool {
        self.linked_devices <= o.linked_devices
            && self.file_bytes <= o.file_bytes
            && self.upload_bytes_per_day <= o.upload_bytes_per_day
            && self.vault_bytes <= o.vault_bytes
            && self.vault_chunks <= o.vault_chunks
            && self.packs_per_month <= o.packs_per_month
    }

    fn max(&self, o: &Self) -> Self {
        Self {
            linked_devices: self.linked_devices.max(o.linked_devices),
            file_bytes: self.file_bytes.max(o.file_bytes),
            upload_bytes_per_day: self.upload_bytes_per_day.max(o.upload_bytes_per_day),
            vault_bytes: self.vault_bytes.max(o.vault_bytes),
            vault_chunks: self.vault_chunks.max(o.vault_chunks),
            packs_per_month: self.packs_per_month.max(o.packs_per_month),
        }
    }
}

/// What a plan adds that the server cannot enforce: the settings they touch are end-to-end
/// encrypted, so apps check them (D-0126, plans table). None of them is a security feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Flags {
    /// Alternative app icons.
    pub app_icons: bool,
    /// Chat themes.
    pub chat_themes: bool,
    /// Support tickets answered first.
    pub priority_support: bool,
}

impl Flags {
    const fn le(self, o: Self) -> bool {
        (!self.app_icons || o.app_icons)
            && (!self.chat_themes || o.chat_themes)
            && (!self.priority_support || o.priority_support)
    }
}

/// One plan: its limits and flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Numbers.
    pub limits: Limits,
    /// Extras checked by apps.
    #[serde(default)]
    pub flags: Flags,
}

/// The catalogue: every level's plan (`[…plans]` in configuration; the owner's numbers by
/// default, D-0126 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Catalog {
    /// Bumped whenever a number changes; apps re-read the catalogue when it differs.
    pub version: u32,
    /// The default plan.
    pub free: Plan,
    /// Plus (and Family seats).
    pub plus: Plan,
}

const GIB: u64 = 1 << 30;

impl Default for Catalog {
    fn default() -> Self {
        Self {
            version: 1,
            free: Plan {
                limits: Limits {
                    linked_devices: 5,
                    file_bytes: 2 * GIB,
                    upload_bytes_per_day: 10 * GIB,
                    vault_bytes: 5 * GIB,
                    vault_chunks: 100_000,
                    packs_per_month: 5,
                },
                flags: Flags::default(),
            },
            plus: Plan {
                limits: Limits {
                    linked_devices: 10,
                    file_bytes: 4 * GIB,
                    upload_bytes_per_day: 50 * GIB,
                    vault_bytes: 50 * GIB,
                    vault_chunks: 1_000_000,
                    packs_per_month: 50,
                },
                flags: Flags {
                    app_icons: true,
                    chat_themes: true,
                    priority_support: true,
                },
            },
        }
    }
}

/// A catalogue that breaks a rule (the field named, never a value).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// A number outside its bounds.
    #[error("plans: {0} out of bounds")]
    Bounds(&'static str),
    /// A higher level allows less than a lower one.
    #[error("plans: a higher level allows less than a lower one")]
    NotMonotone,
}

/// Bounds every plan's numbers must stay within, whatever the configuration says.
pub mod bounds {
    use std::ops::RangeInclusive;
    /// Linked devices besides the primary (a signed device list holds at most 16 devices,
    /// `songbird_proto::devices::MAX_LIST_DEVICES`).
    pub const LINKED_DEVICES: RangeInclusive<u32> = 1..=15;
    /// Largest file: at least 64 MiB, at most 16 GiB.
    pub const FILE_BYTES: RangeInclusive<u64> = (64 << 20)..=(16 << 30);
    /// Uploads a day: 64 MiB to 1 TiB.
    pub const UPLOAD_BYTES_PER_DAY: RangeInclusive<u64> = (64 << 20)..=(1 << 40);
    /// Vault space: 64 MiB to 1 TiB.
    pub const VAULT_BYTES: RangeInclusive<u64> = (64 << 20)..=(1 << 40);
    /// Vault chunks.
    pub const VAULT_CHUNKS: RangeInclusive<u64> = 100..=10_000_000;
    /// New packs per 30 days.
    pub const PACKS_PER_MONTH: RangeInclusive<u32> = 1..=10_000;
}

impl Catalog {
    /// Checks every bound and that a higher level never allows less.
    ///
    /// # Errors
    /// [`CatalogError`].
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.version == 0 {
            return Err(CatalogError::Bounds("version"));
        }
        for p in [&self.free, &self.plus] {
            let l = &p.limits;
            let checks: [(bool, &'static str); 6] = [
                (
                    bounds::LINKED_DEVICES.contains(&l.linked_devices),
                    "linked_devices",
                ),
                (bounds::FILE_BYTES.contains(&l.file_bytes), "file_bytes"),
                (
                    bounds::UPLOAD_BYTES_PER_DAY.contains(&l.upload_bytes_per_day),
                    "upload_bytes_per_day",
                ),
                (bounds::VAULT_BYTES.contains(&l.vault_bytes), "vault_bytes"),
                (
                    bounds::VAULT_CHUNKS.contains(&l.vault_chunks),
                    "vault_chunks",
                ),
                (
                    bounds::PACKS_PER_MONTH.contains(&l.packs_per_month),
                    "packs_per_month",
                ),
            ];
            if let Some((_, name)) = checks.iter().find(|(ok, _)| !ok) {
                return Err(CatalogError::Bounds(name));
            }
        }
        if !(self.free.limits.le(&self.plus.limits) && self.free.flags.le(self.plus.flags)) {
            return Err(CatalogError::NotMonotone);
        }
        Ok(())
    }

    /// A level's plan.
    #[must_use]
    pub const fn plan(&self, level: Level) -> &Plan {
        match level {
            Level::Free => &self.free,
            Level::Plus => &self.plus,
        }
    }

    /// A level's limits.
    #[must_use]
    pub const fn limits(&self, level: Level) -> &Limits {
        &self.plan(level).limits
    }

    /// The highest of every limit over every level: the hard bound of anything an account may
    /// already hold (a downgraded account's devices, an upload in flight).
    #[must_use]
    pub fn ceiling(&self) -> Limits {
        self.free.limits.max(&self.plus.limits)
    }
}

/// The UTC day (days since the Unix epoch) at `t`.
#[must_use]
pub fn day_of(t: SystemTime) -> u32 {
    let s = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    u32::try_from(s / 86_400).unwrap_or(u32::MAX)
}

/// Today's UTC day.
#[must_use]
pub fn today() -> u32 {
    day_of(SystemTime::now())
}

/// The last moment (Unix seconds, exclusive) of UTC day `day`.
#[must_use]
pub fn end_of_day(day: u32) -> u64 {
    (u64::from(day) + 1) * 86_400
}

/// An account's entitlement as the snapshot holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The level held.
    pub level: Level,
    /// The last UTC day it is held (inclusive).
    pub last_day: u32,
}

impl Entry {
    /// The level on `today`: [`Level::Free`] once past the last day.
    #[must_use]
    pub fn level_on(&self, today: u32) -> Level {
        if self.last_day >= today {
            self.level
        } else {
            Level::Free
        }
    }
}

/// An account's standing (D-0131). Good standing has no row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Standing {
    /// The default.
    #[default]
    Good,
    /// Automatically limited (metadata signals): tighter budgets for new conversations, no new
    /// group invite links; lifts by itself after a quiet week.
    Limited,
    /// Suspended by a moderator: cannot send or call; can receive, export, delete and appeal.
    Suspended,
}

impl Standing {
    /// From the stored name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "limited" => Some(Self::Limited),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }

    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Limited => "limited",
            Self::Suspended => "suspended",
        }
    }
}

/// The accounts not on the default plan, and those not in good standing, at one registry
/// version.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    version: i64,
    entries: HashMap<AccountId, Entry>,
    standings: HashMap<AccountId, (Standing, Option<u32>)>,
}

impl Snapshot {
    /// From registry rows read at `version` (read the version first, then the rows: a change in
    /// between is picked up by the next poll). Rows of a level this build does not know are
    /// left out (Free), never promoted.
    #[must_use]
    pub fn from_rows(version: i64, rows: &[EntRow]) -> Self {
        let entries = rows
            .iter()
            .filter_map(|r| {
                Level::from_u8(r.level).map(|level| {
                    (
                        r.account,
                        Entry {
                            level,
                            last_day: r.last_day,
                        },
                    )
                })
            })
            .collect();
        Self {
            version,
            entries,
            standings: HashMap::new(),
        }
    }

    /// With standings (`(account, kind, last day or none)`); unknown kinds are left out.
    #[must_use]
    pub fn with_standings(
        mut self,
        rows: impl IntoIterator<Item = (AccountId, Standing, Option<u32>)>,
    ) -> Self {
        self.standings = rows
            .into_iter()
            .filter(|(_, s, _)| *s != Standing::Good)
            .map(|(a, s, u)| (a, (s, u)))
            .collect();
        self
    }

    /// The account's standing on `today`.
    #[must_use]
    pub fn standing(&self, account: &AccountId, today: u32) -> Standing {
        self.standings
            .get(account)
            .filter(|(_, until)| until.is_none_or(|u| u >= today))
            .map_or(Standing::Good, |(s, _)| *s)
    }

    /// The registry version it was read at.
    #[must_use]
    pub const fn version(&self) -> i64 {
        self.version
    }

    /// How many accounts it lists (lapsed ones included until the sweep).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it lists no account.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The account's entry while held on `today`.
    #[must_use]
    pub fn entry(&self, account: &AccountId, today: u32) -> Option<Entry> {
        self.entries
            .get(account)
            .copied()
            .filter(|e| e.last_day >= today)
    }

    /// The account's level on `today`.
    #[must_use]
    pub fn level(&self, account: &AccountId, today: u32) -> Level {
        self.entry(account, today).map_or(Level::Free, |e| e.level)
    }
}

/// The snapshot every request reads (no lock), replaced whole on a change.
#[derive(Debug, Default)]
pub struct Live {
    current: arc_swap::ArcSwap<Snapshot>,
}

impl From<Snapshot> for Live {
    fn from(s: Snapshot) -> Self {
        Self {
            current: arc_swap::ArcSwap::from_pointee(s),
        }
    }
}

impl Live {
    /// The current snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<Snapshot>> {
        self.current.load()
    }

    /// Replaces it.
    pub fn store(&self, s: Snapshot) {
        self.current.store(Arc::new(s));
    }

    /// The account's level today.
    #[must_use]
    pub fn level(&self, account: &AccountId) -> Level {
        self.current.load().level(account, today())
    }

    /// The account's entry today.
    #[must_use]
    pub fn entry(&self, account: &AccountId) -> Option<Entry> {
        self.current.load().entry(account, today())
    }

    /// The account's standing today.
    #[must_use]
    pub fn standing(&self, account: &AccountId) -> Standing {
        self.current.load().standing(account, today())
    }
}

/// Reads the snapshot from the registry (the version first).
///
/// # Errors
/// The registry's.
pub async fn load(registry: &Registry) -> Result<Snapshot, songbird_accounts::RegistryError> {
    let version = registry.entitlements_version().await?;
    let rows = registry.entitlements(today()).await?;
    let standings = registry.standings(today()).await?;
    Ok(Snapshot::from_rows(version, &rows).with_standings(
        standings
            .into_iter()
            .filter_map(|r| Standing::parse(&r.kind).map(|s| (r.account, s, r.until))),
    ))
}

/// Keeps `live` in step with the registry: polls the version every `every` and reloads on a
/// change. A failed poll or reload keeps the last snapshot; its entries still expire by date.
pub async fn follow(
    registry: Arc<Registry>,
    live: Arc<Live>,
    every: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let v = match registry.entitlements_version().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "entitlements version poll failed");
                continue;
            }
        };
        if v == live.load().version() {
            continue;
        }
        match load(&registry).await {
            Ok(s) => live.store(s),
            Err(e) => tracing::warn!(error = %e, "entitlements reload failed"),
        }
    }
}

#[cfg(test)]
mod tests;
