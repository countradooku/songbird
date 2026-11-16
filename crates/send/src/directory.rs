//! Device directory: which devices exist, which account each belongs to, and their
//! authentication keys.
//!
//! Loaded from the account registry in SurrealDB (D-0036) and reloaded whenever its version
//! changes ([`LiveDirectory`]: readers take no lock), or from a static file (development and CI
//! only; refused in staging and production by configuration validation).

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::Path;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use songbird_proto::PUBLIC_KEY_LEN;
use songbird_types::{AccountId, DeviceId};

/// Largest directory file accepted (checked before reading).
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Above this many recipients the device-list check uses hash sets instead of linear scans.
const LINEAR_MAX: usize = 32;

/// Directory loading errors. Never echo file contents.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    /// The file could not be read.
    #[error("cannot read device directory: {0}")]
    Io(#[from] std::io::Error),
    /// Over [`MAX_FILE_BYTES`].
    #[error("device directory larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    /// Not valid TOML of the expected shape.
    #[error("device directory is malformed")]
    Malformed,
    /// An entry has a bad ID or key (index given, never the value).
    #[error("device directory entry {0} is invalid")]
    Entry(usize),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    devices: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    auth_key: String,
    /// Owning account; absent means the device is an account of its own.
    #[serde(default)]
    account: Option<String>,
}

#[derive(Clone, Copy)]
struct Device {
    key: [u8; PUBLIC_KEY_LEN],
    account: AccountId,
}

/// The sender's view of some accounts' devices is out of date (`SendResult` status 2).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// Devices of the addressed accounts the send left out.
    pub missing: Vec<DeviceId>,
    /// Addressed devices that do not exist.
    pub extra: Vec<DeviceId>,
}

/// An account's send settings (Prompt 4, D-0062): who may send to it without a request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Access {
    /// Its unidentified-access key, if it set a profile: a sender holding it is a contact.
    pub key: Option<[u8; 16]>,
    /// Anyone may send to it without a request (the profile's "anyone may send").
    pub open: bool,
    /// Message requests to it are dropped (silently).
    pub requests_off: bool,
}

impl Access {
    /// An open account: what a static development directory gives every account, so sends
    /// between its devices need no keys.
    pub const OPEN: Self = Self {
        key: None,
        open: true,
        requests_off: false,
    };
}

/// Known devices, their accounts and Ed25519 authentication public keys.
#[derive(Default)]
pub struct Directory {
    devices: HashMap<DeviceId, Device>,
    accounts: HashMap<AccountId, Vec<DeviceId>>,
    /// Accounts' send settings (from their profiles and request policy).
    access: HashMap<AccountId, Access>,
    /// For an account with no entry: open in a static directory, closed from the registry.
    default_access: Access,
    /// Linked devices not yet in their account's signed list (D-0052): they authenticate, but
    /// no sender is asked to encrypt to them and a send addressing one is refused as extra.
    pending: HashSet<DeviceId>,
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("devices", &self.devices.len())
            .field("accounts", &self.accounts.len())
            .field("pending", &self.pending.len())
            .field("access", &self.access.len())
            .field("default_access", &self.default_access)
            .finish()
    }
}

/// The account a device forms on its own (static files without an `account` field).
fn own_account(d: &DeviceId) -> AccountId {
    AccountId::from_bytes(*d.as_bytes())
}

impl Directory {
    /// An empty directory (no device can authenticate).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Loads the static directory file.
    ///
    /// # Errors
    /// [`DirectoryError`].
    pub fn load(path: &Path) -> Result<Self, DirectoryError> {
        let f = std::fs::File::open(path)?;
        if f.metadata()?.len() > MAX_FILE_BYTES {
            return Err(DirectoryError::TooLarge);
        }
        let mut text = String::new();
        f.take(MAX_FILE_BYTES + 1).read_to_string(&mut text)?;
        Self::parse(&text)
    }

    /// Parses directory TOML.
    ///
    /// # Errors
    /// [`DirectoryError`].
    pub fn parse(text: &str) -> Result<Self, DirectoryError> {
        let file: File = toml::from_str(text).map_err(|_| DirectoryError::Malformed)?;
        let mut entries = Vec::with_capacity(file.devices.len());
        for (i, e) in file.devices.iter().enumerate() {
            let id = DeviceId::parse_hex(&e.id).map_err(|_| DirectoryError::Entry(i))?;
            let mut key = [0u8; PUBLIC_KEY_LEN];
            hex::decode_to_slice(&e.auth_key, &mut key).map_err(|_| DirectoryError::Entry(i))?;
            let account = match &e.account {
                Some(a) => AccountId::parse_hex(a).map_err(|_| DirectoryError::Entry(i))?,
                None => own_account(&id),
            };
            entries.push((id, key, account));
        }
        let mut dir = Self::from_entries(entries.iter().copied());
        if dir.devices.len() != entries.len() {
            // A duplicate device ID: report the first repeat.
            let mut seen = HashSet::new();
            let i = entries
                .iter()
                .position(|(id, _, _)| !seen.insert(*id))
                .unwrap_or(0);
            return Err(DirectoryError::Entry(i));
        }
        dir.accounts.values_mut().for_each(|v| v.sort_unstable());
        Ok(dir)
    }

    /// A static directory: every account open (development, CI and tests only; refused in
    /// staging and production by configuration validation).
    fn from_entries(
        entries: impl IntoIterator<Item = (DeviceId, [u8; PUBLIC_KEY_LEN], AccountId)>,
    ) -> Self {
        let mut dir = Self {
            default_access: Access::OPEN,
            ..Self::default()
        };
        for (id, key, account) in entries {
            if dir.devices.insert(id, Device { key, account }).is_none() {
                dir.accounts.entry(account).or_default().push(id);
            }
        }
        dir
    }

    /// Builds a directory where every device is an account of its own (tests, load generator).
    #[must_use]
    pub fn from_keys(keys: impl IntoIterator<Item = (DeviceId, [u8; PUBLIC_KEY_LEN])>) -> Self {
        Self::from_entries(keys.into_iter().map(|(d, k)| (d, k, own_account(&d))))
    }

    /// Sets accounts' send settings; an account without one is closed (no key, requests
    /// allowed). What the registry gives.
    #[must_use]
    pub fn with_access(mut self, rows: impl IntoIterator<Item = (AccountId, Access)>) -> Self {
        self.default_access = Access::default();
        self.access = rows.into_iter().collect();
        self
    }

    /// An account's send settings.
    #[must_use]
    pub fn access(&self, account: &AccountId) -> Access {
        self.access
            .get(account)
            .copied()
            .unwrap_or(self.default_access)
    }

    /// Builds a directory with explicit accounts (tests).
    #[must_use]
    pub fn from_accounts(
        entries: impl IntoIterator<Item = (DeviceId, [u8; PUBLIC_KEY_LEN], AccountId)>,
    ) -> Self {
        let mut dir = Self::from_entries(entries);
        dir.accounts.values_mut().for_each(|v| v.sort_unstable());
        dir
    }

    /// Marks devices as pending (linked, not yet vouched for by a signed device list): they
    /// still authenticate, but leave their account's recipient set. Unknown IDs are ignored.
    #[must_use]
    pub fn with_pending(mut self, pending: impl IntoIterator<Item = DeviceId>) -> Self {
        for d in pending {
            if let Some(dev) = self.devices.get(&d) {
                if let Some(list) = self.accounts.get_mut(&dev.account) {
                    list.retain(|x| *x != d);
                }
                self.pending.insert(d);
            }
        }
        self
    }

    /// Loads the registry's enabled devices, pending ones marked.
    ///
    /// # Errors
    /// The registry failed.
    pub async fn from_registry(
        registry: &songbird_accounts::Registry,
    ) -> Result<Self, songbird_accounts::RegistryError> {
        // One query for devices and pending flags, so a device removed in between is never loaded
        // as a recipient. Access settings are a second query: a profile changed in between is
        // picked up by the next reload (its version bump).
        let rows = registry.load_directory_full().await?;
        let access = registry.load_access().await?;
        let pending: Vec<DeviceId> = rows.iter().filter(|r| r.3).map(|r| r.0).collect();
        Ok(
            Self::from_accounts(rows.into_iter().map(|(d, a, k, _)| (d, k, a)))
                .with_pending(pending)
                .with_access(access.into_iter().map(|r| {
                    (
                        r.account,
                        Access {
                            key: r.key,
                            open: r.open,
                            requests_off: r.requests_off,
                        },
                    )
                })),
        )
    }

    /// Number of devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Whether `device` exists.
    #[must_use]
    pub fn contains(&self, device: &DeviceId) -> bool {
        self.devices.contains_key(device)
    }

    /// The account `device` belongs to.
    #[must_use]
    pub fn account_of(&self, device: &DeviceId) -> Option<AccountId> {
        self.devices.get(device).map(|d| d.account)
    }

    /// The account of a device its account's signed list vouches for: `None` for an unknown or
    /// still pending device (groups admit listed devices only, Prompt 5).
    #[must_use]
    pub fn listed_account(&self, device: &DeviceId) -> Option<AccountId> {
        if self.pending.contains(device) {
            return None;
        }
        self.account_of(device)
    }

    /// Whether `signature` over `msg` verifies under `device`'s key. An unknown device and a bad
    /// signature are indistinguishable to the caller (no device-existence oracle).
    #[must_use]
    pub fn verify(&self, device: &DeviceId, msg: &[u8], signature: &[u8]) -> bool {
        // Verify against a fixed dummy key for unknown devices so both paths cost the same.
        const DUMMY: [u8; PUBLIC_KEY_LEN] = [0x5a; PUBLIC_KEY_LEN];
        let (key, known) = self
            .devices
            .get(device)
            .map_or((&DUMMY, false), |d| (&d.key, true));
        let ok = UnparsedPublicKey::new(&ED25519, key)
            .verify(msg, signature)
            .is_ok();
        ok && known
    }

    /// The device-list check (master prompt §5, `send`): every addressed device must exist, and
    /// a send that addresses an account must address all of its devices (except the sender).
    ///
    /// # Errors
    /// [`Mismatch`] listing missing and extra devices; the client re-encrypts and retries.
    pub fn check_devices(
        &self,
        sender: &DeviceId,
        recipients: &[DeviceId],
    ) -> Result<(), Mismatch> {
        let mut m = Mismatch::default();
        // Accounts addressed: a send addresses one or a few, kept inline (no allocation per send,
        // M3); a large group spills to a vector.
        let mut accounts = SmallAccounts::default();
        for r in recipients {
            match self.devices.get(r) {
                None => m.extra.push(*r),
                Some(_) if self.pending.contains(r) => m.extra.push(*r),
                Some(d) => accounts.insert(d.account),
            }
        }
        let set: Option<HashSet<&DeviceId>> =
            (recipients.len() > LINEAR_MAX).then(|| recipients.iter().collect());
        let addressed = |d: &DeviceId| match &set {
            Some(s) => s.contains(d),
            None => recipients.contains(d),
        };
        for a in accounts.iter() {
            for d in self.accounts.get(a).map(Vec::as_slice).unwrap_or_default() {
                if d != sender && !addressed(d) {
                    m.missing.push(*d);
                }
            }
        }
        if m.missing.is_empty() && m.extra.is_empty() {
            Ok(())
        } else {
            Err(m)
        }
    }
}

/// The directory sessions read, swapped whole when the registry changes. Readers take no lock
/// (`arc-swap`): authentication and the device-list check load the current snapshot.
#[derive(Debug)]
pub struct LiveDirectory {
    current: arc_swap::ArcSwap<Directory>,
}

impl From<Directory> for LiveDirectory {
    fn from(d: Directory) -> Self {
        Self {
            current: arc_swap::ArcSwap::from_pointee(d),
        }
    }
}

impl LiveDirectory {
    /// The current snapshot, owned (off the hot path: an `Arc` to keep across `await`s or
    /// threads).
    #[must_use]
    pub fn snapshot(&self) -> std::sync::Arc<Directory> {
        self.current.load_full()
    }

    /// The current snapshot.
    pub fn load(&self) -> arc_swap::Guard<std::sync::Arc<Directory>> {
        self.current.load()
    }

    /// Replaces the snapshot.
    pub fn store(&self, d: Directory) {
        self.current.store(std::sync::Arc::new(d));
    }
}

/// Keeps a [`LiveDirectory`] and the store generation in step with the registry: polls them
/// every `every` and reloads the directory on a change. A failed poll keeps the last snapshot (sessions keep working; a
/// deleted device stays authenticated until the registry is back, which the runbook covers).
pub async fn follow_registry(
    registry: std::sync::Arc<songbird_accounts::Registry>,
    live: std::sync::Arc<LiveDirectory>,
    generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    mut version: i64,
    every: std::time::Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        // The store generation (D-0040): it only ever grows.
        match registry.store_generation().await {
            Ok(g) => {
                generation.fetch_max(g, std::sync::atomic::Ordering::AcqRel);
            }
            Err(e) => tracing::warn!(error = %e, "store generation poll failed"),
        }
        let v = match registry.directory_version().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "directory version poll failed");
                continue;
            }
        };
        if v == version {
            continue;
        }
        match Directory::from_registry(&registry).await {
            Ok(d) => {
                live.store(d);
                version = v;
            }
            Err(e) => tracing::warn!(error = %e, "directory reload failed"),
        }
    }
}

/// A set of accounts, inline up to [`SmallAccounts::INLINE`] (no allocation for an ordinary send).
#[derive(Default)]
struct SmallAccounts {
    inline: [Option<AccountId>; SmallAccounts::INLINE],
    spill: Vec<AccountId>,
}

impl SmallAccounts {
    const INLINE: usize = 8;

    fn insert(&mut self, a: AccountId) {
        if self.iter().any(|x| *x == a) {
            return;
        }
        match self.inline.iter_mut().find(|s| s.is_none()) {
            Some(slot) => *slot = Some(a),
            None => self.spill.push(a),
        }
    }

    fn iter(&self) -> impl Iterator<Item = &AccountId> {
        self.inline.iter().flatten().chain(self.spill.iter())
    }
}

/// Renders a directory file (used by tests).
#[must_use]
pub fn render(entries: &[(DeviceId, [u8; PUBLIC_KEY_LEN])]) -> String {
    let mut out = String::with_capacity(entries.len().saturating_mul(120));
    out.push_str("# Static device directory (development and CI only).\n");
    for (id, key) in entries {
        out.push_str("[[devices]]\nid = \"");
        out.push_str(&id.to_hex_unredacted());
        out.push_str("\"\nauth_key = \"");
        out.push_str(&hex::encode(key));
        out.push_str("\"\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn verifies_known_devices_only() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(pair.public_key().as_ref());
        let dir = Directory::parse(&render(&[(dev(1), pk)])).unwrap();
        assert_eq!(dir.len(), 1);
        let sig = pair.sign(b"msg");
        assert!(dir.verify(&dev(1), b"msg", sig.as_ref()));
        assert!(!dir.verify(&dev(1), b"other", sig.as_ref()));
        assert!(!dir.verify(&dev(2), b"msg", sig.as_ref()));
        assert!(!dir.verify(&dev(1), b"msg", &[0; 64]));
    }

    #[test]
    fn rejects_bad_files_without_echoing_them() {
        assert!(matches!(
            Directory::parse("devices = 3"),
            Err(DirectoryError::Malformed)
        ));
        let e = Directory::parse("[[devices]]\nid = \"zz\"\nauth_key = \"00\"\n").unwrap_err();
        assert_eq!(e.to_string(), "device directory entry 0 is invalid");
        let dup = render(&[(dev(1), [0; 32]), (dev(1), [1; 32])]);
        assert!(matches!(
            Directory::parse(&dup),
            Err(DirectoryError::Entry(1))
        ));
    }

    #[test]
    fn device_list_check() {
        let alice = AccountId::from_bytes([0xA; 16]);
        let bob = AccountId::from_bytes([0xB; 16]);
        let dir = Directory::from_accounts([
            (dev(1), [0; 32], alice),
            (dev(2), [0; 32], alice),
            (dev(3), [0; 32], bob),
            (dev(4), [0; 32], bob),
        ]);
        // Alice's device 1 to Bob (both devices) and her own other device: complete.
        assert_eq!(
            dir.check_devices(&dev(1), &[dev(3), dev(4), dev(2)]),
            Ok(())
        );
        // Not syncing to her own devices is allowed (her account is not addressed).
        assert_eq!(dir.check_devices(&dev(1), &[dev(3), dev(4)]), Ok(()));
        // Bob's device 4 left out, an unknown device added.
        let m = dir.check_devices(&dev(1), &[dev(3), dev(9)]).unwrap_err();
        assert_eq!(m.missing, vec![dev(4)]);
        assert_eq!(m.extra, vec![dev(9)]);
        // Large sends use sets and give the same answer.
        let mut many: Vec<DeviceId> = (100..200).map(dev).collect();
        many.push(dev(3));
        let m = dir.check_devices(&dev(1), &many).unwrap_err();
        assert_eq!(m.missing, vec![dev(4)]);
        assert_eq!(m.extra.len(), 100);
    }

    #[test]
    fn pending_devices_authenticate_but_are_not_recipients() {
        let bob = AccountId::from_bytes([0xB; 16]);
        let alice = AccountId::from_bytes([0xA; 16]);
        let dir = Directory::from_accounts([
            (dev(1), [0; 32], alice),
            (dev(3), [0; 32], bob),
            (dev(4), [0; 32], bob),
        ])
        .with_pending([dev(4), dev(9)]);
        // Still known (it authenticates), but no one must encrypt to it.
        assert!(dir.contains(&dev(4)));
        assert_eq!(dir.check_devices(&dev(1), &[dev(3)]), Ok(()));
        // Addressing it is refused as extra, as for a device that does not exist.
        let m = dir.check_devices(&dev(1), &[dev(3), dev(4)]).unwrap_err();
        assert_eq!(m.extra, vec![dev(4)]);
        assert_eq!(m.missing, Vec::<DeviceId>::new());
        // The pending device itself may send to its account's listed devices.
        assert_eq!(dir.check_devices(&dev(4), &[dev(3)]), Ok(()));
    }
}
