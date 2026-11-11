//! Device directory: which devices exist and their authentication keys.
//!
//! Milestone 1 loads a static file (development and CI only; refused in staging and production
//! by configuration validation). The identity service (Prompt 3) replaces it with SurrealDB.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use songbird_proto::PUBLIC_KEY_LEN;
use songbird_types::DeviceId;

/// Largest directory file accepted (checked before reading).
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

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
}

/// Known devices and their Ed25519 authentication public keys.
#[derive(Default)]
pub struct Directory {
    keys: HashMap<DeviceId, [u8; PUBLIC_KEY_LEN]>,
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("devices", &self.keys.len())
            .finish()
    }
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
        let mut keys = HashMap::with_capacity(file.devices.len());
        for (i, e) in file.devices.iter().enumerate() {
            let id = DeviceId::parse_hex(&e.id).map_err(|_| DirectoryError::Entry(i))?;
            let mut key = [0u8; PUBLIC_KEY_LEN];
            hex::decode_to_slice(&e.auth_key, &mut key).map_err(|_| DirectoryError::Entry(i))?;
            if keys.insert(id, key).is_some() {
                return Err(DirectoryError::Entry(i));
            }
        }
        Ok(Self { keys })
    }

    /// Builds a directory from known keys (tests, load generator).
    #[must_use]
    pub fn from_keys(keys: impl IntoIterator<Item = (DeviceId, [u8; PUBLIC_KEY_LEN])>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// Number of devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether `device` exists.
    #[must_use]
    pub fn contains(&self, device: &DeviceId) -> bool {
        self.keys.contains_key(device)
    }

    /// Whether `signature` over `msg` verifies under `device`'s key. An unknown device and a bad
    /// signature are indistinguishable to the caller (no device-existence oracle).
    #[must_use]
    pub fn verify(&self, device: &DeviceId, msg: &[u8], signature: &[u8]) -> bool {
        // Verify against a fixed dummy key for unknown devices so both paths cost the same.
        const DUMMY: [u8; PUBLIC_KEY_LEN] = [0x5a; PUBLIC_KEY_LEN];
        let (key, known) = self.keys.get(device).map_or((&DUMMY, false), |k| (k, true));
        let ok = UnparsedPublicKey::new(&ED25519, key)
            .verify(msg, signature)
            .is_ok();
        ok && known
    }
}

/// Renders a directory file (used by the load generator and tests).
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

    #[test]
    fn verifies_known_devices_only() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(pair.public_key().as_ref());
        let dev = DeviceId::from_bytes([1; 16]);
        let dir = Directory::parse(&render(&[(dev, pk)])).unwrap();
        assert_eq!(dir.len(), 1);
        let sig = pair.sign(b"msg");
        assert!(dir.verify(&dev, b"msg", sig.as_ref()));
        assert!(!dir.verify(&dev, b"other", sig.as_ref()));
        assert!(!dir.verify(&DeviceId::from_bytes([2; 16]), b"msg", sig.as_ref()));
        assert!(!dir.verify(&dev, b"msg", &[0; 64]));
    }

    #[test]
    fn rejects_bad_files_without_echoing_them() {
        assert!(matches!(
            Directory::parse("devices = 3"),
            Err(DirectoryError::Malformed)
        ));
        let e = Directory::parse("[[devices]]\nid = \"zz\"\nauth_key = \"00\"\n").unwrap_err();
        assert_eq!(e.to_string(), "device directory entry 0 is invalid");
        let dup = render(&[
            (DeviceId::from_bytes([1; 16]), [0; 32]),
            (DeviceId::from_bytes([1; 16]), [1; 32]),
        ]);
        assert!(matches!(
            Directory::parse(&dup),
            Err(DirectoryError::Entry(1))
        ));
    }
}
