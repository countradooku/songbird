//! The recovery key and every key derived from it (PROTOCOL §11.1).
//!
//! A recovery key is 64 characters of Crockford base32: 320 bits holding a 256-bit secret and a
//! 64-bit check, shown as 16 groups of 4. Reading one ignores case, spaces and dashes and reads
//! `I` and `L` as `1` and `O` as `0`, so a key copied by hand still parses; a typo fails the check
//! on the device, before any request.
//!
//! Every backup key comes from the secret by HKDF-SHA256 (salt `"songbird.v1/backup"`, info
//! `"songbird.v1/backup/" || label`):
//!
//! | Label | Bytes | Use |
//! | --- | --- | --- |
//! | `vault-id` | 32 | Where the backup is, on any store |
//! | `vault-access` | 32 | The Songbird vault's bearer secret (it stores only a hash) |
//! | `manifest` | 32 | XChaCha20-Poly1305 key of manifests |
//! | `chunk` | 32 | XChaCha20-Poly1305 key of chunks |
//! | `chunk-name` | 32 | HMAC-SHA256 key naming chunks and media |
//! | `chunker` | 2,048 | The chunker's gear table (256 big-endian `u64`) |

use std::fmt;

use aws_lc_rs::{digest, hkdf};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{Error, Rng};

/// Crockford's base32 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters in a recovery key.
pub const KEY_CHARS: usize = 64;
/// Bytes of secret in a recovery key.
pub const SECRET_LEN: usize = 32;
/// Bytes of check in a recovery key.
const CHECK_LEN: usize = 8;
const CHECK_CONTEXT: &[u8] = b"songbird.v1/recovery-key\0";
const SALT: &[u8] = b"songbird.v1/backup";
const INFO_PREFIX: &[u8] = b"songbird.v1/backup/";

/// A recovery key: the 256-bit secret. `Debug` never shows it; it is wiped when dropped.
#[derive(Clone)]
pub struct RecoveryKey(Zeroizing<[u8; SECRET_LEN]>);

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

impl PartialEq for RecoveryKey {
    fn eq(&self, other: &Self) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(self.0.as_ref(), other.0.as_ref()).is_ok()
    }
}
impl Eq for RecoveryKey {}

fn check(secret: &[u8; SECRET_LEN]) -> [u8; CHECK_LEN] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(CHECK_CONTEXT);
    ctx.update(secret);
    let d = ctx.finish();
    let mut out = [0u8; CHECK_LEN];
    out.copy_from_slice(d.as_ref().split_at(CHECK_LEN).0);
    out
}

fn symbol(c: char) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    let c = match c {
        'I' | 'L' => '1',
        'O' => '0',
        c => c,
    };
    let b = u8::try_from(u32::from(c)).ok()?;
    ALPHABET
        .iter()
        .position(|&a| a == b)
        .and_then(|p| u8::try_from(p).ok())
}

impl RecoveryKey {
    /// A new random key.
    ///
    /// # Errors
    /// The random source failed.
    pub fn generate(rng: &mut dyn Rng) -> Result<Self, Error> {
        let mut s = Zeroizing::new([0u8; SECRET_LEN]);
        rng.fill(s.as_mut())?;
        Ok(Self(s))
    }

    /// The key holding exactly this secret (vectors, and keys sent inside a transfer).
    #[must_use]
    pub fn from_secret(secret: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(secret))
    }

    /// The secret.
    #[must_use]
    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// Reads a key as a person typed it.
    ///
    /// # Errors
    /// [`Error::KeyCharacter`] for a character outside the alphabet, [`Error::KeyLength`] for
    /// anything but 64 symbols, [`Error::KeyCheck`] when the check does not match (a typo).
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut bits = Zeroizing::new([0u8; SECRET_LEN + CHECK_LEN]);
        let mut n = 0usize;
        for c in text.chars() {
            if c.is_whitespace() || c == '-' {
                continue;
            }
            let v = symbol(c).ok_or(Error::KeyCharacter)?;
            if n >= KEY_CHARS {
                return Err(Error::KeyLength);
            }
            // Symbol n covers bits 5n..5n+5, most significant first.
            for k in 0..5 {
                if v & (0x10 >> k) != 0 {
                    let bit = n * 5 + k;
                    if let Some(byte) = bits.get_mut(bit / 8) {
                        *byte |= 0x80 >> (bit % 8);
                    }
                }
            }
            n += 1;
        }
        if n != KEY_CHARS {
            return Err(Error::KeyLength);
        }
        let (head, given) = bits.split_at(SECRET_LEN);
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(head);
        if aws_lc_rs::constant_time::verify_slices_are_equal(given, &check(&secret)).is_err() {
            return Err(Error::KeyCheck);
        }
        Ok(Self(secret))
    }

    /// The 64 characters, without separators.
    #[must_use]
    pub fn to_chars(&self) -> Zeroizing<String> {
        let mut bits = Zeroizing::new([0u8; SECRET_LEN + CHECK_LEN]);
        let (secret, tail) = bits.split_at_mut(SECRET_LEN);
        secret.copy_from_slice(self.0.as_ref());
        tail.copy_from_slice(&check(&self.0));
        let mut out = Zeroizing::new(String::with_capacity(KEY_CHARS));
        for n in 0..KEY_CHARS {
            let mut v = 0usize;
            for k in 0..5 {
                let bit = n * 5 + k;
                let set = bits
                    .get(bit / 8)
                    .is_some_and(|b| b & (0x80 >> (bit % 8)) != 0);
                v = (v << 1) | usize::from(set);
            }
            out.push(char::from(ALPHABET.get(v).copied().unwrap_or(b'0')));
        }
        out
    }

    /// The 16 groups of four, as the app shows them.
    #[must_use]
    pub fn groups(&self) -> Vec<Zeroizing<String>> {
        let chars = self.to_chars();
        chars
            .as_bytes()
            .chunks(4)
            .map(|g| Zeroizing::new(String::from_utf8_lossy(g).into_owned()))
            .collect()
    }

    /// The groups joined by dashes (`XXXX-XXXX-…`).
    #[must_use]
    pub fn display(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(KEY_CHARS + 15));
        for (i, g) in self.groups().iter().enumerate() {
            if i > 0 {
                s.push('-');
            }
            s.push_str(g);
        }
        s
    }

    /// Every key derived from this one.
    ///
    /// # Errors
    /// [`Error::Crypto`] if HKDF refuses a length (never for these).
    pub fn derive(&self) -> Result<BackupKeys, Error> {
        BackupKeys::derive(&self.0)
    }
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &hkdf::Prk, label: &str, out: &mut [u8]) -> Result<(), Error> {
    let info = [INFO_PREFIX, label.as_bytes()];
    prk.expand(&info, Len(out.len()))
        .and_then(|o| o.fill(out))
        .map_err(|_| Error::Crypto)
}

/// A 32-byte key that is wiped when dropped and never printed.
pub type Key32 = Zeroizing<[u8; 32]>;

/// Every key of one backup. `Debug` shows only the vault ID's first bytes.
#[derive(Clone)]
pub struct BackupKeys {
    /// Where the backup is (not secret from the store, but derived from the secret).
    pub vault_id: [u8; 32],
    /// The Songbird vault's bearer secret.
    pub vault_access: Key32,
    /// Manifest encryption key.
    pub manifest: Key32,
    /// Chunk encryption key.
    pub chunk: Key32,
    /// HMAC key naming chunks and media.
    pub chunk_name: Key32,
    /// The chunker's gear table.
    pub gear: Box<[u64; 256]>,
}

impl fmt::Debug for BackupKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupKeys").finish_non_exhaustive()
    }
}

impl Drop for BackupKeys {
    fn drop(&mut self) {
        self.gear.as_mut_slice().zeroize();
    }
}

impl BackupKeys {
    fn derive(secret: &[u8; SECRET_LEN]) -> Result<Self, Error> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(secret);
        let mut vault_id = [0u8; 32];
        expand(&prk, "vault-id", &mut vault_id)?;
        let mut keys = [
            Zeroizing::new([0u8; 32]),
            Zeroizing::new([0u8; 32]),
            Zeroizing::new([0u8; 32]),
            Zeroizing::new([0u8; 32]),
        ];
        for (k, label) in keys
            .iter_mut()
            .zip(["vault-access", "manifest", "chunk", "chunk-name"])
        {
            expand(&prk, label, k.as_mut())?;
        }
        let mut raw = Zeroizing::new([0u8; 2048]);
        expand(&prk, "chunker", raw.as_mut())?;
        let mut gear = Box::new([0u64; 256]);
        for (g, w) in gear.iter_mut().zip(raw.as_chunks::<8>().0) {
            *g = u64::from_be_bytes(*w);
        }
        let [vault_access, manifest, chunk, chunk_name] = keys;
        Ok(Self {
            vault_id,
            vault_access,
            manifest,
            chunk,
            chunk_name,
            gear,
        })
    }

    /// What the Songbird vault stores in place of the access secret:
    /// `SHA-256("songbird.v1/vault-access\0" || vault_access)`.
    #[must_use]
    pub fn access_hash(&self) -> [u8; 32] {
        access_hash(&self.vault_access)
    }
}

/// `SHA-256("songbird.v1/vault-access\0" || secret)`, the hash the vault keeps.
#[must_use]
pub fn access_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(songbird_proto::vault::ACCESS_CONTEXT);
    ctx.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}
