//! Records and the manifest: their plaintext, padding and encryption (PROTOCOL §10.1).
//!
//! # Keys
//!
//! The account's 32-byte **storage key** is held only by its devices (a linked device gets it in
//! the provisioning message, version 2). From it:
//!
//! - `key_id = HMAC-SHA256(storage key, "songbird.v1/storage-key-id")[..8]`, in the clear in
//!   the manifest, so a device holding an older key knows it must wait for the new one;
//! - a record's key: `HKDF-SHA256(salt = "songbird.v1/storage", ikm = storage key,
//!   info = "record\0" ‖ id)`, 32 bytes, AES-256-GCM-SIV with a zero nonce (one key per record,
//!   and a record is never rewritten under its ID), AAD `"songbird.v1/storage-record\0" ‖ id`;
//! - the manifest's key: the same HKDF with `info = "manifest"`, AES-256-GCM-SIV with a random
//!   nonce, AAD `"songbird.v1/storage-manifest\0" ‖ key_id`.
//!
//! # Record plaintext
//!
//! `be32(len) ‖ RecordPlain (protobuf) ‖ zeros`, to the Padmé length of [`MIN_RECORD_PADDED`] to
//! [`MAX_RECORD_PADDED`] bytes (`songbird_proto::storage`). `RecordPlain` carries the logical
//! key, the stamp, whether it is a tombstone, and the value.
//!
//! # Manifest
//!
//! `key_id [8] ‖ nonce [12] ‖ AES-256-GCM-SIV(version u64 ‖ digest [32]) ‖ tag [16]` (76 bytes),
//! where `digest = SHA-256("songbird.v1/storage-ids\0" ‖ sorted IDs)` and `version` is the store
//! version the manifest was written at.

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::{digest, hkdf, hmac};
use prost::Message as _;
use songbird_proto::storage::{ID_LEN, MAX_RECORD_PADDED, TAG_LEN, record_padded_len};
use zeroize::{Zeroize as _, Zeroizing};

use crate::SyncError;
use crate::hlc::Hlc;

/// Longest logical key.
pub const MAX_KEY: usize = 256;
/// Largest value inside a record (what is left of the padded plaintext after the frame).
pub const MAX_VALUE: usize = MAX_RECORD_PADDED - 4 - MAX_KEY - 64;
/// Manifest ciphertext length.
pub const MANIFEST_LEN: usize = 8 + NONCE_LEN + 8 + 32 + TAG_LEN;

const RECORD_AAD: &[u8] = b"songbird.v1/storage-record\0";
const MANIFEST_AAD: &[u8] = b"songbird.v1/storage-manifest\0";
const IDS_CONTEXT: &[u8] = b"songbird.v1/storage-ids\0";

/// The account's storage key. Wiped when dropped.
#[derive(Clone)]
pub struct StorageKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageKey(..)")
    }
}

impl StorageKey {
    /// Wraps 32 bytes.
    #[must_use]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// A fresh random key.
    ///
    /// # Errors
    /// [`SyncError::Random`].
    pub fn generate() -> Result<Self, SyncError> {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(b.as_mut()).map_err(|_| SyncError::Random)?;
        Ok(Self(b))
    }

    /// The key bytes (for the provisioning message).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key's public identifier.
    #[must_use]
    pub fn id(&self) -> [u8; 8] {
        let k = hmac::Key::new(hmac::HMAC_SHA256, self.0.as_ref());
        let tag = hmac::sign(&k, b"songbird.v1/storage-key-id");
        let mut id = [0u8; 8];
        id.copy_from_slice(tag.as_ref().get(..8).unwrap_or(&[0; 8]));
        id
    }

    fn derive(&self, info: &[&[u8]]) -> Result<LessSafeKey, SyncError> {
        let mut k = Zeroizing::new([0u8; 32]);
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1/storage")
            .extract(self.0.as_ref())
            .expand(info, hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(k.as_mut()))
            .map_err(|_| SyncError::Crypto)?;
        let u = UnboundKey::new(&AES_256_GCM_SIV, k.as_ref()).map_err(|_| SyncError::Crypto)?;
        Ok(LessSafeKey::new(u))
    }
}

/// A record's plaintext.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecordPlain {
    /// The logical key (`s/theme`, `c/<chat>/mute`, `k/<contact>`; PROTOCOL §10.2).
    #[prost(string, tag = "1")]
    pub key: String,
    /// The stamp's wall time.
    #[prost(uint64, tag = "2")]
    pub wall_ms: u64,
    /// The stamp's counter.
    #[prost(uint32, tag = "3")]
    pub counter: u32,
    /// The stamp's node (16 bytes).
    #[prost(bytes = "vec", tag = "4")]
    pub node: Vec<u8>,
    /// A tombstone: the key was deleted.
    #[prost(bool, tag = "5")]
    pub deleted: bool,
    /// The value (empty for a tombstone).
    #[prost(bytes = "vec", tag = "6")]
    pub value: Vec<u8>,
}

impl RecordPlain {
    /// A record for `key` at `hlc`.
    #[must_use]
    pub fn new(key: &str, hlc: Hlc, value: Option<Vec<u8>>) -> Self {
        Self {
            key: key.to_owned(),
            wall_ms: hlc.wall_ms,
            counter: hlc.counter,
            node: hlc.node.to_vec(),
            deleted: value.is_none(),
            value: value.unwrap_or_default(),
        }
    }

    /// Its stamp.
    #[must_use]
    pub fn hlc(&self) -> Hlc {
        let mut node = [0u8; 16];
        if let Some(n) = self.node.get(..16) {
            node.copy_from_slice(n);
        }
        Hlc {
            wall_ms: self.wall_ms,
            counter: self.counter,
            node,
        }
    }

    fn check(&self) -> Result<(), SyncError> {
        if self.key.is_empty()
            || self.key.len() > MAX_KEY
            || self.node.len() != 16
            || self.value.len() > MAX_VALUE
            || (self.deleted && !self.value.is_empty())
        {
            return Err(SyncError::Malformed);
        }
        Ok(())
    }
}

/// Encrypts a record under a fresh random ID.
///
/// # Errors
/// [`SyncError::Malformed`] for a key or value too long; [`SyncError::Random`];
/// [`SyncError::Crypto`].
pub fn seal_record(
    key: &StorageKey,
    plain: &RecordPlain,
) -> Result<([u8; ID_LEN], Vec<u8>), SyncError> {
    plain.check()?;
    let mut id = [0u8; ID_LEN];
    getrandom::fill(&mut id).map_err(|_| SyncError::Random)?;
    let body = plain.encode_to_vec();
    let framed = 4 + body.len();
    let padded = record_padded_len(framed).ok_or(SyncError::Malformed)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(padded + TAG_LEN));
    buf.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| SyncError::Malformed)?
            .to_be_bytes(),
    );
    buf.extend_from_slice(&body);
    buf.resize(padded, 0);
    let k = key.derive(&[b"record\0", &id])?;
    let mut out = buf.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; NONCE_LEN]),
        Aad::from(record_aad(&id)),
        &mut out,
    )
    .map_err(|_| SyncError::Crypto)?;
    let mut body = body;
    body.zeroize();
    Ok((id, out))
}

fn record_aad(id: &[u8; ID_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(RECORD_AAD.len() + ID_LEN);
    a.extend_from_slice(RECORD_AAD);
    a.extend_from_slice(id);
    a
}

/// Opens a record.
///
/// # Errors
/// [`SyncError::Tampered`] if it does not open under this key and ID (the server changed it, or
/// moved it to another ID); [`SyncError::Malformed`] for a bad frame.
pub fn open_record(
    key: &StorageKey,
    id: &[u8; ID_LEN],
    blob: &[u8],
) -> Result<RecordPlain, SyncError> {
    let k = key.derive(&[b"record\0", id])?;
    let mut buf = Zeroizing::new(blob.to_vec());
    let plain = k
        .open_in_place(
            Nonce::assume_unique_for_key([0; NONCE_LEN]),
            Aad::from(record_aad(id)),
            &mut buf,
        )
        .map_err(|_| SyncError::Tampered)?;
    let (len, rest) = plain.split_first_chunk::<4>().ok_or(SyncError::Malformed)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| SyncError::Malformed)?;
    let body = rest.get(..len).ok_or(SyncError::Malformed)?;
    if rest.get(len..).is_some_and(|z| z.iter().any(|b| *b != 0)) {
        return Err(SyncError::Malformed);
    }
    let r = RecordPlain::decode(body).map_err(|_| SyncError::Malformed)?;
    r.check()?;
    Ok(r)
}

/// The digest of a set of record IDs (any order).
#[must_use]
pub fn ids_digest(ids: &[[u8; ID_LEN]]) -> [u8; 32] {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(IDS_CONTEXT);
    for i in &sorted {
        ctx.update(i);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// A manifest's plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Manifest {
    /// The store version it was written at.
    pub version: u64,
    /// [`ids_digest`] of the store's IDs at that version.
    pub digest: [u8; 32],
}

fn manifest_aad(key_id: [u8; 8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(MANIFEST_AAD.len() + 8);
    a.extend_from_slice(MANIFEST_AAD);
    a.extend_from_slice(&key_id);
    a
}

/// Encrypts a manifest.
///
/// # Errors
/// [`SyncError::Random`]; [`SyncError::Crypto`].
pub fn seal_manifest(key: &StorageKey, m: &Manifest) -> Result<Vec<u8>, SyncError> {
    let id = key.id();
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SyncError::Random)?;
    let mut body = Vec::with_capacity(8 + 32 + TAG_LEN);
    body.extend_from_slice(&m.version.to_be_bytes());
    body.extend_from_slice(&m.digest);
    key.derive(&[b"manifest"])?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(manifest_aad(id)),
            &mut body,
        )
        .map_err(|_| SyncError::Crypto)?;
    let mut out = Vec::with_capacity(MANIFEST_LEN);
    out.extend_from_slice(&id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a manifest.
///
/// # Errors
/// [`SyncError::KeyChanged`] if another storage key wrote it (the account rotated its key);
/// [`SyncError::Tampered`] if it does not open.
pub fn open_manifest(key: &StorageKey, blob: &[u8]) -> Result<Manifest, SyncError> {
    if blob.len() != MANIFEST_LEN {
        return Err(SyncError::Tampered);
    }
    let (id, rest) = blob.split_first_chunk::<8>().ok_or(SyncError::Tampered)?;
    if *id != key.id() {
        return Err(SyncError::KeyChanged);
    }
    let (nonce, ct) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(SyncError::Tampered)?;
    let mut buf = ct.to_vec();
    let plain = key
        .derive(&[b"manifest"])?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(manifest_aad(*id)),
            &mut buf,
        )
        .map_err(|_| SyncError::Tampered)?;
    let (v, d) = plain.split_first_chunk::<8>().ok_or(SyncError::Tampered)?;
    let digest: [u8; 32] = d.try_into().map_err(|_| SyncError::Tampered)?;
    Ok(Manifest {
        version: u64::from_be_bytes(*v),
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use songbird_proto::storage::valid_record_len;

    fn key(b: u8) -> StorageKey {
        StorageKey::from_bytes([b; 32])
    }

    #[test]
    fn records_round_trip_padded_to_a_length_the_server_accepts() {
        let k = key(1);
        let hlc = Hlc {
            wall_ms: 5,
            counter: 1,
            node: [2; 16],
        };
        for n in [0usize, 1, 100, 1_000, MAX_VALUE] {
            let p = RecordPlain::new("s/theme", hlc, Some(vec![7; n]));
            let (id, blob) = seal_record(&k, &p).unwrap_or_else(|_| ([0; 16], Vec::new()));
            assert!(valid_record_len(blob.len()), "{n} -> {}", blob.len());
            assert_eq!(open_record(&k, &id, &blob).ok(), Some(p));
        }
        let too_big = RecordPlain::new("s/x", hlc, Some(vec![0; MAX_VALUE + 1]));
        assert!(seal_record(&k, &too_big).is_err());
    }

    #[test]
    fn a_record_moved_changed_or_under_another_key_does_not_open() {
        let k = key(1);
        let p = RecordPlain::new("s/a", Hlc::default(), Some(b"v".to_vec()));
        let Ok((id, blob)) = seal_record(&k, &p) else {
            panic!("seal")
        };
        assert_eq!(open_record(&k, &[9; 16], &blob), Err(SyncError::Tampered));
        assert_eq!(open_record(&key(2), &id, &blob), Err(SyncError::Tampered));
        let mut bad = blob;
        if let Some(b) = bad.get_mut(3) {
            *b ^= 1;
        }
        assert_eq!(open_record(&k, &id, &bad), Err(SyncError::Tampered));
    }

    #[test]
    fn manifests_round_trip_and_name_their_key() {
        let m = Manifest {
            version: 4,
            digest: ids_digest(&[[1; 16], [2; 16]]),
        };
        assert_eq!(ids_digest(&[[2; 16], [1; 16]]), m.digest);
        let Ok(b) = seal_manifest(&key(1), &m) else {
            panic!("seal")
        };
        assert_eq!(b.len(), MANIFEST_LEN);
        assert_eq!(open_manifest(&key(1), &b), Ok(m));
        assert_eq!(open_manifest(&key(2), &b), Err(SyncError::KeyChanged));
        let mut bad = b;
        if let Some(x) = bad.last_mut() {
            *x ^= 1;
        }
        assert_eq!(open_manifest(&key(1), &bad), Err(SyncError::Tampered));
    }
}
