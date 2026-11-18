//! The account record store (`docs/PROTOCOL.md` §10.1; Prompt 9, M1; D-0101, D-0102).
//!
//! An account's settings, chat preferences and contacts are encrypted records the server stores
//! opaque, under random 16-byte IDs it never chose. A record is never changed in place: a new
//! value is a new record under a fresh ID and the old ID is deleted, so the set of IDs names the
//! account's whole state. A small encrypted manifest, written in the same compare-and-swap, holds
//! a digest of that set, so a device notices a record withheld, replayed or rolled back.
//!
//! The server checks only lengths: a record's ciphertext must be a Padmé-padded plaintext of
//! [`MIN_RECORD_PADDED`] to [`MAX_RECORD_PADDED`] bytes plus the 16-byte tag
//! ([`valid_record_len`]), so no client can leak a record's exact size.
//!
//! # Head (`GET /v1/storage`)
//!
//! ```text
//! version u64 | mlen u16 | manifest (0 when the store is empty, else 16..=256)
//! ```
//!
//! # IDs (`GET /v1/storage/ids`)
//!
//! ```text
//! version u64 | n u32 | id [16] * n
//! ```
//!
//! # Read (`POST /v1/storage/read`)
//!
//! ```text
//! request:  n u16 (1..=1024) | id [16] * n
//! answer:   n u16 | (id [16] | len u16 | record) * n      (IDs that no longer exist are left out)
//! ```
//!
//! # Write (`PUT /v1/storage`)
//!
//! ```text
//! version u8 (1) | expected u64 | mlen u16 | manifest (16..=256)
//!   | ndel u32 | id [16] * ndel | nins u32 | (id [16] | len u16 | record) * nins
//! ```
//!
//! The store moves from `expected` to `expected + 1` atomically, or not at all (409 with the
//! current version).

use crate::media::padme;

/// Format version of the write body.
pub const VERSION: u8 = 1;
/// Record ID length.
pub const ID_LEN: usize = 16;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Smallest padded record plaintext.
/// Small settings records (most of them) all share this one size.
pub const MIN_RECORD_PADDED: usize = 256;
/// Largest padded record plaintext.
pub const MAX_RECORD_PADDED: usize = 4096;
/// Largest record ciphertext.
pub const MAX_RECORD: usize = MAX_RECORD_PADDED + TAG_LEN;
/// Smallest manifest ciphertext.
pub const MIN_MANIFEST: usize = 16;
/// Largest manifest ciphertext.
pub const MAX_MANIFEST: usize = 256;
/// Most IDs one read asks for.
pub const MAX_READ: usize = 1024;
/// Most deletions and most insertions one write may carry (each). A key rotation rewrites every
/// record in one write, so this is the per-account record cap's ceiling.
pub const MAX_CHANGES: usize = 20_000;
/// Largest storage object (a custom wallpaper, encrypted).
pub const MAX_OBJECT: usize = 2 * 1024 * 1024;

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed storage message")]
pub struct StorageError;

/// Whether `len` is a record ciphertext length the format produces.
#[must_use]
pub fn valid_record_len(len: usize) -> bool {
    let Some(padded) = len.checked_sub(TAG_LEN) else {
        return false;
    };
    (MIN_RECORD_PADDED..=MAX_RECORD_PADDED).contains(&padded)
        && u64::try_from(padded).is_ok_and(|p| padme(p) == p)
}

/// The padded plaintext length for a record plaintext of `n` bytes, if it fits.
#[must_use]
pub fn record_padded_len(n: usize) -> Option<usize> {
    let p = padme(u64::try_from(n.max(MIN_RECORD_PADDED)).ok()?);
    let p = usize::try_from(p).ok()?;
    (p <= MAX_RECORD_PADDED).then_some(p)
}

/// One stored record.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// Its random ID.
    pub id: [u8; ID_LEN],
    /// Its ciphertext.
    pub blob: Vec<u8>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("blob", &self.blob.len())
            .finish_non_exhaustive()
    }
}

/// A write: compare-and-swap from `expected`.
#[derive(Clone, PartialEq, Eq)]
pub struct Write {
    /// The version the writer last saw.
    pub expected: u64,
    /// The new encrypted manifest.
    pub manifest: Vec<u8>,
    /// Records to delete.
    pub deletes: Vec<[u8; ID_LEN]>,
    /// Records to insert (fresh IDs).
    pub inserts: Vec<Record>,
}

impl std::fmt::Debug for Write {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Write")
            .field("expected", &self.expected)
            .field("deletes", &self.deletes.len())
            .field("inserts", &self.inserts.len())
            .finish_non_exhaustive()
    }
}

fn be_u16(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

fn be_u32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

/// A bounds-checked reader.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StorageError> {
        if self.0.len() < n {
            return Err(StorageError);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, StorageError> {
        Ok(*self.take(1)?.first().ok_or(StorageError)?)
    }
    fn u16(&mut self) -> Result<usize, StorageError> {
        let b: [u8; 2] = self.take(2)?.try_into().map_err(|_| StorageError)?;
        Ok(usize::from(u16::from_be_bytes(b)))
    }
    fn u32(&mut self) -> Result<usize, StorageError> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| StorageError)?;
        usize::try_from(u32::from_be_bytes(b)).map_err(|_| StorageError)
    }
    fn u64(&mut self) -> Result<u64, StorageError> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| StorageError)?;
        Ok(u64::from_be_bytes(b))
    }
    fn id(&mut self) -> Result<[u8; ID_LEN], StorageError> {
        self.take(ID_LEN)?.try_into().map_err(|_| StorageError)
    }
    fn end(&self) -> Result<(), StorageError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(StorageError)
        }
    }
}

impl Write {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(
            1 + 8
                + 2
                + self.manifest.len()
                + 4
                + self.deletes.len() * ID_LEN
                + 4
                + self
                    .inserts
                    .iter()
                    .map(|r| ID_LEN + 2 + r.blob.len())
                    .sum::<usize>(),
        );
        b.push(VERSION);
        b.extend_from_slice(&self.expected.to_be_bytes());
        b.extend_from_slice(&be_u16(self.manifest.len()));
        b.extend_from_slice(&self.manifest);
        b.extend_from_slice(&be_u32(self.deletes.len()));
        for d in &self.deletes {
            b.extend_from_slice(d);
        }
        b.extend_from_slice(&be_u32(self.inserts.len()));
        for r in &self.inserts {
            b.extend_from_slice(&r.id);
            b.extend_from_slice(&be_u16(r.blob.len()));
            b.extend_from_slice(&r.blob);
        }
        b
    }

    /// Decodes the whole input: every count is checked against the bytes left before anything
    /// is allocated, every record length must be one the format produces, and no ID may appear
    /// twice (among deletions, among insertions, or in both).
    ///
    /// # Errors
    /// [`StorageError`].
    pub fn decode(input: &[u8]) -> Result<Self, StorageError> {
        let mut r = Reader(input);
        if r.u8()? != VERSION {
            return Err(StorageError);
        }
        let expected = r.u64()?;
        let mlen = r.u16()?;
        if !(MIN_MANIFEST..=MAX_MANIFEST).contains(&mlen) {
            return Err(StorageError);
        }
        let manifest = r.take(mlen)?.to_vec();
        let ndel = r.u32()?;
        if ndel > MAX_CHANGES || ndel.saturating_mul(ID_LEN) > r.0.len() {
            return Err(StorageError);
        }
        let mut deletes = Vec::with_capacity(ndel);
        for _ in 0..ndel {
            deletes.push(r.id()?);
        }
        let nins = r.u32()?;
        // Each insertion takes at least its ID, its length and the smallest record.
        let min_ins = ID_LEN + 2 + MIN_RECORD_PADDED + TAG_LEN;
        if nins > MAX_CHANGES || nins.saturating_mul(min_ins) > r.0.len() {
            return Err(StorageError);
        }
        let mut inserts = Vec::with_capacity(nins);
        for _ in 0..nins {
            let id = r.id()?;
            let len = r.u16()?;
            if !valid_record_len(len) {
                return Err(StorageError);
            }
            inserts.push(Record {
                id,
                blob: r.take(len)?.to_vec(),
            });
        }
        r.end()?;
        let mut all: Vec<[u8; ID_LEN]> = deletes
            .iter()
            .copied()
            .chain(inserts.iter().map(|x| x.id))
            .collect();
        all.sort_unstable();
        if all.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(StorageError);
        }
        Ok(Self {
            expected,
            manifest,
            deletes,
            inserts,
        })
    }
}

/// The store's head: its version and manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct Head {
    /// The store's version (0 before the first write).
    pub version: u64,
    /// The encrypted manifest (empty before the first write).
    pub manifest: Vec<u8>,
}

impl std::fmt::Debug for Head {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Head")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Head {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + 2 + self.manifest.len());
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&be_u16(self.manifest.len()));
        b.extend_from_slice(&self.manifest);
        b
    }

    /// Decodes the whole input.
    ///
    /// # Errors
    /// [`StorageError`].
    pub fn decode(input: &[u8]) -> Result<Self, StorageError> {
        let mut r = Reader(input);
        let version = r.u64()?;
        let mlen = r.u16()?;
        if mlen != 0 && !(MIN_MANIFEST..=MAX_MANIFEST).contains(&mlen) {
            return Err(StorageError);
        }
        let manifest = r.take(mlen)?.to_vec();
        r.end()?;
        Ok(Self { version, manifest })
    }
}

/// Every record ID of the store, at a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ids {
    /// The store's version.
    pub version: u64,
    /// The IDs (any order).
    pub ids: Vec<[u8; ID_LEN]>,
}

impl Ids {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + 4 + self.ids.len() * ID_LEN);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&be_u32(self.ids.len()));
        for i in &self.ids {
            b.extend_from_slice(i);
        }
        b
    }

    /// Decodes the whole input.
    ///
    /// # Errors
    /// [`StorageError`].
    pub fn decode(input: &[u8]) -> Result<Self, StorageError> {
        let mut r = Reader(input);
        let version = r.u64()?;
        let n = r.u32()?;
        if n.saturating_mul(ID_LEN) != r.0.len() {
            return Err(StorageError);
        }
        let mut ids = Vec::with_capacity(n);
        for _ in 0..n {
            ids.push(r.id()?);
        }
        r.end()?;
        Ok(Self { version, ids })
    }
}

/// A read request.
///
/// # Errors
/// [`StorageError`] for none or more than [`MAX_READ`] IDs.
pub fn encode_read(ids: &[[u8; ID_LEN]]) -> Result<Vec<u8>, StorageError> {
    if ids.is_empty() || ids.len() > MAX_READ {
        return Err(StorageError);
    }
    let mut b = Vec::with_capacity(2 + ids.len() * ID_LEN);
    b.extend_from_slice(&be_u16(ids.len()));
    for i in ids {
        b.extend_from_slice(i);
    }
    Ok(b)
}

/// Decodes a read request.
///
/// # Errors
/// [`StorageError`].
pub fn decode_read(input: &[u8]) -> Result<Vec<[u8; ID_LEN]>, StorageError> {
    let mut r = Reader(input);
    let n = r.u16()?;
    if n == 0 || n > MAX_READ || n * ID_LEN != r.0.len() {
        return Err(StorageError);
    }
    let mut ids = Vec::with_capacity(n);
    for _ in 0..n {
        ids.push(r.id()?);
    }
    r.end()?;
    Ok(ids)
}

/// A read answer.
#[must_use]
pub fn encode_records(records: &[Record]) -> Vec<u8> {
    let mut b = Vec::with_capacity(
        2 + records
            .iter()
            .map(|r| ID_LEN + 2 + r.blob.len())
            .sum::<usize>(),
    );
    b.extend_from_slice(&be_u16(records.len()));
    for r in records {
        b.extend_from_slice(&r.id);
        b.extend_from_slice(&be_u16(r.blob.len()));
        b.extend_from_slice(&r.blob);
    }
    b
}

/// Decodes a read answer.
///
/// # Errors
/// [`StorageError`].
pub fn decode_records(input: &[u8]) -> Result<Vec<Record>, StorageError> {
    let mut r = Reader(input);
    let n = r.u16()?;
    if n > MAX_READ || n.saturating_mul(ID_LEN + 2 + MIN_RECORD_PADDED + TAG_LEN) > r.0.len() {
        return Err(StorageError);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let id = r.id()?;
        let len = r.u16()?;
        if !valid_record_len(len) {
            return Err(StorageError);
        }
        out.push(Record {
            id,
            blob: r.take(len)?.to_vec(),
        });
    }
    r.end()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn record(id: u8, padded: usize) -> Record {
        Record {
            id: [id; ID_LEN],
            blob: vec![0xAB; padded + TAG_LEN],
        }
    }

    #[test]
    fn record_lengths_are_padme_values_with_a_tag() {
        assert!(valid_record_len(256 + 16));
        assert!(!valid_record_len(64 + 16));
        assert!(valid_record_len(4096 + 16));
        assert!(!valid_record_len(255 + 16));
        assert!(!valid_record_len(4097 + 16));
        assert!(!valid_record_len(15));
        // 1,000 is not a Padmé value (it rounds to 1,024).
        assert!(!valid_record_len(1_000 + 16));
        assert!(valid_record_len(1_024 + 16));
        assert_eq!(record_padded_len(0), Some(256));
        assert_eq!(record_padded_len(1_000), Some(1_024));
        assert_eq!(record_padded_len(4_096), Some(4_096));
        assert_eq!(record_padded_len(4_097), None);
    }

    #[test]
    fn a_write_round_trips_and_refuses_duplicates() {
        let w = Write {
            expected: 7,
            manifest: vec![1; 56],
            deletes: vec![[9; ID_LEN]],
            inserts: vec![record(1, 256), record(2, 1_024)],
        };
        assert_eq!(Write::decode(&w.encode()), Ok(w.clone()));
        let mut dup = w.clone();
        dup.deletes.push([1; ID_LEN]);
        assert_eq!(Write::decode(&dup.encode()), Err(StorageError));
        let mut dup = w.clone();
        dup.inserts.push(record(2, 256));
        assert_eq!(Write::decode(&dup.encode()), Err(StorageError));
        let mut bad = w;
        bad.inserts.push(Record {
            id: [3; ID_LEN],
            blob: vec![0; 100],
        });
        assert_eq!(Write::decode(&bad.encode()), Err(StorageError));
    }

    #[test]
    fn a_huge_declared_count_allocates_nothing() {
        let mut b = vec![VERSION];
        b.extend_from_slice(&0u64.to_be_bytes());
        b.extend_from_slice(&16u16.to_be_bytes());
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Write::decode(&b), Err(StorageError));
        assert_eq!(
            Ids::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255]),
            Err(StorageError)
        );
    }

    #[test]
    fn heads_ids_and_reads_round_trip() {
        let h = Head {
            version: 3,
            manifest: vec![2; 56],
        };
        assert_eq!(Head::decode(&h.encode()), Ok(h));
        let empty = Head {
            version: 0,
            manifest: Vec::new(),
        };
        assert_eq!(Head::decode(&empty.encode()), Ok(empty));
        let ids = Ids {
            version: 9,
            ids: vec![[1; ID_LEN], [2; ID_LEN]],
        };
        assert_eq!(Ids::decode(&ids.encode()), Ok(ids));
        let req = encode_read(&[[5; ID_LEN]]).unwrap_or_default();
        assert_eq!(decode_read(&req), Ok(vec![[5; ID_LEN]]));
        assert!(encode_read(&[]).is_err());
        let recs = vec![record(1, 256), record(2, 288)];
        assert_eq!(decode_records(&encode_records(&recs)), Ok(recs));
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = Write::decode(&b);
            let _ = Head::decode(&b);
            let _ = Ids::decode(&b);
            let _ = decode_read(&b);
            let _ = decode_records(&b);
        }
    }
}
