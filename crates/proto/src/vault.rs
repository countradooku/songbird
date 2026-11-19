//! The Songbird vault's wire rules (Prompt 10, M2, D-0121; PROTOCOL §11.8).
//!
//! The vault stores a backup's objects (`crates/backup-format`) without opening them. These
//! are the few facts the server checks: the headers that name and open a vault, the access hash
//! it stores, the shape of chunk and manifest objects (magic, version, a padded length, the
//! manifest's generation), and the binary bodies of listing and deleting chunks.
//!
//! ```text
//! list request:  after [32] (absent: from the start)
//! list answer:   n u16 | name [32] * n | more u8 (0 or 1)
//! delete body:   n u16 (1..=1000) | name [32] * n
//! ```

use crate::media::padme;

/// Header naming the vault: 64 lowercase hex characters (the vault ID).
pub const VAULT_HEADER: &str = "x-songbird-vault";
/// Header carrying the access secret: 64 hex characters.
pub const ACCESS_HEADER: &str = "x-songbird-vault-access";
/// Header carrying the generation a manifest write expects to replace (decimal, 0: none).
pub const EXPECTED_HEADER: &str = "x-songbird-vault-expected";
/// Context of the access hash the vault stores: `SHA-256(ACCESS_CONTEXT || secret)`.
pub const ACCESS_CONTEXT: &[u8] = b"songbird.v1/vault-access\0";

/// Chunk names per list page and per delete.
pub const MAX_NAMES: usize = 1000;
/// Bytes of a chunk object's header (`"SBC" | version | nonce`).
pub const CHUNK_HEADER: usize = 28;
/// Bytes of a manifest object's header (`"SBM" | version | generation | nonce`).
pub const MANIFEST_HEADER: usize = 36;
/// AEAD tag.
pub const TAG: usize = 16;
/// The smallest padded plaintext of either object.
pub const MIN_PADDED: u64 = 1024;
/// The largest chunk plaintext (8 MiB).
pub const MAX_CHUNK_PLAINTEXT: u64 = 8 << 20;

/// Whether `p` is a padded plaintext length the format produces.
#[must_use]
pub fn valid_padded(p: u64) -> bool {
    p >= MIN_PADDED && padme(p) == p
}

/// The largest chunk object.
#[must_use]
pub fn max_chunk_object() -> u64 {
    let p = padme(MAX_CHUNK_PLAINTEXT + 4);
    p + u64::try_from(CHUNK_HEADER + TAG).unwrap_or(0)
}

/// Whether `object` has a chunk object's shape: magic, version, and a padded length no larger
/// than the largest chunk. The server cannot check more; the reader checks the rest.
#[must_use]
pub fn chunk_object_ok(object: &[u8]) -> bool {
    let Ok(len) = u64::try_from(object.len()) else {
        return false;
    };
    let over = u64::try_from(CHUNK_HEADER + TAG).unwrap_or(u64::MAX);
    object.get(..4) == Some(b"SBC\x01")
        && len <= max_chunk_object()
        && len.checked_sub(over).is_some_and(valid_padded)
}

/// A manifest object's generation, if the object has a manifest's shape and is at most `max`
/// bytes.
#[must_use]
pub fn manifest_generation(object: &[u8], max: usize) -> Option<u64> {
    if object.len() > max || object.get(..4) != Some(b"SBM\x01") {
        return None;
    }
    let p = u64::try_from(object.len().checked_sub(MANIFEST_HEADER + TAG)?).ok()?;
    if !valid_padded(p) {
        return None;
    }
    let g: [u8; 8] = object.get(4..12)?.try_into().ok()?;
    Some(u64::from_be_bytes(g))
}

/// Decodes a delete body; `None` when malformed.
#[must_use]
pub fn decode_names(b: &[u8]) -> Option<Vec<[u8; 32]>> {
    let (n, rest) = b.split_first_chunk::<2>()?;
    let n = usize::from(u16::from_be_bytes(*n));
    if n == 0 || n > MAX_NAMES || rest.len() != n * 32 {
        return None;
    }
    Some(rest.as_chunks::<32>().0.to_vec())
}

/// Encodes a delete body (at most [`MAX_NAMES`] names).
#[must_use]
pub fn encode_names(names: &[[u8; 32]]) -> Vec<u8> {
    let n = names.len().min(MAX_NAMES);
    let mut b = Vec::with_capacity(2 + n * 32);
    b.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
    for x in names.iter().take(n) {
        b.extend_from_slice(x);
    }
    b
}

/// Encodes a list answer.
#[must_use]
pub fn encode_page(names: &[[u8; 32]], more: bool) -> Vec<u8> {
    let mut b = encode_names(names);
    if names.is_empty() {
        b = vec![0, 0];
    }
    b.push(u8::from(more));
    b
}

/// Decodes a list answer; `None` when malformed.
#[must_use]
pub fn decode_page(b: &[u8]) -> Option<(Vec<[u8; 32]>, bool)> {
    let (more, rest) = b.split_last()?;
    if *more > 1 {
        return None;
    }
    if rest == [0, 0] {
        return Some((vec![], *more == 1));
    }
    Some((decode_names(rest)?, *more == 1))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn shapes() {
        let mut c = b"SBC\x01".to_vec();
        c.resize(CHUNK_HEADER + 1024 + TAG, 0);
        assert!(chunk_object_ok(&c));
        c.push(0);
        assert!(!chunk_object_ok(&c));
        let mut big = b"SBC\x01".to_vec();
        big.resize(usize::try_from(max_chunk_object()).unwrap(), 0);
        assert!(chunk_object_ok(&big));
        big.extend_from_slice(&vec![0; 1 << 20]);
        assert!(!chunk_object_ok(&big));
        let mut m = b"SBM\x01".to_vec();
        m.extend_from_slice(&7u64.to_be_bytes());
        m.resize(MANIFEST_HEADER + 1024 + TAG, 0);
        assert_eq!(manifest_generation(&m, 1 << 20), Some(7));
        assert_eq!(manifest_generation(&m, 100), None);
        assert_eq!(manifest_generation(&c, 1 << 20), None);
    }

    #[test]
    fn bodies_round_trip() {
        let names = vec![[1u8; 32], [2; 32]];
        assert_eq!(decode_names(&encode_names(&names)).unwrap(), names);
        assert!(decode_names(&[0, 0]).is_none());
        assert!(decode_names(&[0, 1, 0]).is_none());
        assert_eq!(
            decode_page(&encode_page(&names, true)).unwrap(),
            (names, true)
        );
        assert_eq!(
            decode_page(&encode_page(&[], false)).unwrap(),
            (vec![], false)
        );
        assert!(decode_page(&[0, 0, 2]).is_none());
    }
}
