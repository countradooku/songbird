//! Attachment sizes (Prompt 6, PROTOCOL §7.1, D-0080): the arithmetic the server needs to check
//! an upload grant without ever seeing the encryption.
//!
//! Apps encrypt an attachment of `n` bytes as follows (the format itself lives in
//! `songbird-content`, which no service links):
//!
//! 1. Pad the plaintext with zeros to [`padded_len`]`(n)`: Padmé (Nikitin et al., "Reducing
//!    Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019) over a floor
//!    of [`MIN_PADDED`]. It costs at most 12 % and leaves O(log log n) bits of the size.
//! 2. Seal it in [`CHUNK`]-byte chunks, each with a [`TAG`]-byte tag, after a [`HEADER`]-byte
//!    header. An empty padded plaintext is still one (empty) chunk; it never happens in
//!    practice because of the floor.
//!
//! So every legal ciphertext length is [`ciphertext_len`]`(n)` for some `n`, and
//! [`padded_from_ciphertext`] recognises one, which lets `api` refuse a grant for any other size:
//! an uploader cannot pick an exact size to leak the real one.

/// Plaintext bytes per chunk.
pub const CHUNK: u64 = 65_536;
/// AEAD tag bytes per chunk.
pub const TAG: u64 = 16;
/// Header bytes: a version byte and a 32-byte salt.
pub const HEADER: u64 = 33;
/// The smallest padded plaintext: a 40-byte thumbnail and a 1,000-byte one look the same.
pub const MIN_PADDED: u64 = 1_024;
/// The largest padded plaintext the format describes (a 2^32-chunk counter is far beyond it;
/// plans cap uploads well below, D-0079).
pub const MAX_PADDED: u64 = 1 << 40;

/// Padmé: rounds `n` up so that only its top O(log log n) bits remain significant.
#[must_use]
pub fn padme(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    // E = floor(log2 n) >= 1; S = floor(log2 E) + 1; the last E - S bits are cleared.
    let e = n.ilog2();
    let s = e.ilog2() + 1;
    let mask = (1u64 << (e - s)) - 1;
    n.saturating_add(mask) & !mask
}

/// The padded plaintext length for an attachment of `n` bytes, or `None` past [`MAX_PADDED`].
#[must_use]
pub fn padded_len(n: u64) -> Option<u64> {
    let p = padme(n.max(MIN_PADDED));
    (p <= MAX_PADDED).then_some(p)
}

/// How many chunks hold a padded plaintext of `padded` bytes (at least one).
#[must_use]
pub fn chunks(padded: u64) -> u64 {
    padded.div_ceil(CHUNK).max(1)
}

/// The ciphertext length of a padded plaintext of `padded` bytes.
#[must_use]
pub fn ciphertext_len_padded(padded: u64) -> u64 {
    HEADER + padded + TAG * chunks(padded)
}

/// The ciphertext (and so the upload and grant) length of an attachment of `n` bytes.
#[must_use]
pub fn ciphertext_len(n: u64) -> Option<u64> {
    padded_len(n).map(ciphertext_len_padded)
}

/// The padded plaintext length behind a ciphertext of `len` bytes, if `len` is one the format
/// produces; `None` for every other length.
#[must_use]
pub fn padded_from_ciphertext(len: u64) -> Option<u64> {
    let body = len.checked_sub(HEADER)?;
    let k = body.div_ceil(CHUNK + TAG).max(1);
    let padded = body.checked_sub(k.checked_mul(TAG)?)?;
    ((MIN_PADDED..=MAX_PADDED).contains(&padded)
        && padme(padded) == padded
        && chunks(padded) == k
        && ciphertext_len_padded(padded) == len)
        .then_some(padded)
}

/// Where chunk `index` starts in the ciphertext.
#[must_use]
pub fn chunk_offset(index: u64) -> u64 {
    HEADER.saturating_add(index.saturating_mul(CHUNK + TAG))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn padme_matches_the_paper() {
        // Values from the paper's definition, worked by hand.
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(1_000), 1_024);
        assert_eq!(padme(17), 18);
        assert_eq!(padme(1_024), 1_024);
        assert_eq!(padme(1_025), 1_088);
        assert_eq!(padme(1_000_000), 1_015_808);
        assert_eq!(padme((1 << 30) + 1), (1 << 30) + (1 << 25));
    }

    #[test]
    fn small_files_share_one_size() {
        assert_eq!(padded_len(0), Some(1_024));
        assert_eq!(padded_len(1_024), Some(1_024));
        assert_eq!(ciphertext_len(40), ciphertext_len(1_000));
        assert_eq!(ciphertext_len(40), Some(33 + 1_024 + 16));
    }

    #[test]
    fn chunk_boundaries() {
        assert_eq!(chunks(0), 1);
        assert_eq!(chunks(CHUNK), 1);
        assert_eq!(chunks(CHUNK + 1), 2);
        assert_eq!(ciphertext_len_padded(CHUNK), HEADER + CHUNK + TAG);
        assert_eq!(chunk_offset(2), HEADER + 2 * (CHUNK + TAG));
        // A whole extra (empty) chunk is never a legal length.
        assert_eq!(padded_from_ciphertext(HEADER + CHUNK + 2 * TAG), None);
        assert_eq!(padded_from_ciphertext(HEADER + CHUNK + TAG), Some(CHUNK));
    }

    #[test]
    fn every_length_up_to_a_few_megabytes_round_trips_and_nothing_else_is_legal() {
        let mut n = 0;
        while n < 4 << 20 {
            let c = ciphertext_len(n).unwrap();
            assert_eq!(padded_from_ciphertext(c), padded_len(n));
            n += 97;
        }
        let legal: std::collections::BTreeSet<u64> = (MIN_PADDED..4 << 20)
            .filter(|p| padme(*p) == *p)
            .map(ciphertext_len_padded)
            .collect();
        let max = *legal.iter().next_back().unwrap();
        for c in 0..=max {
            assert_eq!(
                padded_from_ciphertext(c).is_some(),
                legal.contains(&c),
                "{c}"
            );
        }
    }

    proptest! {
        #[test]
        fn padme_is_monotone_idempotent_and_cheap(n in 2u64..(1 << 41)) {
            let p = padme(n);
            prop_assert!(p >= n);
            prop_assert_eq!(padme(p), p);
            prop_assert!(padme(n + 1) >= p);
            // At most 12 % overhead (the paper's bound).
            prop_assert!((p - n) * 100 <= n * 12);
        }

        #[test]
        fn ciphertext_lengths_invert(n in 0u64..MAX_PADDED) {
            let c = ciphertext_len(n).unwrap();
            prop_assert_eq!(padded_from_ciphertext(c), padded_len(n));
        }

        #[test]
        fn arbitrary_lengths_never_panic(c in any::<u64>()) {
            if let Some(p) = padded_from_ciphertext(c) {
                prop_assert_eq!(ciphertext_len_padded(p), c);
            }
        }
    }
}
