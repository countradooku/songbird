//! Usernames the server stores only as a hash with a proof (Prompt 3, M2; D-0047, D-0049).
//!
//! **Unique handles** (the owner's decision, D-0049): one person per username, as on WhatsApp,
//! built on Signal's construction: the server stores a Ristretto hash and checks a proof that the
//! client knows what it hashes, never the username itself. Signal's own scheme adds a numeric
//! discriminator (`name.42`); Songbird has none, so the hash and the proof statement are
//! Songbird's own. The stateful hash object ([`Sho`]) and the proof follow libsignal's poksho
//! exactly: `tests/username_vectors.rs` checks [`Sho`] against libsignal's published vector and
//! libsignal's output at commit `8be00c2`, and the username vector's proof is the one poksho
//! itself produces and verifies for the same statement and randomness.
//!
//! # Username
//!
//! 3 to 32 characters: ASCII letters (compared in lower case), digits, `_` and `.`; starts with a
//! letter; no `..`; does not end with `.`. ASCII only, so no look-alike letters from other
//! scripts. Shown as typed; unique in lower case.
//!
//! # Hash
//!
//! ```text
//! s    = SHA-512("songbird.v1/username\0" || lower-cased username) reduced mod l
//! hash = s·G   (Ristretto255, compressed, 32 bytes)
//! ```
//!
//! `G` is squeezed from a SHO with a public label ([`GENERATOR_LABEL`]): nobody knows its
//! discrete logarithm, so a username hash is not also some key's public point.
//!
//! # Proof
//!
//! A Schnorr proof of knowledge of `s` with `hash = s·G`: a poksho proof of the statement
//! `hash = s·G` (poksho's statement encoding, label, transcript and nonce derivation), so
//! libsignal's own verifier accepts it: `challenge || response`, two canonical scalars, 64 bytes. The server checks it, so nobody registers a point that is not a
//! username's hash, or a hash whose username they do not know.
//!
//! # What this does not hide
//!
//! The hash cannot be salted (a client computes it from the name alone), so whoever holds it can
//! test guesses: a common name is found by trying it. The scheme keeps usernames out of the
//! database and out of requests in plain text; it does not make a guessable username secret.
//! Lookups are therefore signed, rate-limited and exact-match only, and the optional username key
//! answers "not found" to strangers without it (D-0049).

use aws_lc_rs::{digest, hmac};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// Hash length.
pub const HASH_LEN: usize = 32;
/// Proof length: challenge and response.
pub const PROOF_LEN: usize = 64;
/// Shortest username.
pub const MIN_LEN: usize = 3;
/// Longest username.
pub const MAX_LEN: usize = 32;
/// Domain separation of the hash's scalar.
pub const HASH_CONTEXT: &[u8] = b"songbird.v1/username\0";
/// Label of the SHO the generator is squeezed from.
pub const GENERATOR_LABEL: &[u8] = b"songbird.v1/username-generator";
/// Label of the proof transcript: poksho's own, so every username proof is a standard poksho
/// proof that libsignal's verifier accepts (checked by `tests/username_vectors.rs`). Domain
/// separation comes from the statement and the points it names, `G` being Songbird's alone.
pub const PROOF_LABEL: &[u8] = b"POKSHO_Ristretto_SHOHMACSHA256";

/// The proof statement in poksho's encoding: one equation, left side point 1 (the hash), one
/// term (scalar 0, point 2 = `G`). Point 0 is the Ristretto base point, always first in poksho's
/// point list.
const STATEMENT: [u8; 5] = [1, 1, 1, 0, 2];

/// A stateful hash object over HMAC-SHA256 (poksho's `ShoHmacSha256`): absorb input, ratchet
/// (fix a chaining value), squeeze output. Used for the generators and the proof transcript.
#[derive(Clone)]
pub struct Sho {
    cv: [u8; 32],
    /// The input absorbed since the last ratchet (`None`: ratcheted).
    absorbing: Option<hmac::Context>,
}

impl std::fmt::Debug for Sho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sho(..)")
    }
}

impl Sho {
    /// A SHO with a label: the chaining value starts at zeros and absorbs the label.
    #[must_use]
    pub fn new(label: &[u8]) -> Self {
        let mut s = Self {
            cv: [0; 32],
            absorbing: None,
        };
        s.absorb(label);
        s.ratchet();
        s
    }

    /// Absorbs input (an HMAC keyed with the chaining value).
    pub fn absorb(&mut self, input: &[u8]) {
        let cv = self.cv;
        self.absorbing
            .get_or_insert_with(|| hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &cv)))
            .update(input);
    }

    /// Fixes what was absorbed: the chaining value becomes the HMAC of it followed by `0x00`.
    /// Nothing absorbed since the last ratchet: no change.
    pub fn ratchet(&mut self) {
        if let Some(mut h) = self.absorbing.take() {
            h.update(&[0x00]);
            self.cv.copy_from_slice(h.sign().as_ref());
        }
    }

    /// Absorbs and ratchets.
    pub fn absorb_and_ratchet(&mut self, input: &[u8]) {
        self.absorb(input);
        self.ratchet();
    }

    /// Squeezes `out.len()` bytes (`HMAC(cv, i u64 || 0x01)` blocks), then ratchets
    /// (`cv = HMAC(cv, len u64 || 0x02)`). Ratchets first if anything was absorbed.
    pub fn squeeze_and_ratchet(&mut self, out: &mut [u8]) {
        self.ratchet();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.cv);
        for (i, chunk) in (0u64..).zip(out.chunks_mut(32)) {
            let mut h = hmac::Context::with_key(&key);
            h.update(&i.to_be_bytes());
            h.update(&[0x01]);
            let block = h.sign();
            chunk.copy_from_slice(block.as_ref().get(..chunk.len()).unwrap_or_default());
        }
        let mut h = hmac::Context::with_key(&key);
        h.update(&u64::try_from(out.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(&[0x02]);
        self.cv.copy_from_slice(h.sign().as_ref());
    }

    fn scalar(&mut self) -> Scalar {
        let mut wide = [0u8; 64];
        self.squeeze_and_ratchet(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

/// The generator `G`: `Sho::new(GENERATOR_LABEL)`, one 64-byte squeeze mapped to Ristretto.
#[must_use]
pub fn generator() -> RistrettoPoint {
    let mut sho = Sho::new(GENERATOR_LABEL);
    let mut wide = [0u8; 64];
    sho.squeeze_and_ratchet(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Why a string is not a username (for the app's messages; the server never sees one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    /// Fewer than 3 or more than 32 characters.
    #[error("length")]
    Length,
    /// Does not start with a letter.
    #[error("must start with a letter")]
    Start,
    /// A character other than ASCII letters, digits, `_` and `.`.
    #[error("character")]
    Character,
    /// `..`, or a final `.`.
    #[error("periods")]
    Periods,
}

/// A username.
#[derive(Clone, PartialEq, Eq)]
pub struct Username(String);

impl std::fmt::Debug for Username {
    // A username is personal data: never printed by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Username(..)")
    }
}

impl Username {
    /// Parses a username as typed.
    ///
    /// # Errors
    /// [`UsernameError`].
    pub fn parse(s: &str) -> Result<Self, UsernameError> {
        let b = s.as_bytes();
        if !b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.')
        {
            return Err(UsernameError::Character);
        }
        if !(MIN_LEN..=MAX_LEN).contains(&b.len()) {
            return Err(UsernameError::Length);
        }
        if !b.first().is_some_and(u8::is_ascii_alphabetic) {
            return Err(UsernameError::Start);
        }
        if b.ends_with(b".") || b.windows(2).any(|w| w == b"..") {
            return Err(UsernameError::Periods);
        }
        Ok(Self(s.to_owned()))
    }

    /// As typed.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.0
    }

    fn scalar(&self) -> Scalar {
        let mut sha = digest::Context::new(&digest::SHA512);
        sha.update(HASH_CONTEXT);
        sha.update(self.0.to_ascii_lowercase().as_bytes());
        let mut wide = [0u8; 64];
        wide.copy_from_slice(sha.finish().as_ref());
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    /// The hash the server stores.
    #[must_use]
    pub fn hash(&self) -> [u8; HASH_LEN] {
        (self.scalar() * generator()).compress().to_bytes()
    }

    /// The proof that the hash is this username's, with 32 bytes of fresh randomness.
    #[must_use]
    pub fn proof(&self, randomness: &[u8; 32]) -> [u8; PROOF_LEN] {
        let g = generator();
        let secret = self.scalar();
        let hash_point = secret * g;
        let hash = hash_point.compress().to_bytes();
        let mut sho = transcript_prefix(&hash_point, &g);
        // The nonce from the randomness, the secret and the message (poksho's derivation: a
        // repeated randomness never reuses a nonce for another secret or message).
        let mut nonce_sho = sho.clone();
        nonce_sho.absorb(randomness);
        nonce_sho.absorb(secret.as_bytes());
        nonce_sho.ratchet();
        nonce_sho.absorb_and_ratchet(&hash);
        let nonce = nonce_sho.scalar();
        sho.absorb((nonce * g).compress().as_bytes());
        sho.absorb_and_ratchet(&hash);
        let challenge = sho.scalar();
        let mut out = [0u8; PROOF_LEN];
        out[..32].copy_from_slice(challenge.as_bytes());
        out[32..].copy_from_slice((nonce + secret * challenge).as_bytes());
        out
    }
}

/// The transcript up to the commitment: label, statement, then every point of the statement in
/// order (base point, hash, `G`), ratcheted.
fn transcript_prefix(hash: &RistrettoPoint, g: &RistrettoPoint) -> Sho {
    let mut sho = Sho::new(PROOF_LABEL);
    sho.absorb(&STATEMENT);
    for p in [RISTRETTO_BASEPOINT_POINT, *hash, *g] {
        sho.absorb(p.compress().as_bytes());
    }
    sho.ratchet();
    sho
}

/// Whether `proof` proves knowledge of the username behind `hash`. Refuses a hash that is not a
/// canonical Ristretto encoding (or is the identity), a proof of the wrong length, and
/// non-canonical scalars.
#[must_use]
pub fn verify_proof(hash: &[u8; HASH_LEN], proof: &[u8]) -> bool {
    let Some(hash_point) = CompressedRistretto(*hash).decompress() else {
        return false;
    };
    if hash_point == RistrettoPoint::default() {
        return false;
    }
    let Ok(proof) = <&[u8; PROOF_LEN]>::try_from(proof) else {
        return false;
    };
    let [c, r] = proof.as_chunks::<32>().0 else {
        return false;
    };
    let (Some(challenge), Some(response)) = (
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*c)),
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*r)),
    ) else {
        return false;
    };
    let g = generator();
    let commitment = response * g - challenge * hash_point;
    let mut sho = transcript_prefix(&hash_point, &g);
    sho.absorb(commitment.compress().as_bytes());
    sho.absorb_and_ratchet(hash);
    // Public values: a plain comparison leaks nothing.
    sho.scalar() == challenge
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use super::*;

    /// The group order l, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    #[test]
    fn proofs_verify_and_tampering_does_not() {
        let u = Username::parse("songbird").unwrap();
        let h = u.hash();
        let p = u.proof(&[7; 32]);
        assert!(verify_proof(&h, &p));
        assert_ne!(p, u.proof(&[8; 32]), "fresh randomness, fresh proof");
        // Another username's hash, any changed byte, a short proof.
        assert!(!verify_proof(
            &Username::parse("songbirb").unwrap().hash(),
            &p
        ));
        for i in 0..PROOF_LEN {
            let mut q = p;
            q[i] ^= 1;
            assert!(!verify_proof(&h, &q), "byte {i}");
        }
        assert!(!verify_proof(&h, &p[..32]));
        // Not a Ristretto encoding; the identity point.
        assert!(!verify_proof(&[0xFF; 32], &p));
        assert!(!verify_proof(&[0; 32], &p));
        // A non-canonical scalar (the response plus the group order l) is refused, not reduced.
        let mut q = p;
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(q[32 + i]) + u16::from(L[i]) + carry;
            q[32 + i] = u8::try_from(sum & 0xFF).unwrap();
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verify_proof(&h, &q));
    }

    #[test]
    fn case_does_not_change_the_hash_but_display_keeps_it() {
        let a = Username::parse("Radu").unwrap();
        let b = Username::parse("radu").unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.display(), "Radu");
        assert_eq!(format!("{a:?}"), "Username(..)");
    }

    #[test]
    fn rules() {
        use UsernameError::*;
        for (s, want) in [
            ("radu", Ok(())),
            ("Radu_D", Ok(())),
            ("radu.diaconu", Ok(())),
            ("r2d2", Ok(())),
            ("abc", Ok(())),
            ("a2345678901234567890123456789012", Ok(())),
            ("ab", Err(Length)),
            ("a23456789012345678901234567890123", Err(Length)),
            ("1radu", Err(Start)),
            ("_radu", Err(Start)),
            (".radu", Err(Start)),
            ("radu.", Err(Periods)),
            ("ra..du", Err(Periods)),
            ("ra-du", Err(Character)),
            ("ra du", Err(Character)),
            ("r\u{0430}du", Err(Character)),
            ("", Err(Length)),
        ] {
            assert_eq!(Username::parse(s).map(|_| ()), want, "{s:?}");
        }
    }
}
