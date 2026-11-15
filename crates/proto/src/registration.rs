//! Registration (`docs/PROTOCOL.md` §4.1) and invite codes (§4.2).
//!
//! # `POST /v1/registration` body
//!
//! ```text
//! version u8 (1) | challenge [51] | k u8 | k × solution u32 | flags u8
//!   | [invite [15] if flags & 1] | identity_key [32] | auth_key [32]
//!   | identity_sig [64] | auth_sig [64]
//! ```
//!
//! Integers are big-endian; unknown flag bits are refused. `identity_key` is the account identity
//! key (Ed25519; it will sign the device list) and `auth_key` the first device's authentication
//! key (Ed25519, §2). Each signs its own transcript ([`transcript`]), proving possession; the two
//! contexts differ, so neither signature can stand in for the other. The server assigns the
//! account and device IDs.
//!
//! # Invite codes
//!
//! 15 random bytes (120 bits), shown as 24 Crockford base32 symbols in six groups of four
//! (`ABCD-EFGH-JKMN-PQRS-TVWX-YZ01`). Parsing ignores case, hyphens and spaces and reads `O` as
//! `0` and `I`, `L` as `1`, so a code read aloud or retyped still works.
//!
//! Like [`crate::auth`], this module only builds and parses bytes; signatures and the proof of
//! work are checked by the server (`songbird-api`, `songbird-pow`).

use crate::control::MAX_SERVER_NAME_LEN;
use crate::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Request format version.
pub const VERSION: u8 = 1;
/// Proof-of-work challenge length (`songbird-pow`).
pub const CHALLENGE_LEN: usize = 51;
/// Invite code length in bytes.
pub const INVITE_LEN: usize = 15;
/// Most proof-of-work solutions a request may carry.
pub const MAX_SOLUTIONS: usize = 64;
/// Flag: an invite code follows.
pub const FLAG_INVITE: u8 = 1;
/// Longest request body.
pub const MAX_LEN: usize = 1
    + CHALLENGE_LEN
    + 1
    + MAX_SOLUTIONS * 4
    + 1
    + INVITE_LEN
    + 2 * PUBLIC_KEY_LEN
    + 2 * SIGNATURE_LEN;

/// Context of the identity key's signature.
pub const IDENTITY_CONTEXT: &[u8] = b"songbird.v1/register-identity\0";
/// Context of the authentication key's signature.
pub const DEVICE_CONTEXT: &[u8] = b"songbird.v1/register-device\0";

/// A registration request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    /// The proof-of-work challenge, as issued.
    pub challenge: [u8; CHALLENGE_LEN],
    /// Its solutions.
    pub solutions: Vec<u32>,
    /// An invite code (required in invite-only mode).
    pub invite: Option<[u8; INVITE_LEN]>,
    /// The account identity key (Ed25519).
    pub identity_key: [u8; PUBLIC_KEY_LEN],
    /// The first device's authentication key (Ed25519).
    pub auth_key: [u8; PUBLIC_KEY_LEN],
    /// `identity_key`'s signature over [`transcript`] with [`IDENTITY_CONTEXT`].
    pub identity_sig: [u8; SIGNATURE_LEN],
    /// `auth_key`'s signature over [`transcript`] with [`DEVICE_CONTEXT`].
    pub auth_sig: [u8; SIGNATURE_LEN],
}

/// Why a request did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Too long, too short, a wrong version or unknown flags.
    #[error("malformed registration request")]
    Malformed,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(DecodeError::Malformed)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Malformed)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }
}

impl RegisterRequest {
    /// Encodes the request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MAX_LEN);
        b.push(VERSION);
        b.extend_from_slice(&self.challenge);
        b.push(u8::try_from(self.solutions.len()).unwrap_or(u8::MAX));
        for s in &self.solutions {
            b.extend_from_slice(&s.to_be_bytes());
        }
        match &self.invite {
            Some(code) => {
                b.push(FLAG_INVITE);
                b.extend_from_slice(code);
            }
            None => b.push(0),
        }
        b.extend_from_slice(&self.identity_key);
        b.extend_from_slice(&self.auth_key);
        b.extend_from_slice(&self.identity_sig);
        b.extend_from_slice(&self.auth_sig);
        b
    }

    /// Decodes a request: the whole input, nothing more. The length is checked before anything
    /// proportional to it is allocated (at most [`MAX_SOLUTIONS`] counters).
    ///
    /// # Errors
    /// [`DecodeError::Malformed`].
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() > MAX_LEN {
            return Err(DecodeError::Malformed);
        }
        let mut r = Reader(input);
        if r.u8()? != VERSION {
            return Err(DecodeError::Malformed);
        }
        let challenge = r.array()?;
        let k = usize::from(r.u8()?);
        if k == 0 || k > MAX_SOLUTIONS {
            return Err(DecodeError::Malformed);
        }
        let solutions = r
            .take(k * 4)?
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_be_bytes(*c))
            .collect();
        let invite = match r.u8()? {
            0 => None,
            FLAG_INVITE => Some(r.array()?),
            _ => return Err(DecodeError::Malformed),
        };
        let out = Self {
            challenge,
            solutions,
            invite,
            identity_key: r.array()?,
            auth_key: r.array()?,
            identity_sig: r.array()?,
            auth_sig: r.array()?,
        };
        if !r.0.is_empty() {
            return Err(DecodeError::Malformed);
        }
        Ok(out)
    }
}

/// The bytes each key signs:
///
/// ```text
/// context || u8 len(server_name) || server_name || challenge [51] || identity_key [32]
///   || auth_key [32]
/// ```
///
/// The challenge is single use, so a signature cannot be replayed into another registration; the
/// server name binds it to one deployment; both keys are covered by both signatures.
///
/// # Errors
/// [`DecodeError::Malformed`] for an empty or overlong server name.
pub fn transcript(
    context: &[u8],
    server_name: &str,
    challenge: &[u8; CHALLENGE_LEN],
    identity_key: &[u8; PUBLIC_KEY_LEN],
    auth_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<Vec<u8>, DecodeError> {
    if server_name.is_empty() || server_name.len() > MAX_SERVER_NAME_LEN {
        return Err(DecodeError::Malformed);
    }
    let len = u8::try_from(server_name.len()).map_err(|_| DecodeError::Malformed)?;
    let mut t = Vec::with_capacity(
        context.len() + 1 + server_name.len() + CHALLENGE_LEN + 2 * PUBLIC_KEY_LEN,
    );
    t.extend_from_slice(context);
    t.push(len);
    t.extend_from_slice(server_name.as_bytes());
    t.extend_from_slice(challenge);
    t.extend_from_slice(identity_key);
    t.extend_from_slice(auth_key);
    Ok(t)
}

/// Invite code text form.
pub mod invite {
    use super::INVITE_LEN;

    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    /// Symbols in a code (120 bits / 5).
    pub const SYMBOLS: usize = 24;

    fn value(c: u8) -> Option<u8> {
        let c = c.to_ascii_uppercase();
        let c = match c {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            other => other,
        };
        ALPHABET
            .iter()
            .position(|&a| a == c)
            .and_then(|p| u8::try_from(p).ok())
    }

    /// The display form: six groups of four symbols joined by hyphens.
    #[must_use]
    pub fn format(code: &[u8; INVITE_LEN]) -> String {
        let mut out = String::with_capacity(SYMBOLS + 5);
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        let mut n = 0usize;
        for &byte in code {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let i = usize::try_from((acc >> bits) & 31).unwrap_or(0);
                if n > 0 && n.is_multiple_of(4) {
                    out.push('-');
                }
                out.push(char::from(ALPHABET.get(i).copied().unwrap_or(b'0')));
                n += 1;
            }
            acc &= (1 << bits) - 1;
        }
        out
    }

    /// Parses a code typed by a person. `None` for anything that is not exactly 24 symbols
    /// (separators aside).
    #[must_use]
    pub fn parse(text: &str) -> Option<[u8; INVITE_LEN]> {
        if text.len() > 64 {
            return None;
        }
        let mut out = [0u8; INVITE_LEN];
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        let mut symbols = 0usize;
        let mut o = 0usize;
        for &c in text.as_bytes() {
            if c == b'-' || c == b' ' {
                continue;
            }
            let v = value(c)?;
            symbols += 1;
            if symbols > SYMBOLS {
                return None;
            }
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                *out.get_mut(o)? = u8::try_from((acc >> bits) & 0xFF).ok()?;
                o += 1;
                acc &= (1 << bits) - 1;
            }
        }
        (symbols == SYMBOLS && o == INVITE_LEN).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use proptest::prelude::*;

    use super::*;

    fn sample(invite: bool) -> RegisterRequest {
        RegisterRequest {
            challenge: [1; CHALLENGE_LEN],
            solutions: vec![3, 9, 12],
            invite: invite.then_some([4; INVITE_LEN]),
            identity_key: [5; 32],
            auth_key: [6; 32],
            identity_sig: [7; 64],
            auth_sig: [8; 64],
        }
    }

    #[test]
    fn requests_round_trip_and_decode_strictly() {
        for invite in [false, true] {
            let r = sample(invite);
            let b = r.encode();
            assert_eq!(RegisterRequest::decode(&b), Ok(r));
            for cut in 0..b.len() {
                assert!(RegisterRequest::decode(&b[..cut]).is_err());
            }
            let mut long = b.clone();
            long.push(0);
            assert!(RegisterRequest::decode(&long).is_err());
        }
        let mut b = sample(false).encode();
        b[0] = 2;
        assert!(RegisterRequest::decode(&b).is_err());
        // Unknown flags.
        let mut b = sample(false).encode();
        b[1 + CHALLENGE_LEN + 1 + 12] = 2;
        assert!(RegisterRequest::decode(&b).is_err());
        // Zero or too many solutions.
        let mut r = sample(false);
        r.solutions.clear();
        assert!(RegisterRequest::decode(&r.encode()).is_err());
        r.solutions = vec![0; MAX_SOLUTIONS + 1];
        assert!(RegisterRequest::decode(&r.encode()).is_err());
        r.solutions = vec![0; MAX_SOLUTIONS];
        r.invite = Some([0; INVITE_LEN]);
        assert_eq!(r.encode().len(), MAX_LEN);
        assert!(RegisterRequest::decode(&r.encode()).is_ok());
    }

    #[test]
    fn transcripts_differ_by_context_and_refuse_bad_names() {
        let a = transcript(
            IDENTITY_CONTEXT,
            "chat.example",
            &[1; 51],
            &[2; 32],
            &[3; 32],
        )
        .unwrap();
        let b = transcript(DEVICE_CONTEXT, "chat.example", &[1; 51], &[2; 32], &[3; 32]).unwrap();
        assert_ne!(a, b);
        assert!(transcript(IDENTITY_CONTEXT, "", &[1; 51], &[2; 32], &[3; 32]).is_err());
        let long = "a".repeat(MAX_SERVER_NAME_LEN + 1);
        assert!(transcript(IDENTITY_CONTEXT, &long, &[1; 51], &[2; 32], &[3; 32]).is_err());
    }

    #[test]
    fn invite_codes_tolerate_how_people_type_them() {
        let code = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let s = invite::format(&code);
        assert_eq!(s.len(), 29);
        assert_eq!(invite::parse(&s), Some(code));
        assert_eq!(
            invite::parse(&s.to_lowercase().replace('-', " ")),
            Some(code)
        );
        let with_o = s.replace('0', "O");
        assert_eq!(invite::parse(&with_o), Some(code));
        assert_eq!(invite::parse(&s[..28]), None);
        assert_eq!(invite::parse(&format!("{s}0")), None);
        assert_eq!(invite::parse(&s.replacen('-', "U", 1)), None);
        assert_eq!(invite::parse(""), None);
    }

    proptest! {
        #[test]
        fn invite_codes_round_trip(code in any::<[u8; INVITE_LEN]>()) {
            prop_assert_eq!(invite::parse(&invite::format(&code)), Some(code));
        }

        #[test]
        fn decoding_never_panics(b in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = RegisterRequest::decode(&b);
        }
    }
}
