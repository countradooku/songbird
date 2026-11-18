//! Parental supervision of a child account (`docs/PROTOCOL.md` §10.6; Prompt 9, M4, D-0105).
//!
//! A parent links to a child in person; the parent's device makes a fresh Ed25519 **policy key**
//! for this child, unlinked to the parent's account. Every policy is signed by it:
//!
//! ```text
//! version u8 (1) | child [16] | policy_key [32] | policy_version u64 | flags u8
//!   | unlink_at_s u64 | clen u16 | client_rules (0..=512) | signature [64]
//! ```
//!
//! `signature` is Ed25519 by `policy_key` over `"songbird.v1/supervision\0"` followed by every
//! byte before it. Flags the server enforces: [`NO_REQUESTS`], [`GROUP_APPROVAL`], [`HIDDEN`];
//! [`UNLINK`] ends supervision. `client_rules` is ciphertext under a secret the parent and child
//! agreed in person (calls from non-contacts, nudges, quiet hours): the server never reads it.
//! `unlink_at_s` is the day supervision ends by itself (the child's device computes it from the
//! age the child entered; the birth date never leaves the device).
//!
//! A group add of a child whose policy has [`GROUP_APPROVAL`] carries the parent's approval:
//!
//! ```text
//! expires_s u64 | signature [64]   over "songbird.v1/group-approval\0" ‖ group [16] ‖ child [16] ‖ expires_s
//! ```

use songbird_types::AccountId;
use songbird_types::id::ID_LEN;

/// Format version.
pub const VERSION: u8 = 1;
/// Message requests are refused (the child's contacts are the ones the parent approved).
pub const NO_REQUESTS: u8 = 0x01;
/// Group adds of the child need the parent's approval.
pub const GROUP_APPROVAL: u8 = 0x02;
/// The child is not found by username.
pub const HIDDEN: u8 = 0x04;
/// Supervision ends.
pub const UNLINK: u8 = 0x80;
/// Flags a policy may carry.
pub const KNOWN: u8 = NO_REQUESTS | GROUP_APPROVAL | HIDDEN | UNLINK;
/// Largest client-rules ciphertext.
pub const MAX_CLIENT_RULES: usize = 512;
/// Domain separation of the policy signature.
pub const POLICY_CONTEXT: &[u8] = b"songbird.v1/supervision\0";
/// Domain separation of a group approval.
pub const APPROVAL_CONTEXT: &[u8] = b"songbird.v1/group-approval\0";
/// The longest an approval may be valid.
pub const MAX_APPROVAL_S: u64 = 7 * 24 * 3600;
/// An approval's length.
pub const APPROVAL_LEN: usize = 8 + 64;

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed supervision message")]
pub struct SupervisionError;

/// A signed policy.
#[derive(Clone, PartialEq, Eq)]
pub struct Policy {
    /// The child account.
    pub child: AccountId,
    /// The parent's policy key for this child.
    pub policy_key: [u8; 32],
    /// Strictly increasing.
    pub policy_version: u64,
    /// [`NO_REQUESTS`], [`GROUP_APPROVAL`], [`HIDDEN`], [`UNLINK`].
    pub flags: u8,
    /// When supervision ends by itself (seconds since the epoch).
    pub unlink_at_s: u64,
    /// Rules only apps enforce, encrypted.
    pub client_rules: Vec<u8>,
    /// Ed25519 by `policy_key`.
    pub signature: [u8; 64],
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("policy_version", &self.policy_version)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl Policy {
    /// The bytes the signature covers.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(
            POLICY_CONTEXT.len() + 1 + ID_LEN + 32 + 8 + 1 + 8 + 2 + self.client_rules.len(),
        );
        b.extend_from_slice(POLICY_CONTEXT);
        b.extend_from_slice(&self.body());
        b
    }

    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + ID_LEN + 32 + 8 + 1 + 8 + 2 + self.client_rules.len());
        b.push(VERSION);
        b.extend_from_slice(self.child.as_bytes());
        b.extend_from_slice(&self.policy_key);
        b.extend_from_slice(&self.policy_version.to_be_bytes());
        b.push(self.flags);
        b.extend_from_slice(&self.unlink_at_s.to_be_bytes());
        b.extend_from_slice(
            &u16::try_from(self.client_rules.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        b.extend_from_slice(&self.client_rules);
        b
    }

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decodes the whole input (the signature is checked by the caller, against the stored key).
    ///
    /// # Errors
    /// [`SupervisionError`].
    pub fn decode(input: &[u8]) -> Result<Self, SupervisionError> {
        let (&version, r) = input.split_first().ok_or(SupervisionError)?;
        let (child, r) = r.split_first_chunk::<ID_LEN>().ok_or(SupervisionError)?;
        let (key, r) = r.split_first_chunk::<32>().ok_or(SupervisionError)?;
        let (pv, r) = r.split_first_chunk::<8>().ok_or(SupervisionError)?;
        let (&flags, r) = r.split_first().ok_or(SupervisionError)?;
        let (unlink, r) = r.split_first_chunk::<8>().ok_or(SupervisionError)?;
        let (clen, r) = r.split_first_chunk::<2>().ok_or(SupervisionError)?;
        let clen = usize::from(u16::from_be_bytes(*clen));
        if version != VERSION || flags & !KNOWN != 0 || clen > MAX_CLIENT_RULES {
            return Err(SupervisionError);
        }
        let (rules, r) = r.split_at_checked(clen).ok_or(SupervisionError)?;
        let signature: [u8; 64] = r.try_into().map_err(|_| SupervisionError)?;
        Ok(Self {
            child: AccountId::from_bytes(*child),
            policy_key: *key,
            policy_version: u64::from_be_bytes(*pv),
            flags,
            unlink_at_s: u64::from_be_bytes(*unlink),
            client_rules: rules.to_vec(),
            signature,
        })
    }
}

/// The bytes a group approval's signature covers.
#[must_use]
pub fn approval_bytes(group: &[u8; 16], child: &AccountId, expires_s: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(APPROVAL_CONTEXT.len() + 16 + ID_LEN + 8);
    b.extend_from_slice(APPROVAL_CONTEXT);
    b.extend_from_slice(group);
    b.extend_from_slice(child.as_bytes());
    b.extend_from_slice(&expires_s.to_be_bytes());
    b
}

/// Splits an approval into its expiry and signature.
///
/// # Errors
/// [`SupervisionError`] for any other length.
pub fn split_approval(b: &[u8]) -> Result<(u64, [u8; 64]), SupervisionError> {
    let (e, s) = b.split_first_chunk::<8>().ok_or(SupervisionError)?;
    let s: [u8; 64] = s.try_into().map_err(|_| SupervisionError)?;
    Ok((u64::from_be_bytes(*e), s))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use super::*;
    use proptest::prelude::*;

    fn sample() -> Policy {
        Policy {
            child: AccountId::from_bytes([1; 16]),
            policy_key: [2; 32],
            policy_version: 3,
            flags: NO_REQUESTS | HIDDEN,
            unlink_at_s: 1_900_000_000,
            client_rules: vec![9; 40],
            signature: [7; 64],
        }
    }

    #[test]
    fn policies_round_trip_and_decode_strictly() {
        let p = sample();
        let b = p.encode();
        assert_eq!(Policy::decode(&b), Ok(p.clone()));
        for cut in 0..b.len() {
            assert!(Policy::decode(&b[..cut]).is_err());
        }
        let mut long = b.clone();
        long.push(0);
        assert!(Policy::decode(&long).is_err());
        let unknown = Policy {
            flags: 0x10,
            ..p.clone()
        };
        assert!(Policy::decode(&unknown.encode()).is_err());
        assert!(p.signed_bytes().starts_with(POLICY_CONTEXT));
        assert_eq!(
            &p.signed_bytes()[POLICY_CONTEXT.len()..],
            &b[..b.len() - 64]
        );
    }

    #[test]
    fn approvals_split() {
        let mut b = 5u64.to_be_bytes().to_vec();
        b.extend_from_slice(&[1; 64]);
        assert_eq!(split_approval(&b), Ok((5, [1; 64])));
        assert!(split_approval(&b[..71]).is_err());
    }

    proptest! {
        #[test]
        fn the_decoder_never_panics(b in proptest::collection::vec(any::<u8>(), 0..1024)) {
            if let Ok(p) = Policy::decode(&b) {
                prop_assert_eq!(p.encode(), b);
            }
        }
    }
}
