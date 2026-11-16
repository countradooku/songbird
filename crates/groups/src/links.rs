//! Invite-link proofs members can check (D-0076).
//!
//! D-0071 left one thing to the server's word: whether someone joining by an invite link held a
//! usable link. A link's secret now also yields an Ed25519 key pair (HKDF-SHA-256, salt
//! `songbird.v1/group-link`, info `proof`, as the seed). Whoever makes the link commits its
//! public key, under the link's handle, into the group's roles extension (`Roles::links`), which
//! every member verifies and only the `links` role may change. A joiner signs its external
//! commit with the link's key and carries the signature in the commit's authenticated data:
//!
//! ```text
//! version u8 (1) | handle [16] | signature [64]
//! ```
//!
//! over [`proof_content`]: a label, the group, the epoch the commit is made from, the handle,
//! the joining device and its new leaf's signature key. So a proof cannot be moved to another
//! group, epoch, device or leaf, and only someone who held the link's secret can make one. The
//! server keeps only `SHA-256(auth)` (another key from the same secret), so it cannot sign one.
//!
//! [`verify`] is the one rule: the server runs it on every join by link, and apps run it on
//! every external commit from an account that was not in the group.

use songbird_types::DeviceId;

use crate::crypto::VerifyOnlyCrypto;
use crate::roles::Roles;
use crate::wire::GROUP_ID_LEN;

/// The proof's only encoding version.
pub const PROOF_V1: u8 = 1;
/// A proof's length: version, handle, signature.
pub const PROOF_LEN: usize = 1 + 16 + 64;
/// Most link keys a group's roles extension holds (as many as a group may have links).
pub const MAX_LINK_KEYS: usize = 16;

/// Why a link proof was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("no link proof")]
    Missing,
    #[error("malformed link proof")]
    Malformed,
    #[error("the proof names another link than the one used")]
    OtherLink,
    #[error("the group's members never published this link")]
    UnknownLink,
    #[error("the link proof's signature does not verify")]
    Signature,
}

/// A parsed proof (the commit's authenticated data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkProof<'a> {
    pub handle: &'a [u8; 16],
    pub signature: &'a [u8; 64],
}

impl<'a> LinkProof<'a> {
    /// Parses a proof, exactly; empty authenticated data is [`ProofError::Missing`].
    pub fn parse(aad: &'a [u8]) -> Result<Self, ProofError> {
        if aad.is_empty() {
            return Err(ProofError::Missing);
        }
        let b: &[u8; PROOF_LEN] = aad.try_into().map_err(|_| ProofError::Malformed)?;
        let (version, rest) = b.split_first().ok_or(ProofError::Malformed)?;
        if *version != PROOF_V1 {
            return Err(ProofError::Malformed);
        }
        let (handle, signature) = rest.split_at(16);
        Ok(Self {
            handle: handle.try_into().map_err(|_| ProofError::Malformed)?,
            signature: signature.try_into().map_err(|_| ProofError::Malformed)?,
        })
    }

    /// Encodes a proof (apps and tests).
    #[must_use]
    pub fn encode(handle: &[u8; 16], signature: &[u8; 64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_LEN);
        out.push(PROOF_V1);
        out.extend_from_slice(handle);
        out.extend_from_slice(signature);
        out
    }
}

/// What a link proof's signature covers.
#[must_use]
pub fn proof_content(
    group: &[u8; GROUP_ID_LEN],
    from_epoch: u64,
    handle: &[u8; 16],
    device: &DeviceId,
    leaf_key: &[u8],
) -> Vec<u8> {
    let label = b"songbird.v1/link-proof\0";
    let mut out = Vec::with_capacity(label.len() + 16 + 8 + 16 + 16 + 2 + leaf_key.len());
    out.extend_from_slice(label);
    out.extend_from_slice(group);
    out.extend_from_slice(&from_epoch.to_be_bytes());
    out.extend_from_slice(handle);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(
        &u16::try_from(leaf_key.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(leaf_key);
    out
}

/// Checks a joiner's link proof against the group's roles *before* the join (`roles`): the
/// link's key must be one the members published, and the signature its. `used` is the handle
/// the server counted the join against (the server knows it; apps pass `None`). Returns the
/// handle.
///
/// # Errors
/// [`ProofError`].
pub fn verify(
    roles: &Roles,
    group: &[u8; GROUP_ID_LEN],
    from_epoch: u64,
    aad: &[u8],
    device: &DeviceId,
    leaf_key: &[u8],
    used: Option<&[u8; 16]>,
) -> Result<[u8; 16], ProofError> {
    use openmls_traits::crypto::OpenMlsCrypto as _;
    let proof = LinkProof::parse(aad)?;
    if used.is_some_and(|h| h != proof.handle) {
        return Err(ProofError::OtherLink);
    }
    let key = roles
        .links
        .get(proof.handle)
        .ok_or(ProofError::UnknownLink)?;
    let content = proof_content(group, from_epoch, proof.handle, device, leaf_key);
    VerifyOnlyCrypto
        .verify_signature(
            openmls_traits::types::SignatureScheme::ED25519,
            &content,
            key,
            proof.signature,
        )
        .map_err(|_| ProofError::Signature)?;
    Ok(*proof.handle)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;
    use crate::roles::Policy;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    use songbird_types::AccountId;

    fn key(seed: u8) -> (Ed25519KeyPair, [u8; 32]) {
        let k = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let p = k.public_key().as_ref().try_into().unwrap();
        (k, p)
    }

    #[test]
    fn proofs_bind_the_link_group_epoch_device_and_leaf() {
        let (k, pk) = key(1);
        let handle = [7u8; 16];
        let mut roles = Roles::new(AccountId::from_bytes([1; 16]), Policy::GROUP);
        roles.links.insert(handle, pk);
        let (g, d, leaf) = ([5u8; 16], DeviceId::from_bytes([9; 16]), [3u8; 32]);
        let sign = |c: &[u8]| -> [u8; 64] { k.sign(c).as_ref().try_into().unwrap() };
        let aad = LinkProof::encode(&handle, &sign(&proof_content(&g, 4, &handle, &d, &leaf)));
        assert_eq!(verify(&roles, &g, 4, &aad, &d, &leaf, None), Ok(handle));
        assert_eq!(
            verify(&roles, &g, 4, &aad, &d, &leaf, Some(&handle)),
            Ok(handle)
        );
        // Moved anywhere else, it fails.
        let other_device = DeviceId::from_bytes([8; 16]);
        for (g2, e, d2, l2) in [
            ([6u8; 16], 4, d, leaf),
            (g, 5, d, leaf),
            (g, 4, other_device, leaf),
            (g, 4, d, [4u8; 32]),
        ] {
            assert_eq!(
                verify(&roles, &g2, e, &aad, &d2, &l2, None),
                Err(ProofError::Signature)
            );
        }
        assert_eq!(
            verify(&roles, &g, 4, &aad, &d, &leaf, Some(&[1; 16])),
            Err(ProofError::OtherLink)
        );
        // A link the members never published, or signed with another key.
        let unknown =
            LinkProof::encode(&[2; 16], &sign(&proof_content(&g, 4, &[2; 16], &d, &leaf)));
        assert_eq!(
            verify(&roles, &g, 4, &unknown, &d, &leaf, None),
            Err(ProofError::UnknownLink)
        );
        let (k2, _) = key(2);
        let forged: [u8; 64] = k2
            .sign(&proof_content(&g, 4, &handle, &d, &leaf))
            .as_ref()
            .try_into()
            .unwrap();
        assert_eq!(
            verify(
                &roles,
                &g,
                4,
                &LinkProof::encode(&handle, &forged),
                &d,
                &leaf,
                None
            ),
            Err(ProofError::Signature)
        );
        // No proof, a truncated one, another version.
        assert_eq!(
            verify(&roles, &g, 4, &[], &d, &leaf, None),
            Err(ProofError::Missing)
        );
        assert_eq!(
            verify(&roles, &g, 4, &aad[..80], &d, &leaf, None),
            Err(ProofError::Malformed)
        );
        let mut v2 = aad.clone();
        v2[0] = 2;
        assert_eq!(
            verify(&roles, &g, 4, &v2, &d, &leaf, None),
            Err(ProofError::Malformed)
        );
    }
}
