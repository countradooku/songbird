//! The delivery service as an MLS external sender (RFC 9420 §12.1.8.1; D-0075).
//!
//! Every Songbird group names the delivery service in its context's `external_senders`
//! extension: one entry, the service's Ed25519 public key with a basic credential
//! [`DS_IDENTITY`]. When a device leaves the directory (its account is deleted, or it is removed
//! from its account's signed device list), the service queues an external `Remove` proposal for
//! its leaf in each group that holds it, and fans it out. The next committer includes it by
//! reference.
//!
//! The service can only *propose*: a member commits. Members accept (store, and later commit) a
//! server proposal only for a device that is no longer in its account's signed device list
//! (`roles::Change::external`, `roles::Denied::Listed`), and the server refuses any other external
//! proposal kind (an external `Add` or context change would let a server admit or reshape).
//!
//! The signing key lives here, outside the verify-only OpenMLS provider (`crate::crypto`): that
//! provider still never signs. The proposal is encoded by hand (OpenMLS's own constructor needs
//! a full client provider type), then checked by the service's own `PublicGroup` like any
//! member's proposal before it is queued, so an encoding mistake can never be stored.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

use crate::wire::GROUP_ID_LEN;

/// The basic credential's identity in the delivery service's `external_senders` entry.
pub const DS_IDENTITY: &[u8] = b"songbird.v1/ds";
/// The delivery service's index in `external_senders` (it is the only entry).
pub const DS_SENDER_INDEX: u32 = 0;

/// RFC 9420 constants used by the encoding.
const MLS10: u16 = 1;
const WIRE_PUBLIC: u16 = 1;
const SENDER_EXTERNAL: u8 = 2;
const CONTENT_PROPOSAL: u8 = 2;
const PROPOSAL_REMOVE: u16 = 3;
const SIGN_LABEL: &[u8] = b"MLS 1.0 FramedContentTBS";

/// The delivery service's external-sender signing key.
pub struct DsSigner {
    key: Ed25519KeyPair,
    public: [u8; 32],
}

impl std::fmt::Debug for DsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsSigner")
            .field("public", &self.public.get(..4))
            .finish_non_exhaustive()
    }
}

impl DsSigner {
    /// The key from a 32-byte seed (every `api` node derives the same seed from the cluster
    /// secret, so every node signs with the key every group names).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Option<Self> {
        let key = Ed25519KeyPair::from_seed_unchecked(seed).ok()?;
        let public: [u8; 32] = key.public_key().as_ref().try_into().ok()?;
        Some(Self { key, public })
    }

    /// The public key groups name in `external_senders`.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.key.sign(msg).as_ref());
        out
    }
}

/// RFC 9420 §2.1.2 variable-length integer (minimal encoding), for lengths below 2^30.
fn varint(out: &mut Vec<u8>, n: usize) {
    if n < 1 << 6 {
        out.push(u8::try_from(n).unwrap_or(0));
    } else if n < 1 << 14 {
        let v = u16::try_from(n).unwrap_or(0) | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        let v = u32::try_from(n).unwrap_or(0) | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn opaque(out: &mut Vec<u8>, b: &[u8]) {
    varint(out, b.len());
    out.extend_from_slice(b);
}

/// `FramedContent` of an external `Remove` proposal (RFC 9420 §6): group, epoch, sender
/// `external(DS_SENDER_INDEX)`, no authenticated data, `proposal`, `Remove { removed }`.
fn framed_remove(group: &[u8; GROUP_ID_LEN], epoch: u64, leaf: u32) -> Vec<u8> {
    let mut c = Vec::with_capacity(48);
    opaque(&mut c, group);
    c.extend_from_slice(&epoch.to_be_bytes());
    c.push(SENDER_EXTERNAL);
    c.extend_from_slice(&DS_SENDER_INDEX.to_be_bytes());
    opaque(&mut c, &[]);
    c.push(CONTENT_PROPOSAL);
    c.extend_from_slice(&PROPOSAL_REMOVE.to_be_bytes());
    c.extend_from_slice(&leaf.to_be_bytes());
    c
}

/// What the delivery service signs (RFC 9420 §6.1, `SignWithLabel(…, "FramedContentTBS", …)`):
/// `SignContent { label<V>, content<V> }`, where the content is `FramedContentTBS` (version,
/// wire format, the framed content; an external sender signs no group context).
#[must_use]
pub fn remove_signed_content(group: &[u8; GROUP_ID_LEN], epoch: u64, leaf: u32) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(52);
    tbs.extend_from_slice(&MLS10.to_be_bytes());
    tbs.extend_from_slice(&WIRE_PUBLIC.to_be_bytes());
    tbs.extend_from_slice(&framed_remove(group, epoch, leaf));
    let mut out = Vec::with_capacity(80);
    opaque(&mut out, SIGN_LABEL);
    opaque(&mut out, &tbs);
    out
}

/// An external `Remove` proposal for `leaf` at `epoch`, signed by the delivery service: an
/// `MLSMessage` carrying a `PublicMessage` (no membership tag: the sender is not a member).
#[must_use]
pub fn remove_proposal(
    group: &[u8; GROUP_ID_LEN],
    epoch: u64,
    leaf: u32,
    signer: &DsSigner,
) -> Vec<u8> {
    let signature = signer.sign(&remove_signed_content(group, epoch, leaf));
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&MLS10.to_be_bytes());
    out.extend_from_slice(&WIRE_PUBLIC.to_be_bytes());
    out.extend_from_slice(&framed_remove(group, epoch, leaf));
    opaque(&mut out, &signature);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};

    #[test]
    fn varints_are_minimal() {
        for (n, want) in [
            (0usize, vec![0u8]),
            (63, vec![63]),
            (64, vec![0x40, 64]),
            (16_383, vec![0x7f, 0xff]),
            (16_384, vec![0x80, 0, 0x40, 0]),
        ] {
            let mut v = Vec::new();
            varint(&mut v, n);
            assert_eq!(v, want, "{n}");
        }
    }

    #[test]
    fn a_remove_proposal_has_the_rfc_layout_and_the_services_signature() {
        let signer = DsSigner::from_seed(&[7; 32]).unwrap();
        let group = [0x5B; 16];
        let msg = remove_proposal(&group, 9, 3, &signer);
        // version | wire format | group<V> | epoch | external(0) | aad<V> | proposal | remove(3)
        let mut want = vec![0, 1, 0, 1, 16];
        want.extend_from_slice(&group);
        want.extend_from_slice(&9u64.to_be_bytes());
        want.extend_from_slice(&[2, 0, 0, 0, 0, 0, 2, 0, 3, 0, 0, 0, 3, 0x40, 64]);
        assert_eq!(&msg[..want.len()], &want[..]);
        assert_eq!(msg.len(), want.len() + 64);
        let sig = &msg[want.len()..];
        let pk = signer.public_key();
        let key = UnparsedPublicKey::new(&ED25519, &pk);
        assert!(
            key.verify(&remove_signed_content(&group, 9, 3), sig)
                .is_ok()
        );
        assert!(
            key.verify(&remove_signed_content(&group, 9, 4), sig)
                .is_err()
        );
        assert!(
            key.verify(&remove_signed_content(&group, 10, 3), sig)
                .is_err()
        );
        // Deterministic: a retried proposal is byte for byte the same (one idempotency key).
        assert_eq!(msg, remove_proposal(&group, 9, 3, &signer));
        assert!(!format!("{signer:?}").contains(&format!("{:?}", [7u8; 32])));
    }
}
