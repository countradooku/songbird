//! Signed epoch heads: `version u8 (1) | epoch u64 | root [32] | time_ms u64 | signature [64]`,
//! Ed25519 by the log key over `"songbird.v1/kt-head\0"` followed by the bytes before it. Apps pin
//! the log key and the VRF key; a head signed for one root cannot be shown for another, so two
//! heads for one epoch are evidence of a fork.

/// Head length.
pub const LEN: usize = 1 + 8 + 32 + 8 + 64;
/// Domain separation.
pub const CONTEXT: &[u8] = b"songbird.v1/kt-head\0";

/// A signed epoch head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedHead {
    /// The epoch.
    pub epoch: u64,
    /// Its root hash.
    pub root: [u8; 32],
    /// When it was signed (Unix milliseconds).
    pub time_ms: u64,
    /// Ed25519 by the log key.
    pub signature: [u8; 64],
}

/// A malformed head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed head")]
pub struct HeadError;

impl SignedHead {
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LEN);
        b.push(1);
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.time_ms.to_be_bytes());
        b
    }

    /// What the signature covers.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut b = CONTEXT.to_vec();
        b.extend_from_slice(&self.body());
        b
    }

    /// Signs a head.
    #[must_use]
    pub fn sign(
        key: &aws_lc_rs::signature::Ed25519KeyPair,
        epoch: u64,
        root: [u8; 32],
        time_ms: u64,
    ) -> Self {
        let mut h = Self {
            epoch,
            root,
            time_ms,
            signature: [0; 64],
        };
        let sig = key.sign(&h.signed_bytes());
        h.signature.copy_from_slice(sig.as_ref());
        h
    }

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decodes exactly [`LEN`] bytes.
    ///
    /// # Errors
    /// [`HeadError`].
    pub fn decode(b: &[u8]) -> Result<Self, HeadError> {
        if b.len() != LEN || b.first() != Some(&1) {
            return Err(HeadError);
        }
        let take = |a: usize, z: usize| b.get(a..z).ok_or(HeadError);
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(take(1, 9)?);
        let mut root = [0u8; 32];
        root.copy_from_slice(take(9, 41)?);
        let mut t = [0u8; 8];
        t.copy_from_slice(take(41, 49)?);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(49, 113)?);
        Ok(Self {
            epoch: u64::from_be_bytes(epoch),
            root,
            time_ms: u64::from_be_bytes(t),
            signature,
        })
    }
}
