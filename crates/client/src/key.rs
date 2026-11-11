//! The device authentication key (Ed25519, D-0018).

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use songbird_proto::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use songbird_types::DeviceId;

/// A device and its authentication key pair.
pub struct DeviceKey {
    device: DeviceId,
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

/// The key pair could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid device key")]
pub struct KeyError;

impl DeviceKey {
    /// From a 32-byte Ed25519 seed (the private key). The app keeps the seed in its secure
    /// storage; the server only ever learns the public key.
    ///
    /// # Errors
    /// [`KeyError`] if the seed is rejected.
    pub fn from_seed(device: DeviceId, seed: &[u8; 32]) -> Result<Self, KeyError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError)?;
        Ok(Self { device, pair })
    }

    /// A fresh random key for `device`.
    ///
    /// # Errors
    /// [`KeyError`] if the system random source fails.
    pub fn generate(device: DeviceId) -> Result<(Self, [u8; 32]), KeyError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| KeyError)?;
        Ok((Self::from_seed(device, &seed)?, seed))
    }

    /// The device.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// The public key, registered with the server.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        let pk = self.pair.public_key().as_ref();
        if let Some(src) = pk.get(..PUBLIC_KEY_LEN) {
            out.copy_from_slice(src);
        }
        out
    }

    /// Signs `msg`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        let mut out = [0u8; SIGNATURE_LEN];
        let sig = self.pair.sign(msg);
        if let Some(src) = sig.as_ref().get(..SIGNATURE_LEN) {
            out.copy_from_slice(src);
        }
        out
    }
}
