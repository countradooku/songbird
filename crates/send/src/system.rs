//! Server-signed system frames (D-0037, D-0044; format in `songbird_proto::system`).
//!
//! A notice is signed once per recipient device (the device is inside the signed bytes) and
//! stored through the same mailbox path as a message, so it is durable before anything is
//! acknowledged, ordered by `seq` and pushed to an offline device. The notice ID is the send's
//! idempotency key: a retried notice is stored once.

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use songbird_mailbox::{NewEnvelope, Payload, StoreRequest, StoreSend};
use songbird_proto::frame::{Recipient, RejectReason, SendPayload, SendStatus};
use songbird_proto::system::{KEY_ID_LEN, Kind, NOTICE_ID_LEN, SystemFrame};
use songbird_proto::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use songbird_router::Router;
use songbird_types::DeviceId;

use crate::{RETRY_MS, SendPath};

/// Why a notice could not be signed or sent.
#[derive(Debug, thiserror::Error)]
pub enum SystemError {
    /// The seed is not a valid Ed25519 key, or no randomness.
    #[error("system key unusable")]
    Key,
    /// The body is over the format's limit.
    #[error("system frame body too large")]
    TooLarge,
    /// A target device is not in the directory; nothing was stored.
    #[error("unknown device")]
    UnknownDevice,
    /// The mailbox did not store it (status for a retry).
    #[error("not stored")]
    NotStored(SendStatus),
}

/// The server's system key: signs notices. Held only by services that issue them.
pub struct SystemSigner {
    key: Ed25519KeyPair,
    key_id: [u8; KEY_ID_LEN],
}

impl std::fmt::Debug for SystemSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemSigner").finish_non_exhaustive()
    }
}

/// The key ID of a system public key: the first bytes of its SHA-256.
#[must_use]
pub fn key_id(public_key: &[u8; PUBLIC_KEY_LEN]) -> [u8; KEY_ID_LEN] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, public_key);
    let mut id = [0u8; KEY_ID_LEN];
    if let Some(s) = d.as_ref().get(..KEY_ID_LEN) {
        id.copy_from_slice(s);
    }
    id
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl SystemSigner {
    /// From the 32-byte Ed25519 seed (a secret from the secrets store, D-0010).
    ///
    /// # Errors
    /// [`SystemError::Key`].
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, SystemError> {
        // The copy is wiped when it goes out of scope (best effort).
        let seed = zeroize::Zeroizing::new(*seed);
        let key =
            Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).map_err(|_| SystemError::Key)?;
        let key_id = key_id(&public(&key));
        Ok(Self { key, key_id })
    }

    /// The public key apps pin.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        public(&self.key)
    }

    /// Signs a notice for one device (a fresh notice ID, issued now).
    ///
    /// # Errors
    /// [`SystemError::TooLarge`] or [`SystemError::Key`] (no randomness).
    pub fn sign(
        &self,
        device: DeviceId,
        kind: Kind,
        body: &[u8],
        notice_id: [u8; NOTICE_ID_LEN],
    ) -> Result<bytes::Bytes, SystemError> {
        let frame = SystemFrame {
            key_id: self.key_id,
            device,
            issued_at_ms: now_ms(),
            notice_id,
            kind,
            body: bytes::Bytes::copy_from_slice(body),
        };
        let input = frame.signing_input().map_err(|_| SystemError::TooLarge)?;
        let sig = self.key.sign(&input);
        let mut s = [0u8; SIGNATURE_LEN];
        s.copy_from_slice(sig.as_ref());
        frame.encode_signed(&s).map_err(|_| SystemError::TooLarge)
    }
}

fn public(key: &Ed25519KeyPair) -> [u8; PUBLIC_KEY_LEN] {
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk.copy_from_slice(key.public_key().as_ref());
    pk
}

impl<M: StoreSend, R: Router> SendPath<'_, M, R> {
    /// Sends a notice to `devices` (each must exist): signed per device, stored durably in one
    /// send (all or nothing, invariant 1), then routed, with push wake-ups for offline devices.
    /// No device-list completeness rule applies: the server chooses exactly whom it tells.
    ///
    /// # Errors
    /// [`SystemError`]; on [`SystemError::NotStored`] the caller retries later (the notice ID
    /// makes a retry with the same ID store once).
    pub async fn send_system(
        &self,
        signer: &SystemSigner,
        devices: &[DeviceId],
        kind: Kind,
        body: &[u8],
        notice_id: [u8; NOTICE_ID_LEN],
    ) -> Result<(), SystemError> {
        {
            let dir = self.directory.load();
            if devices.iter().any(|d| !dir.contains(d)) {
                return Err(SystemError::UnknownDevice);
            }
        }
        let mut recipients = Vec::with_capacity(devices.len());
        for d in devices {
            recipients.push(Recipient {
                device: *d,
                envelope: signer.sign(*d, kind, body, notice_id)?,
            });
        }
        let req = StoreRequest {
            idempotency_key: Some(notice_id),
            mls: None,
            payload: Payload::PerDevice(
                recipients
                    .iter()
                    .map(|r| NewEnvelope {
                        device: r.device,
                        envelope: r.envelope.clone(),
                    })
                    .collect(),
            ),
        };
        let outcome = self.mailbox.store_send(req).await.map_err(|e| {
            self.metrics.mailbox_errors.inc();
            let reason = match e {
                songbird_mailbox::MailboxError::IdempotencyConflict => {
                    RejectReason::IdempotencyConflict
                }
                _ => RejectReason::Unavailable,
            };
            SystemError::NotStored(SendStatus::Rejected {
                reason,
                retry_after_ms: RETRY_MS,
            })
        })?;
        self.route(SendPayload::PerDevice(recipients), outcome.seqs)
            .await;
        Ok(())
    }
}
