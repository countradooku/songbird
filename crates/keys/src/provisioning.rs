//! Device provisioning (Prompt 3, M4, D-0052; `docs/PROTOCOL.md` §4.6): what clients do around
//! the server's provisioning channel. The server only stores and forwards the sealed bytes; it
//! never runs [`open`] and never holds a provisioning key. Here so the client library and the
//! tests share one implementation.
//!
//! - The new device draws a [`ProvisioningKey`] and shows its public key (with the channel ID)
//!   as a QR code.
//! - The primary [`seal`]s the provisioning message to it: X25519 with a fresh ephemeral key,
//!   HKDF-SHA256, AES-256-GCM; the key is used once, so the nonce is fixed.
//! - The new device [`open`]s it; another key, a changed byte or a truncation fails.
//! - The new device proves to the primary that the keys it registered are its own with
//!   [`confirm_tag`], a MAC under a key that travelled only inside the sealed message, so the
//!   server, which sees the link request, cannot substitute keys of its own.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::{hkdf, hmac};

use crate::xeddsa::x25519_public_key_ok;

/// Envelope version.
pub const VERSION: u8 = 1;
/// X25519 public key length.
pub const PUBLIC_LEN: usize = 32;
/// Envelope overhead: version, ephemeral key, GCM tag.
pub const OVERHEAD: usize = 1 + PUBLIC_LEN + 16;

const SALT: &[u8] = b"songbird.v1/provisioning";
const CONFIRM_CONTEXT: &[u8] = b"songbird.v1/link-confirm\0";

/// Provisioning failed (one answer for every cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("provisioning envelope refused")]
pub struct ProvisioningError;

/// The new device's provisioning key (X25519), shown as its public half in the QR code.
pub struct ProvisioningKey {
    private: PrivateKey,
    public: [u8; PUBLIC_LEN],
}

impl std::fmt::Debug for ProvisioningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningKey").finish_non_exhaustive()
    }
}

impl ProvisioningKey {
    /// A fresh key.
    ///
    /// # Errors
    /// The random source failed.
    pub fn generate() -> Result<Self, ProvisioningError> {
        let private = PrivateKey::generate(&X25519).map_err(|_| ProvisioningError)?;
        let public = private
            .compute_public_key()
            .map_err(|_| ProvisioningError)?
            .as_ref()
            .try_into()
            .map_err(|_| ProvisioningError)?;
        Ok(Self { private, public })
    }

    /// The key from its 32-byte private scalar (an operator's offline key, such as the
    /// moderation key that opens sealed reports, Prompt 4).
    ///
    /// # Errors
    /// The bytes are not an X25519 private key.
    pub fn from_private(private: &[u8; 32]) -> Result<Self, ProvisioningError> {
        let private =
            PrivateKey::from_private_key(&X25519, private).map_err(|_| ProvisioningError)?;
        let public = private
            .compute_public_key()
            .map_err(|_| ProvisioningError)?
            .as_ref()
            .try_into()
            .map_err(|_| ProvisioningError)?;
        Ok(Self { private, public })
    }

    /// The public key for the QR code.
    #[must_use]
    pub fn public(&self) -> [u8; PUBLIC_LEN] {
        self.public
    }
}

fn aead_key(
    salt: &[u8],
    shared: &[u8],
    ephemeral: &[u8; PUBLIC_LEN],
    recipient: &[u8; PUBLIC_LEN],
) -> Result<LessSafeKey, ProvisioningError> {
    // An all-zero shared secret means a low-order peer key: refused (aws-lc-rs refuses it too).
    if shared.iter().all(|b| *b == 0) {
        return Err(ProvisioningError);
    }
    let mut info = [0u8; 2 * PUBLIC_LEN];
    info[..PUBLIC_LEN].copy_from_slice(ephemeral);
    info[PUBLIC_LEN..].copy_from_slice(recipient);
    let mut k = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
        .extract(shared)
        .expand(&[&info], &AES_256_GCM)
        .and_then(|o| o.fill(&mut k))
        .map_err(|_| ProvisioningError)?;
    UnboundKey::new(&AES_256_GCM, &k)
        .map(LessSafeKey::new)
        .map_err(|_| ProvisioningError)
}

fn aad(ephemeral: &[u8; PUBLIC_LEN], recipient: &[u8; PUBLIC_LEN]) -> [u8; 1 + 2 * PUBLIC_LEN] {
    let mut a = [0u8; 1 + 2 * PUBLIC_LEN];
    a[0] = VERSION;
    a[1..=PUBLIC_LEN].copy_from_slice(ephemeral);
    a[1 + PUBLIC_LEN..].copy_from_slice(recipient);
    a
}

/// Seals `plaintext` to the new device's provisioning public key:
/// `version u8 | ephemeral [32] | AES-256-GCM(plaintext) || tag [16]`.
///
/// # Errors
/// A dishonest recipient key or a random-source failure.
pub fn seal(recipient: &[u8; PUBLIC_LEN], plaintext: &[u8]) -> Result<Vec<u8>, ProvisioningError> {
    seal_with(SALT, recipient, plaintext)
}

/// [`seal`] under another domain (the HKDF salt): the same construction for another purpose
/// (sealed reports, Prompt 4), so an envelope sealed for one purpose never opens for another.
///
/// # Errors
/// As [`seal`].
pub fn seal_with(
    domain: &[u8],
    recipient: &[u8; PUBLIC_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, ProvisioningError> {
    if !x25519_public_key_ok(recipient) {
        return Err(ProvisioningError);
    }
    let eph = ProvisioningKey::generate()?;
    let key = agreement::agree(
        &eph.private,
        UnparsedPublicKey::new(&X25519, recipient),
        ProvisioningError,
        |shared| aead_key(domain, shared, &eph.public, recipient),
    )?;
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.push(VERSION);
    out.extend_from_slice(&eph.public);
    let mut body = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::from(aad(&eph.public, recipient)),
        &mut body,
    )
    .map_err(|_| ProvisioningError)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens an envelope sealed to `key`.
///
/// # Errors
/// [`ProvisioningError`] for another key, any changed byte, a truncation, a dishonest
/// ephemeral key.
pub fn open(key: &ProvisioningKey, envelope: &[u8]) -> Result<Vec<u8>, ProvisioningError> {
    open_with(SALT, key, envelope)
}

/// [`open`] under another domain ([`seal_with`]).
///
/// # Errors
/// As [`open`], and for an envelope sealed under another domain.
pub fn open_with(
    domain: &[u8],
    key: &ProvisioningKey,
    envelope: &[u8],
) -> Result<Vec<u8>, ProvisioningError> {
    let (&version, rest) = envelope.split_first().ok_or(ProvisioningError)?;
    let (eph, ct) = rest.split_at_checked(PUBLIC_LEN).ok_or(ProvisioningError)?;
    let eph: [u8; PUBLIC_LEN] = eph.try_into().map_err(|_| ProvisioningError)?;
    if version != VERSION || ct.len() < 16 || !x25519_public_key_ok(&eph) {
        return Err(ProvisioningError);
    }
    let aead = agreement::agree(
        &key.private,
        UnparsedPublicKey::new(&X25519, &eph),
        ProvisioningError,
        |shared| aead_key(domain, shared, &eph, &key.public),
    )?;
    let mut body = ct.to_vec();
    let plain = aead
        .open_in_place(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::from(aad(&eph, &key.public)),
            &mut body,
        )
        .map_err(|_| ProvisioningError)?;
    Ok(plain.to_vec())
}

/// The link confirmation tag: HMAC-SHA256 under the confirmation key the primary sent inside
/// the sealed message, over a context and the link transcript
/// (`songbird_proto::devices::link_transcript`).
#[must_use]
pub fn confirm_tag(confirm_key: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, confirm_key);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(CONFIRM_CONTEXT);
    ctx.update(transcript);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// Checks a confirmation tag in constant time.
#[must_use]
pub fn confirm_ok(confirm_key: &[u8; 32], transcript: &[u8], tag: &[u8; 32]) -> bool {
    let k = hmac::Key::new(hmac::HMAC_SHA256, confirm_key);
    let mut msg = CONFIRM_CONTEXT.to_vec();
    msg.extend_from_slice(transcript);
    hmac::verify(&k, &msg, tag).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use super::*;

    #[test]
    fn sealed_messages_open_only_for_their_key_and_unchanged() {
        let k = ProvisioningKey::generate().unwrap();
        let other = ProvisioningKey::generate().unwrap();
        let e = seal(&k.public(), b"provision me").unwrap();
        assert_eq!(e.len(), OVERHEAD + 12);
        assert_eq!(open(&k, &e).unwrap(), b"provision me");
        // Wrong recipient.
        assert_eq!(open(&other, &e), Err(ProvisioningError));
        // Every flipped byte and every truncation.
        for i in 0..e.len() {
            let mut t = e.clone();
            t[i] ^= 1;
            assert!(open(&k, &t).is_err(), "byte {i}");
            assert!(open(&k, &e[..i]).is_err(), "cut {i}");
        }
        // Two seals of one message differ (fresh ephemeral keys).
        assert_ne!(
            seal(&k.public(), b"x").unwrap(),
            seal(&k.public(), b"x").unwrap()
        );
        // A low-order recipient key is refused.
        assert!(seal(&[0; 32], b"x").is_err());
    }

    #[test]
    fn a_domain_seals_for_its_purpose_only() {
        let k = ProvisioningKey::generate().unwrap();
        let e = seal_with(b"songbird.v1/report", &k.public(), b"report").unwrap();
        assert_eq!(open_with(b"songbird.v1/report", &k, &e).unwrap(), b"report");
        assert!(open(&k, &e).is_err(), "not a provisioning message");
        assert!(open_with(b"songbird.v1/report", &k, &seal(&k.public(), b"p").unwrap()).is_err());
    }

    #[test]
    fn confirmation_tags_bind_key_and_transcript() {
        let t = confirm_tag(&[1; 32], b"transcript");
        assert!(confirm_ok(&[1; 32], b"transcript", &t));
        assert!(!confirm_ok(&[2; 32], b"transcript", &t));
        assert!(!confirm_ok(&[1; 32], b"transcripT", &t));
    }
}
