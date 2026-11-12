//! Push registrations, sealed so that only the push service can read them (D-0036).
//!
//! `api` (which receives the registration) and `worker` hold only the push service's X25519
//! public key; the database holds only the sealed form, under a keyed hash of the device ID. A
//! stolen database, `api` or `worker` reveals no token.
//!
//! Sealing (an ECIES construction): a fresh X25519 key per registration; the shared secret goes
//! through HKDF-SHA256 (salt: both public keys; info: `songbird-push-token-v1`) to an
//! AES-256-GCM key; the AAD is the row key, so a sealed token moved to another device's row does
//! not open. Layout: `version u8 | ephemeral public key [32] | nonce [12] | ciphertext | tag`.
//!
//! Plaintext (bounded on decode): `kind u8 | fields`:
//! - 1 APNs: `token_len u8 | token | voip_len u8 | voip token` (`voip_len` 0: none)
//! - 2 FCM: `len u16 | token (UTF-8)`
//! - 3 Web Push: `len u16 | endpoint (UTF-8) | p256dh [65] | auth [16]`

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf;

const VERSION: u8 = 1;
const INFO: &[u8] = b"songbird-push-token-v1";

/// Longest APNs device token accepted (Apple's are 32 bytes today; they reserve up to 100).
pub const MAX_APNS_TOKEN: usize = 100;
/// Longest FCM registration token accepted.
pub const MAX_FCM_TOKEN: usize = 4096;
/// Longest Web Push endpoint URL accepted.
pub const MAX_ENDPOINT: usize = 2048;

/// Where a device is woken.
#[derive(Clone, PartialEq, Eq)]
pub enum Registration {
    /// Apple: the alert token and, for calls, the `PushKit` token.
    Apns {
        /// Device token for alert pushes.
        token: Vec<u8>,
        /// `PushKit` token for call pushes.
        voip: Option<Vec<u8>>,
    },
    /// Firebase Cloud Messaging.
    Fcm {
        /// Registration token.
        token: String,
    },
    /// `UnifiedPush` through Web Push to the user's own distributor.
    WebPush {
        /// The distributor's endpoint URL (validated by the push service before use).
        endpoint: String,
        /// The device's P-256 public key (uncompressed).
        p256dh: [u8; 65],
        /// The device's authentication secret.
        auth: [u8; 16],
    },
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Apns { .. } => "Apns",
            Self::Fcm { .. } => "Fcm",
            Self::WebPush { .. } => "WebPush",
        };
        f.debug_tuple("Registration").field(&kind).finish()
    }
}

/// Why a registration was refused or did not open. Carries nothing of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// A field is empty or too long.
    #[error("push registration invalid")]
    Invalid,
    /// It does not open (wrong key, wrong row, tampering, unknown version).
    #[error("push registration does not open")]
    Sealed,
}

impl Registration {
    /// Checks lengths.
    ///
    /// # Errors
    /// [`TokenError::Invalid`].
    pub fn validate(&self) -> Result<(), TokenError> {
        let ok = match self {
            Self::Apns { token, voip } => {
                (1..=MAX_APNS_TOKEN).contains(&token.len())
                    && voip
                        .as_ref()
                        .is_none_or(|v| (1..=MAX_APNS_TOKEN).contains(&v.len()))
            }
            Self::Fcm { token } => (1..=MAX_FCM_TOKEN).contains(&token.len()),
            Self::WebPush { endpoint, .. } => (1..=MAX_ENDPOINT).contains(&endpoint.len()),
        };
        if ok { Ok(()) } else { Err(TokenError::Invalid) }
    }

    fn encode(&self) -> Result<Vec<u8>, TokenError> {
        self.validate()?;
        let mut b = Vec::with_capacity(128);
        match self {
            Self::Apns { token, voip } => {
                b.push(1);
                b.push(u8::try_from(token.len()).map_err(|_| TokenError::Invalid)?);
                b.extend_from_slice(token);
                let v = voip.as_deref().unwrap_or_default();
                b.push(u8::try_from(v.len()).map_err(|_| TokenError::Invalid)?);
                b.extend_from_slice(v);
            }
            Self::Fcm { token } => {
                b.push(2);
                b.extend_from_slice(
                    &u16::try_from(token.len())
                        .map_err(|_| TokenError::Invalid)?
                        .to_be_bytes(),
                );
                b.extend_from_slice(token.as_bytes());
            }
            Self::WebPush {
                endpoint,
                p256dh,
                auth,
            } => {
                b.push(3);
                b.extend_from_slice(
                    &u16::try_from(endpoint.len())
                        .map_err(|_| TokenError::Invalid)?
                        .to_be_bytes(),
                );
                b.extend_from_slice(endpoint.as_bytes());
                b.extend_from_slice(p256dh);
                b.extend_from_slice(auth);
            }
        }
        Ok(b)
    }

    fn decode(b: &[u8]) -> Result<Self, TokenError> {
        let bad = || TokenError::Invalid;
        let (&kind, rest) = b.split_first().ok_or_else(bad)?;
        let r = match kind {
            1 => {
                let (&n, rest) = rest.split_first().ok_or_else(bad)?;
                let (token, rest) = rest.split_at_checked(usize::from(n)).ok_or_else(bad)?;
                let (&m, rest) = rest.split_first().ok_or_else(bad)?;
                if rest.len() != usize::from(m) {
                    return Err(bad());
                }
                Self::Apns {
                    token: token.to_vec(),
                    voip: (m > 0).then(|| rest.to_vec()),
                }
            }
            2 => {
                let (n, rest) = rest.split_at_checked(2).ok_or_else(bad)?;
                let n = usize::from(u16::from_be_bytes(n.try_into().map_err(|_| bad())?));
                if rest.len() != n {
                    return Err(bad());
                }
                Self::Fcm {
                    token: String::from_utf8(rest.to_vec()).map_err(|_| bad())?,
                }
            }
            3 => {
                let (n, rest) = rest.split_at_checked(2).ok_or_else(bad)?;
                let n = usize::from(u16::from_be_bytes(n.try_into().map_err(|_| bad())?));
                let (endpoint, rest) = rest.split_at_checked(n).ok_or_else(bad)?;
                let (p, auth) = rest.split_at_checked(65).ok_or_else(bad)?;
                Self::WebPush {
                    endpoint: String::from_utf8(endpoint.to_vec()).map_err(|_| bad())?,
                    p256dh: p.try_into().map_err(|_| bad())?,
                    auth: auth.try_into().map_err(|_| bad())?,
                }
            }
            _ => return Err(bad()),
        };
        r.validate()?;
        Ok(r)
    }
}

fn aead_key(shared: &[u8], eph: &[u8], recipient: &[u8]) -> Result<LessSafeKey, Unspecified> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph);
    salt.extend_from_slice(recipient);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(shared);
    let mut k = [0u8; 32];
    prk.expand(&[INFO], hkdf::HKDF_SHA256)?.fill(&mut k)?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k)?);
    k.fill(0);
    Ok(key)
}

/// Seals a registration to the push service's public key, bound to its row (`index`).
///
/// # Errors
/// [`TokenError::Invalid`] for a registration out of bounds; [`TokenError::Sealed`] if the key
/// or the random source fails.
pub fn seal(
    push_public: &[u8; 32],
    index: &[u8; 32],
    reg: &Registration,
) -> Result<Vec<u8>, TokenError> {
    let mut body = reg.encode()?;
    let eph = PrivateKey::generate(&X25519).map_err(|_| TokenError::Sealed)?;
    let eph_pub = eph.compute_public_key().map_err(|_| TokenError::Sealed)?;
    let key = agreement::agree(
        &eph,
        UnparsedPublicKey::new(&X25519, push_public),
        TokenError::Sealed,
        |s| aead_key(s, eph_pub.as_ref(), push_public).map_err(|_| TokenError::Sealed),
    )?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| TokenError::Sealed)?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(index.as_slice()),
        &mut body,
    )
    .map_err(|_| TokenError::Sealed)?;
    let mut out = Vec::with_capacity(1 + 32 + NONCE_LEN + body.len());
    out.push(VERSION);
    out.extend_from_slice(eph_pub.as_ref());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a sealed registration with the push service's private key.
///
/// # Errors
/// [`TokenError`].
pub fn open(
    push_private: &PrivateKey,
    index: &[u8; 32],
    sealed: &[u8],
) -> Result<Registration, TokenError> {
    if sealed.len() > 16 * 1024 {
        return Err(TokenError::Sealed);
    }
    let (&v, rest) = sealed.split_first().ok_or(TokenError::Sealed)?;
    if v != VERSION {
        return Err(TokenError::Sealed);
    }
    let (eph, rest) = rest.split_at_checked(32).ok_or(TokenError::Sealed)?;
    let (nonce, ct) = rest.split_at_checked(NONCE_LEN).ok_or(TokenError::Sealed)?;
    let mine = push_private
        .compute_public_key()
        .map_err(|_| TokenError::Sealed)?;
    let key = agreement::agree(
        push_private,
        UnparsedPublicKey::new(&X25519, eph),
        TokenError::Sealed,
        |s| aead_key(s, eph, mine.as_ref()).map_err(|_| TokenError::Sealed),
    )?;
    let mut buf = ct.to_vec();
    let plain = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| TokenError::Sealed)?,
            Aad::from(index.as_slice()),
            &mut buf,
        )
        .map_err(|_| TokenError::Sealed)?;
    Registration::decode(plain)
}

/// The push service's key pair from its 32-byte private key (hex in the secrets store): the
/// private key for `push`, the public key for `api` and `worker` configuration.
///
/// # Errors
/// The key is not a valid X25519 private key.
pub fn key_pair(private: &[u8; 32]) -> Result<(PrivateKey, [u8; 32]), TokenError> {
    let k = PrivateKey::from_private_key(&X25519, private).map_err(|_| TokenError::Sealed)?;
    let p = k.compute_public_key().map_err(|_| TokenError::Sealed)?;
    let public: [u8; 32] = p.as_ref().try_into().map_err(|_| TokenError::Sealed)?;
    Ok((k, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn regs() -> Vec<Registration> {
        vec![
            Registration::Apns {
                token: vec![7; 32],
                voip: Some(vec![8; 32]),
            },
            Registration::Apns {
                token: vec![7; 32],
                voip: None,
            },
            Registration::Fcm {
                token: "fcm-token:abc".into(),
            },
            Registration::WebPush {
                endpoint: "https://push.example.org/x/y".into(),
                p256dh: [4; 65],
                auth: [5; 16],
            },
        ]
    }

    #[test]
    fn only_the_push_key_opens_and_only_on_its_row() {
        let (private, public) = key_pair(&[0x42; 32]).unwrap();
        let (other, _) = key_pair(&[0x43; 32]).unwrap();
        for r in regs() {
            let sealed = seal(&public, &[1; 32], &r).unwrap();
            assert_eq!(open(&private, &[1; 32], &sealed).unwrap(), r);
            assert_eq!(open(&private, &[2; 32], &sealed), Err(TokenError::Sealed));
            assert_eq!(open(&other, &[1; 32], &sealed), Err(TokenError::Sealed));
            // Nothing of the token is visible.
            assert!(!sealed.windows(8).any(|w| w == [7; 8] || w == b"fcm-toke"));
            assert!(!sealed.windows(8).any(|w| w == b"https://"));
            // Every sealing differs (fresh ephemeral key).
            assert_ne!(sealed, seal(&public, &[1; 32], &r).unwrap());
        }
    }

    #[test]
    fn bounds_are_enforced() {
        let (_, public) = key_pair(&[0x42; 32]).unwrap();
        for bad in [
            Registration::Apns {
                token: vec![],
                voip: None,
            },
            Registration::Apns {
                token: vec![1; MAX_APNS_TOKEN + 1],
                voip: None,
            },
            Registration::Fcm {
                token: "x".repeat(MAX_FCM_TOKEN + 1),
            },
            Registration::WebPush {
                endpoint: String::new(),
                p256dh: [0; 65],
                auth: [0; 16],
            },
        ] {
            assert_eq!(seal(&public, &[1; 32], &bad), Err(TokenError::Invalid));
        }
        assert_eq!(format!("{:?}", regs()[2]), "Registration(\"Fcm\")");
    }

    proptest! {
        #[test]
        fn decode_and_open_never_panic(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = Registration::decode(&b);
            let (private, _) = key_pair(&[0x42; 32]).unwrap();
            prop_assert!(open(&private, &[1; 32], &b).is_err());
        }
    }
}
