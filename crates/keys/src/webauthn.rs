//! Passkeys: Songbird's own minimal WebAuthn relying-party verifier (Prompt 3, M4b, D-0053; the
//! owner's choice over a WebAuthn library). Proven against the W3C WebAuthn Level 3 test vectors
//! (`tests/webauthn_vectors.rs`).
//!
//! What it checks:
//!
//! - **Registration**: `clientDataJSON` (`type` `webauthn.create`, the expected challenge, an
//!   allowed origin, not cross-origin); the attestation object's authenticator data (RP ID hash,
//!   user present, user verified when required, attested credential data); the credential public
//!   key: ES256 (P-256, validated point) or EdDSA (an honest Ed25519 key). The attestation
//!   statement is **not** verified: Songbird asks for no attestation and trusts no authenticator
//!   vendor, so its format is only required to be a map.
//! - **Assertion**: `clientDataJSON` (`type` `webauthn.get`, challenge, origin, not cross-origin),
//!   the authenticator data (RP ID hash, flags, no attested data, signature counter growing
//!   unless both are zero), and the signature over `authenticatorData || SHA-256(clientDataJSON)`.
//!
//! CBOR is read by a strict subset parser: definite lengths, minimal integer encodings, no tags,
//! no floats, bounded depth and size.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ParsedPublicKey};

/// Largest attestation object or assertion part accepted.
pub const MAX_LEN: usize = 4096;
/// Longest credential ID (WebAuthn: at most 1023 bytes).
pub const MAX_CREDENTIAL_ID: usize = 1023;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// Why a ceremony was refused (one variant per check, for the caller's error codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebAuthnError {
    /// Malformed `clientDataJSON`, CBOR or authenticator data.
    #[error("malformed")]
    Malformed,
    /// Wrong `type`, challenge, origin, or cross-origin.
    #[error("client data")]
    ClientData,
    /// Another RP ID, or a required flag missing.
    #[error("authenticator data")]
    AuthenticatorData,
    /// An algorithm other than ES256 or EdDSA, or a dishonest key.
    #[error("unsupported key")]
    Key,
    /// The signature does not verify.
    #[error("signature")]
    Signature,
    /// The signature counter did not grow (a cloned authenticator).
    #[error("counter")]
    Counter,
}

/// A credential's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKey {
    /// ES256: uncompressed P-256 point `04 || x || y`.
    Es256([u8; 65]),
    /// EdDSA with Ed25519.
    Ed25519([u8; 32]),
}

impl CredentialKey {
    /// Stored form: `1 || 65 bytes` (ES256) or `2 || 32 bytes` (Ed25519).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Es256(k) => [&[1u8][..], k].concat(),
            Self::Ed25519(k) => [&[2u8][..], k].concat(),
        }
    }

    /// From the stored form.
    ///
    /// # Errors
    /// [`WebAuthnError::Key`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WebAuthnError> {
        match b.split_first() {
            Some((1, k)) => Ok(Self::Es256(k.try_into().map_err(|_| WebAuthnError::Key)?)),
            Some((2, k)) => Ok(Self::Ed25519(k.try_into().map_err(|_| WebAuthnError::Key)?)),
            _ => Err(WebAuthnError::Key),
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Es256(k) => ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, k)
                .is_ok_and(|p| p.verify_sig(message, signature).is_ok()),
            Self::Ed25519(k) => {
                <&[u8; 64]>::try_from(signature).is_ok_and(|s| crate::ed25519_verify(k, message, s))
            }
        }
    }
}

/// A registered credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Its ID.
    pub id: Vec<u8>,
    /// Its public key.
    pub key: CredentialKey,
    /// Its signature counter at registration.
    pub sign_count: u32,
}

/// The relying party: its ID and allowed origins.
#[derive(Debug, Clone)]
pub struct RelyingParty<'a> {
    /// RP ID (a domain).
    pub id: &'a str,
    /// Origins `clientDataJSON` may name (`https://…`, or an app's origin).
    pub origins: &'a [String],
    /// Require the user-verified flag (on in production; the W3C vectors lack it).
    pub require_uv: bool,
}

// ----- CBOR (strict subset) -----

#[derive(Debug, Clone, PartialEq)]
enum Cbor<'a> {
    Int(i128),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Cbor<'a>>),
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
}

struct Reader<'a> {
    b: &'a [u8],
    items: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WebAuthnError> {
        let (h, t) = self.b.split_at_checked(n).ok_or(WebAuthnError::Malformed)?;
        self.b = t;
        Ok(h)
    }

    fn head(&mut self) -> Result<(u8, u64), WebAuthnError> {
        let first = *self.take(1)?.first().ok_or(WebAuthnError::Malformed)?;
        let (major, info) = (first >> 5, first & 0x1f);
        let arg = match info {
            0..=23 => u64::from(info),
            24..=27 => {
                let n = 1usize << (info - 24);
                let v = self
                    .take(n)?
                    .iter()
                    .fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
                // Minimal encodings only.
                let min = match n {
                    1 => 24,
                    2 => 0x100,
                    4 => 0x1_0000,
                    _ => 0x1_0000_0000,
                };
                if v < min {
                    return Err(WebAuthnError::Malformed);
                }
                v
            }
            _ => return Err(WebAuthnError::Malformed),
        };
        Ok((major, arg))
    }

    fn item(&mut self, depth: usize) -> Result<Cbor<'a>, WebAuthnError> {
        self.items += 1;
        if depth > 8 || self.items > 512 {
            return Err(WebAuthnError::Malformed);
        }
        let (major, arg) = self.head()?;
        let len = |a: u64| usize::try_from(a).map_err(|_| WebAuthnError::Malformed);
        Ok(match major {
            0 => Cbor::Int(i128::from(arg)),
            1 => Cbor::Int(-1 - i128::from(arg)),
            2 => Cbor::Bytes(self.take(len(arg)?)?),
            3 => Cbor::Text(
                std::str::from_utf8(self.take(len(arg)?)?).map_err(|_| WebAuthnError::Malformed)?,
            ),
            4 => {
                let n = len(arg)?;
                if n > 64 {
                    return Err(WebAuthnError::Malformed);
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.item(depth + 1)?);
                }
                Cbor::Array(v)
            }
            5 => {
                let n = len(arg)?;
                if n > 64 {
                    return Err(WebAuthnError::Malformed);
                }
                let mut v: Vec<(Cbor<'a>, Cbor<'a>)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    if v.iter().any(|(x, _)| *x == k) {
                        return Err(WebAuthnError::Malformed);
                    }
                    let val = self.item(depth + 1)?;
                    v.push((k, val));
                }
                Cbor::Map(v)
            }
            _ => return Err(WebAuthnError::Malformed),
        })
    }
}

/// One CBOR item from the front of `b`; the rest.
fn cbor(b: &[u8]) -> Result<(Cbor<'_>, &[u8]), WebAuthnError> {
    let mut r = Reader { b, items: 0 };
    let v = r.item(0)?;
    Ok((v, r.b))
}

fn get<'a, 'b>(map: &'b [(Cbor<'a>, Cbor<'a>)], key: &Cbor<'_>) -> Option<&'b Cbor<'a>> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn cose_key(key: &Cbor<'_>) -> Result<CredentialKey, WebAuthnError> {
    let Cbor::Map(m) = key else {
        return Err(WebAuthnError::Key);
    };
    let int = |k: i128| match get(m, &Cbor::Int(k)) {
        Some(Cbor::Int(v)) => Some(*v),
        _ => None,
    };
    let bytes = |k: i128| match get(m, &Cbor::Int(k)) {
        Some(Cbor::Bytes(v)) => Some(*v),
        _ => None,
    };
    match (int(1), int(3), int(-1)) {
        // EC2, ES256, P-256.
        (Some(2), Some(-7), Some(1)) => {
            let (Some(x), Some(y)) = (bytes(-2), bytes(-3)) else {
                return Err(WebAuthnError::Key);
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(WebAuthnError::Key);
            }
            let mut k = [0u8; 65];
            k[0] = 4;
            k[1..33].copy_from_slice(x);
            k[33..].copy_from_slice(y);
            ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, k).map_err(|_| WebAuthnError::Key)?;
            Ok(CredentialKey::Es256(k))
        }
        // OKP, EdDSA, Ed25519.
        (Some(1), Some(-8), Some(6)) => {
            let x: [u8; 32] = bytes(-2)
                .and_then(|x| x.try_into().ok())
                .ok_or(WebAuthnError::Key)?;
            if !crate::ed25519_public_key_ok(&x) {
                return Err(WebAuthnError::Key);
            }
            Ok(CredentialKey::Ed25519(x))
        }
        _ => Err(WebAuthnError::Key),
    }
}

// ----- client data -----

/// Unpadded base64url (RFC 4648 §5), as `clientDataJSON` carries the challenge.
#[must_use]
pub fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, x)| acc | (u32::from(*x) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            s.push(char::from(*A.get(idx).unwrap_or(&b'A')));
        }
    }
    s
}

fn check_client_data(
    json: &[u8],
    kind: &str,
    challenge: &[u8],
    rp: &RelyingParty<'_>,
) -> Result<(), WebAuthnError> {
    if json.len() > MAX_LEN {
        return Err(WebAuthnError::Malformed);
    }
    let v: serde_json::Value =
        serde_json::from_slice(json).map_err(|_| WebAuthnError::Malformed)?;
    let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
    let ok = s("type") == Some(kind)
        && s("challenge") == Some(base64url(challenge).as_str())
        && s("origin").is_some_and(|o| rp.origins.iter().any(|x| x == o))
        && !matches!(v.get("crossOrigin"), Some(serde_json::Value::Bool(true)))
        && v.get("topOrigin").is_none();
    if ok {
        Ok(())
    } else {
        Err(WebAuthnError::ClientData)
    }
}

struct AuthData<'a> {
    flags: u8,
    sign_count: u32,
    attested: Option<(&'a [u8], CredentialKey)>,
}

fn auth_data<'a>(
    b: &'a [u8],
    rp: &RelyingParty<'_>,
    want_attested: bool,
) -> Result<AuthData<'a>, WebAuthnError> {
    if b.len() > MAX_LEN || b.len() < 37 {
        return Err(WebAuthnError::Malformed);
    }
    let (rp_hash, rest) = b.split_at(32);
    let (&flags, rest) = rest.split_first().ok_or(WebAuthnError::Malformed)?;
    let (count, mut rest) = rest.split_at_checked(4).ok_or(WebAuthnError::Malformed)?;
    if rp_hash != digest(&SHA256, rp.id.as_bytes()).as_ref()
        || flags & FLAG_UP == 0
        || (rp.require_uv && flags & FLAG_UV == 0)
        || (flags & FLAG_AT != 0) != want_attested
    {
        return Err(WebAuthnError::AuthenticatorData);
    }
    let sign_count = u32::from_be_bytes(count.try_into().map_err(|_| WebAuthnError::Malformed)?);
    let attested = if want_attested {
        let (_aaguid, r) = rest.split_at_checked(16).ok_or(WebAuthnError::Malformed)?;
        let (n, r) = r.split_at_checked(2).ok_or(WebAuthnError::Malformed)?;
        let n = usize::from(u16::from_be_bytes(
            n.try_into().map_err(|_| WebAuthnError::Malformed)?,
        ));
        if n == 0 || n > MAX_CREDENTIAL_ID {
            return Err(WebAuthnError::Malformed);
        }
        let (id, r) = r.split_at_checked(n).ok_or(WebAuthnError::Malformed)?;
        let (key, r) = cbor(r)?;
        rest = r;
        Some((id, cose_key(&key)?))
    } else {
        None
    };
    if flags & FLAG_ED != 0 {
        let (ext, r) = cbor(rest)?;
        if !matches!(ext, Cbor::Map(_)) {
            return Err(WebAuthnError::Malformed);
        }
        rest = r;
    }
    if !rest.is_empty() {
        return Err(WebAuthnError::Malformed);
    }
    Ok(AuthData {
        flags,
        sign_count,
        attested,
    })
}

/// The challenge a passkey signs to approve linking a device:
/// `SHA-256("songbird.v1/link-passkey\0" || transcript)`, the transcript being the link request's
/// identity-context one, so the assertion is bound to the token, the device ID, both new keys and
/// the server, and needs no server state.
#[must_use]
pub fn link_challenge(transcript: &[u8]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&SHA256);
    ctx.update(b"songbird.v1/link-passkey\0");
    ctx.update(transcript);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Checks a registration (`navigator.credentials.create`) and returns the credential.
///
/// # Errors
/// [`WebAuthnError`].
pub fn check_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: &[u8],
    rp: &RelyingParty<'_>,
) -> Result<Credential, WebAuthnError> {
    check_client_data(client_data_json, "webauthn.create", challenge, rp)?;
    if attestation_object.len() > MAX_LEN {
        return Err(WebAuthnError::Malformed);
    }
    let (obj, rest) = cbor(attestation_object)?;
    let Cbor::Map(m) = obj else {
        return Err(WebAuthnError::Malformed);
    };
    if !rest.is_empty()
        || !matches!(get(&m, &Cbor::Text("fmt")), Some(Cbor::Text(_)))
        || !matches!(get(&m, &Cbor::Text("attStmt")), Some(Cbor::Map(_)))
    {
        return Err(WebAuthnError::Malformed);
    }
    let Some(Cbor::Bytes(ad)) = get(&m, &Cbor::Text("authData")) else {
        return Err(WebAuthnError::Malformed);
    };
    let a = auth_data(ad, rp, true)?;
    let (id, key) = a.attested.ok_or(WebAuthnError::Malformed)?;
    Ok(Credential {
        id: id.to_vec(),
        key,
        sign_count: a.sign_count,
    })
}

/// Checks an assertion (`navigator.credentials.get`) by a stored credential; returns the new
/// signature counter to store.
///
/// # Errors
/// [`WebAuthnError`].
pub fn check_assertion(
    key: &CredentialKey,
    stored_count: u32,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    challenge: &[u8],
    rp: &RelyingParty<'_>,
) -> Result<u32, WebAuthnError> {
    check_client_data(client_data_json, "webauthn.get", challenge, rp)?;
    let a = auth_data(authenticator_data, rp, false)?;
    let _ = a.flags;
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(digest(&SHA256, client_data_json).as_ref());
    if signature.len() > 256 || !key.verify(&message, signature) {
        return Err(WebAuthnError::Signature);
    }
    if (a.sign_count != 0 || stored_count != 0) && a.sign_count <= stored_count {
        return Err(WebAuthnError::Counter);
    }
    Ok(a.sign_count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    #[test]
    fn base64url_matches_rfc4648() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn cbor_refuses_non_minimal_indefinite_tags_and_duplicates() {
        assert!(cbor(&[0x18, 0x17]).is_err()); // 23 in two bytes
        assert!(cbor(&[0x5f]).is_err()); // indefinite bytes
        assert!(cbor(&[0xc0, 0x00]).is_err()); // a tag
        assert!(cbor(&[0xf5]).is_err()); // true
        assert!(cbor(&[0xa2, 0x01, 0x00, 0x01, 0x00]).is_err()); // duplicate key
        assert_eq!(cbor(&[0x38, 0x18]).unwrap().0, Cbor::Int(-25));
        // Deep nesting.
        assert!(cbor(&[0x81; 20]).is_err());
    }
}
