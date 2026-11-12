//! Signed device requests (D-0036).
//!
//! Every request to `api` is signed with the device's Ed25519 authentication key, the same key
//! it authenticates to `delivery` with. No bearer tokens exist, so none can leak or be replayed
//! from logs. The signature covers a domain-separated transcript:
//!
//! ```text
//! "songbird-api-v1\0" | server name | "\0" | method | "\0" | path | "\0" |
//! timestamp ms u64 | nonce [16] | device [16] | body SHA-256 [32] (all zero: unsigned body)
//! ```
//!
//! Headers: `authorization: Songbird <device hex>.<timestamp ms>.<nonce hex>.<signature hex>`
//! and `x-songbird-content-sha256: <hex>` for a signed body. Only an attachment upload may send
//! an unsigned body (the content is the client's own AEAD ciphertext, checked by length).
//!
//! The server accepts timestamps within [`MAX_SKEW`] of its clock and each (device, nonce) once:
//! a keyed record in `valkey-hot` expires after twice the skew. Unknown and disabled devices
//! fail exactly like a bad signature, after the same work (no enumeration).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use songbird_types::DeviceId;

/// Largest accepted difference between a request's timestamp and the server's clock.
pub const MAX_SKEW: Duration = Duration::from_secs(60);

/// Header carrying the signature.
pub const AUTHORIZATION: &str = "authorization";
/// Header carrying the body digest.
pub const CONTENT_SHA256: &str = "x-songbird-content-sha256";

const DOMAIN: &[u8] = b"songbird-api-v1\0";

/// A parsed `authorization` header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signed {
    /// Claimed device.
    pub device: DeviceId,
    /// Milliseconds since the Unix epoch.
    pub ts_ms: u64,
    /// Single-use nonce.
    pub nonce: [u8; 16],
    /// Ed25519 signature.
    pub sig: [u8; 64],
}

impl std::fmt::Debug for Signed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signed(<redacted>)")
    }
}

impl Signed {
    /// Parses `Songbird <device>.<ts>.<nonce>.<sig>`; `None` for anything else.
    #[must_use]
    pub fn parse(h: &str) -> Option<Self> {
        let rest = h.strip_prefix("Songbird ")?;
        if rest.len() > 32 + 1 + 20 + 1 + 32 + 1 + 128 {
            return None;
        }
        let mut parts = rest.split('.');
        let device = DeviceId::parse_hex(parts.next()?).ok()?;
        let ts = parts.next()?;
        if ts.is_empty() || ts.len() > 20 || !ts.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let ts_ms = ts.parse().ok()?;
        let mut nonce = [0u8; 16];
        hex::decode_to_slice(parts.next()?, &mut nonce).ok()?;
        let mut sig = [0u8; 64];
        hex::decode_to_slice(parts.next()?, &mut sig).ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            device,
            ts_ms,
            nonce,
            sig,
        })
    }
}

/// The signed transcript.
#[must_use]
pub fn transcript(
    server_name: &str,
    method: &str,
    path: &str,
    ts_ms: u64,
    nonce: &[u8; 16],
    device: &DeviceId,
    body_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DOMAIN.len() + server_name.len() + path.len() + 96);
    t.extend_from_slice(DOMAIN);
    t.extend_from_slice(server_name.as_bytes());
    t.push(0);
    t.extend_from_slice(method.as_bytes());
    t.push(0);
    t.extend_from_slice(path.as_bytes());
    t.push(0);
    t.extend_from_slice(&ts_ms.to_be_bytes());
    t.extend_from_slice(nonce);
    t.extend_from_slice(device.as_bytes());
    t.extend_from_slice(body_sha256);
    t
}

/// SHA-256 of a body.
#[must_use]
pub fn body_sha256(body: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, body);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Whether `signed` verifies for `key` (or, with no key, runs the same check against a dummy
/// key and fails: unknown devices cost the same).
#[must_use]
pub fn verify(key: Option<&[u8; 32]>, transcript: &[u8], sig: &[u8; 64]) -> bool {
    const DUMMY: [u8; 32] = [0x5a; 32];
    let k = key.unwrap_or(&DUMMY);
    let ok = UnparsedPublicKey::new(&ED25519, k)
        .verify(transcript, sig)
        .is_ok();
    ok && key.is_some()
}

/// Whether `ts_ms` is within [`MAX_SKEW`] of now.
#[must_use]
pub fn fresh(ts_ms: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let skew = u64::try_from(MAX_SKEW.as_millis()).unwrap_or(u64::MAX);
    now.abs_diff(ts_ms) <= skew
}

/// The `valkey-hot` key recording a used nonce: a hash, so Valkey holds neither the device ID
/// nor the nonce.
#[must_use]
pub fn nonce_key(device: &DeviceId, nonce: &[u8; 16]) -> String {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"songbird-api-nonce\0");
    ctx.update(device.as_bytes());
    ctx.update(nonce);
    let d = ctx.finish();
    let mut k = String::with_capacity(34);
    k.push_str("n:");
    k.push_str(&hex::encode(d.as_ref().get(..16).unwrap_or_default()));
    k
}

/// Signs a request (clients and tests): returns the `authorization` header value and, for a
/// signed body, the `x-songbird-content-sha256` value.
#[must_use]
pub fn sign(
    key: &Ed25519KeyPair,
    device: &DeviceId,
    server_name: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> (String, Option<String>) {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mut nonce = [0u8; 16];
    let _ = aws_lc_rs::rand::fill(&mut nonce);
    let hash = body.map(body_sha256);
    let t = transcript(
        server_name,
        method,
        path,
        ts_ms,
        &nonce,
        device,
        &hash.unwrap_or([0; 32]),
    );
    let sig = key.sign(&t);
    let mut header = String::with_capacity(9 + 32 + 1 + 20 + 1 + 32 + 1 + 128);
    header.push_str("Songbird ");
    header.push_str(&device.to_hex_unredacted());
    header.push('.');
    header.push_str(&ts_ms.to_string());
    header.push('.');
    header.push_str(&hex::encode(nonce));
    header.push('.');
    header.push_str(&hex::encode(sig.as_ref()));
    (header, hash.map(hex::encode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;

    #[test]
    #[allow(clippy::many_single_char_names, reason = "test")]
    fn signatures_bind_every_field() {
        let kp = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(kp.public_key().as_ref());
        let d = DeviceId::from_bytes([9; 16]);
        let (h, c) = sign(&kp, &d, "api.test", "PUT", "/v1/push", Some(b"{}"));
        let s = Signed::parse(&h).unwrap();
        assert_eq!(s.device, d);
        assert!(fresh(s.ts_ms));
        let hash = body_sha256(b"{}");
        assert_eq!(c.unwrap(), hex::encode(hash));
        let t = |name: &str, m: &str, p: &str, h: &[u8; 32]| {
            transcript(name, m, p, s.ts_ms, &s.nonce, &d, h)
        };
        assert!(verify(
            Some(&pk),
            &t("api.test", "PUT", "/v1/push", &hash),
            &s.sig
        ));
        for bad in [
            t("api.other", "PUT", "/v1/push", &hash),
            t("api.test", "DELETE", "/v1/push", &hash),
            t("api.test", "PUT", "/v1/account", &hash),
            t("api.test", "PUT", "/v1/push", &[0; 32]),
        ] {
            assert!(!verify(Some(&pk), &bad, &s.sig));
        }
        // Unknown device: refused after the same verification.
        assert!(!verify(
            None,
            &t("api.test", "PUT", "/v1/push", &hash),
            &s.sig
        ));
    }

    #[test]
    fn headers_parse_strictly() {
        assert!(Signed::parse("Bearer x").is_none());
        assert!(Signed::parse("Songbird a.b.c.d").is_none());
        let kp = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let (h, _) = sign(&kp, &DeviceId::from_bytes([9; 16]), "s", "GET", "/", None);
        assert!(Signed::parse(&format!("{h}.x")).is_none());
        assert!(Signed::parse(&h.replacen("Songbird ", "songbird ", 1)).is_none());
        assert_eq!(
            format!("{:?}", Signed::parse(&h).unwrap()),
            "Signed(<redacted>)"
        );
        assert!(!fresh(0));
        let k = nonce_key(&DeviceId::from_bytes([9; 16]), &[1; 16]);
        assert_eq!(k.len(), 34);
        assert!(!k.contains(&"09".repeat(16)));
    }
}
