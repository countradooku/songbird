//! The little of JOSE billing needs, on aws-lc-rs and rustls-webpki (D-0129):
//!
//! - base64 (standard with padding, for `x5c` and Pub/Sub data; unpadded base64url for JWS);
//! - **verifying** Apple's JWS (`ES256` with an `x5c` chain to a pinned root, Apple's marker
//!   extensions on the leaf and the intermediate) and Google's OIDC tokens (`RS256` with a key
//!   from Google's published set);
//! - **signing** the JWTs that authenticate billing to Apple (`ES256`) and Google (`RS256`).
//!
//! Every input here comes from the network: sizes are bounded before decoding, every algorithm
//! other than the one expected is refused, and no error carries the input.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde_json::Value;

use crate::der;

/// The largest compact JWS accepted (Apple's notifications carry three certificates and nested
/// signed transactions: about 12 KiB in practice).
pub const MAX_JWS: usize = 64 * 1024;

/// Why a token was refused (never the input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JoseError {
    /// Not a compact JWS of the expected shape, size or algorithm.
    #[error("malformed")]
    Malformed,
    /// The chain or the signature does not verify.
    #[error("signature")]
    Signature,
    /// A claim is wrong (issuer, audience, expiry).
    #[error("claims")]
    Claims,
}

// ----- base64 -----

fn value(c: u8, url: bool) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' if url => 62,
        b'_' if url => 63,
        b'+' if !url => 62,
        b'/' if !url => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

fn decode(input: &str, url: bool) -> Option<Vec<u8>> {
    let s = if url {
        input
    } else {
        // Standard base64 comes padded to a multiple of four.
        if !input.len().is_multiple_of(4) {
            return None;
        }
        input.trim_end_matches('=')
    };
    if !url && input.len() - s.len() > 2 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c, url)? << (18 - 6 * u32::try_from(i).ok()?);
        }
        let [_, b0, b1, b2] = n.to_be_bytes();
        match chunk.len() {
            2 if n.trailing_zeros() >= 16 => out.push(b0),
            3 if n.trailing_zeros() >= 8 => out.extend_from_slice(&[b0, b1]),
            4 => out.extend_from_slice(&[b0, b1, b2]),
            _ => return None,
        }
    }
    Some(out)
}

/// Unpadded base64url (RFC 4648 §5), strict.
#[must_use]
pub fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    decode(input, true)
}

/// Standard padded base64 (RFC 4648 §4), strict.
#[must_use]
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    decode(input, false)
}

fn encode(input: &[u8], url: bool) -> String {
    let alphabet: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let sym = |v: u32| {
        char::from(
            alphabet
                .get(usize::try_from(v & 63).unwrap_or(0))
                .copied()
                .unwrap_or(b'A'),
        )
    };
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        if chunk.len() > 1 {
            out.push(sym(n >> 6));
        } else if !url {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(sym(n));
        } else if !url {
            out.push('=');
        }
    }
    out
}

/// Unpadded base64url.
#[must_use]
pub fn b64url_encode(input: &[u8]) -> String {
    encode(input, true)
}

/// Standard padded base64.
#[must_use]
pub fn b64_encode(input: &[u8]) -> String {
    encode(input, false)
}

// ----- compact JWS -----

/// A compact JWS split and decoded, before any check.
struct Parts {
    header: Value,
    payload: Vec<u8>,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

fn split(jws: &str) -> Result<Parts, JoseError> {
    if jws.len() > MAX_JWS {
        return Err(JoseError::Malformed);
    }
    let mut it = jws.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(JoseError::Malformed);
    };
    let header: Value = b64url_decode(h)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JoseError::Malformed)?;
    let payload = b64url_decode(p).ok_or(JoseError::Malformed)?;
    let signature = b64url_decode(s).ok_or(JoseError::Malformed)?;
    let mut signing_input = Vec::with_capacity(h.len() + 1 + p.len());
    signing_input.extend_from_slice(h.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(p.as_bytes());
    Ok(Parts {
        header,
        payload,
        signing_input,
        signature,
    })
}

/// A fixed-length ECDSA signature `r || s` (JWS) as the ASN.1 `SEQUENCE { r, s }` webpki
/// verifies.
fn ecdsa_fixed_to_der(sig: &[u8]) -> Option<Vec<u8>> {
    if sig.len() != 64 {
        return None;
    }
    let int = |x: &[u8]| {
        let x = {
            let mut i = 0;
            while i + 1 < x.len() && x.get(i) == Some(&0) {
                i += 1;
            }
            x.get(i..).unwrap_or_default()
        };
        let mut v = Vec::with_capacity(x.len() + 3);
        v.push(0x02);
        let pad = x.first().is_some_and(|b| b & 0x80 != 0);
        v.push(u8::try_from(x.len() + usize::from(pad)).ok()?);
        if pad {
            v.push(0);
        }
        v.extend_from_slice(x);
        Some(v)
    };
    let (r, s) = sig.split_at(32);
    let (r, s) = (int(r)?, int(s)?);
    let mut out = vec![0x30, u8::try_from(r.len() + s.len()).ok()?];
    out.extend(r);
    out.extend(s);
    Some(out)
}

/// What an Apple JWS chain must show.
#[derive(Debug, Clone)]
pub struct AppleTrust {
    /// The pinned root (Apple Root CA - G3 in production; a test root in tests).
    pub root: Vec<u8>,
    /// The marker extension the leaf must carry (`1.2.840.113635.100.6.11.1`).
    pub leaf_oid: Vec<u8>,
    /// The marker extension the intermediate must carry (`1.2.840.113635.100.6.2.1`).
    pub intermediate_oid: Vec<u8>,
}

/// DER content of `1.2.840.113635.100.6.11.1` (Apple's App Store receipt signing).
pub const APPLE_LEAF_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x0b, 0x01];
/// DER content of `1.2.840.113635.100.6.2.1` (Apple's WWDR intermediate).
pub const APPLE_INTERMEDIATE_OID: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01];

/// Accepts whatever extended key usages a certificate lists: Apple's chains are pinned to their
/// root and checked by their marker extensions instead.
struct AnyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, _: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

impl AppleTrust {
    /// Production: Apple's root (DER) with Apple's marker extensions.
    #[must_use]
    pub fn apple(root: Vec<u8>) -> Self {
        Self {
            root,
            leaf_oid: APPLE_LEAF_OID.to_vec(),
            intermediate_oid: APPLE_INTERMEDIATE_OID.to_vec(),
        }
    }

    /// Verifies an Apple JWS signed at or after nothing in particular, now: `alg` `ES256`;
    /// `x5c` exactly `[leaf, intermediate, root]` with `root` byte-equal to the pinned one; the
    /// marker extensions; the chain (validity at `now`, signatures) by rustls-webpki; then the
    /// JWS signature by the leaf. Returns the payload.
    ///
    /// # Errors
    /// [`JoseError::Malformed`], [`JoseError::Signature`].
    pub fn verify(&self, jws: &str, now: UnixTime) -> Result<Vec<u8>, JoseError> {
        let p = split(jws)?;
        if p.header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(JoseError::Malformed);
        }
        let x5c = p
            .header
            .get("x5c")
            .and_then(Value::as_array)
            .ok_or(JoseError::Malformed)?;
        let certs = x5c
            .iter()
            .map(|c| c.as_str().and_then(b64_decode))
            .collect::<Option<Vec<_>>>()
            .ok_or(JoseError::Malformed)?;
        let [leaf, intermediate, root] = certs.as_slice() else {
            return Err(JoseError::Malformed);
        };
        if *root != self.root {
            return Err(JoseError::Signature);
        }
        if !der::has_extension(leaf, &self.leaf_oid)
            || !der::has_extension(intermediate, &self.intermediate_oid)
        {
            return Err(JoseError::Signature);
        }
        let root_der = CertificateDer::from(self.root.as_slice());
        let anchor =
            webpki::anchor_from_trusted_cert(&root_der).map_err(|_| JoseError::Signature)?;
        let leaf_der = CertificateDer::from(leaf.as_slice());
        let ee = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| JoseError::Signature)?;
        let inter = [CertificateDer::from(intermediate.as_slice())];
        ee.verify_for_usage(
            &[
                webpki::aws_lc_rs::ECDSA_P256_SHA256,
                webpki::aws_lc_rs::ECDSA_P256_SHA384,
                webpki::aws_lc_rs::ECDSA_P384_SHA256,
                webpki::aws_lc_rs::ECDSA_P384_SHA384,
            ],
            &[anchor],
            &inter,
            now,
            AnyUsage,
            None,
            None,
        )
        .map_err(|_| JoseError::Signature)?;
        let sig = ecdsa_fixed_to_der(&p.signature).ok_or(JoseError::Signature)?;
        ee.verify_signature(webpki::aws_lc_rs::ECDSA_P256_SHA256, &p.signing_input, &sig)
            .map_err(|_| JoseError::Signature)?;
        Ok(p.payload)
    }
}

/// An RSA public key from a JWK set (`n`, `e` big-endian).
#[derive(Clone, PartialEq, Eq)]
pub struct RsaJwk {
    /// The key ID.
    pub kid: String,
    /// The modulus.
    pub n: Vec<u8>,
    /// The public exponent.
    pub e: Vec<u8>,
}

impl std::fmt::Debug for RsaJwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaJwk")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Parses a JWK set (`{"keys": [{"kty": "RSA", "kid", "n", "e", ...}]}`), keeping RSA keys.
#[must_use]
pub fn rsa_jwks(body: &[u8]) -> Vec<RsaJwk> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    v.get("keys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
                .filter_map(|k| {
                    Some(RsaJwk {
                        kid: k.get("kid")?.as_str()?.to_owned(),
                        n: b64url_decode(k.get("n")?.as_str()?)?,
                        e: b64url_decode(k.get("e")?.as_str()?)?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Verifies an `RS256` JWT against the key its `kid` names; returns its claims. The caller checks
/// the claims (issuer, audience, expiry, subject).
///
/// # Errors
/// [`JoseError::Malformed`], [`JoseError::Signature`].
pub fn verify_rs256(jwt: &str, keys: &[RsaJwk]) -> Result<Value, JoseError> {
    let p = split(jwt)?;
    if p.header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(JoseError::Malformed);
    }
    let kid = p
        .header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(JoseError::Malformed)?;
    let key = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(JoseError::Signature)?;
    signature::RsaPublicKeyComponents {
        n: key.n.as_slice(),
        e: key.e.as_slice(),
    }
    .verify(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        &p.signing_input,
        &p.signature,
    )
    .map_err(|_| JoseError::Signature)?;
    serde_json::from_slice(&p.payload).map_err(|_| JoseError::Malformed)
}

/// `base64url(header) "." base64url(claims) "." base64url(signature)`.
fn compact(
    header: &Value,
    claims: &Value,
    sign: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Option<String> {
    let mut out = b64url_encode(header.to_string().as_bytes());
    out.push('.');
    out.push_str(&b64url_encode(claims.to_string().as_bytes()));
    let sig = sign(out.as_bytes())?;
    out.push('.');
    out.push_str(&b64url_encode(&sig));
    Some(out)
}

/// Signs `ES256` JWTs (Apple's App Store Server API).
pub struct Es256 {
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for Es256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Es256(<private key>)")
    }
}

impl Es256 {
    /// From a PKCS#8 P-256 key (Apple's `.p8`, DER).
    ///
    /// # Errors
    /// Not a P-256 PKCS#8 key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
                .map_err(|_| "not a P-256 PKCS#8 key")?,
            rng: SystemRandom::new(),
        })
    }

    /// A compact JWS of `claims` under `header`.
    #[must_use]
    pub fn sign(&self, header: &Value, claims: &Value) -> Option<String> {
        compact(header, claims, |m| {
            self.key
                .sign(&self.rng, m)
                .ok()
                .map(|s| s.as_ref().to_vec())
        })
    }
}

/// Signs `RS256` JWTs (Google's service-account assertion).
pub struct Rs256 {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for Rs256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rs256(<private key>)")
    }
}

impl Rs256 {
    /// From a PKCS#8 RSA key (DER).
    ///
    /// # Errors
    /// Not an RSA PKCS#8 key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            key: RsaKeyPair::from_pkcs8(der).map_err(|_| "not an RSA PKCS#8 key")?,
            rng: SystemRandom::new(),
        })
    }

    /// A compact JWS of `claims` under `header`.
    #[must_use]
    pub fn sign(&self, header: &Value, claims: &Value) -> Option<String> {
        compact(header, claims, |m| {
            let mut sig = vec![0u8; self.key.public_modulus_len()];
            self.key
                .sign(&RSA_PKCS1_SHA256, &self.rng, m, &mut sig)
                .ok()
                .map(|()| sig)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn base64_is_strict_both_ways() {
        for v in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(b64url_decode(&b64url_encode(v)).unwrap(), v);
            assert_eq!(b64_decode(&b64_encode(v)).unwrap(), v);
        }
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        // Wrong alphabet, wrong padding, non-canonical bits.
        assert!(b64url_decode("+/8").is_none());
        assert!(b64_decode("-_8=").is_none());
        assert!(b64_decode("Zm8").is_none());
        assert!(b64_decode("Zm9=").is_none());
        assert!(b64url_decode("Zm9").is_none());
        assert!(b64_decode("Z===").is_none());
    }

    #[test]
    fn ecdsa_signatures_convert_to_der() {
        let mut sig = [0u8; 64];
        sig[0] = 0x80;
        sig[63] = 1;
        let d = ecdsa_fixed_to_der(&sig).unwrap();
        assert_eq!(&d[..4], &[0x30, 0x26, 0x02, 0x21]);
        assert_eq!(&d[d.len() - 3..], &[0x02, 0x01, 0x01]);
        assert!(ecdsa_fixed_to_der(&[0; 63]).is_none());
    }

    #[test]
    fn jws_shapes_are_refused_before_any_crypto() {
        let trust = AppleTrust::apple(vec![1, 2, 3]);
        let now = UnixTime::now();
        for bad in [
            "",
            "a.b",
            "a.b.c.d",
            &"a".repeat(MAX_JWS + 1),
            &format!("{}.e30.AA", b64url_encode(br#"{"alg":"none"}"#)),
            &format!("{}.e30.AA", b64url_encode(br#"{"alg":"ES256"}"#)),
            &format!(
                "{}.e30.AA",
                b64url_encode(br#"{"alg":"ES256","x5c":["AA=="]}"#)
            ),
        ] {
            assert!(trust.verify(bad, now).is_err());
        }
        assert_eq!(verify_rs256("a.b.c", &[]), Err(JoseError::Malformed));
        let hs = format!("{}.e30.AA", b64url_encode(br#"{"alg":"HS256","kid":"k"}"#));
        assert_eq!(verify_rs256(&hs, &[]), Err(JoseError::Malformed));
    }
}
