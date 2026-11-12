//! Compact JWS signing (ES256 for APNs and VAPID, RS256 for Google's OAuth assertion) with
//! aws-lc-rs. Only signing: we never accept a JWT.

use std::fmt;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::pem::PemObject as _;

use crate::ConfigError;
use crate::b64::encode_url;

/// A PKCS#8 private key from PEM (`-----BEGIN PRIVATE KEY-----`, as Apple's `.p8` files and
/// Google's service-account files hold them).
pub(crate) fn pkcs8_from_pem(pem: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>, ConfigError> {
    PrivatePkcs8KeyDer::from_pem_slice(pem).map_err(|_| ConfigError::Key("expected a PKCS#8 PEM"))
}

/// `base64url(header) "." base64url(claims) "." base64url(signature)`.
fn compact(
    header: &str,
    claims: &str,
    sign: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Option<String> {
    let mut out = encode_url(header.as_bytes());
    out.push('.');
    out.push_str(&encode_url(claims.as_bytes()));
    let sig = sign(out.as_bytes())?;
    out.push('.');
    out.push_str(&encode_url(&sig));
    Some(out)
}

/// An ES256 (ECDSA P-256, SHA-256, fixed-length `r || s`) signer.
pub(crate) struct Es256 {
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl fmt::Debug for Es256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Es256(<private key>)")
    }
}

impl Es256 {
    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, ConfigError> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|_| ConfigError::Key("expected a P-256 PKCS#8 key"))?;
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }

    /// The public key, uncompressed (65 bytes).
    pub(crate) fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }

    pub(crate) fn sign(&self, header: &str, claims: &str) -> Option<String> {
        compact(header, claims, |input| {
            self.key
                .sign(&self.rng, input)
                .ok()
                .map(|s| s.as_ref().to_vec())
        })
    }
}

/// An RS256 (RSASSA-PKCS1-v1_5, SHA-256) signer.
pub(crate) struct Rs256 {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl fmt::Debug for Rs256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rs256(<private key>)")
    }
}

impl Rs256 {
    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, ConfigError> {
        let key = RsaKeyPair::from_pkcs8(der)
            .map_err(|_| ConfigError::Key("expected an RSA PKCS#8 key"))?;
        if key.public_modulus_len() < 256 {
            return Err(ConfigError::Key("RSA key shorter than 2048 bits"));
        }
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }

    pub(crate) fn sign(&self, header: &str, claims: &str) -> Option<String> {
        compact(header, claims, |input| {
            let mut sig = vec![0; self.key.public_modulus_len()];
            self.key
                .sign(&RSA_PKCS1_SHA256, &self.rng, input, &mut sig)
                .ok()?;
            Some(sig)
        })
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey,
    };

    use super::*;
    use crate::b64::decode_url;

    fn split(jwt: &str) -> (String, String, Vec<u8>, String) {
        let mut it = jwt.split('.');
        let h = it.next().unwrap();
        let c = it.next().unwrap();
        let s = it.next().unwrap();
        assert!(it.next().is_none());
        (
            String::from_utf8(decode_url(h).unwrap()).unwrap(),
            String::from_utf8(decode_url(c).unwrap()).unwrap(),
            decode_url(s).unwrap(),
            format!("{h}.{c}"),
        )
    }

    #[test]
    fn es256_signature_verifies_and_is_fixed_length() {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let s = Es256::from_pkcs8_der(doc.as_ref()).unwrap();
        let jwt = s.sign(r#"{"alg":"ES256"}"#, r#"{"iss":"x"}"#).unwrap();
        let (h, c, sig, input) = split(&jwt);
        assert_eq!(h, r#"{"alg":"ES256"}"#);
        assert_eq!(c, r#"{"iss":"x"}"#);
        assert_eq!(sig.len(), 64);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, s.public_key())
            .verify(input.as_bytes(), &sig)
            .unwrap();
        assert_eq!(s.public_key().len(), 65);
        assert!(!format!("{s:?}").contains(&hex::encode(doc.as_ref())));
    }

    #[test]
    fn rs256_signature_verifies() {
        let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = kp.as_der().unwrap();
        let s = Rs256::from_pkcs8_der(der.as_ref()).unwrap();
        let jwt = s.sign(r#"{"alg":"RS256"}"#, "{}").unwrap();
        let (_, _, sig, input) = split(&jwt);
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, kp.public_key().as_ref())
            .verify(input.as_bytes(), &sig)
            .unwrap();
    }

    #[test]
    fn wrong_key_kinds_are_refused() {
        let ec =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        assert!(Rs256::from_pkcs8_der(ec.as_ref()).is_err());
        assert!(Es256::from_pkcs8_der(b"junk").is_err());
        assert!(pkcs8_from_pem(b"not pem").is_err());
    }
}
