//! Songbird's OpenMLS crypto provider for the delivery service, on aws-lc-rs (D-0065 §1).
//!
//! The delivery service verifies; it never decrypts, encapsulates or signs. So this provider
//! implements hashing, Ed25519 verification, HMAC and HKDF (what `PublicGroup` uses to check
//! handshakes, tree hashes and references). Every operation that needs a private key or a
//! group secret (AEAD, HPKE, signing, key generation) is refused with an error. A server that
//! cannot sign or open anything cannot be tricked into doing so.
//!
//! Ciphersuites (D-0065 §3): new groups use X-Wing,
//! `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (`0x004F`, the provisional code point of
//! draft-ietf-mls-pq-ciphersuites). `0x0001` and `0x0003` stay accepted for KeyPackages
//! (D-0051), but groups are checked against [`GROUP_CIPHERSUITES`] by the caller.

use aws_lc_rs::{digest, hkdf, hmac, signature};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKeyPair, KemOutput, SignatureScheme,
};
use tls_codec::SecretVLBytes;

/// The ciphersuite every new Songbird group uses (D-0065 §3).
pub const GROUP_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// Ciphersuites a group may use on this server.
pub const GROUP_CIPHERSUITES: &[Ciphersuite] = &[GROUP_CIPHERSUITE];

/// Ciphersuites this provider can verify.
const SUPPORTED: &[Ciphersuite] = &[
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    GROUP_CIPHERSUITE,
];

/// Verify-only crypto on aws-lc-rs. Stateless; one instance serves every group.
#[derive(Debug, Default, Clone, Copy)]
pub struct VerifyOnlyCrypto;

fn digest_alg(hash: HashType) -> &'static digest::Algorithm {
    match hash {
        HashType::Sha2_256 => &digest::SHA256,
        HashType::Sha2_384 => &digest::SHA384,
        HashType::Sha2_512 => &digest::SHA512,
    }
}

fn hmac_alg(hash: HashType) -> hmac::Algorithm {
    match hash {
        HashType::Sha2_256 => hmac::HMAC_SHA256,
        HashType::Sha2_384 => hmac::HMAC_SHA384,
        HashType::Sha2_512 => hmac::HMAC_SHA512,
    }
}

fn hkdf_alg(hash: HashType) -> hkdf::Algorithm {
    match hash {
        HashType::Sha2_256 => hkdf::HKDF_SHA256,
        HashType::Sha2_384 => hkdf::HKDF_SHA384,
        HashType::Sha2_512 => hkdf::HKDF_SHA512,
    }
}

/// An HKDF output length for aws-lc-rs.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl OpenMlsCrypto for VerifyOnlyCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if SUPPORTED.contains(&ciphersuite) {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        SUPPORTED.to_vec()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM) (RFC 5869 §2.2); aws-lc-rs keeps the PRK
        // opaque, so it is computed as the HMAC it is defined to be.
        self.hmac(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let key = hmac::Key::new(hmac_alg(hash_type), key);
        Ok(SecretVLBytes::new(
            hmac::sign(&key, message).as_ref().to_vec(),
        ))
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);
        // RFC 5869 §2.3: L <= 255 * HashLen.
        if okm_len == 0 || okm_len > 255 * hash_type.size() {
            return Err(CryptoError::HkdfOutputLengthInvalid);
        }
        let prk = hkdf::Prk::new_less_safe(alg, prk);
        let info = [info];
        let okm = prk
            .expand(&info, Len(okm_len))
            .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
        let mut out = vec![0u8; okm_len];
        okm.fill(&mut out)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        Ok(SecretVLBytes::new(out))
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(digest::digest(digest_alg(hash_type), data)
            .as_ref()
            .to_vec())
    }

    fn aead_encrypt(
        &self,
        _alg: AeadType,
        _key: &[u8],
        _data: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedAeadAlgorithm)
    }

    fn aead_decrypt(
        &self,
        _alg: AeadType,
        _key: &[u8],
        _ct_tag: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedAeadAlgorithm)
    }

    fn signature_key_gen(&self, _alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        Err(CryptoError::UnsupportedSignatureScheme)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match alg {
            SignatureScheme::ED25519 => {
                // An honest key and a canonical signature only (D-0048's checks, D-0051).
                let key: &[u8; songbird_keys::ED25519_PUBLIC_LEN] =
                    pk.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
                if !songbird_keys::ed25519_public_key_ok(key) {
                    return Err(CryptoError::InvalidPublicKey);
                }
                if signature.len() != songbird_keys::ED25519_SIGNATURE_LEN {
                    return Err(CryptoError::InvalidSignature);
                }
                signature::UnparsedPublicKey::new(&signature::ED25519, pk)
                    .verify(data, signature)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(
        &self,
        _alg: SignatureScheme,
        _data: &[u8],
        _key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::SigningError)
    }

    fn hpke_seal(
        &self,
        _config: HpkeConfig,
        _pk_r: &[u8],
        _info: &[u8],
        _aad: &[u8],
        _ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        Err(CryptoError::HpkeEncryptionError)
    }

    fn hpke_open(
        &self,
        _config: HpkeConfig,
        _input: &HpkeCiphertext,
        _sk_r: &[u8],
        _info: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::HpkeDecryptionError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        _config: HpkeConfig,
        _pk_r: &[u8],
        _info: &[u8],
        _exporter_context: &[u8],
        _exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        Err(CryptoError::SenderSetupError)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        _config: HpkeConfig,
        _enc: &[u8],
        _sk_r: &[u8],
        _info: &[u8],
        _exporter_context: &[u8],
        _exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        Err(CryptoError::ReceiverSetupError)
    }

    fn derive_hpke_keypair(
        &self,
        _config: HpkeConfig,
        _ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hkdf_matches_rfc_5869_case_1() {
        let c = VerifyOnlyCrypto;
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let prk = c.hkdf_extract(HashType::Sha2_256, &salt, &ikm).unwrap();
        assert_eq!(
            prk.as_slice(),
            unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = c
            .hkdf_expand(HashType::Sha2_256, prk.as_slice(), &info, 42)
            .unwrap();
        assert_eq!(
            okm.as_slice(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
        assert!(
            c.hkdf_expand(HashType::Sha2_256, prk.as_slice(), &info, 255 * 32 + 1)
                .is_err()
        );
        assert!(
            c.hkdf_expand(HashType::Sha2_256, prk.as_slice(), &info, 0)
                .is_err()
        );
    }

    #[test]
    fn secrets_and_signing_are_refused() {
        let c = VerifyOnlyCrypto;
        assert!(c.sign(SignatureScheme::ED25519, b"x", &[0; 32]).is_err());
        assert!(c.signature_key_gen(SignatureScheme::ED25519).is_err());
        assert!(
            c.aead_decrypt(AeadType::Aes128Gcm, &[0; 16], &[0; 32], &[0; 12], b"")
                .is_err()
        );
        assert!(c.supports(GROUP_CIPHERSUITE).is_ok());
        assert!(
            c.supports(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
                .is_err()
        );
    }

    #[test]
    fn ed25519_rfc_8032_test_1_verifies_and_tampering_fails() {
        let c = VerifyOnlyCrypto;
        let pk = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert!(
            c.verify_signature(SignatureScheme::ED25519, b"", &pk, &sig)
                .is_ok()
        );
        assert!(
            c.verify_signature(SignatureScheme::ED25519, b"x", &pk, &sig)
                .is_err()
        );
        assert!(
            c.verify_signature(SignatureScheme::ED25519, b"", &pk[..31], &sig)
                .is_err()
        );
        assert!(
            c.verify_signature(SignatureScheme::ED25519, b"", &[0; 32], &sig)
                .is_err()
        );
    }
}
