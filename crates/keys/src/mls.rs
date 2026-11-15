//! MLS KeyPackages (RFC 9420 §10), as the server checks them before publishing (Prompt 3, M3b;
//! D-0051: Songbird's own focused parser, the owner's choice over OpenMLS on the server).
//!
//! Clients validate KeyPackages fully before adding anyone to a group (RFC 9420 §10.1); the
//! server's checks are defence in depth and, above all, **bind a KeyPackage to the device that
//! uploads it**: a device cannot publish packages that claim to be another device. Checked:
//!
//! - the TLS presentation language encoding, strictly (minimal variable-length integers, no
//!   trailing bytes, at most [`MAX_LEN`] bytes, duplicate extension types refused);
//! - `version` mls10; `cipher_suite` one of [`ALLOWED_SUITES`] (X25519 for HPKE, Ed25519 for
//!   signatures);
//! - `init_key` and the leaf's `encryption_key`: honest X25519 keys, different from each other;
//!   `signature_key`: an honest Ed25519 key;
//! - the credential: basic, its identity exactly the uploading device's ID;
//! - capabilities list mls10, the package's ciphersuite and the basic credential;
//! - the leaf's source is `key_package`, its lifetime current and at most [`MAX_LIFETIME_SECS`];
//! - both signatures (`SignWithLabel` with `"LeafNodeTBS"` and `"KeyPackageTBS"`) by the signature
//!   key, verified with aws-lc-rs.
//!
//! A package carrying the `last_resort` extension (type 10, from the MLS extensions draft, as
//! OpenMLS writes it) is the device's last-resort package. Its reference (`KeyPackageRef`,
//! RFC 9420 §5.2) is computed here.
//!
//! `tests/mls_vectors.rs` parses KeyPackages OpenMLS 0.9.2 makes (in a tool outside the
//! workspace) and checks each refusal against them.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};

/// Longest KeyPackage accepted (an X25519/Ed25519 package with a basic credential is about
/// 300 bytes).
pub const MAX_LEN: usize = 2048;
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and
/// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.
pub const ALLOWED_SUITES: [u16; 2] = [0x0001, 0x0003];
/// mls10.
const MLS10: u16 = 1;
/// Basic credential.
const BASIC: u16 = 1;
/// `leaf_node_source` `key_package`.
const SOURCE_KEY_PACKAGE: u8 = 1;
/// `last_resort` extension type.
pub const LAST_RESORT: u16 = 10;
/// Longest lifetime a package may claim (OpenMLS's default is 12 weeks plus a margin).
pub const MAX_LIFETIME_SECS: u64 = 100 * 86_400;
/// How far in the future `not_before` may lie (clock skew).
const SKEW_SECS: u64 = 3_600;

/// A KeyPackage that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// `KeyPackageRef`: `SHA-256(RefHashInput("MLS 1.0 KeyPackage Reference", package))`.
    pub reference: [u8; 32],
    /// Whether it carries the `last_resort` extension.
    pub last_resort: bool,
    /// The ciphersuite.
    pub cipher_suite: u16,
    /// When it stops being valid (Unix seconds).
    pub not_after: u64,
}

/// Why a KeyPackage was refused (for the uploader; deliberately coarse).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MlsError {
    /// Not a well-formed KeyPackage.
    #[error("malformed")]
    Malformed,
    /// Another version or ciphersuite, a non-basic credential, missing capabilities, another
    /// leaf source.
    #[error("unsupported")]
    Unsupported,
    /// A dishonest or reused key.
    #[error("keys")]
    Keys,
    /// The credential names another device.
    #[error("identity")]
    Identity,
    /// Not yet valid, expired, or valid too long.
    #[error("lifetime")]
    Lifetime,
    /// A signature does not verify.
    #[error("signature")]
    Signature,
}

struct Reader<'a> {
    all: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MlsError> {
        let end = self.pos.checked_add(n).ok_or(MlsError::Malformed)?;
        let s = self.all.get(self.pos..end).ok_or(MlsError::Malformed)?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, MlsError> {
        Ok(*self.take(1)?.first().ok_or(MlsError::Malformed)?)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], MlsError> {
        self.take(N)?.try_into().map_err(|_| MlsError::Malformed)
    }
    fn u16(&mut self) -> Result<u16, MlsError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, MlsError> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| MlsError::Malformed)?;
        Ok(u64::from_be_bytes(b))
    }
    /// RFC 9420 §2.1.2 variable-length integer: 1, 2 or 4 bytes, minimal encoding only.
    fn varint(&mut self) -> Result<usize, MlsError> {
        let first = self.u8()?;
        let (len, value) = match first >> 6 {
            0 => (1, u32::from(first & 0x3F)),
            1 => {
                let b = self.u8()?;
                (2, (u32::from(first & 0x3F) << 8) | u32::from(b))
            }
            2 => {
                let [b0, b1, b2] = self.array::<3>()?;
                (
                    4,
                    (u32::from(first & 0x3F) << 24)
                        | (u32::from(b0) << 16)
                        | (u32::from(b1) << 8)
                        | u32::from(b2),
                )
            }
            _ => return Err(MlsError::Malformed),
        };
        let minimal = match len {
            1 => true,
            2 => value >= 64,
            _ => value >= 16_384,
        };
        if !minimal {
            return Err(MlsError::Malformed);
        }
        usize::try_from(value).map_err(|_| MlsError::Malformed)
    }
    /// `opaque <V>`.
    fn vector(&mut self) -> Result<&'a [u8], MlsError> {
        let n = self.varint()?;
        self.take(n)
    }
}

/// A `uint16 <V>` list.
fn u16_list(bytes: &[u8]) -> Result<Vec<u16>, MlsError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(MlsError::Malformed);
    }
    Ok(bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect())
}

/// An `Extension extensions<V>` list: the types, each once.
fn extension_types(bytes: &[u8]) -> Result<Vec<u16>, MlsError> {
    let mut r = Reader { all: bytes, pos: 0 };
    let mut types = Vec::new();
    while r.pos < bytes.len() {
        let t = r.u16()?;
        r.vector()?;
        if types.contains(&t) {
            return Err(MlsError::Malformed);
        }
        types.push(t);
    }
    Ok(types)
}

fn put_varint(out: &mut Vec<u8>, n: usize) {
    // RFC 9420 §2.1.2: 1, 2 or 4 bytes, the shortest that fits (lengths here are far below 2^30).
    if let Ok(v) = u8::try_from(n)
        && v < 64
    {
        out.push(v);
    } else if let Ok(v) = u16::try_from(n)
        && v < 16_384
    {
        out.extend_from_slice(&(v | 0x4000).to_be_bytes());
    } else {
        let v = u32::try_from(n).unwrap_or(u32::MAX).min((1 << 30) - 1);
        out.extend_from_slice(&(v | 0x8000_0000).to_be_bytes());
    }
}

/// `SignContent` for `SignWithLabel(key, label, content)`: `"MLS 1.0 " + label` and the content,
/// each as `opaque <V>`.
fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let full = format!("MLS 1.0 {label}");
    let mut out = Vec::with_capacity(full.len() + content.len() + 4);
    put_varint(&mut out, full.len());
    out.extend_from_slice(full.as_bytes());
    put_varint(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// `KeyPackageRef` (RFC 9420 §5.2, SHA-256 for the allowed suites).
#[must_use]
pub fn reference(package: &[u8]) -> [u8; 32] {
    let label = b"MLS 1.0 KeyPackage Reference";
    let mut input = Vec::with_capacity(label.len() + package.len() + 4);
    put_varint(&mut input, label.len());
    input.extend_from_slice(label);
    put_varint(&mut input, package.len());
    input.extend_from_slice(package);
    let d = digest::digest(&digest::SHA256, &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn x25519(key: &[u8]) -> Result<[u8; 32], MlsError> {
    let k: [u8; 32] = key.try_into().map_err(|_| MlsError::Keys)?;
    if crate::xeddsa::x25519_public_key_ok(&k) {
        Ok(k)
    } else {
        Err(MlsError::Keys)
    }
}

/// Checks a KeyPackage uploaded by `device` (its 16-byte ID) at `now` (Unix seconds).
///
/// # Errors
/// [`MlsError`].
pub fn check(package: &[u8], device: &[u8; 16], now: u64) -> Result<Checked, MlsError> {
    if package.len() > MAX_LEN {
        return Err(MlsError::Malformed);
    }
    let mut r = Reader {
        all: package,
        pos: 0,
    };
    let version = r.u16()?;
    let suite = r.u16()?;
    let init_key = r.vector()?;
    // LeafNode.
    let leaf_start = r.pos;
    let encryption_key = r.vector()?;
    let signature_key = r.vector()?;
    let credential_type = r.u16()?;
    if credential_type != BASIC {
        return Err(MlsError::Unsupported);
    }
    let identity = r.vector()?;
    let versions = u16_list(r.vector()?)?;
    let suites = u16_list(r.vector()?)?;
    let _ext_caps = u16_list(r.vector()?)?;
    let _proposal_caps = u16_list(r.vector()?)?;
    let credential_caps = u16_list(r.vector()?)?;
    let source = r.u8()?;
    if source != SOURCE_KEY_PACKAGE {
        return Err(MlsError::Unsupported);
    }
    let not_before = r.u64()?;
    let not_after = r.u64()?;
    extension_types(r.vector()?)?;
    let leaf_tbs_end = r.pos;
    let leaf_sig = r.vector()?;
    // The KeyPackage's own extensions and signature.
    let kp_extensions = extension_types(r.vector()?)?;
    let kp_tbs_end = r.pos;
    let kp_sig = r.vector()?;
    if r.pos != package.len() {
        return Err(MlsError::Malformed);
    }

    if version != MLS10
        || !ALLOWED_SUITES.contains(&suite)
        || !versions.contains(&MLS10)
        || !suites.contains(&suite)
        || !credential_caps.contains(&BASIC)
    {
        return Err(MlsError::Unsupported);
    }
    if x25519(init_key)? == x25519(encryption_key)? {
        return Err(MlsError::Keys);
    }
    let sig_key: [u8; 32] = signature_key.try_into().map_err(|_| MlsError::Keys)?;
    if !crate::ed25519_public_key_ok(&sig_key) {
        return Err(MlsError::Keys);
    }
    if identity != device {
        return Err(MlsError::Identity);
    }
    if not_before > now.saturating_add(SKEW_SECS)
        || not_after <= now
        || not_after.saturating_sub(not_before) > MAX_LIFETIME_SECS
    {
        return Err(MlsError::Lifetime);
    }
    let verify = |label: &str, tbs: &[u8], sig: &[u8]| {
        UnparsedPublicKey::new(&ED25519, &sig_key)
            .verify(&sign_content(label, tbs), sig)
            .is_ok()
    };
    let leaf_tbs = package
        .get(leaf_start..leaf_tbs_end)
        .ok_or(MlsError::Malformed)?;
    let kp_tbs = package.get(..kp_tbs_end).ok_or(MlsError::Malformed)?;
    if !verify("LeafNodeTBS", leaf_tbs, leaf_sig) || !verify("KeyPackageTBS", kp_tbs, kp_sig) {
        return Err(MlsError::Signature);
    }
    Ok(Checked {
        reference: reference(package),
        last_resort: kp_extensions.contains(&LAST_RESORT),
        cipher_suite: suite,
        not_after,
    })
}

/// What [`encode`] builds a KeyPackage from (clients and tests; the server only checks).
#[derive(Debug, Clone, Copy)]
pub struct Params<'a> {
    /// An allowed ciphersuite.
    pub cipher_suite: u16,
    /// HPKE init key (X25519).
    pub init_key: &'a [u8; 32],
    /// The leaf's HPKE encryption key (X25519).
    pub encryption_key: &'a [u8; 32],
    /// The basic credential's identity (Songbird: the device ID).
    pub identity: &'a [u8],
    /// Lifetime, Unix seconds.
    pub not_before: u64,
    /// Lifetime, Unix seconds.
    pub not_after: u64,
    /// Whether to carry the `last_resort` extension.
    pub last_resort: bool,
}

fn put_vector(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn put_u16_list(out: &mut Vec<u8>, list: &[u16]) {
    let bytes: Vec<u8> = list.iter().flat_map(|v| v.to_be_bytes()).collect();
    put_vector(out, &bytes);
}

/// Encodes and signs a KeyPackage with an Ed25519 key pair (RFC 9420 §10, a basic credential,
/// capabilities for mls10, the package's suite and basic credentials, `last_resort` listed when
/// used). For clients and tests: [`check`] accepts what this builds.
#[must_use]
pub fn encode(p: &Params<'_>, signer: &aws_lc_rs::signature::Ed25519KeyPair) -> Vec<u8> {
    use aws_lc_rs::signature::KeyPair as _;
    let mut leaf = Vec::new();
    put_vector(&mut leaf, p.encryption_key);
    put_vector(&mut leaf, signer.public_key().as_ref());
    leaf.extend_from_slice(&BASIC.to_be_bytes());
    put_vector(&mut leaf, p.identity);
    put_u16_list(&mut leaf, &[MLS10]);
    put_u16_list(&mut leaf, &[p.cipher_suite]);
    put_u16_list(&mut leaf, if p.last_resort { &[LAST_RESORT] } else { &[] });
    put_u16_list(&mut leaf, &[]);
    put_u16_list(&mut leaf, &[BASIC]);
    leaf.push(SOURCE_KEY_PACKAGE);
    leaf.extend_from_slice(&p.not_before.to_be_bytes());
    leaf.extend_from_slice(&p.not_after.to_be_bytes());
    put_vector(&mut leaf, &[]);
    let leaf_sig = signer.sign(&sign_content("LeafNodeTBS", &leaf));
    put_vector(&mut leaf, leaf_sig.as_ref());
    let mut kp = Vec::new();
    kp.extend_from_slice(&MLS10.to_be_bytes());
    kp.extend_from_slice(&p.cipher_suite.to_be_bytes());
    put_vector(&mut kp, p.init_key);
    kp.extend_from_slice(&leaf);
    let mut ext = Vec::new();
    if p.last_resort {
        ext.extend_from_slice(&LAST_RESORT.to_be_bytes());
        put_vector(&mut ext, &[]);
    }
    put_vector(&mut kp, &ext);
    let kp_sig = signer.sign(&sign_content("KeyPackageTBS", &kp));
    put_vector(&mut kp, kp_sig.as_ref());
    kp
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use super::*;

    #[test]
    fn varints_are_minimal_and_bounded() {
        let read = |b: &[u8]| Reader { all: b, pos: 0 }.varint();
        assert_eq!(read(&[0x25]), Ok(0x25));
        assert_eq!(read(&[0x40, 0x40]), Ok(64));
        assert_eq!(read(&[0x40, 0x25]), Err(MlsError::Malformed)); // 37 in two bytes
        assert_eq!(read(&[0x80, 0x00, 0x40, 0x00]), Ok(16_384));
        assert_eq!(read(&[0x80, 0x00, 0x00, 0x25]), Err(MlsError::Malformed));
        assert_eq!(read(&[0xC0, 0, 0, 0, 0, 0, 0, 1]), Err(MlsError::Malformed));
        assert_eq!(read(&[0x40]), Err(MlsError::Malformed));
        // The encoder writes what the reader accepts, at every size class.
        for n in [0usize, 63, 64, 16_383, 16_384, 1 << 20] {
            let mut b = Vec::new();
            put_varint(&mut b, n);
            assert_eq!(read(&b), Ok(n), "{n}");
        }
    }

    #[test]
    fn what_encode_builds_check_accepts() {
        use crate::xeddsa::Signer;
        let signer = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        let (init, enc) = (
            Signer::new(&[1; 32]).public(),
            Signer::new(&[2; 32]).public(),
        );
        let mut p = Params {
            cipher_suite: 0x0001,
            init_key: &init,
            encryption_key: &enc,
            identity: &[7; 16],
            not_before: 1_000,
            not_after: 2_000,
            last_resort: false,
        };
        let c = check(&encode(&p, &signer), &[7; 16], 1_500).unwrap();
        assert!(!c.last_resort);
        p.last_resort = true;
        assert!(
            check(&encode(&p, &signer), &[7; 16], 1_500)
                .unwrap()
                .last_resort
        );
        // The same key twice is refused.
        p.encryption_key = &init;
        assert_eq!(
            check(&encode(&p, &signer), &[7; 16], 1_500),
            Err(MlsError::Keys)
        );
    }

    #[test]
    fn sign_content_and_reference_shapes() {
        let c = sign_content("KeyPackageTBS", &[1, 2, 3]);
        assert_eq!(c[0], 21); // "MLS 1.0 KeyPackageTBS"
        assert_eq!(&c[1..22], b"MLS 1.0 KeyPackageTBS");
        assert_eq!(&c[22..], &[3, 1, 2, 3]);
        assert_ne!(reference(&[1]), reference(&[2]));
    }
}
