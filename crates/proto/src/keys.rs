//! The key directory's wire formats (`docs/PROTOCOL.md` §4.4; Prompt 3, M3; D-0050).
//!
//! Keys are libsignal's serializations, so a PQXDH implementation reads them as they are:
//!
//! - an X25519 key (device identity key, signed prekey, one-time prekey): `0x05 || u [32]`;
//! - an ML-KEM-1024 key (post-quantum prekey): `0x0A || encapsulation key [1568]`;
//! - a signature: XEdDSA by the device identity key over the key's serialization, 64 bytes.
//!
//! Integers are big-endian. Every count is checked against its bound before anything
//! proportional to it is allocated (invariant 7). Like the rest of this crate, nothing here
//! verifies a signature or a key: the server does (`songbird-keys`).

use songbird_types::DeviceId;
use songbird_types::id::ID_LEN;

/// Format version.
pub const VERSION: u8 = 1;
/// libsignal's type byte for X25519 keys.
pub const TYPE_X25519: u8 = 0x05;
/// libsignal's type byte for ML-KEM-1024 keys.
pub const TYPE_ML_KEM_1024: u8 = 0x0A;
/// A serialized X25519 key.
pub const EC_LEN: usize = 33;
/// A serialized ML-KEM-1024 key.
pub const KEM_LEN: usize = 1 + 1568;
/// An XEdDSA signature.
pub const SIG_LEN: usize = 64;
/// Most one-time keys of each kind in one upload.
pub const MAX_ONE_TIME_PER_UPLOAD: usize = 100;
/// Most device bundles in one fetch answer.
pub const MAX_BUNDLES: usize = 16;

/// A signed X25519 prekey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEc {
    /// Client-chosen ID.
    pub id: u32,
    /// `0x05 || u`.
    pub key: [u8; EC_LEN],
    /// XEdDSA over `key`.
    pub sig: [u8; SIG_LEN],
}

/// A signed ML-KEM-1024 prekey (last-resort or one-time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKem {
    /// Client-chosen ID.
    pub id: u32,
    /// `0x0A || encapsulation key`.
    pub key: Box<[u8; KEM_LEN]>,
    /// XEdDSA over `key`.
    pub sig: [u8; SIG_LEN],
}

/// A one-time X25519 prekey (unsigned, as in PQXDH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeEc {
    /// Client-chosen ID.
    pub id: u32,
    /// `0x05 || u`.
    pub key: [u8; EC_LEN],
}

/// `PUT /v1/keys`:
///
/// ```text
/// version u8 (1) | flags u8 (1 identity, 2 signed prekey, 4 last-resort KEM prekey)
///   | [identity [33]] | [id u32 | key [33] | sig [64]] | [id u32 | key [1569] | sig [64]]
///   | n u16 | n × (id u32 | key [33])                      one-time X25519, n <= 100
///   | m u16 | m × (id u32 | key [1569] | sig [64])         one-time ML-KEM-1024, m <= 100
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Upload {
    /// The device identity key (set once; first upload).
    pub identity: Option<[u8; EC_LEN]>,
    /// A new signed prekey (replaces the current one).
    pub signed: Option<SignedEc>,
    /// A new last-resort post-quantum prekey (replaces the current one).
    pub last_resort: Option<SignedKem>,
    /// One-time X25519 prekeys to add.
    pub one_time_ec: Vec<OneTimeEc>,
    /// One-time post-quantum prekeys to add.
    pub one_time_kem: Vec<SignedKem>,
}

/// One device's keys, as a fetch hands them out.
///
/// ```text
/// device [16] | identity [33] | signed: id u32 | key [33] | sig [64]
///   | flags u8 (1 one-time X25519 follows, 2 the KEM prekey is one-time, not last-resort)
///   | [id u32 | key [33]] | kem: id u32 | key [1569] | sig [64]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The device.
    pub device: DeviceId,
    /// Its identity key.
    pub identity: [u8; EC_LEN],
    /// Its signed prekey.
    pub signed: SignedEc,
    /// A one-time X25519 prekey, claimed for this fetch (absent when none is left or the
    /// device's one-time budget is spent).
    pub one_time_ec: Option<OneTimeEc>,
    /// A one-time post-quantum prekey claimed for this fetch, or the last-resort one.
    pub kem: SignedKem,
    /// Whether `kem` is one-time.
    pub kem_one_time: bool,
}

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeysError {
    /// Wrong version, unknown flags, a count above its bound, truncated or trailing bytes.
    #[error("malformed key message")]
    Malformed,
}

const FLAG_IDENTITY: u8 = 1;
const FLAG_SIGNED: u8 = 2;
const FLAG_LAST_RESORT: u8 = 4;
const FLAG_ONE_TIME_EC: u8 = 1;
const FLAG_KEM_ONE_TIME: u8 = 2;

/// Longest upload.
pub const MAX_UPLOAD_LEN: usize = 2
    + EC_LEN
    + (4 + EC_LEN + SIG_LEN)
    + (4 + KEM_LEN + SIG_LEN)
    + 2
    + MAX_ONE_TIME_PER_UPLOAD * (4 + EC_LEN)
    + 2
    + MAX_ONE_TIME_PER_UPLOAD * (4 + KEM_LEN + SIG_LEN);

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KeysError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(KeysError::Malformed)?;
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeysError> {
        self.take(N)?.try_into().map_err(|_| KeysError::Malformed)
    }
    fn u8(&mut self) -> Result<u8, KeysError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, KeysError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, KeysError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn signed_ec(&mut self) -> Result<SignedEc, KeysError> {
        Ok(SignedEc {
            id: self.u32()?,
            key: self.array()?,
            sig: self.array()?,
        })
    }
    fn signed_kem(&mut self) -> Result<SignedKem, KeysError> {
        let id = self.u32()?;
        let key: [u8; KEM_LEN] = self.array()?;
        Ok(SignedKem {
            id,
            key: Box::new(key),
            sig: self.array()?,
        })
    }
    fn one_time_ec(&mut self) -> Result<OneTimeEc, KeysError> {
        Ok(OneTimeEc {
            id: self.u32()?,
            key: self.array()?,
        })
    }
    fn count(&mut self, max: usize) -> Result<usize, KeysError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(KeysError::Malformed);
        }
        Ok(n)
    }
    fn end(&self) -> Result<(), KeysError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(KeysError::Malformed)
        }
    }
}

fn put_signed_ec(b: &mut Vec<u8>, k: &SignedEc) {
    b.extend_from_slice(&k.id.to_be_bytes());
    b.extend_from_slice(&k.key);
    b.extend_from_slice(&k.sig);
}

fn put_signed_kem(b: &mut Vec<u8>, k: &SignedKem) {
    b.extend_from_slice(&k.id.to_be_bytes());
    b.extend_from_slice(k.key.as_slice());
    b.extend_from_slice(&k.sig);
}

fn count_u16(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

impl Upload {
    /// Encodes the upload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(VERSION);
        let mut flags = 0;
        if self.identity.is_some() {
            flags |= FLAG_IDENTITY;
        }
        if self.signed.is_some() {
            flags |= FLAG_SIGNED;
        }
        if self.last_resort.is_some() {
            flags |= FLAG_LAST_RESORT;
        }
        b.push(flags);
        if let Some(i) = &self.identity {
            b.extend_from_slice(i);
        }
        if let Some(s) = &self.signed {
            put_signed_ec(&mut b, s);
        }
        if let Some(k) = &self.last_resort {
            put_signed_kem(&mut b, k);
        }
        b.extend_from_slice(&count_u16(self.one_time_ec.len()));
        for k in &self.one_time_ec {
            b.extend_from_slice(&k.id.to_be_bytes());
            b.extend_from_slice(&k.key);
        }
        b.extend_from_slice(&count_u16(self.one_time_kem.len()));
        for k in &self.one_time_kem {
            put_signed_kem(&mut b, k);
        }
        b
    }

    /// Decodes an upload: the whole input, nothing more.
    ///
    /// # Errors
    /// [`KeysError::Malformed`].
    pub fn decode(input: &[u8]) -> Result<Self, KeysError> {
        if input.len() > MAX_UPLOAD_LEN {
            return Err(KeysError::Malformed);
        }
        let mut r = Reader(input);
        if r.u8()? != VERSION {
            return Err(KeysError::Malformed);
        }
        let flags = r.u8()?;
        if flags & !(FLAG_IDENTITY | FLAG_SIGNED | FLAG_LAST_RESORT) != 0 {
            return Err(KeysError::Malformed);
        }
        let identity = if flags & FLAG_IDENTITY != 0 {
            Some(r.array()?)
        } else {
            None
        };
        let signed = if flags & FLAG_SIGNED != 0 {
            Some(r.signed_ec()?)
        } else {
            None
        };
        let last_resort = if flags & FLAG_LAST_RESORT != 0 {
            Some(r.signed_kem()?)
        } else {
            None
        };
        let n = r.count(MAX_ONE_TIME_PER_UPLOAD)?;
        let mut one_time_ec = Vec::with_capacity(n);
        for _ in 0..n {
            one_time_ec.push(r.one_time_ec()?);
        }
        let m = r.count(MAX_ONE_TIME_PER_UPLOAD)?;
        let mut one_time_kem = Vec::with_capacity(m);
        for _ in 0..m {
            one_time_kem.push(r.signed_kem()?);
        }
        r.end()?;
        Ok(Self {
            identity,
            signed,
            last_resort,
            one_time_ec,
            one_time_kem,
        })
    }
}

impl SignedEc {
    /// Stored form: `id u32 | key [33] | sig [64]` (101 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + EC_LEN + SIG_LEN);
        put_signed_ec(&mut b, self);
        b
    }

    /// From the stored form.
    ///
    /// # Errors
    /// [`KeysError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, KeysError> {
        let mut r = Reader(b);
        let k = r.signed_ec()?;
        r.end()?;
        Ok(k)
    }
}

impl SignedKem {
    /// Stored form: `id u32 | key [1569] | sig [64]` (1,637 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + KEM_LEN + SIG_LEN);
        put_signed_kem(&mut b, self);
        b
    }

    /// From the stored form.
    ///
    /// # Errors
    /// [`KeysError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, KeysError> {
        let mut r = Reader(b);
        let k = r.signed_kem()?;
        r.end()?;
        Ok(k)
    }
}

impl OneTimeEc {
    /// Stored form: `id u32 | key [33]` (37 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + EC_LEN);
        b.extend_from_slice(&self.id.to_be_bytes());
        b.extend_from_slice(&self.key);
        b
    }

    /// From the stored form.
    ///
    /// # Errors
    /// [`KeysError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, KeysError> {
        let mut r = Reader(b);
        let k = r.one_time_ec()?;
        r.end()?;
        Ok(k)
    }
}

/// Encodes a fetch answer: `version u8 | n u8 | n × bundle`.
#[must_use]
pub fn encode_bundles(bundles: &[Bundle]) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(VERSION);
    b.push(u8::try_from(bundles.len()).unwrap_or(u8::MAX));
    for x in bundles {
        b.extend_from_slice(x.device.as_bytes());
        b.extend_from_slice(&x.identity);
        put_signed_ec(&mut b, &x.signed);
        let mut flags = 0;
        if x.one_time_ec.is_some() {
            flags |= FLAG_ONE_TIME_EC;
        }
        if x.kem_one_time {
            flags |= FLAG_KEM_ONE_TIME;
        }
        b.push(flags);
        if let Some(k) = &x.one_time_ec {
            b.extend_from_slice(&k.id.to_be_bytes());
            b.extend_from_slice(&k.key);
        }
        put_signed_kem(&mut b, &x.kem);
    }
    b
}

/// Decodes a fetch answer (clients).
///
/// # Errors
/// [`KeysError::Malformed`].
pub fn decode_bundles(input: &[u8]) -> Result<Vec<Bundle>, KeysError> {
    let mut r = Reader(input);
    if r.u8()? != VERSION {
        return Err(KeysError::Malformed);
    }
    let n = usize::from(r.u8()?);
    if n > MAX_BUNDLES {
        return Err(KeysError::Malformed);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let device = DeviceId::from_slice(r.take(ID_LEN)?).map_err(|_| KeysError::Malformed)?;
        let identity = r.array()?;
        let signed = r.signed_ec()?;
        let flags = r.u8()?;
        if flags & !(FLAG_ONE_TIME_EC | FLAG_KEM_ONE_TIME) != 0 {
            return Err(KeysError::Malformed);
        }
        let one_time_ec = if flags & FLAG_ONE_TIME_EC != 0 {
            Some(r.one_time_ec()?)
        } else {
            None
        };
        out.push(Bundle {
            device,
            identity,
            signed,
            one_time_ec,
            kem: r.signed_kem()?,
            kem_one_time: flags & FLAG_KEM_ONE_TIME != 0,
        });
    }
    r.end()?;
    Ok(out)
}

/// Longest MLS KeyPackage accepted (`songbird_keys::mls::MAX_LEN`; X-Wing packages are about
/// 2,700 bytes, D-0066).
pub const MAX_KEY_PACKAGE_LEN: usize = 4096;
/// Most KeyPackages in one upload.
pub const MAX_KEY_PACKAGES_PER_UPLOAD: usize = 100;
/// Longest KeyPackage upload.
pub const MAX_KEY_PACKAGE_UPLOAD_LEN: usize =
    2 + MAX_KEY_PACKAGES_PER_UPLOAD * (2 + MAX_KEY_PACKAGE_LEN);

/// `PUT /v1/keypackages`: `version u8 (1) | n u8 | n × (len u16 | KeyPackage)`, n <= 100, each
/// at most 4,096 bytes. A package with the `last_resort` extension replaces the device's
/// last-resort package; the others are single use.
///
/// # Errors
/// [`KeysError::Malformed`].
pub fn decode_key_packages(input: &[u8]) -> Result<Vec<&[u8]>, KeysError> {
    if input.len() > MAX_KEY_PACKAGE_UPLOAD_LEN {
        return Err(KeysError::Malformed);
    }
    let mut r = Reader(input);
    if r.u8()? != VERSION {
        return Err(KeysError::Malformed);
    }
    let n = usize::from(r.u8()?);
    if n == 0 || n > MAX_KEY_PACKAGES_PER_UPLOAD {
        return Err(KeysError::Malformed);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = usize::from(r.u16()?);
        if len == 0 || len > MAX_KEY_PACKAGE_LEN {
            return Err(KeysError::Malformed);
        }
        out.push(r.take(len)?);
    }
    r.end()?;
    Ok(out)
}

/// Encodes a KeyPackage upload.
#[must_use]
pub fn encode_key_packages(packages: &[&[u8]]) -> Vec<u8> {
    let mut b = vec![VERSION, u8::try_from(packages.len()).unwrap_or(u8::MAX)];
    for p in packages {
        b.extend_from_slice(&count_u16(p.len()));
        b.extend_from_slice(p);
    }
    b
}

/// One device's KeyPackage, as a fetch hands it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageBundle {
    /// The device.
    pub device: DeviceId,
    /// Whether the package is single use (claimed for this fetch), not the last-resort one.
    pub one_time: bool,
    /// The TLS-serialized KeyPackage.
    pub package: Vec<u8>,
}

/// Encodes a KeyPackage fetch answer: `version u8 | n u8 | n × (device [16] | flags u8 (1 single
/// use) | len u16 | KeyPackage)`.
#[must_use]
pub fn encode_key_package_bundles(bundles: &[KeyPackageBundle]) -> Vec<u8> {
    let mut b = vec![VERSION, u8::try_from(bundles.len()).unwrap_or(u8::MAX)];
    for x in bundles {
        b.extend_from_slice(x.device.as_bytes());
        b.push(u8::from(x.one_time));
        b.extend_from_slice(&count_u16(x.package.len()));
        b.extend_from_slice(&x.package);
    }
    b
}

/// Decodes a KeyPackage fetch answer (clients).
///
/// # Errors
/// [`KeysError::Malformed`].
pub fn decode_key_package_bundles(input: &[u8]) -> Result<Vec<KeyPackageBundle>, KeysError> {
    let mut r = Reader(input);
    if r.u8()? != VERSION {
        return Err(KeysError::Malformed);
    }
    let n = usize::from(r.u8()?);
    if n > MAX_BUNDLES {
        return Err(KeysError::Malformed);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let device = DeviceId::from_slice(r.take(ID_LEN)?).map_err(|_| KeysError::Malformed)?;
        let one_time = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(KeysError::Malformed),
        };
        let len = usize::from(r.u16()?);
        if len == 0 || len > MAX_KEY_PACKAGE_LEN {
            return Err(KeysError::Malformed);
        }
        out.push(KeyPackageBundle {
            device,
            one_time,
            package: r.take(len)?.to_vec(),
        });
    }
    r.end()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use proptest::prelude::*;

    use super::*;

    fn kem(id: u32) -> SignedKem {
        SignedKem {
            id,
            key: Box::new([0x0A; KEM_LEN]),
            sig: [2; SIG_LEN],
        }
    }

    fn sample() -> Upload {
        Upload {
            identity: Some([5; EC_LEN]),
            signed: Some(SignedEc {
                id: 1,
                key: [6; EC_LEN],
                sig: [7; SIG_LEN],
            }),
            last_resort: Some(kem(2)),
            one_time_ec: vec![OneTimeEc {
                id: 3,
                key: [8; EC_LEN],
            }],
            one_time_kem: vec![kem(4), kem(5)],
        }
    }

    #[test]
    fn uploads_round_trip_and_decode_strictly() {
        for u in [sample(), Upload::default()] {
            let b = u.encode();
            assert_eq!(Upload::decode(&b), Ok(u));
            for cut in 0..b.len() {
                assert!(Upload::decode(&b[..cut]).is_err());
            }
            let mut long = b.clone();
            long.push(0);
            assert!(Upload::decode(&long).is_err());
        }
        let mut b = sample().encode();
        b[1] |= 8;
        assert!(Upload::decode(&b).is_err());
        // A count above its bound is refused before reading further.
        let mut over = vec![VERSION, 0];
        over.extend_from_slice(
            &u16::try_from(MAX_ONE_TIME_PER_UPLOAD + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert!(Upload::decode(&over).is_err());
        // The longest upload decodes.
        let full = Upload {
            one_time_ec: (0..100)
                .map(|i| OneTimeEc {
                    id: i,
                    key: [1; EC_LEN],
                })
                .collect(),
            one_time_kem: (0..100).map(kem).collect(),
            ..sample()
        };
        assert_eq!(full.encode().len(), MAX_UPLOAD_LEN);
        assert!(Upload::decode(&full.encode()).is_ok());
    }

    #[test]
    fn bundles_round_trip() {
        let s = sample();
        let bundles = vec![
            Bundle {
                device: DeviceId::from_bytes([1; 16]),
                identity: [5; EC_LEN],
                signed: s.signed.clone().unwrap(),
                one_time_ec: Some(s.one_time_ec[0].clone()),
                kem: kem(9),
                kem_one_time: true,
            },
            Bundle {
                device: DeviceId::from_bytes([2; 16]),
                identity: [5; EC_LEN],
                signed: s.signed.unwrap(),
                one_time_ec: None,
                kem: kem(10),
                kem_one_time: false,
            },
        ];
        let b = encode_bundles(&bundles);
        assert_eq!(decode_bundles(&b), Ok(bundles));
        for cut in 0..b.len() {
            assert!(decode_bundles(&b[..cut]).is_err());
        }
    }

    #[test]
    fn key_package_messages_round_trip_and_decode_strictly() {
        let a = vec![1u8; 300];
        let b = vec![2u8; MAX_KEY_PACKAGE_LEN];
        let up = encode_key_packages(&[&a, &b]);
        assert_eq!(decode_key_packages(&up).unwrap(), vec![&a[..], &b[..]]);
        for cut in 0..up.len() {
            assert!(decode_key_packages(&up[..cut]).is_err());
        }
        assert!(decode_key_packages(&encode_key_packages(&[])).is_err());
        let too_long = vec![3u8; MAX_KEY_PACKAGE_LEN + 1];
        assert!(decode_key_packages(&encode_key_packages(&[&too_long])).is_err());
        let bundles = vec![
            KeyPackageBundle {
                device: DeviceId::from_bytes([1; 16]),
                one_time: true,
                package: a.clone(),
            },
            KeyPackageBundle {
                device: DeviceId::from_bytes([2; 16]),
                one_time: false,
                package: b,
            },
        ];
        let enc = encode_key_package_bundles(&bundles);
        assert_eq!(decode_key_package_bundles(&enc).unwrap(), bundles);
        let mut bad_flag = enc.clone();
        bad_flag[2 + 16] = 2;
        assert!(decode_key_package_bundles(&bad_flag).is_err());
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = Upload::decode(&b);
            let _ = decode_bundles(&b);
            let _ = decode_key_packages(&b);
            let _ = decode_key_package_bundles(&b);
        }
    }
}
