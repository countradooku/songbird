//! What a job says, and how it is sealed before it reaches Valkey.
//!
//! A job carries IDs only (master prompt §5). Even IDs are metadata: `valkey-jobs` persists to
//! disk, and a readable queue of device IDs would record who was messaged and when. So every job
//! is sealed (AES-256-GCM-SIV) under a key derived from the jobs secret and bound to its stream:
//! a job moved to another stream does not open, and Valkey, its append-only file and its backups
//! hold only random-looking blobs.
//!
//! Plaintext layout (big-endian): `version u8 | job id [16] | attempt u16 | kind u8 | fields`.
//! Sealed layout: `nonce [12] | ciphertext | tag [16]`.

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf;
use songbird_types::{AccountId, DeviceId, JobId};

const VERSION: u8 = 1;

const KIND_PUSH: u8 = 1;
const KIND_DELETE_ACCOUNT: u8 = 2;
const KIND_DELETE_OBJECT: u8 = 3;

const FLAG_CALL: u8 = 0x01;

/// Largest sealed job accepted (checked before decrypting; real jobs are under 100 bytes).
pub const MAX_SEALED: usize = 1024;

/// An object in the attachment store: 32 random bytes, also its name in `RustFS`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectKey(pub [u8; 32]);

impl std::fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObjectKey(<redacted>)")
    }
}

impl ObjectKey {
    /// A fresh random key.
    ///
    /// # Errors
    /// The system random source failed.
    pub fn random() -> Result<Self, aws_lc_rs::error::Unspecified> {
        let mut k = [0u8; 32];
        aws_lc_rs::rand::fill(&mut k)?;
        Ok(Self(k))
    }

    /// The object's name in the store (64 hex characters). Never log it.
    #[must_use]
    pub fn to_hex_unredacted(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses 64 lowercase hex characters.
    #[must_use]
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || s.bytes().any(|c| c.is_ascii_uppercase()) {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(Self(out))
    }
}

/// The work a job asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    /// Wake a device that has a message (or a call) waiting.
    Push {
        /// The device.
        device: DeviceId,
        /// A call: the high-priority `VoIP` path.
        call: bool,
    },
    /// Delete an account from every store (outbox, D-0036).
    DeleteAccount {
        /// The account.
        account: AccountId,
    },
    /// Delete one attachment object and its record.
    DeleteObject {
        /// The object.
        object: ObjectKey,
    },
}

impl Work {
    /// The stream this work belongs on.
    #[must_use]
    pub fn stream(&self) -> crate::Stream {
        match self {
            Self::Push { .. } => crate::Stream::Push,
            Self::DeleteAccount { .. } => crate::Stream::Deletion,
            Self::DeleteObject { .. } => crate::Stream::Cleanup,
        }
    }
}

/// A job: its identity, how often it has been tried, and its work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Stable across retries and repeats (outbox relays may repeat a job; handlers are
    /// idempotent).
    pub id: JobId,
    /// Failed attempts so far.
    pub attempt: u16,
    /// What to do.
    pub work: Work,
}

/// Why a sealed job did not open. Carries nothing of the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JobError {
    /// Too long, too short, wrong key, wrong stream or tampered.
    #[error("job does not open")]
    Sealed,
    /// Opened, but the content is malformed or of an unknown version.
    #[error("job malformed")]
    Malformed,
}

impl Job {
    /// A new job with a fresh random ID.
    ///
    /// # Errors
    /// The system random source failed.
    pub fn new(work: Work) -> Result<Self, songbird_types::IdError> {
        Ok(Self {
            id: JobId::random()?,
            attempt: 0,
            work,
        })
    }

    /// The job's plaintext encoding (for the outbox table, which lives in the database that
    /// holds these IDs anyway).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    /// Decodes [`Job::to_bytes`].
    ///
    /// # Errors
    /// [`JobError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, JobError> {
        if b.len() > MAX_SEALED {
            return Err(JobError::Malformed);
        }
        Self::decode(b)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        b.push(VERSION);
        b.extend_from_slice(self.id.as_bytes());
        b.extend_from_slice(&self.attempt.to_be_bytes());
        match &self.work {
            Work::Push { device, call } => {
                b.push(KIND_PUSH);
                b.extend_from_slice(device.as_bytes());
                b.push(if *call { FLAG_CALL } else { 0 });
            }
            Work::DeleteAccount { account } => {
                b.push(KIND_DELETE_ACCOUNT);
                b.extend_from_slice(account.as_bytes());
            }
            Work::DeleteObject { object } => {
                b.push(KIND_DELETE_OBJECT);
                b.extend_from_slice(&object.0);
            }
        }
        b
    }

    pub(crate) fn decode(b: &[u8]) -> Result<Self, JobError> {
        let (&version, rest) = b.split_first().ok_or(JobError::Malformed)?;
        if version != VERSION {
            return Err(JobError::Malformed);
        }
        let (id, rest) = rest.split_at_checked(16).ok_or(JobError::Malformed)?;
        let (attempt, rest) = rest.split_at_checked(2).ok_or(JobError::Malformed)?;
        let (&kind, rest) = rest.split_first().ok_or(JobError::Malformed)?;
        let work = match (kind, rest.len()) {
            (KIND_PUSH, 17) => {
                let (d, flags) = rest.split_at(16);
                let flags = flags.first().copied().ok_or(JobError::Malformed)?;
                if flags & !FLAG_CALL != 0 {
                    return Err(JobError::Malformed);
                }
                Work::Push {
                    device: DeviceId::from_slice(d).map_err(|_| JobError::Malformed)?,
                    call: flags & FLAG_CALL != 0,
                }
            }
            (KIND_DELETE_ACCOUNT, 16) => Work::DeleteAccount {
                account: AccountId::from_slice(rest).map_err(|_| JobError::Malformed)?,
            },
            (KIND_DELETE_OBJECT, 32) => {
                let mut o = [0u8; 32];
                o.copy_from_slice(rest);
                Work::DeleteObject {
                    object: ObjectKey(o),
                }
            }
            _ => return Err(JobError::Malformed),
        };
        Ok(Self {
            id: JobId::from_slice(id).map_err(|_| JobError::Malformed)?,
            attempt: u16::from_be_bytes(attempt.try_into().map_err(|_| JobError::Malformed)?),
            work,
        })
    }
}

/// Seals and opens jobs (pure; unit-tested).
pub(crate) struct Sealer {
    aead: LessSafeKey,
}

impl Sealer {
    pub(crate) fn new(secret: &[u8; 32]) -> Result<Self, JobError> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-jobs-v1").extract(secret);
        let mut key = [0u8; 32];
        prk.expand(&[b"seal"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut key))
            .map_err(|_| JobError::Sealed)?;
        let aead = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM_SIV, &key).map_err(|_| JobError::Sealed)?,
        );
        key.fill(0);
        Ok(Self { aead })
    }

    fn aad(stream: &str) -> Vec<u8> {
        let mut a = Vec::with_capacity(stream.len() + 8);
        a.extend_from_slice(b"job\0");
        a.extend_from_slice(stream.as_bytes());
        a
    }

    pub(crate) fn seal(&self, stream: &str, job: &Job) -> Result<Vec<u8>, JobError> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| JobError::Sealed)?;
        let mut body = job.encode();
        self.aead
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(stream).as_slice()),
                &mut body,
            )
            .map_err(|_| JobError::Sealed)?;
        let mut out = Vec::with_capacity(NONCE_LEN + body.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub(crate) fn open(&self, stream: &str, sealed: &[u8]) -> Result<Job, JobError> {
        if sealed.len() > MAX_SEALED {
            return Err(JobError::Sealed);
        }
        let (nonce, ct) = sealed.split_at_checked(NONCE_LEN).ok_or(JobError::Sealed)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| JobError::Sealed)?;
        let mut buf = ct.to_vec();
        let plain = self
            .aead
            .open_in_place(nonce, Aad::from(Self::aad(stream).as_slice()), &mut buf)
            .map_err(|_| JobError::Sealed)?;
        Job::decode(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn jobs() -> Vec<Job> {
        let id = JobId::from_bytes([7; 16]);
        vec![
            Job {
                id,
                attempt: 0,
                work: Work::Push {
                    device: DeviceId::from_bytes([1; 16]),
                    call: false,
                },
            },
            Job {
                id,
                attempt: 513,
                work: Work::Push {
                    device: DeviceId::from_bytes([2; 16]),
                    call: true,
                },
            },
            Job {
                id,
                attempt: 3,
                work: Work::DeleteAccount {
                    account: AccountId::from_bytes([3; 16]),
                },
            },
            Job {
                id,
                attempt: u16::MAX,
                work: Work::DeleteObject {
                    object: ObjectKey([4; 32]),
                },
            },
        ]
    }

    #[test]
    fn jobs_round_trip_and_seal() {
        let s = Sealer::new(&[9; 32]).unwrap();
        for j in jobs() {
            assert_eq!(Job::decode(&j.encode()).unwrap(), j);
            let sealed = s.seal("j:push", &j).unwrap();
            assert_eq!(s.open("j:push", &sealed).unwrap(), j);
        }
    }

    #[test]
    fn sealed_jobs_reveal_no_ids_and_open_only_on_their_stream_and_key() {
        let s = Sealer::new(&[9; 32]).unwrap();
        let other = Sealer::new(&[8; 32]).unwrap();
        for j in jobs() {
            let sealed = s.seal("j:push", &j).unwrap();
            for needle in [[1u8; 16], [2; 16], [3; 16], [7; 16]] {
                assert!(!sealed.windows(16).any(|w| w == needle));
            }
            assert!(!sealed.windows(32).any(|w| w == [4u8; 32]));
            assert_eq!(s.open("j:cleanup", &sealed), Err(JobError::Sealed));
            assert_eq!(other.open("j:push", &sealed), Err(JobError::Sealed));
            let mut tampered = sealed.clone();
            if let Some(b) = tampered.last_mut() {
                *b ^= 1;
            }
            assert_eq!(s.open("j:push", &tampered), Err(JobError::Sealed));
            // Two seals of one job differ (random nonce): equal jobs are not linkable.
            assert_ne!(sealed, s.seal("j:push", &j).unwrap());
        }
    }

    #[test]
    fn object_keys_hex_round_trip() {
        let k = ObjectKey([0xa5; 32]);
        assert_eq!(ObjectKey::parse_hex(&k.to_hex_unredacted()), Some(k));
        assert_eq!(ObjectKey::parse_hex("A5"), None);
        assert_eq!(ObjectKey::parse_hex(&"A".repeat(64)), None);
        assert_eq!(format!("{k:?}"), "ObjectKey(<redacted>)");
    }

    proptest! {
        #[test]
        fn decode_never_panics(b in proptest::collection::vec(any::<u8>(), 0..80)) {
            let _ = Job::decode(&b);
        }

        #[test]
        fn open_never_panics(b in proptest::collection::vec(any::<u8>(), 0..1100)) {
            let s = Sealer::new(&[9; 32]).unwrap();
            prop_assert!(s.open("j:push", &b).is_err());
        }
    }
}
