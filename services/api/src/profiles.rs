//! Encrypted profiles, avatars and sealed sender (Prompt 3, M5, D-0054; `docs/PROTOCOL.md` §4.8).
//!
//! | Method and path | Who | What |
//! | --- | --- | --- |
//! | `PUT /v1/profile` | a listed device | The encrypted profile, its version and the access key |
//! | `POST /v1/profile/fetch` | a device | An account's encrypted profile |
//! | `PUT /v1/profile/avatar` | a listed device | An encrypted avatar (at most 512 KiB) to `RustFS` |
//! | `GET /v1/profile/avatar/<id>` | a device | An account's current avatar |
//! | `GET /v1/certificate` | a listed device | A sender certificate (flag on) |
//! | `PUT /v1/messages/sealed` | anyone with the access keys | A sealed send (flag on) |
//!
//! The server stores profiles and avatars as opaque ciphertext under keys it never holds. Sealed
//! sends carry no device signature: they are authorized by the recipients' unidentified-access
//! keys (combined by XOR, compared in constant time), so the server learns who receives a
//! message, not who sent it. Their sender proves itself to the recipient with a short-lived
//! certificate inside the end-to-end encrypted envelope.

use std::net::IpAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use aws_lc_rs::{digest, hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::{Registry, RegistryError};
use songbird_proto::frame::{RejectReason, SendStatus};
use songbird_proto::profile::{ProfileUpload, SenderCertificate};
use songbird_types::{AccountId, DeviceId};
use songbird_valkey::ValkeyConn;

use crate::config::ProfileSettings;
use crate::registration::{Registration, range_of};

/// The "sender" a sealed send passes to the send path: no real device has this ID, so the
/// device-list check leaves no device out on its account.
pub const SEALED_SENDER: DeviceId = songbird_send::SEALED_SENDER;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct ProfileMetrics {
    /// Profiles stored.
    pub profiles: songbird_service::telemetry::sharded::ShardedCounter,
    /// Sender certificates issued.
    pub certificates: songbird_service::telemetry::sharded::ShardedCounter,
    /// Sealed sends accepted by the access check.
    pub sealed: songbird_service::telemetry::sharded::ShardedCounter,
    /// Sealed sends refused by the access check.
    pub sealed_refused: songbird_service::telemetry::sharded::ShardedCounter,
    /// Requests refused by a throttle.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
}

impl ProfileMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            (
                "api_profiles_stored",
                "Encrypted profiles stored",
                &self.profiles,
            ),
            (
                "api_certificates",
                "Sender certificates issued",
                &self.certificates,
            ),
            (
                "api_sealed_sends",
                "Sealed sends past the access check",
                &self.sealed,
            ),
            (
                "api_sealed_refused",
                "Sealed sends refused by the access check",
                &self.sealed_refused,
            ),
            (
                "api_profile_throttled",
                "Profile and sealed-send requests refused by a throttle",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// What a profile endpoint answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 204.
    Done,
    /// 200 with JSON.
    Json(serde_json::Value),
    /// 200 with bytes.
    Blob(Bytes),
    /// 200 with a `SendResult` frame.
    Sent(Bytes),
    /// 400 with a reason.
    Malformed(&'static str),
    /// 401 (a sealed send without the right access key).
    Unauthorized,
    /// 404.
    NotFound,
    /// 409 with a reason.
    Conflict(&'static str),
    /// 429 (microseconds).
    Throttled(u64),
    /// 503.
    Unavailable,
}

/// `POST /v1/profile/fetch` body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchBody {
    /// The account, 32 hex characters.
    pub account: String,
}

/// Profile state shared by every request.
pub struct Profiles {
    /// Settings.
    pub settings: ProfileSettings,
    record_key: hmac::Key,
    certificates: Option<(Ed25519KeyPair, [u8; 8])>,
    /// Counters.
    pub metrics: ProfileMetrics,
}

impl std::fmt::Debug for Profiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profiles")
            .field("sealed_sender", &self.settings.sealed_sender)
            .finish_non_exhaustive()
    }
}

/// An avatar's object name.
#[must_use]
pub fn avatar_name(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("p/");
    s.push_str(&hex::encode(id));
    s
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Signs a sender certificate (also the vector in PROTOCOL.md §13).
#[must_use]
pub fn sign_certificate(
    key: &Ed25519KeyPair,
    key_id: [u8; 8],
    account: AccountId,
    device: DeviceId,
    identity_key: [u8; 33],
    expires_ms: u64,
) -> SenderCertificate {
    let mut c = SenderCertificate {
        key_id,
        account,
        device,
        identity_key,
        expires_ms,
        signature: [0; 64],
    };
    let sig = key.sign(&c.signed_bytes());
    c.signature.copy_from_slice(sig.as_ref());
    c
}

/// A certificate key's ID: the first 8 bytes of SHA-256 of its public key.
#[must_use]
pub fn key_id(key: &Ed25519KeyPair) -> [u8; 8] {
    let mut id = [0u8; 8];
    id.copy_from_slice(
        digest::digest(&digest::SHA256, key.public_key().as_ref())
            .as_ref()
            .get(..8)
            .unwrap_or_default(),
    );
    id
}

impl Profiles {
    /// Derives the record key; loads the certificate key, if configured.
    ///
    /// # Errors
    /// HKDF (never) or a malformed certificate key.
    pub fn new(
        settings: ProfileSettings,
        secret: &[u8; 32],
        certificate_seed: Option<&[u8; 32]>,
        metrics: ProfileMetrics,
    ) -> Result<Self, &'static str> {
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-profiles-v1")
            .extract(secret)
            .expand(&[b"profile-records"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut k))
            .map_err(|_| "hkdf")?;
        let certificates = certificate_seed
            .map(|s| Ed25519KeyPair::from_seed_unchecked(s).map_err(|_| "certificate key"))
            .transpose()?
            .map(|k| {
                let id = key_id(&k);
                (k, id)
            });
        Ok(Self {
            settings,
            record_key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            certificates,
            metrics,
        })
    }

    fn record(&self, kind: &str, subject: &[u8]) -> String {
        let mut ctx = hmac::Context::with_key(&self.record_key);
        ctx.update(kind.as_bytes());
        ctx.update(&[0]);
        ctx.update(subject);
        let mut k = String::with_capacity(40);
        k.push_str("p:");
        k.push_str(kind);
        k.push(':');
        k.push_str(&hex::encode(
            ctx.sign().as_ref().get(..16).unwrap_or_default(),
        ));
        k
    }

    async fn throttle(
        &self,
        hot: &ValkeyConn,
        kind: &str,
        subject: &[u8],
        per_hour: u32,
        burst: u32,
    ) -> Result<(), Outcome> {
        match Registration::gcra(hot, &self.record(kind, subject), per_hour, burst, false).await {
            Ok(0) => Ok(()),
            Ok(wait) => {
                self.metrics.throttled.inc();
                Err(Outcome::Throttled(wait))
            }
            Err(()) => Err(Outcome::Unavailable),
        }
    }

    /// `PUT /v1/profile`.
    pub async fn put(&self, registry: &Registry, account: &AccountId, body: &[u8]) -> Outcome {
        let Ok(u) = ProfileUpload::decode(body) else {
            return Outcome::Malformed("profile");
        };
        match registry
            .put_profile(account, u.profile_version, &u.blob, &u.access_key, u.open)
            .await
        {
            Ok(()) => {
                self.metrics.profiles.inc();
                Outcome::Done
            }
            Err(RegistryError::Rollback) => Outcome::Conflict("version"),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/profile/fetch`: `{"account": hex}` → `{"version", "profile": hex}`.
    pub async fn fetch(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        requester: &AccountId,
        body: &[u8],
    ) -> Outcome {
        let s = &self.settings;
        if let Err(o) = self
            .throttle(
                hot,
                "f",
                requester.as_bytes(),
                s.fetches_per_hour,
                s.fetch_burst,
            )
            .await
        {
            return o;
        }
        let Some(account) = serde_json::from_slice::<FetchBody>(body)
            .ok()
            .and_then(|b| {
                let mut a = [0u8; 16];
                hex::decode_to_slice(b.account, &mut a).ok().map(|()| a)
            })
            .map(AccountId::from_bytes)
        else {
            return Outcome::Malformed("request");
        };
        match registry.profile(&account).await {
            Ok(Some((b, v))) => Outcome::Json(serde_json::json!({
                "version": v,
                "profile": hex::encode(b),
            })),
            Ok(None) => Outcome::NotFound,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `PUT /v1/profile/avatar`: stores the encrypted avatar under a fresh random ID.
    pub async fn put_avatar(
        &self,
        registry: &Registry,
        s3: &songbird_s3::Client,
        account: &AccountId,
        body: Bytes,
    ) -> Outcome {
        let mut id = [0u8; 32];
        if getrandom::fill(&mut id).is_err() {
            return Outcome::Unavailable;
        }
        // Recorded first (marked replaced), so a failed or interrupted upload is swept.
        if registry.reserve_avatar(account, &id).await.is_err()
            || s3.put_object_bytes(&avatar_name(&id), body).await.is_err()
        {
            return Outcome::Unavailable;
        }
        if registry.make_avatar_current(account, &id).await.is_ok() {
            Outcome::Json(serde_json::json!({ "avatar": hex::encode(id) }))
        } else {
            Outcome::Unavailable
        }
    }

    /// Whether `GET /v1/profile/avatar/<id>` may serve this object (throttled per requester).
    pub async fn avatar_allowed(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        requester: &AccountId,
        id: &[u8; 32],
    ) -> Result<(), Outcome> {
        let s = &self.settings;
        self.throttle(
            hot,
            "a",
            requester.as_bytes(),
            s.fetches_per_hour,
            s.fetch_burst,
        )
        .await?;
        match registry.avatar_current(id).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Outcome::NotFound),
            Err(_) => Err(Outcome::Unavailable),
        }
    }

    /// `GET /v1/certificate`: a sender certificate for the device, valid `certificate_hours`.
    pub async fn certificate(
        &self,
        registry: &Registry,
        account: &AccountId,
        device: &DeviceId,
    ) -> Outcome {
        let Some((key, id)) = self
            .certificates
            .as_ref()
            .filter(|_| self.settings.sealed_sender)
        else {
            return Outcome::NotFound;
        };
        let identity = match registry.device_keys(device).await {
            Ok(k) => k.identity,
            Err(_) => return Outcome::Unavailable,
        };
        let Some(identity) = identity else {
            return Outcome::Conflict("identity");
        };
        let expires = now_ms().saturating_add(self.settings.certificate_hours * 3_600_000);
        self.metrics.certificates.inc();
        Outcome::Blob(Bytes::from(
            sign_certificate(key, *id, *account, *device, identity, expires).encode(),
        ))
    }

    /// `PUT /v1/messages/sealed`: authorized by the recipients' access keys, not a device.
    pub async fn sealed_send(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        messages: Option<&crate::messages::Messages>,
        peer: IpAddr,
        access_key: Option<[u8; 16]>,
        body: Bytes,
    ) -> Outcome {
        let received = Instant::now();
        let s = &self.settings;
        if !s.sealed_sender {
            return Outcome::NotFound;
        }
        let Some(m) = messages else {
            return Outcome::Unavailable;
        };
        let range = range_of(peer, s.ipv4_prefix, s.ipv6_prefix);
        if let Err(o) = self
            .throttle(hot, "s", &range, s.sealed_per_hour, s.sealed_burst)
            .await
        {
            return o;
        }
        let Some(frame) = crate::messages::decode(&body, &m.limits) else {
            return Outcome::Malformed("request");
        };
        if frame.mls.is_some() {
            return Outcome::Malformed("mls");
        }
        // The access keys are in the header; a sealed send is never a request (requests are
        // identified, so they can be blocked and reported, D-0062).
        if frame.hints.access.is_some() || frame.hints.request {
            return Outcome::Malformed("hints");
        }
        let devices: Vec<DeviceId> = frame.payload.devices().copied().collect();
        let Ok(keys) = registry.access_keys(&devices).await else {
            return Outcome::Unavailable;
        };
        // Every addressed account must allow it: open, or its key in the combined header.
        let closed: Vec<&[u8; 16]> = keys
            .iter()
            .filter(|k| !k.open)
            .filter_map(|k| k.key.as_ref())
            .collect();
        let missing = keys.iter().any(|k| !k.open && k.key.is_none());
        let expected = songbird_keys::sealed::combine(closed.iter().copied());
        let presented = access_key.unwrap_or([0; 16]);
        let ok = !missing
            && (closed.is_empty()
                || aws_lc_rs::constant_time::verify_slices_are_equal(&expected, &presented)
                    .is_ok());
        if !ok {
            self.metrics.sealed_refused.inc();
            return Outcome::Unauthorized;
        }
        // Per recipient account too, so one sender cannot flood an account from many ranges.
        for k in &keys {
            if let Err(o) = self
                .throttle(
                    hot,
                    "t",
                    k.account.as_bytes(),
                    s.sealed_per_account_hour,
                    s.sealed_burst,
                )
                .await
            {
                return o;
            }
        }
        self.metrics.sealed.inc();
        let req_id = frame.req_id;
        let status = m.path.submit(&SEALED_SENDER, frame, received).await;
        if matches!(
            status,
            SendStatus::Rejected {
                reason: RejectReason::Unavailable,
                ..
            }
        ) {
            tracing::warn!("sealed send not stored");
        }
        Outcome::Sent(crate::messages::result_frame(req_id, status))
    }
}

/// Time left on a certificate (tests and clients).
#[must_use]
pub fn certificate_valid(c: &SenderCertificate, public: &[u8; 32], now_ms: u64) -> bool {
    c.expires_ms > now_ms && songbird_keys::ed25519_verify(public, &c.signed_bytes(), &c.signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    /// The certificate vector in PROTOCOL.md §13: a fixed seed and fixed fields give these bytes
    /// (Ed25519 is deterministic).
    #[test]
    fn certificate_vector() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap();
        let c = sign_certificate(
            &key,
            key_id(&key),
            AccountId::from_bytes([1; 16]),
            DeviceId::from_bytes([2; 16]),
            {
                let mut k = [3u8; 33];
                k[0] = 5;
                k
            },
            1_800_000_000_000,
        );
        let public: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
        assert!(certificate_valid(&c, &public, 1_799_999_999_999));
        assert!(!certificate_valid(&c, &public, 1_800_000_000_000));
        let mut t = c.clone();
        t.device = DeviceId::from_bytes([9; 16]);
        assert!(!certificate_valid(&t, &public, 0));
        assert_eq!(SenderCertificate::decode(&c.encode()).unwrap(), c);
        assert_eq!(hex::encode(c.encode()), VECTOR);
    }

    /// Cross-checked with OpenSSL 4.1 (`openssl pkeyutl -sign -rawin` over the same bytes).
    const VECTOR: &str = "013097e2dee2cb4a340101010101010101010101010101010102020202020202020202020202020202050303030303030303030303030303030303030303030303030303030303030303000001a3185c5000e2ba85e62f8006c7ff540bbed16ff64f1636cb28133f05da28b9604b0d4d32596d486dd773916abf4a674b75813703d273e747b840ed8288da465c69f4c98804";
}
