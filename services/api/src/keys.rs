//! The key directory (Prompt 3, M3, D-0050; `docs/PROTOCOL.md` §4.4): PQXDH prekeys per device.
//! Every endpoint is signed by a device ([`crate::auth`]).
//!
//! | Method and path | What |
//! | --- | --- |
//! | `PUT /v1/keys` | Upload: identity key (once), signed prekey, last-resort ML-KEM prekey, one-time prekeys |
//! | `GET /v1/keys` | The device's one-time prekeys left |
//! | `POST /v1/keys/fetch` | `{"account": hex, "device"?: hex}`: a bundle per device, one-time keys claimed |
//! | `PUT /v1/keypackages` | MLS KeyPackages (M3b, D-0051): each checked, bound to the uploading device |
//! | `GET /v1/keypackages` | Single-use KeyPackages left; whether a last-resort one is set |
//! | `POST /v1/keypackages/fetch` | `{"account": hex, "device"?: hex}`: a KeyPackage per device, single-use ones claimed |
//!
//! # What the server checks before storing anything
//!
//! - The identity key: libsignal's `0x05` X25519 serialization, an honest point (canonical, on the
//!   curve, prime order); set once per device and never replaced.
//! - Every X25519 prekey: the same checks. Every ML-KEM prekey: `0x0A` and the FIPS 203 modulus
//!   check, which aws-lc-rs alone does not apply (found while building).
//! - Every signature: XEdDSA by the device identity key over the key's serialization, with a
//!   canonical `s` (stricter than libsignal, which accepts and reduces a larger one).
//!
//! # Exhaustion
//!
//! One-time prekeys protect the first message of a session; an attacker who drains them makes
//! later sessions use the last-resort ML-KEM prekey and no one-time X25519 prekey (still forward
//! secret, but replayable until the recipient rotates). So: fetches are limited per requesting
//! account; one-time keys handed out per target account are limited across all requesters,
//! and when that budget is spent a fetch still answers, with the last-resort key only. A device
//! below the refill threshold gets a server-signed "prekeys low" notice, at most once an hour.

use std::collections::HashSet;
use std::net::IpAddr;

use aws_lc_rs::{hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::{ClaimedKeys, KeysUpdate, Registry, RegistryError, StoredKeyPackage};
use songbird_proto::keys::KeyPackageBundle;
use songbird_proto::keys::{self as wire, Bundle, OneTimeEc, SignedEc, SignedKem, Upload};
use songbird_proto::system::{Kind, PrekeysLow};
use songbird_send::system::SystemSigner;
use songbird_types::{AccountId, DeviceId};
use songbird_valkey::ValkeyConn;

use crate::config::KeySettings;
use crate::registration::{Registration, range_of};

/// Counters (aggregate only; names avoid the redaction rules' sensitive words).
#[derive(Debug, Clone, Default)]
pub struct KeyMetrics {
    /// Uploads stored.
    pub uploads: songbird_service::telemetry::sharded::ShardedCounter,
    /// Uploads refused (malformed, a bad key or signature, identity, full, duplicate).
    pub refused: songbird_service::telemetry::sharded::ShardedCounter,
    /// Bundles handed out.
    pub bundles: songbird_service::telemetry::sharded::ShardedCounter,
    /// Bundles handed out with the last-resort ML-KEM prekey (none one-time left, or the
    /// target's budget spent).
    pub last_resort: songbird_service::telemetry::sharded::ShardedCounter,
    /// "Prekeys low" notices sent.
    pub notices: songbird_service::telemetry::sharded::ShardedCounter,
    /// Fetches refused by a throttle.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
}

impl KeyMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            ("api_prekey_uploads", "Prekey uploads stored", &self.uploads),
            (
                "api_prekey_uploads_refused",
                "Prekey uploads refused",
                &self.refused,
            ),
            (
                "api_prekey_bundles",
                "Prekey bundles handed out",
                &self.bundles,
            ),
            (
                "api_prekey_last_resort",
                "Bundles handed out with the last-resort post-quantum prekey",
                &self.last_resort,
            ),
            (
                "api_prekey_notices",
                "Prekeys-low notices sent",
                &self.notices,
            ),
            (
                "api_prekey_throttled",
                "Prekey fetches refused by a throttle",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// What a key endpoint answers (the HTTP layer maps it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 204.
    Done,
    /// 200: one-time prekeys left.
    Counts(u64, u64),
    /// 200: single-use KeyPackages left, and whether a last-resort one is set.
    KeyPackageCounts(u64, bool),
    /// 200: encoded bundles.
    Bundles(Bytes),
    /// 400 with a reason.
    Malformed(&'static str),
    /// 404.
    NotFound,
    /// 409 with a reason.
    Conflict(&'static str),
    /// 429: wait this long (microseconds).
    Throttled(u64),
    /// 503.
    Unavailable,
}

/// Fetch request body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchBody {
    /// The account, 32 hex characters.
    pub account: String,
    /// One device of it (32 hex characters); absent: all of them.
    #[serde(default)]
    pub device: Option<String>,
}

/// Key directory state shared by every request.
pub struct KeyDirectory {
    /// Settings.
    pub settings: KeySettings,
    throttle_key: hmac::Key,
    signer: Option<SystemSigner>,
    /// Counters.
    pub metrics: KeyMetrics,
}

impl std::fmt::Debug for KeyDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyDirectory")
            .field("notices", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

/// Checks an upload against the device's identity key; returns what to store.
fn verify_upload(u: &Upload, stored_identity: Option<[u8; 33]>) -> Result<KeysUpdate, Outcome> {
    let x25519_ok = |k: &[u8; wire::EC_LEN]| {
        k.split_first().is_some_and(|(t, u)| {
            *t == wire::TYPE_X25519
                && <&[u8; 32]>::try_from(u).is_ok_and(songbird_keys::xeddsa::x25519_public_key_ok)
        })
    };
    if let (Some(new), Some(old)) = (u.identity, stored_identity)
        && new != old
    {
        return Err(Outcome::Conflict("identity"));
    }
    let identity = u
        .identity
        .or(stored_identity)
        .ok_or(Outcome::Malformed("incomplete"))?;
    if !x25519_ok(&identity) {
        return Err(Outcome::Malformed("keys"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(identity.get(1..).unwrap_or_default());
    let signed_ok =
        |key: &[u8], sig: &[u8; wire::SIG_LEN]| songbird_keys::xeddsa::verify(&ik, key, sig);
    if let Some(s) = &u.signed {
        if !x25519_ok(&s.key) {
            return Err(Outcome::Malformed("keys"));
        }
        if !signed_ok(&s.key, &s.sig) {
            return Err(Outcome::Malformed("signature"));
        }
    }
    for k in u.last_resort.iter().chain(&u.one_time_kem) {
        if !songbird_keys::kem::public_key_ok(k.key.as_slice()) {
            return Err(Outcome::Malformed("keys"));
        }
        if !signed_ok(k.key.as_slice(), &k.sig) {
            return Err(Outcome::Malformed("signature"));
        }
    }
    for k in &u.one_time_ec {
        if !x25519_ok(&k.key) {
            return Err(Outcome::Malformed("keys"));
        }
    }
    let unique = |ids: Vec<u32>| ids.len() == ids.iter().collect::<HashSet<_>>().len();
    if !unique(u.one_time_ec.iter().map(|k| k.id).collect())
        || !unique(u.one_time_kem.iter().map(|k| k.id).collect())
    {
        return Err(Outcome::Malformed("duplicate"));
    }
    Ok(KeysUpdate {
        identity: u.identity,
        signed: u.signed.as_ref().map(SignedEc::to_bytes),
        last_resort: u.last_resort.as_ref().map(SignedKem::to_bytes),
        one_time_ec: u.one_time_ec.iter().map(|k| (k.id, k.to_bytes())).collect(),
        one_time_kem: u
            .one_time_kem
            .iter()
            .map(|k| (k.id, k.to_bytes()))
            .collect(),
    })
}

fn to_bundle(c: &ClaimedKeys) -> Option<Bundle> {
    Some(Bundle {
        device: c.device,
        identity: c.identity,
        signed: SignedEc::from_bytes(&c.signed).ok()?,
        one_time_ec: match &c.one_time_ec {
            Some(b) => Some(OneTimeEc::from_bytes(b).ok()?),
            None => None,
        },
        kem: SignedKem::from_bytes(&c.kem).ok()?,
        kem_one_time: c.kem_one_time,
    })
}

impl KeyDirectory {
    /// Derives the throttle key; loads the system key for notices, if configured.
    ///
    /// # Errors
    /// HKDF (never for 32 bytes) or a malformed system key.
    pub fn new(
        settings: KeySettings,
        secret: &[u8; 32],
        system_seed: Option<&[u8; 32]>,
        metrics: KeyMetrics,
    ) -> Result<Self, &'static str> {
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-keys-v1")
            .extract(secret)
            .expand(&[b"prekey-throttle"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut k))
            .map_err(|_| "hkdf")?;
        let signer = system_seed
            .map(SystemSigner::from_seed)
            .transpose()
            .map_err(|_| "system key")?;
        Ok(Self {
            settings,
            throttle_key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            signer,
            metrics,
        })
    }

    fn record(&self, kind: &str, subject: &[u8]) -> String {
        let mut ctx = hmac::Context::with_key(&self.throttle_key);
        ctx.update(kind.as_bytes());
        ctx.update(&[0]);
        ctx.update(subject);
        let tag = ctx.sign();
        let mut k = String::with_capacity(40);
        k.push_str("k:");
        k.push_str(kind);
        k.push(':');
        k.push_str(&hex::encode(tag.as_ref().get(..16).unwrap_or_default()));
        k
    }

    /// `PUT /v1/keys`.
    pub async fn upload(&self, registry: &Registry, device: &DeviceId, body: Bytes) -> Outcome {
        let out = self.upload_inner(registry, device, body).await;
        if out == Outcome::Done {
            self.metrics.uploads.inc();
        } else if out != Outcome::Unavailable {
            self.metrics.refused.inc();
        }
        out
    }

    async fn upload_inner(&self, registry: &Registry, device: &DeviceId, body: Bytes) -> Outcome {
        let Ok(stored) = registry.device_keys(device).await else {
            return Outcome::Unavailable;
        };
        // Up to 200 signatures and ML-KEM parses: off the async runtime.
        let checked = tokio::task::spawn_blocking(move || {
            let u = Upload::decode(&body).map_err(|_| Outcome::Malformed("request"))?;
            verify_upload(&u, stored.identity)
        })
        .await;
        let update = match checked {
            Ok(Ok(u)) => u,
            Ok(Err(o)) => return o,
            Err(_) => return Outcome::Unavailable,
        };
        match registry
            .put_keys(device, &update, self.settings.max_stored)
            .await
        {
            Ok(()) => Outcome::Done,
            Err(RegistryError::IdentityMismatch) => Outcome::Conflict("identity"),
            Err(RegistryError::Full) => Outcome::Conflict("full"),
            Err(RegistryError::Duplicate) => Outcome::Conflict("duplicate"),
            Err(RegistryError::Incomplete) => Outcome::Malformed("incomplete"),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `GET /v1/keys`.
    pub async fn counts(&self, registry: &Registry, device: &DeviceId) -> Outcome {
        match registry.prekey_counts(device).await {
            Ok((ec, kem)) => Outcome::Counts(ec, kem),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/keys/fetch`.
    pub async fn fetch(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        messages: Option<&crate::messages::Messages>,
        requester: (&AccountId, &DeviceId),
        peer: IpAddr,
        body: &[u8],
    ) -> Outcome {
        let t = &self.settings.throttle;
        let range = range_of(peer, t.ipv4_prefix, t.ipv6_prefix);
        for (record, rate, burst) in [
            (
                self.record("f", requester.0.as_bytes()),
                t.fetches_per_hour,
                t.fetch_burst,
            ),
            (
                self.record("r", &range),
                t.range_fetches_per_hour,
                t.range_fetch_burst,
            ),
        ] {
            match Registration::gcra(hot, &record, rate, burst, false).await {
                Ok(0) => {}
                Ok(wait) => {
                    self.metrics.throttled.inc();
                    return Outcome::Throttled(wait);
                }
                Err(()) => return Outcome::Unavailable,
            }
        }
        let Ok(req) = serde_json::from_slice::<FetchBody>(body) else {
            return Outcome::Malformed("request");
        };
        let parse = |h: &str| {
            let mut b = [0u8; 16];
            hex::decode_to_slice(h, &mut b).ok().map(|()| b)
        };
        let Some(account) = parse(&req.account).map(AccountId::from_bytes) else {
            return Outcome::Malformed("account");
        };
        let only = match req.device.as_deref().map(parse) {
            Some(Some(d)) => Some(DeviceId::from_bytes(d)),
            Some(None) => return Outcome::Malformed("device"),
            None => None,
        };
        // The target's one-time budget, across every requester: spent, the fetch still answers
        // with last-resort keys only.
        let one_time = match Registration::gcra(
            hot,
            &self.record("t", account.as_bytes()),
            t.target_one_time_per_hour,
            t.target_one_time_burst,
            false,
        )
        .await
        {
            Ok(wait) => wait == 0,
            Err(()) => return Outcome::Unavailable,
        };
        let Ok(claimed) = registry
            .claim_bundles(&account, only.as_ref(), requester.1, one_time)
            .await
        else {
            return Outcome::Unavailable;
        };
        // A stored row that no longer parses (it cannot, unless the store is corrupted) is
        // skipped, not allowed to cost the other devices' claimed keys.
        let bundles: Vec<Bundle> = claimed.iter().filter_map(to_bundle).collect();
        if bundles.is_empty() {
            return Outcome::NotFound;
        }
        for b in &bundles {
            self.metrics.bundles.inc();
            if !b.kem_one_time {
                self.metrics.last_resort.inc();
            }
        }
        if let (Some(signer), Some(m)) = (&self.signer, messages) {
            for c in claimed
                .iter()
                .filter(|c| c.one_time_ec.is_some() || c.kem_one_time)
            {
                self.maybe_notify(registry, hot, signer, m, &c.device).await;
            }
        }
        Outcome::Bundles(Bytes::from(wire::encode_bundles(&bundles)))
    }

    /// Tells a device its one-time prekeys run low, at most once an hour (best effort: a failure
    /// is retried by the next fetch after the hour).
    async fn maybe_notify(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        signer: &SystemSigner,
        m: &crate::messages::Messages,
        device: &DeviceId,
    ) {
        let Ok((ec, kem)) = registry.prekey_counts(device).await else {
            return;
        };
        let below = u64::from(self.settings.refill_below);
        if ec >= below && kem >= below {
            return;
        }
        let first: Result<redis::Value, _> = hot
            .query(
                redis::cmd("SET")
                    .arg(self.record("n", device.as_bytes()))
                    .arg(1)
                    .arg("NX")
                    .arg("PX")
                    .arg(3_600_000u64),
            )
            .await;
        if !matches!(first, Ok(redis::Value::Okay)) {
            return;
        }
        let body = PrekeysLow {
            ec: u16::try_from(ec).unwrap_or(u16::MAX),
            kem: u16::try_from(kem).unwrap_or(u16::MAX),
        }
        .encode();
        let mut id = [0u8; songbird_proto::system::NOTICE_ID_LEN];
        if getrandom::fill(&mut id).is_err() {
            return;
        }
        match m
            .path
            .system(
                signer,
                std::slice::from_ref(device),
                Kind::PrekeysLow,
                &body,
                id,
            )
            .await
        {
            Ok(()) => self.metrics.notices.inc(),
            Err(e) => tracing::warn!(error = %e, "prekeys-low notice not sent"),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Checks every package of an upload against the uploading device; at most one last-resort.
fn verify_key_packages(
    body: &[u8],
    device: &DeviceId,
    now: u64,
) -> Result<(Vec<StoredKeyPackage>, Option<StoredKeyPackage>), Outcome> {
    let packages = wire::decode_key_packages(body).map_err(|_| Outcome::Malformed("request"))?;
    let mut single_use = Vec::new();
    let mut last_resort = None;
    let mut refs = HashSet::new();
    for p in packages {
        let c = songbird_keys::mls::check(p, device.as_bytes(), now).map_err(|e| {
            Outcome::Malformed(match e {
                songbird_keys::mls::MlsError::Malformed => "request",
                songbird_keys::mls::MlsError::Unsupported => "unsupported",
                songbird_keys::mls::MlsError::Keys => "keys",
                songbird_keys::mls::MlsError::Identity => "identity",
                songbird_keys::mls::MlsError::Lifetime => "lifetime",
                songbird_keys::mls::MlsError::Signature => "signature",
            })
        })?;
        if !refs.insert(c.reference) {
            return Err(Outcome::Malformed("duplicate"));
        }
        let stored = StoredKeyPackage {
            reference: c.reference,
            package: p.to_vec(),
            not_after: c.not_after,
        };
        if c.last_resort {
            if last_resort.is_some() {
                return Err(Outcome::Malformed("last resort"));
            }
            last_resort = Some(stored);
        } else {
            single_use.push(stored);
        }
    }
    Ok((single_use, last_resort))
}

impl KeyDirectory {
    /// `PUT /v1/keypackages`.
    pub async fn upload_key_packages(
        &self,
        registry: &Registry,
        device: &DeviceId,
        body: Bytes,
    ) -> Outcome {
        let dev = *device;
        let checked =
            tokio::task::spawn_blocking(move || verify_key_packages(&body, &dev, now_secs())).await;
        let (single_use, last_resort) = match checked {
            Ok(Ok(x)) => x,
            Ok(Err(o)) => {
                self.metrics.refused.inc();
                return o;
            }
            Err(_) => return Outcome::Unavailable,
        };
        let out = match registry
            .put_key_packages(
                device,
                &single_use,
                last_resort.as_ref(),
                self.settings.max_stored,
            )
            .await
        {
            Ok(()) => Outcome::Done,
            Err(RegistryError::Full) => Outcome::Conflict("full"),
            Err(RegistryError::Duplicate) => Outcome::Conflict("duplicate"),
            Err(_) => Outcome::Unavailable,
        };
        if out == Outcome::Done {
            self.metrics.uploads.inc();
        } else if out != Outcome::Unavailable {
            self.metrics.refused.inc();
        }
        out
    }

    /// `GET /v1/keypackages`.
    pub async fn key_package_counts(&self, registry: &Registry, device: &DeviceId) -> Outcome {
        match registry.key_package_counts(device).await {
            Ok((n, lr)) => Outcome::KeyPackageCounts(n, lr),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/keypackages/fetch`: the same throttles as prekey fetches (their own records),
    /// the same per-target budget with last-resort packages beyond it.
    pub async fn fetch_key_packages(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        messages: Option<&crate::messages::Messages>,
        requester: (&AccountId, &DeviceId),
        peer: IpAddr,
        body: &[u8],
    ) -> Outcome {
        let t = &self.settings.throttle;
        let range = range_of(peer, t.ipv4_prefix, t.ipv6_prefix);
        for (record, rate, burst) in [
            (
                self.record("F", requester.0.as_bytes()),
                t.fetches_per_hour,
                t.fetch_burst,
            ),
            (
                self.record("R", &range),
                t.range_fetches_per_hour,
                t.range_fetch_burst,
            ),
        ] {
            match Registration::gcra(hot, &record, rate, burst, false).await {
                Ok(0) => {}
                Ok(wait) => {
                    self.metrics.throttled.inc();
                    return Outcome::Throttled(wait);
                }
                Err(()) => return Outcome::Unavailable,
            }
        }
        let Ok(req) = serde_json::from_slice::<FetchBody>(body) else {
            return Outcome::Malformed("request");
        };
        let parse = |h: &str| {
            let mut b = [0u8; 16];
            hex::decode_to_slice(h, &mut b).ok().map(|()| b)
        };
        let Some(account) = parse(&req.account).map(AccountId::from_bytes) else {
            return Outcome::Malformed("account");
        };
        let only = match req.device.as_deref().map(parse) {
            Some(Some(d)) => Some(DeviceId::from_bytes(d)),
            Some(None) => return Outcome::Malformed("device"),
            None => None,
        };
        let one_time = match Registration::gcra(
            hot,
            &self.record("T", account.as_bytes()),
            t.target_one_time_per_hour,
            t.target_one_time_burst,
            false,
        )
        .await
        {
            Ok(wait) => wait == 0,
            Err(()) => return Outcome::Unavailable,
        };
        let Ok(claimed) = registry
            .claim_key_packages(&account, only.as_ref(), requester.1, one_time)
            .await
        else {
            return Outcome::Unavailable;
        };
        if claimed.is_empty() {
            return Outcome::NotFound;
        }
        let bundles: Vec<KeyPackageBundle> = claimed
            .iter()
            .map(|c| KeyPackageBundle {
                device: c.device,
                one_time: c.one_time,
                package: c.package.to_vec(),
            })
            .collect();
        for b in &bundles {
            self.metrics.bundles.inc();
            if !b.one_time {
                self.metrics.last_resort.inc();
            }
        }
        if let (Some(signer), Some(m)) = (&self.signer, messages) {
            for c in claimed.iter().filter(|c| c.one_time) {
                self.maybe_notify_key_packages(registry, hot, signer, m, &c.device)
                    .await;
            }
        }
        Outcome::Bundles(Bytes::from(wire::encode_key_package_bundles(&bundles)))
    }

    /// Tells a device its single-use KeyPackages run low, at most once an hour.
    async fn maybe_notify_key_packages(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        signer: &SystemSigner,
        m: &crate::messages::Messages,
        device: &DeviceId,
    ) {
        let Ok((n, _)) = registry.key_package_counts(device).await else {
            return;
        };
        if n >= u64::from(self.settings.refill_below) {
            return;
        }
        let first: Result<redis::Value, _> = hot
            .query(
                redis::cmd("SET")
                    .arg(self.record("N", device.as_bytes()))
                    .arg(1)
                    .arg("NX")
                    .arg("PX")
                    .arg(3_600_000u64),
            )
            .await;
        if !matches!(first, Ok(redis::Value::Okay)) {
            return;
        }
        let body = u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes();
        let mut id = [0u8; songbird_proto::system::NOTICE_ID_LEN];
        if getrandom::fill(&mut id).is_err() {
            return;
        }
        match m
            .path
            .system(
                signer,
                std::slice::from_ref(device),
                Kind::KeyPackagesLow,
                &body,
                id,
            )
            .await
        {
            Ok(()) => self.metrics.notices.inc(),
            Err(e) => tracing::warn!(error = %e, "key packages low notice not sent"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_1024};
    use songbird_keys::xeddsa::Signer;

    use super::*;

    fn ec(signer: &Signer) -> [u8; 33] {
        let mut k = [0u8; 33];
        k[0] = wire::TYPE_X25519;
        k[1..].copy_from_slice(&signer.public());
        k
    }

    fn kem(id: u32, by: &Signer) -> SignedKem {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).unwrap();
        let mut key = [0u8; wire::KEM_LEN];
        key[0] = wire::TYPE_ML_KEM_1024;
        key[1..].copy_from_slice(
            dk.encapsulation_key()
                .unwrap()
                .key_bytes()
                .unwrap()
                .as_ref(),
        );
        let sig = by.sign(&key, &[1; 64]);
        SignedKem {
            id,
            key: Box::new(key),
            sig,
        }
    }

    fn upload(identity: &Signer) -> Upload {
        let spk = Signer::new(&[2; 32]);
        let spk_key = ec(&spk);
        Upload {
            identity: Some(ec(identity)),
            signed: Some(SignedEc {
                id: 1,
                key: spk_key,
                sig: identity.sign(&spk_key, &[3; 64]),
            }),
            last_resort: Some(kem(2, identity)),
            one_time_ec: vec![OneTimeEc {
                id: 3,
                key: ec(&Signer::new(&[4; 32])),
            }],
            one_time_kem: vec![kem(4, identity)],
        }
    }

    #[test]
    fn honest_uploads_pass_and_every_kind_of_tampering_is_refused() {
        let id = Signer::new(&[1; 32]);
        let u = upload(&id);
        let ok = verify_upload(&u, None).unwrap();
        assert_eq!(ok.one_time_kem.len(), 1);
        // The same identity again is fine; another is a conflict.
        assert!(verify_upload(&u, u.identity).is_ok());
        assert_eq!(
            verify_upload(&u, Some(ec(&Signer::new(&[9; 32])))).err(),
            Some(Outcome::Conflict("identity"))
        );
        // No identity anywhere.
        let mut v = u.clone();
        v.identity = None;
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("incomplete"))
        );
        // A signed prekey signed by someone else; a KEM key signed by someone else.
        let other = Signer::new(&[8; 32]);
        let mut v = u.clone();
        let spk_key = v.signed.as_ref().unwrap().key;
        v.signed.as_mut().unwrap().sig = other.sign(&spk_key, &[3; 64]);
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("signature"))
        );
        let mut v = u.clone();
        v.one_time_kem = vec![kem(4, &other)];
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("signature"))
        );
        // A KEM key with a coefficient >= q (re-signed, so only the key check can refuse it).
        let mut v = u.clone();
        let mut bad = *v.last_resort.as_ref().unwrap().key;
        bad[1] = 0xFF;
        bad[2] |= 0x0F;
        v.last_resort = Some(SignedKem {
            id: 2,
            sig: id.sign(&bad, &[5; 64]),
            key: Box::new(bad),
        });
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("keys"))
        );
        // A small-order one-time key; Kyber1024's type byte; duplicate IDs.
        let mut v = u.clone();
        v.one_time_ec[0].key = [0; 33];
        v.one_time_ec[0].key[0] = wire::TYPE_X25519;
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("keys"))
        );
        let mut v = u.clone();
        let mut kyber = *v.one_time_kem[0].key;
        kyber[0] = 0x08;
        v.one_time_kem[0] = SignedKem {
            id: 4,
            sig: id.sign(&kyber, &[6; 64]),
            key: Box::new(kyber),
        };
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("keys"))
        );
        let mut v = u.clone();
        v.one_time_ec.push(v.one_time_ec[0].clone());
        assert_eq!(
            verify_upload(&v, None).err(),
            Some(Outcome::Malformed("duplicate"))
        );
    }
}
