//! The Songbird backup vault (Prompt 10, M2, D-0121; `docs/PROTOCOL.md` §11.8).
//!
//! A vault holds one backup's encrypted objects (`crates/backup-format`): chunks under their
//! keyed names and one manifest. Every request names the vault and proves the access secret,
//! both derived from the recovery key on the device:
//!
//! - `x-songbird-vault`: the vault ID (64 hex); the server keys rows and objects by
//!   `HMAC(secret, vault ID)` and never stores the ID;
//! - `x-songbird-vault-access`: the access secret (64 hex); the server stores only
//!   `SHA-256("songbird.v1/vault-access\0" || secret)` and compares in constant time.
//!
//! Reads need only those two headers, so a new device holding only the recovery key can find and
//! restore its backup. Writes also need a signature by the **primary** device of the account
//! that owns the vault (quota, deletion with the account; D-0119 §3). An unknown vault, a vault
//! being deleted and a wrong secret get the same 404 after the same lookup, and count against
//! the requester's IP range.
//!
//! | Request | Who | What |
//! | --- | --- | --- |
//! | `POST /v1/vault` | the primary | Creates the vault (or confirms it exists) |
//! | `GET /v1/vault` | the secret | `{"generation", "bytes", "chunks", "quota_bytes", "quota_chunks"}` |
//! | `DELETE /v1/vault` | the owner's primary | Turns it off: rows gone at once, objects deleted by the worker |
//! | `GET /v1/vault/manifest` | the secret | The manifest object, or 204 before the first |
//! | `PUT /v1/vault/manifest` | the owner's primary | Compare-and-swap on `x-songbird-vault-expected`; 409 `{"generation"}` |
//! | `PUT /v1/vault/chunks/<name>` | the owner's primary | One chunk object; 409 `full` past the quota |
//! | `GET /v1/vault/chunks/<name>` | the secret | One chunk object |
//! | `GET /v1/vault/chunks?after=<name>` | the secret | A page of names (`songbird_proto::vault`) |
//! | `POST /v1/vault/chunks/delete` | the owner's primary | Forgets up to 1,000 chunks and deletes their objects |
//!
//! No time is stored and no vault ID, name or account reaches a log.

use std::net::IpAddr;

use aws_lc_rs::{constant_time, digest, hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::{DeviceRow, Registry, RegistryError, VaultError, VaultQuota, VaultRow};
use songbird_proto::vault as wire;
use songbird_valkey::ValkeyConn;

use crate::config::VaultSettings;
use crate::profiles::Outcome;
use crate::registration::{Registration, range_of};

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct VaultMetrics {
    /// Chunks stored (new ones).
    pub chunks: songbird_service::telemetry::sharded::ShardedCounter,
    /// Manifests swapped.
    pub manifests: songbird_service::telemetry::sharded::ShardedCounter,
    /// Manifest writes that lost the compare-and-swap.
    pub conflicts: songbird_service::telemetry::sharded::ShardedCounter,
    /// Writes refused by the quota.
    pub full: songbird_service::telemetry::sharded::ShardedCounter,
    /// Requests that named no vault, or with a wrong secret.
    pub misses: songbird_service::telemetry::sharded::ShardedCounter,
    /// Requests refused by a throttle.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
}

impl VaultMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            ("api_vault_chunks", "Backup chunks stored", &self.chunks),
            (
                "api_vault_manifests",
                "Backup manifests swapped",
                &self.manifests,
            ),
            (
                "api_vault_conflicts",
                "Backup manifest writes that lost the compare-and-swap",
                &self.conflicts,
            ),
            (
                "api_vault_full",
                "Backup writes refused by the quota",
                &self.full,
            ),
            (
                "api_vault_misses",
                "Backup requests naming no vault or a wrong secret",
                &self.misses,
            ),
            (
                "api_vault_throttled",
                "Backup requests refused by a throttle",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// The vault endpoints' state.
pub struct Vault {
    /// Settings.
    pub settings: VaultSettings,
    /// The vaults' bucket.
    pub s3: songbird_s3::Client,
    key: hmac::Key,
    record_key: hmac::Key,
    metrics: VaultMetrics,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

/// The two keys every `api` and `worker` node derives from `[api.vault] secret`: the vault key
/// (`HMAC(k, vault ID)`) and the throttle records' key.
///
/// # Errors
/// HKDF (never).
pub fn derive_keys(secret: &[u8; 32]) -> Result<(hmac::Key, hmac::Key), &'static str> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-vault-v1").extract(secret);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    prk.expand(&[b"vault-key"], hkdf::HKDF_SHA256)
        .and_then(|o| o.fill(&mut a))
        .map_err(|_| "hkdf")?;
    prk.expand(&[b"vault-records"], hkdf::HKDF_SHA256)
        .and_then(|o| o.fill(&mut b))
        .map_err(|_| "hkdf")?;
    Ok((
        hmac::Key::new(hmac::HMAC_SHA256, &a),
        hmac::Key::new(hmac::HMAC_SHA256, &b),
    ))
}

/// The prefix of every object of one vault incarnation: `<vault key hex>/<epoch hex>/`. A vault
/// turned off and opened again with the same recovery key gets a new epoch, so the worker
/// deleting the old objects never touches the new ones.
#[must_use]
pub fn prefix(vk: &[u8; 32], epoch: &[u8; 16]) -> String {
    format!("{}/{}/", hex::encode(vk), hex::encode(epoch))
}

/// A chunk's object name: `<prefix>c/<name hex>`.
#[must_use]
pub fn chunk_object(vk: &[u8; 32], epoch: &[u8; 16], name: &[u8; 32]) -> String {
    format!("{}c/{}", prefix(vk, epoch), hex::encode(name))
}

/// A manifest's object name: `<prefix>m/<suffix hex>`.
#[must_use]
pub fn manifest_object(vk: &[u8; 32], epoch: &[u8; 16], suffix: &[u8; 16]) -> String {
    format!("{}m/{}", prefix(vk, epoch), hex::encode(suffix))
}

/// What a request named: the vault ID and the access secret.
#[derive(Clone, Copy)]
pub struct Credentials {
    /// The vault ID.
    pub id: [u8; 32],
    /// The access secret.
    pub access: [u8; 32],
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(..)")
    }
}

/// An opened vault: its key and row.
#[derive(Debug)]
pub struct Opened {
    /// `HMAC(k, vault ID)`.
    pub vk: [u8; 32],
    /// Its row.
    pub row: VaultRow,
}

fn access_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(wire::ACCESS_CONTEXT);
    ctx.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "consumes the error as an answer"
)]
fn vault_error(e: VaultError, m: &VaultMetrics) -> Outcome {
    match e {
        VaultError::Gone => Outcome::NotFound,
        VaultError::Full => {
            m.full.inc();
            Outcome::Conflict("full")
        }
        VaultError::Exists => Outcome::Conflict("exists"),
        VaultError::Generation(g) => {
            m.conflicts.inc();
            Outcome::ConflictJson(serde_json::json!({ "error": "generation", "generation": g }))
        }
        VaultError::Registry(RegistryError::Busy) => Outcome::Throttled(200_000),
        VaultError::Registry(_) => Outcome::Unavailable,
    }
}

impl Vault {
    /// The vault endpoints over their bucket.
    ///
    /// # Errors
    /// HKDF (never).
    pub fn new(
        settings: VaultSettings,
        secret: &[u8; 32],
        s3: songbird_s3::Client,
        metrics: VaultMetrics,
    ) -> Result<Self, &'static str> {
        let (key, record_key) = derive_keys(secret)?;
        Ok(Self {
            settings,
            s3,
            key,
            record_key,
            metrics,
        })
    }

    /// A vault's quota: its owner's plan under the deployment's ceiling (D-0127). After a
    /// downgrade a vault over its quota keeps everything and stays readable; writes that add
    /// are refused until it is back under (deletions always pass).
    #[must_use]
    pub fn quota(
        &self,
        plans: &crate::plans::Plans,
        owner: Option<&songbird_types::AccountId>,
    ) -> VaultQuota {
        let l = owner.map_or_else(
            || *plans.catalog.limits(songbird_entitlements::Level::Free),
            |a| *plans.limits(a),
        );
        VaultQuota {
            bytes: self.settings.quota_bytes.min(l.vault_bytes),
            chunks: self.settings.quota_chunks.min(l.vault_chunks),
        }
    }

    /// `HMAC(k, vault ID)`.
    #[must_use]
    pub fn vault_key(&self, id: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(hmac::sign(&self.key, id).as_ref());
        out
    }

    /// A throttle record: `vt:<kind>:<hmac>`, naming no vault, account or address.
    fn record(&self, kind: &str, subject: &[u8]) -> String {
        let mut ctx = hmac::Context::with_key(&self.record_key);
        ctx.update(kind.as_bytes());
        ctx.update(&[0]);
        ctx.update(subject);
        format!(
            "vt:{kind}:{}",
            hex::encode(ctx.sign().as_ref().get(..16).unwrap_or_default())
        )
    }

    async fn gcra(
        &self,
        hot: &ValkeyConn,
        kind: &str,
        subject: &[u8],
        per_hour: u32,
        burst: u32,
        peek: bool,
    ) -> Result<(), Outcome> {
        match Registration::gcra(hot, &self.record(kind, subject), per_hour, burst, peek).await {
            Ok(0) => Ok(()),
            Ok(wait) => {
                self.metrics.throttled.inc();
                Err(Outcome::Throttled(wait))
            }
            // Fail closed: without the throttle, nothing is served.
            Err(()) => Err(Outcome::Unavailable),
        }
    }

    /// Opens a vault by its credentials, or answers the one 404 for every miss (unknown, turned
    /// off, wrong secret), counted against the requester's range.
    ///
    /// # Errors
    /// The answer to send instead.
    pub async fn open(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        peer: IpAddr,
        c: &Credentials,
    ) -> Result<Opened, Outcome> {
        let s = &self.settings;
        let range = range_of(peer, s.ipv4_prefix, s.ipv6_prefix);
        // A range over its miss budget is refused before the lookup.
        self.gcra(hot, "x", &range, s.misses_per_hour, s.miss_burst, true)
            .await?;
        let vk = self.vault_key(&c.id);
        let row = registry
            .vault(&vk)
            .await
            .map_err(|_| Outcome::Unavailable)?;
        let presented = access_hash(&c.access);
        let stored = row.as_ref().map_or([0u8; 32], |r| r.access);
        let matches = constant_time::verify_slices_are_equal(&presented, &stored).is_ok();
        match row {
            Some(row) if matches => Ok(Opened { vk, row }),
            _ => {
                self.metrics.misses.inc();
                // Charge the miss; the answer is 404 whatever the throttle says now.
                let _ = self
                    .gcra(hot, "x", &range, s.misses_per_hour, s.miss_burst, false)
                    .await;
                Err(Outcome::NotFound)
            }
        }
    }

    /// The read budget of one vault.
    ///
    /// # Errors
    /// 429 or 503.
    pub async fn read_budget(&self, hot: &ValkeyConn, vk: &[u8; 32]) -> Result<(), Outcome> {
        let s = &self.settings;
        self.gcra(hot, "r", vk, s.reads_per_hour, s.read_burst, false)
            .await
    }

    /// Checks a write: the signing device is the primary of the account that owns the vault,
    /// within the account's write budget.
    ///
    /// # Errors
    /// 403 `primary` (a linked or pending device), 403 `owner` (another account), 429, 503.
    pub async fn write_allowed(
        &self,
        hot: &ValkeyConn,
        device: &DeviceRow,
        row: &VaultRow,
    ) -> Result<(), Outcome> {
        if device.pending || !device.primary {
            return Err(Outcome::Forbidden("primary"));
        }
        if row.owner != Some(device.account) {
            return Err(Outcome::Forbidden("owner"));
        }
        let s = &self.settings;
        self.gcra(
            hot,
            "w",
            device.account.as_bytes(),
            s.writes_per_hour,
            s.write_burst,
            false,
        )
        .await
    }

    /// `POST /v1/vault`: creates the vault for the signing primary's account.
    pub async fn create(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        device: &DeviceRow,
        c: &Credentials,
    ) -> Outcome {
        if device.pending || !device.primary {
            return Outcome::Forbidden("primary");
        }
        let s = &self.settings;
        if let Err(o) = self
            .gcra(
                hot,
                "w",
                device.account.as_bytes(),
                s.writes_per_hour,
                s.write_burst,
                false,
            )
            .await
        {
            return o;
        }
        let vk = self.vault_key(&c.id);
        let mut epoch = [0u8; 16];
        if getrandom::fill(&mut epoch).is_err() {
            return Outcome::Unavailable;
        }
        match registry
            .vault_create(
                &device.account,
                &vk,
                &access_hash(&c.access),
                &epoch,
                s.max_vaults,
            )
            .await
        {
            Ok(created) => Outcome::Json(serde_json::json!({ "created": created })),
            Err(e) => vault_error(e, &self.metrics),
        }
    }

    /// `GET /v1/vault`.
    #[must_use]
    pub fn stats(&self, o: &Opened, quota: VaultQuota) -> Outcome {
        Outcome::Json(serde_json::json!({
            "generation": o.row.generation,
            "bytes": o.row.bytes,
            "chunks": o.row.chunks,
            "quota_bytes": quota.bytes,
            "quota_chunks": quota.chunks,
        }))
    }

    /// `DELETE /v1/vault`: the rows go at once (the vault answers as gone, and the same key may
    /// open a new one); the worker deletes the objects.
    pub async fn delete(&self, registry: &Registry, o: &Opened) -> Outcome {
        match registry.vault_retire(&o.vk).await {
            Ok(_) => Outcome::Done,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// The current manifest object's name, if there is one.
    #[must_use]
    pub fn manifest_name(&self, o: &Opened) -> Option<String> {
        o.row
            .manifest
            .map(|m| manifest_object(&o.vk, &o.row.epoch, &m))
    }

    /// `PUT /v1/vault/manifest`: stores the object under a fresh suffix, then swaps the
    /// generation in one transaction; the loser's object and the replaced one are deleted.
    pub async fn put_manifest(
        &self,
        registry: &Registry,
        o: &Opened,
        quota: VaultQuota,
        expected: u64,
        body: Bytes,
    ) -> Outcome {
        let Some(generation) = wire::manifest_generation(&body, self.settings.max_manifest) else {
            return Outcome::Malformed("manifest");
        };
        if Some(generation) != expected.checked_add(1) {
            return Outcome::Malformed("generation");
        }
        if o.row.generation != expected {
            self.metrics.conflicts.inc();
            return Outcome::ConflictJson(
                serde_json::json!({ "error": "generation", "generation": o.row.generation }),
            );
        }
        let mut suffix = [0u8; 16];
        if getrandom::fill(&mut suffix).is_err() {
            return Outcome::Unavailable;
        }
        let name = manifest_object(&o.vk, &o.row.epoch, &suffix);
        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if self.s3.put_object_bytes(&name, body).await.is_err() {
            return Outcome::Unavailable;
        }
        match registry
            .vault_swap_manifest(
                &o.vk,
                &o.row.epoch,
                expected,
                generation,
                &suffix,
                size,
                quota,
            )
            .await
        {
            Ok(old) => {
                self.metrics.manifests.inc();
                if let Some(old) = old {
                    // A failure leaves an orphan the vault's deletion lists and removes.
                    let _ = self
                        .s3
                        .delete_object(&manifest_object(&o.vk, &o.row.epoch, &old))
                        .await;
                }
                Outcome::Json(serde_json::json!({ "generation": generation }))
            }
            Err(e) => {
                let _ = self.s3.delete_object(&name).await;
                vault_error(e, &self.metrics)
            }
        }
    }

    /// `PUT /v1/vault/chunks/<name>`: recorded first (counted against the quota), then stored,
    /// then checked to be still recorded. A name already recorded is left as it is (same name,
    /// same plaintext) and must come with the size recorded for it, so two uploads racing for
    /// one name can't count a small object and store a large one. An upload whose chunk was
    /// forgotten, or whose vault was turned off, while it was in flight deletes its object again
    /// rather than leave it uncounted (D-0125).
    pub async fn put_chunk(
        &self,
        registry: &Registry,
        o: &Opened,
        quota: VaultQuota,
        name: &[u8; 32],
        body: Bytes,
    ) -> Outcome {
        if !wire::chunk_object_ok(&body) {
            return Outcome::Malformed("chunk");
        }
        let object = chunk_object(&o.vk, &o.row.epoch, name);
        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        match registry
            .vault_reserve_chunk(&o.vk, &o.row.epoch, name, size, quota)
            .await
        {
            Ok(Some(recorded)) if recorded != size => {
                self.metrics.conflicts.inc();
                return Outcome::ConflictJson(serde_json::json!({ "error": "size" }));
            }
            Ok(Some(_)) => {
                // Recorded already: stored unless an earlier upload failed after recording.
                match self.s3.head_object(&object).await {
                    Ok(Some(_)) => return Outcome::Done,
                    Ok(None) => {}
                    Err(_) => return Outcome::Unavailable,
                }
            }
            Ok(None) => self.metrics.chunks.inc(),
            Err(e) => return vault_error(e, &self.metrics),
        }
        if self.s3.put_object_bytes(&object, body).await.is_err() {
            return Outcome::Unavailable;
        }
        match registry.vault_chunk_live(&o.vk, &o.row.epoch, name).await {
            Ok(true) => Outcome::Done,
            Ok(false) => {
                // Forgotten (or the vault turned off) meanwhile: what was deleted stays deleted.
                // A failure here is caught by the vault's deletion, which lists its prefix.
                let _ = self.s3.delete_object(&object).await;
                vault_error(VaultError::Gone, &self.metrics)
            }
            Err(_) => Outcome::Unavailable,
        }
    }

    /// Whether a chunk is recorded in the vault (a GET serves recorded chunks only).
    ///
    /// # Errors
    /// 404, 503.
    pub async fn chunk_recorded(
        &self,
        registry: &Registry,
        o: &Opened,
        name: &[u8; 32],
    ) -> Result<String, Outcome> {
        match registry.vault_has_chunk(&o.vk, name).await {
            Ok(true) => Ok(chunk_object(&o.vk, &o.row.epoch, name)),
            Ok(false) => Err(Outcome::NotFound),
            Err(_) => Err(Outcome::Unavailable),
        }
    }

    /// `GET /v1/vault/chunks?after=<name>`.
    pub async fn list(&self, registry: &Registry, o: &Opened, after: Option<[u8; 32]>) -> Outcome {
        let n = u64::try_from(wire::MAX_NAMES).unwrap_or(1000);
        match registry.vault_chunks(&o.vk, after.as_ref(), n + 1).await {
            Ok(mut names) => {
                let more = names.len() > wire::MAX_NAMES;
                names.truncate(wire::MAX_NAMES);
                Outcome::Blob(Bytes::from(wire::encode_page(&names, more)))
            }
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/vault/chunks/delete`: forgets the chunks, then deletes their objects.
    pub async fn delete_chunks(&self, registry: &Registry, o: &Opened, body: &[u8]) -> Outcome {
        let Some(names) = wire::decode_names(body) else {
            return Outcome::Malformed("names");
        };
        match registry.vault_forget_chunks(&o.vk, &names).await {
            Ok(_) => {}
            Err(e) => return vault_error(e, &self.metrics),
        }
        for n in &names {
            // A failure leaves an orphan the vault's deletion lists and removes.
            let _ = self
                .s3
                .delete_object(&chunk_object(&o.vk, &o.row.epoch, n))
                .await;
        }
        Outcome::Done
    }
}

/// Parses the two credential headers.
#[must_use]
pub fn credentials(headers: &hyper::HeaderMap) -> Option<Credentials> {
    let get = |h: &str| {
        let v = headers.get(h)?.to_str().ok()?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(v, &mut out).ok()?;
        Some(out)
    };
    Some(Credentials {
        id: get(wire::VAULT_HEADER)?,
        access: get(wire::ACCESS_HEADER)?,
    })
}

/// A chunk name in a path (`/v1/vault/chunks/<64 lowercase hex>`).
#[must_use]
pub fn chunk_name(path: &str) -> Option<[u8; 32]> {
    let h = path.strip_prefix("/v1/vault/chunks/")?;
    if h.len() != 64 || h.bytes().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(h, &mut out).ok()?;
    Some(out)
}

/// `after=<64 hex>` from a query string.
///
/// # Errors
/// 400 for anything else present.
pub fn after(query: Option<&str>) -> Result<Option<[u8; 32]>, Outcome> {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return Ok(None);
    };
    let bad = || Outcome::Malformed("after");
    let h = q.strip_prefix("after=").ok_or_else(bad)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(h, &mut out).map_err(|_| bad())?;
    Ok(Some(out))
}
