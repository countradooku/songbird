//! The account record store (Prompt 9, M1, D-0102; `docs/PROTOCOL.md` §10.1).
//!
//! | Method and path | Who | What |
//! | --- | --- | --- |
//! | `GET /v1/storage` | a listed device | The store's version and encrypted manifest |
//! | `GET /v1/storage/ids` | a listed device | Every record ID, with the version |
//! | `POST /v1/storage/read` | a listed device | Up to 1,024 records by ID |
//! | `PUT /v1/storage` | a listed device | A compare-and-swap write |
//! | `PUT /v1/storage/object` | a listed device | An encrypted object (at most 2 MiB) |
//! | `GET /v1/storage/object/<id>` | a listed device | One of the account's own objects |
//! | `DELETE /v1/storage/object/<id>` | a listed device | Deletes one |
//!
//! "Listed" means a device of the account that is not pending (D-0052): a device still waiting
//! to be confirmed reads and writes nothing of the account's settings. Every record and object is
//! ciphertext under keys only the account's devices hold; the server checks lengths, counts and
//! versions, never content. No write time is stored.

use aws_lc_rs::{hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::{Registry, RegistryError, StorageCaps, StorageWriteError};
use songbird_proto::storage::{self, Head, Ids, Write};
use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;

use crate::config::StorageSettings;
use crate::profiles::Outcome;
use crate::registration::Registration;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct StorageMetrics {
    /// Writes applied.
    pub writes: songbird_service::telemetry::sharded::ShardedCounter,
    /// Writes refused because another write won (409).
    pub conflicts: songbird_service::telemetry::sharded::ShardedCounter,
    /// Writes refused by a cap.
    pub full: songbird_service::telemetry::sharded::ShardedCounter,
    /// Requests refused by a throttle.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
}

impl StorageMetrics {
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
                "api_storage_writes",
                "Record store writes applied",
                &self.writes,
            ),
            (
                "api_storage_conflicts",
                "Record store writes refused because another write won",
                &self.conflicts,
            ),
            (
                "api_storage_full",
                "Record store writes refused by a cap",
                &self.full,
            ),
            (
                "api_storage_throttled",
                "Record store requests refused by a throttle",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// The record store's endpoints.
pub struct Storage {
    /// Its settings.
    pub settings: StorageSettings,
    record_key: hmac::Key,
    metrics: StorageMetrics,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage").finish_non_exhaustive()
    }
}

/// A storage object's name in `RustFS`.
#[must_use]
pub fn object_name(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("s/");
    s.push_str(&hex::encode(id));
    s
}

impl Storage {
    /// Derives the throttle record key.
    ///
    /// # Errors
    /// HKDF (never).
    pub fn new(
        settings: StorageSettings,
        secret: &[u8; 32],
        metrics: StorageMetrics,
    ) -> Result<Self, &'static str> {
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-storage-v1")
            .extract(secret)
            .expand(&[b"storage-records"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut k))
            .map_err(|_| "hkdf")?;
        Ok(Self {
            settings,
            record_key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            metrics,
        })
    }

    fn caps(&self) -> StorageCaps {
        StorageCaps {
            max_records: u64::from(self.settings.max_records),
            max_bytes: u64::from(self.settings.max_bytes),
            max_objects: u64::from(self.settings.max_objects),
        }
    }

    /// The keyed throttle record name: `st:<kind>:<hmac>`, naming no account.
    fn record(&self, kind: &str, account: &AccountId) -> String {
        let mut ctx = hmac::Context::with_key(&self.record_key);
        ctx.update(kind.as_bytes());
        ctx.update(&[0]);
        ctx.update(account.as_bytes());
        let mut k = String::with_capacity(40);
        k.push_str("st:");
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
        write: bool,
        account: &AccountId,
    ) -> Result<(), Outcome> {
        let s = &self.settings;
        let (kind, per_hour, burst) = if write {
            ("w", s.writes_per_hour, s.write_burst)
        } else {
            ("r", s.reads_per_hour, s.read_burst)
        };
        match Registration::gcra(hot, &self.record(kind, account), per_hour, burst, false).await {
            Ok(0) => Ok(()),
            Ok(wait) => {
                self.metrics.throttled.inc();
                Err(Outcome::Throttled(wait))
            }
            Err(()) => Err(Outcome::Unavailable),
        }
    }

    /// The second write budget (D-0108): one unit per record a write deletes or inserts, so a
    /// stream of full rewrites can't churn the database at the writes' count alone.
    /// Cost-weighted GCRA on Valkey's clock.
    async fn record_units(
        &self,
        hot: &ValkeyConn,
        account: &AccountId,
        w: &Write,
    ) -> Result<(), Outcome> {
        let s = &self.settings;
        let cost = 1 + w.deletes.len() + w.inserts.len();
        let interval_us = 3_600_000_000 / u64::from(s.record_units_per_hour.max(1));
        let wait = hot
            .query::<i64>(
                redis::cmd("EVAL")
                    .arg(songbird_send::gate::GCRA_COST)
                    .arg(1)
                    .arg(self.record("u", account))
                    .arg(interval_us)
                    .arg(interval_us.saturating_mul(u64::from(s.record_units_burst.max(1))))
                    .arg(cost),
            )
            .await;
        match wait.map(|w| u64::try_from(w).unwrap_or(0)) {
            Ok(0) => Ok(()),
            Ok(wait) => {
                self.metrics.throttled.inc();
                Err(Outcome::Throttled(wait))
            }
            Err(_) => Err(Outcome::Unavailable),
        }
    }

    /// `GET /v1/storage`.
    pub async fn head(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
    ) -> Outcome {
        if let Err(o) = self.throttle(hot, false, account).await {
            return o;
        }
        match registry.storage_head(account).await {
            Ok((version, manifest)) => Outcome::Blob(Bytes::from(
                Head {
                    version,
                    manifest: manifest.to_vec(),
                }
                .encode(),
            )),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `GET /v1/storage/ids`.
    pub async fn ids(&self, registry: &Registry, hot: &ValkeyConn, account: &AccountId) -> Outcome {
        if let Err(o) = self.throttle(hot, false, account).await {
            return o;
        }
        match registry.storage_ids(account).await {
            Ok((version, ids)) => Outcome::Blob(Bytes::from(Ids { version, ids }.encode())),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/storage/read`.
    pub async fn read(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        body: &[u8],
    ) -> Outcome {
        let Ok(ids) = storage::decode_read(body) else {
            return Outcome::Malformed("storage");
        };
        if let Err(o) = self.throttle(hot, false, account).await {
            return o;
        }
        match registry.storage_read(account, &ids).await {
            Ok(records) => Outcome::Blob(Bytes::from(storage::encode_records(&records))),
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `PUT /v1/storage`: 200 `{"version"}`, or 409 `{"error": "version", "version"}` when
    /// another write moved the store on.
    pub async fn write(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        body: &[u8],
    ) -> Outcome {
        let Ok(w) = Write::decode(body) else {
            return Outcome::Malformed("storage");
        };
        if let Err(o) = self.throttle(hot, true, account).await {
            return o;
        }
        if let Err(o) = self.record_units(hot, account, &w).await {
            return o;
        }
        match registry.storage_write(account, &w, self.caps()).await {
            Ok(version) => {
                self.metrics.writes.inc();
                Outcome::Json(serde_json::json!({ "version": version }))
            }
            Err(StorageWriteError::Version(current)) => {
                self.metrics.conflicts.inc();
                Outcome::ConflictJson(serde_json::json!({
                    "error": "version",
                    "version": current,
                }))
            }
            Err(StorageWriteError::Full) => {
                self.metrics.full.inc();
                Outcome::Conflict("full")
            }
            Err(StorageWriteError::Exists) => Outcome::Conflict("exists"),
            Err(StorageWriteError::Gone) => Outcome::NotFound,
            Err(StorageWriteError::Registry(_)) => Outcome::Unavailable,
        }
    }

    /// `PUT /v1/storage/object`: stores an encrypted object under a fresh random ID.
    pub async fn put_object(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        s3: &songbird_s3::Client,
        account: &AccountId,
        body: Bytes,
    ) -> Outcome {
        if let Err(o) = self.throttle(hot, true, account).await {
            return o;
        }
        let mut id = [0u8; 32];
        if getrandom::fill(&mut id).is_err() {
            return Outcome::Unavailable;
        }
        // Recorded first, so an upload that fails still goes with the account.
        match registry
            .reserve_storage_object(account, &id, self.caps().max_objects)
            .await
        {
            Ok(()) => {}
            Err(RegistryError::Full) => return Outcome::Conflict("full"),
            Err(RegistryError::NotFound) => return Outcome::NotFound,
            Err(_) => return Outcome::Unavailable,
        }
        if s3.put_object_bytes(&object_name(&id), body).await.is_err() {
            return Outcome::Unavailable;
        }
        Outcome::Json(serde_json::json!({ "object": hex::encode(id) }))
    }

    /// Whether `GET /v1/storage/object/<id>` may serve this object: the account's own only (one
    /// answer, 404, for another account's and for none).
    pub async fn object_allowed(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        id: &[u8; 32],
    ) -> Result<(), Outcome> {
        self.throttle(hot, false, account).await?;
        match registry.storage_object_of(account, id).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Outcome::NotFound),
            Err(_) => Err(Outcome::Unavailable),
        }
    }

    /// `DELETE /v1/storage/object/<id>`.
    pub async fn delete_object(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        s3: &songbird_s3::Client,
        account: &AccountId,
        id: &[u8; 32],
    ) -> Outcome {
        if let Err(o) = self.throttle(hot, true, account).await {
            return o;
        }
        match registry.storage_object_of(account, id).await {
            Ok(true) => {}
            Ok(false) => return Outcome::NotFound,
            Err(_) => return Outcome::Unavailable,
        }
        if s3.delete_object(&object_name(id)).await.is_err()
            || registry.delete_storage_object(id).await.is_err()
        {
            return Outcome::Unavailable;
        }
        Outcome::Done
    }
}
