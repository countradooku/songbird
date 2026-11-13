//! The account registry in SurrealDB (D-0036).
//!
//! A minimal registry until Prompt 3 builds identity on top of it: accounts, their devices
//! (Ed25519 authentication keys), a directory version that delivery nodes poll, and the rows M5
//! adds, each holding only what the threat model lists:
//!
//! | Table | Key | Holds | Gone |
//! | --- | --- | --- | --- |
//! | `account` | account ID | creation time, `deleting` | with the account |
//! | `device` | device ID | account ID, auth key, `disabled` | with the device |
//! | `push_token` | keyed hash of the device ID | the token sealed to `push`'s public key | unregistered, or with the device |
//! | `upload_grant` | object key | uploading device, exact size, fetches due, expiry | at upload, expiry, or with the device |
//! | `attachment` | object key | size, fetches left, expiry (30 days) | at the last fetch or expiry |
//! | `outbox` | job ID | the job (IDs only) | relayed to the queue |
//!
//! An attachment row has no link to the account that uploaded it (owner-approved threat-model
//! row, D-0036).
#![forbid(unsafe_code)]

mod db;
pub mod push_token;

use std::time::Duration;

use bytes::Bytes;
use songbird_jobs::{Job, ObjectKey};
use songbird_surreal::Value;
use songbird_types::{AccountId, DeviceId, JobId};

pub use db::{Db, DbError, SurrealSettings};

/// Ed25519 public key length.
pub const AUTH_KEY_LEN: usize = 32;

/// Attachments live at most this long (invariant 3).
pub const ATTACHMENT_MAX_AGE: Duration = Duration::from_hours(30 * 24);

const SCHEMA: &str = "
DEFINE TABLE IF NOT EXISTS account SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS at ON account TYPE datetime;
DEFINE FIELD IF NOT EXISTS deleting ON account TYPE bool;
DEFINE TABLE IF NOT EXISTS device SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON device TYPE bytes;
DEFINE FIELD IF NOT EXISTS key ON device TYPE bytes;
DEFINE FIELD IF NOT EXISTS disabled ON device TYPE bool;
DEFINE FIELD IF NOT EXISTS at ON device TYPE datetime;
DEFINE INDEX IF NOT EXISTS device_account ON device FIELDS account;
DEFINE TABLE IF NOT EXISTS directory SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS version ON directory TYPE int;
DEFINE TABLE IF NOT EXISTS push_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS sealed ON push_token TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON push_token TYPE datetime;
DEFINE TABLE IF NOT EXISTS upload_grant SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS device ON upload_grant TYPE bytes;
DEFINE FIELD IF NOT EXISTS size ON upload_grant TYPE int;
DEFINE FIELD IF NOT EXISTS fetches ON upload_grant TYPE int;
DEFINE FIELD IF NOT EXISTS expires ON upload_grant TYPE datetime;
DEFINE INDEX IF NOT EXISTS upload_grant_device ON upload_grant FIELDS device;
DEFINE INDEX IF NOT EXISTS upload_grant_expires ON upload_grant FIELDS expires;
DEFINE TABLE IF NOT EXISTS attachment SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS size ON attachment TYPE int;
DEFINE FIELD IF NOT EXISTS left ON attachment TYPE int;
DEFINE FIELD IF NOT EXISTS expires ON attachment TYPE datetime;
DEFINE INDEX IF NOT EXISTS attachment_expires ON attachment FIELDS expires;
DEFINE TABLE IF NOT EXISTS outbox SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS job ON outbox TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON outbox TYPE datetime;
DEFINE INDEX IF NOT EXISTS outbox_at ON outbox FIELDS at;
UPSERT directory:v SET version = version ?? 1 RETURN NONE;
DEFINE TABLE IF NOT EXISTS store SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS generation ON store TYPE int;
UPSERT store:g SET generation = generation ?? 1 RETURN NONE;
";

/// Registry failures. They carry no identifiers.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The database is unreachable or failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The account or a device already exists.
    #[error("already exists")]
    Exists,
    /// A row did not have the expected shape.
    #[error("unexpected row shape")]
    Shape,
}

/// A device as authentication sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRow {
    /// Its account.
    pub account: AccountId,
    /// Ed25519 authentication public key.
    pub key: [u8; AUTH_KEY_LEN],
    /// Disabled: the account is being deleted (or the device removed).
    pub disabled: bool,
}

/// A pending upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The device allowed to upload.
    pub device: DeviceId,
    /// Exact (padded) size in bytes.
    pub size: u64,
    /// Recipient fetches due once uploaded.
    pub fetches: u32,
}

/// An uploaded attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attachment {
    /// Size in bytes.
    pub size: u64,
    /// Fetches still due.
    pub left: u32,
}

/// What is left of an account after deletion (all zero when it is gone everywhere here).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Remnants {
    /// The account row.
    pub account: u64,
    /// Device rows.
    pub devices: u64,
    /// Push tokens of the devices.
    pub push_tokens: u64,
    /// Upload grants of the devices.
    pub grants: u64,
}

impl Remnants {
    /// Nothing left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Bytes::copy_from_slice(b))
}

fn var(name: &str, v: Value) -> (String, Value) {
    (name.to_owned(), v)
}

fn int(v: u64) -> Value {
    Value::Int(i64::try_from(v).unwrap_or(i64::MAX))
}

fn first_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        Value::Array(a) => a.first().and_then(Value::as_i64),
        _ => None,
    }
}

fn id16(v: &Value) -> Option<[u8; 16]> {
    v.as_bytes().and_then(|b| b.as_ref().try_into().ok())
}

fn id32(v: &Value) -> Option<[u8; 32]> {
    v.as_bytes().and_then(|b| b.as_ref().try_into().ok())
}

fn rows(v: Value) -> Vec<Value> {
    v.into_array().unwrap_or_default()
}

/// The account registry.
#[derive(Debug)]
pub struct Registry {
    db: Db,
}

impl Registry {
    /// Connects and creates the schema if missing.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn connect(db: Db) -> Result<Self, RegistryError> {
        db.exec(SCHEMA, Vec::new()).await?;
        Ok(Self { db })
    }

    /// The database handle (for tests and verification).
    #[must_use]
    pub fn db(&self) -> &Db {
        &self.db
    }

    // ----- accounts and devices -----

    /// Creates an account with its first devices (registration stand-in until Prompt 3).
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the account or a device exists.
    pub async fn create_account(
        &self,
        account: &AccountId,
        devices: &[(DeviceId, [u8; AUTH_KEY_LEN])],
    ) -> Result<(), RegistryError> {
        let list: Vec<Value> = devices
            .iter()
            .map(|(d, k)| Value::Array(vec![bytes(d.as_bytes()), bytes(k)]))
            .collect();
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 CREATE account:[$a] SET at = time::now(), deleting = false RETURN NONE;
                 FOR $d IN $devices {
                   CREATE device:[$d[0]] SET account = $a, key = $d[1], disabled = false,
                     at = time::now() RETURN NONE;
                 };
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("devices", Value::Array(list)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(kind)) if kind.contains("AlreadyExists") => {
                Err(RegistryError::Exists)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The directory version: bumped by every change to accounts or devices.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn directory_version(&self) -> Result<i64, RegistryError> {
        let v = self
            .db
            .query1("SELECT VALUE version FROM ONLY directory:v;", Vec::new())
            .await?;
        first_int(&v).ok_or(RegistryError::Shape)
    }

    /// The store generation sent to clients in `Hello` (PROTOCOL.md §3.6, D-0040).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn store_generation(&self) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1("SELECT VALUE generation FROM ONLY store:g;", Vec::new())
            .await?;
        first_int(&v)
            .and_then(|g| u64::try_from(g).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Increments the store generation after a restore or a loss of the mailbox, to at least the
    /// current Unix time in milliseconds: a restored registry carries the generation of its
    /// backup, which can be below one clients have already seen, and `+1` alone could land on it.
    /// Every value issued is at most the wall clock plus the bumps made within one millisecond,
    /// so a bump a millisecond later passes all of them. Returns the new generation.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn bump_store_generation(&self) -> Result<u64, RegistryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let v = self
            .db
            .query1(
                "UPDATE ONLY store:g SET generation = math::max([generation + 1, $now]) RETURN VALUE generation;",
                vec![var("now", int(now))],
            )
            .await?;
        first_int(&v)
            .and_then(|g| u64::try_from(g).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Every enabled device: (device, account, key). Delivery's directory.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn load_directory(
        &self,
    ) -> Result<Vec<(DeviceId, AccountId, [u8; AUTH_KEY_LEN])>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d, account AS a, key AS k FROM device WHERE disabled = false;",
                Vec::new(),
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(d), Some(a), Some(k)) = (
                r.get("d").and_then(id16),
                r.get("a").and_then(id16),
                r.get("k").and_then(id32),
            ) else {
                return Err(RegistryError::Shape);
            };
            out.push((DeviceId::from_bytes(d), AccountId::from_bytes(a), k));
        }
        Ok(out)
    }

    /// One device, for request authentication.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn device(&self, device: &DeviceId) -> Result<Option<DeviceRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT account AS a, key AS k, disabled FROM ONLY device:[$d];",
                vec![var("d", bytes(device.as_bytes()))],
            )
            .await?;
        if v.is_absent() {
            return Ok(None);
        }
        let (Some(a), Some(k), Some(disabled)) = (
            v.get("a").and_then(id16),
            v.get("k").and_then(id32),
            v.get("disabled").map(|d| matches!(d, Value::Bool(true))),
        ) else {
            return Err(RegistryError::Shape);
        };
        Ok(Some(DeviceRow {
            account: AccountId::from_bytes(a),
            key: k,
            disabled,
        }))
    }

    /// Every device of an account, disabled ones included.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn account_devices(
        &self,
        account: &AccountId,
    ) -> Result<Vec<DeviceId>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM device WHERE account = $a;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|d| {
                id16(d)
                    .map(DeviceId::from_bytes)
                    .ok_or(RegistryError::Shape)
            })
            .collect()
    }

    /// Starts deleting an account: in one transaction, marks it, disables its devices (every
    /// delivery node drops them at its next directory reload) and writes the deletion job to the
    /// outbox. Returns false if the account does not exist; repeating it is harmless.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn begin_account_deletion(
        &self,
        account: &AccountId,
        job: &Job,
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) { THROW 'no_account' };
                 UPDATE account:[$a] SET deleting = true RETURN NONE;
                 UPDATE device SET disabled = true WHERE account = $a RETURN NONE;
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ],
            )
            .await;
        match v {
            Ok(_) => Ok(true),
            Err(DbError::Statement(kind)) if kind == "Thrown" => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes an account's device rows and its account row (last step of deletion).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_account_rows(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 DELETE device WHERE account = $a RETURN NONE;
                 DELETE account:[$a] RETURN NONE;
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(())
    }

    /// What is left of an account and its devices.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn remnants(
        &self,
        account: &AccountId,
        devices: &[DeviceId],
        push_index: &[[u8; 32]],
    ) -> Result<Remnants, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let ps: Vec<Value> = push_index.iter().map(|p| bytes(p)).collect();
        let v = self
            .db
            .query(
                "RETURN count(SELECT id FROM account:[$a]);
                 RETURN count(SELECT id FROM device WHERE account = $a OR meta::id(id)[0] IN $ds);
                 RETURN count(SELECT id FROM push_token WHERE meta::id(id)[0] IN $ps);
                 RETURN count(SELECT id FROM upload_grant WHERE device IN $ds);",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("ds", Value::Array(ds)),
                    var("ps", Value::Array(ps)),
                ],
            )
            .await?;
        let n = |i: usize| {
            v.get(i)
                .and_then(first_int)
                .and_then(|x| u64::try_from(x).ok())
                .ok_or(RegistryError::Shape)
        };
        Ok(Remnants {
            account: n(0)?,
            devices: n(1)?,
            push_tokens: n(2)?,
            grants: n(3)?,
        })
    }

    // ----- push tokens -----

    /// Stores (or replaces) a device's sealed push token under its keyed hash.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn put_push_token(
        &self,
        index: &[u8; 32],
        sealed: &[u8],
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPSERT push_token:[$p] SET sealed = $s, at = time::now() RETURN NONE;",
                vec![var("p", bytes(index)), var("s", bytes(sealed))],
            )
            .await?;
        Ok(())
    }

    /// A device's sealed push token.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn push_token(&self, index: &[u8; 32]) -> Result<Option<Bytes>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE sealed FROM ONLY push_token:[$p];",
                vec![var("p", bytes(index))],
            )
            .await?;
        Ok(v.as_bytes().cloned())
    }

    /// Deletes push tokens (unregistered, or their device deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_push_tokens(&self, index: &[[u8; 32]]) -> Result<(), RegistryError> {
        let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
        self.db
            .query(
                "FOR $p IN $ps { DELETE push_token:[$p] RETURN NONE; };",
                vec![var("ps", Value::Array(ps))],
            )
            .await?;
        Ok(())
    }

    // ----- uploads and attachments -----

    /// Records an upload grant.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn create_grant(
        &self,
        object: &ObjectKey,
        grant: &Grant,
        ttl: Duration,
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "CREATE upload_grant:[$o] SET device = $d, size = $n, fetches = $f,
                   expires = time::now() + duration::from_secs($ttl) RETURN NONE;",
                vec![
                    var("o", bytes(&object.0)),
                    var("d", bytes(grant.device.as_bytes())),
                    var("n", int(grant.size)),
                    var("f", int(u64::from(grant.fetches))),
                    var("ttl", int(ttl.as_secs())),
                ],
            )
            .await?;
        Ok(())
    }

    /// An unexpired grant.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn grant(&self, object: &ObjectKey) -> Result<Option<Grant>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT device, size, fetches FROM ONLY upload_grant:[$o] WHERE expires > time::now();",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.swap_remove(0),
            Value::Array(_) => return Ok(None),
            other => other,
        };
        if v.is_absent() {
            return Ok(None);
        }
        let (Some(d), Some(size), Some(fetches)) = (
            v.get("device").and_then(id16),
            v.get("size")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok()),
            v.get("fetches")
                .and_then(Value::as_i64)
                .and_then(|n| u32::try_from(n).ok()),
        ) else {
            return Err(RegistryError::Shape);
        };
        Ok(Some(Grant {
            device: DeviceId::from_bytes(d),
            size,
            fetches,
        }))
    }

    /// Turns a used grant into an attachment record (no link to the uploader), in one
    /// transaction. Returns false if the grant is gone (expired or used).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn complete_upload(&self, object: &ObjectKey) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 LET $n = (SELECT VALUE size FROM ONLY upload_grant:[$o]);
                 LET $f = (SELECT VALUE fetches FROM ONLY upload_grant:[$o]);
                 IF $n = NONE OR $f = NONE { THROW 'no_grant' };
                 DELETE upload_grant:[$o] RETURN NONE;
                 CREATE attachment:[$o] SET size = $n, left = $f,
                   expires = time::now() + duration::from_secs($age) RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("o", bytes(&object.0)),
                    var("age", int(ATTACHMENT_MAX_AGE.as_secs())),
                ],
            )
            .await;
        match v {
            Ok(_) => Ok(true),
            Err(DbError::Statement(kind)) if kind == "Thrown" => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes a grant (expired, or its device deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_grant(&self, object: &ObjectKey) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE upload_grant:[$o] RETURN NONE;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        Ok(())
    }

    /// Pending grants of some devices.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn grants_of(&self, devices: &[DeviceId]) -> Result<Vec<ObjectKey>, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM upload_grant WHERE device IN $ds;",
                vec![var("ds", Value::Array(ds))],
            )
            .await?;
        objects(v)
    }

    /// Up to `limit` expired grants.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn expired_grants(&self, limit: usize) -> Result<Vec<ObjectKey>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM upload_grant WHERE expires <= time::now() LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        objects(v)
    }

    /// An unexpired attachment.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn attachment(
        &self,
        object: &ObjectKey,
    ) -> Result<Option<Attachment>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT size, left FROM ONLY attachment:[$o] WHERE expires > time::now() AND left > 0;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.swap_remove(0),
            Value::Array(_) => return Ok(None),
            other => other,
        };
        if v.is_absent() {
            return Ok(None);
        }
        let (Some(size), Some(left)) = (
            v.get("size")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok()),
            v.get("left")
                .and_then(Value::as_i64)
                .and_then(|n| u32::try_from(n).ok()),
        ) else {
            return Err(RegistryError::Shape);
        };
        Ok(Some(Attachment { size, left }))
    }

    /// Counts one completed fetch; returns the fetches still due (0: the last one; delete the
    /// object), or `None` if there was nothing left to fetch.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn count_fetch(&self, object: &ObjectKey) -> Result<Option<u32>, RegistryError> {
        let v = self
            .db
            .query1(
                "UPDATE attachment:[$o] SET left -= 1 WHERE left > 0 RETURN VALUE left;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        Ok(first_int(&v).and_then(|n| u32::try_from(n).ok()))
    }

    /// Deletes an attachment record.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_attachment(&self, object: &ObjectKey) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE attachment:[$o] RETURN NONE;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        Ok(())
    }

    /// Up to `limit` attachments past their 30 days, or fully fetched.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn expired_attachments(&self, limit: usize) -> Result<Vec<ObjectKey>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM attachment WHERE expires <= time::now() OR left <= 0 LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        objects(v)
    }

    // ----- outbox -----

    /// Writes a job to the outbox on its own (most outbox rows are written inside the
    /// transaction of the change that needs them).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn outbox_put(&self, job: &Job) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;",
                vec![
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ],
            )
            .await?;
        Ok(())
    }
}

fn objects(v: Value) -> Result<Vec<ObjectKey>, RegistryError> {
    rows(v)
        .iter()
        .map(|o| id32(o).map(ObjectKey).ok_or(RegistryError::Shape))
        .collect()
}

impl songbird_jobs::Outbox for Registry {
    async fn take(&self, limit: usize) -> Result<Vec<Job>, String> {
        let v = self
            .db
            .query1(
                "SELECT VALUE job FROM outbox ORDER BY at LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for j in rows(v) {
            match j.as_bytes().map(|b| Job::from_bytes(b)) {
                Some(Ok(job)) => out.push(job),
                _ => {
                    // A row that does not decode would block the outbox forever: drop it loudly.
                    tracing::error!("outbox row does not decode; dropped");
                }
            }
        }
        Ok(out)
    }

    async fn remove(&self, ids: &[JobId]) -> Result<(), String> {
        let js: Vec<Value> = ids.iter().map(|j| bytes(j.as_bytes())).collect();
        self.db
            .query(
                "FOR $j IN $js { DELETE outbox:[$j] RETURN NONE; };",
                vec![var("js", Value::Array(js))],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// The keyed hash a push token is stored under (HMAC-SHA256 of the device ID with the
/// push-index secret): the table alone does not say which device a token belongs to.
#[must_use]
pub fn push_index(secret: &[u8; 32], device: &DeviceId) -> [u8; 32] {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret);
    let tag = aws_lc_rs::hmac::sign(&key, device.as_bytes());
    let mut out = [0u8; 32];
    if let Some(t) = tag.as_ref().get(..32) {
        out.copy_from_slice(t);
    }
    out
}
