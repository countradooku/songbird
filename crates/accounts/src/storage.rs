//! The account record store (Prompt 9, M1, D-0102; `docs/PROTOCOL.md` §10.1).
//!
//! Records are opaque ciphertext under random IDs the client drew, keyed `srec:[account, id]`.
//! The account row holds the store's version (`st_v`) and its encrypted manifest (`st_m`). A
//! write is one transaction: it checks the version, deletes, inserts, checks the caps, and moves
//! the version on by one, or changes nothing. No write time is stored; the server keeps the
//! version counter only.
//!
//! Storage objects (custom wallpapers) are opaque objects in `RustFS` under server-drawn IDs,
//! recorded `sobj:[id]` with their account, readable by the account's own devices only.

use bytes::Bytes;
use songbird_proto::storage::{ID_LEN, Record, Write};
use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::{self, DbError};
use crate::{Registry, RegistryError, bytes, first_int, id16, id32, int, rows, var};

/// Per-account caps of the record store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCaps {
    /// Most records.
    pub max_records: u64,
    /// Most record bytes in all (ciphertext).
    pub max_bytes: u64,
    /// Most storage objects.
    pub max_objects: u64,
}

impl Default for StorageCaps {
    fn default() -> Self {
        Self {
            max_records: 10_000,
            max_bytes: 16 * 1024 * 1024,
            max_objects: 16,
        }
    }
}

/// Why a write did not apply.
#[derive(Debug, thiserror::Error)]
pub enum StorageWriteError {
    /// Another write moved the store on: the current version.
    #[error("version moved on")]
    Version(u64),
    /// The write would pass a cap.
    #[error("store full")]
    Full,
    /// An inserted ID exists already (a client drawing IDs badly).
    #[error("record id exists")]
    Exists,
    /// The account is gone or being deleted.
    #[error("gone")]
    Gone,
    /// The registry failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

impl Registry {
    /// The store's version and manifest (0 and empty before the first write).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn storage_head(&self, account: &AccountId) -> Result<(u64, Bytes), RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT st_v, st_m FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let version = v
            .get("st_v")
            .and_then(Value::as_i64)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0);
        let manifest = v
            .get("st_m")
            .and_then(|b| b.as_bytes().cloned())
            .unwrap_or_default();
        Ok((version, manifest))
    }

    /// Every record ID with the store's version, read in one transaction.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn storage_ids(
        &self,
        account: &AccountId,
    ) -> Result<(u64, Vec<[u8; ID_LEN]>), RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 LET $v = account:[$a].st_v ?? 0;
                 LET $ids = (SELECT VALUE meta::id(id)[1] FROM srec WHERE account = $a);
                 RETURN [$v, $ids];
                 COMMIT TRANSACTION;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let pair = v
            .into_iter()
            .rev()
            .find_map(|x| x.into_array().filter(|a| a.len() == 2))
            .ok_or(RegistryError::Shape)?;
        let mut it = pair.into_iter();
        let version = it
            .next()
            .as_ref()
            .and_then(first_int)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)?;
        let ids = it
            .next()
            .map(rows)
            .unwrap_or_default()
            .iter()
            .map(|x| id16(x).ok_or(RegistryError::Shape))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((version, ids))
    }

    /// The records of `ids` that exist (others are left out).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn storage_read(
        &self,
        account: &AccountId,
        ids: &[[u8; ID_LEN]],
    ) -> Result<Vec<Record>, RegistryError> {
        let keys: Vec<Value> = ids.iter().map(|i| bytes(i)).collect();
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[1] AS i, blob FROM srec
                   WHERE account = $a AND meta::id(id)[1] INSIDE $keys;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("keys", Value::Array(keys)),
                ],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| {
                Ok(Record {
                    id: r.get("i").and_then(id16).ok_or(RegistryError::Shape)?,
                    blob: r
                        .get("blob")
                        .and_then(Value::as_bytes)
                        .ok_or(RegistryError::Shape)?
                        .to_vec(),
                })
            })
            .collect()
    }

    /// Applies a write if the store is at `w.expected`; returns the new version.
    ///
    /// # Errors
    /// [`StorageWriteError`].
    pub async fn storage_write(
        &self,
        account: &AccountId,
        w: &Write,
        caps: StorageCaps,
    ) -> Result<u64, StorageWriteError> {
        let dels: Vec<Value> = w.deletes.iter().map(|d| bytes(d)).collect();
        let ins: Vec<Value> = w
            .inserts
            .iter()
            .map(|r| {
                Value::Array(vec![
                    bytes(&r.id),
                    bytes(&r.blob),
                    int(u64::try_from(r.blob.len()).unwrap_or(u64::MAX)),
                ])
            })
            .collect();
        let next = w.expected.checked_add(1).ok_or(StorageWriteError::Full)?;
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF account:[$a].deleting != false { THROW 'songbird:gone' };
                 IF (account:[$a].st_v ?? 0) != $e { THROW 'songbird:version' };
                 FOR $d IN $dels { DELETE srec:[$a, $d] RETURN NONE; };
                 FOR $r IN $ins {
                   CREATE srec:[$a, $r[0]] SET account = $a, blob = $r[1], size = $r[2]
                     RETURN NONE;
                 };
                 LET $t = (SELECT count() AS n, math::sum(size) AS b FROM srec
                   WHERE account = $a GROUP ALL);
                 IF ($t[0].n ?? 0) > $maxn OR ($t[0].b ?? 0) > $maxb { THROW 'songbird:full' };
                 UPDATE account:[$a] SET st_v = $next, st_m = $m RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("e", int(w.expected)),
                    var("next", int(next)),
                    var("m", bytes(&w.manifest)),
                    var("dels", Value::Array(dels)),
                    var("ins", Value::Array(ins)),
                    var("maxn", int(caps.max_records)),
                    var("maxb", int(caps.max_bytes)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(next),
            Err(DbError::Statement(k)) => match k.as_str() {
                "Thrown:gone" => Err(StorageWriteError::Gone),
                "Thrown:full" => Err(StorageWriteError::Full),
                "Thrown:version" => Err(StorageWriteError::Version(
                    self.storage_head(account).await?.0,
                )),
                k if k.contains("AlreadyExists") => Err(StorageWriteError::Exists),
                // A concurrent write to the same account won: the client fetches and retries.
                k if k == db::TRANSACTION_CONFLICT => Err(StorageWriteError::Version(
                    self.storage_head(account).await?.0,
                )),
                _ => Err(RegistryError::from(DbError::Statement(k)).into()),
            },
            Err(e) => Err(RegistryError::from(e).into()),
        }
    }

    /// The store's size: records and their bytes (for the export and tests).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn storage_size(&self, account: &AccountId) -> Result<(u64, u64), RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT count() AS n, math::sum(size) AS b FROM srec WHERE account = $a GROUP ALL;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let r = rows(v);
        let Some(row) = r.first() else {
            return Ok((0, 0));
        };
        let get = |k: &str| {
            row.get(k)
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or(0)
        };
        Ok((get("n"), get("b")))
    }

    /// Records a storage object **before** it is uploaded, so an upload that never completes is
    /// still deleted with the account. Refuses past the cap.
    ///
    /// # Errors
    /// [`RegistryError::Full`]; [`RegistryError::NotFound`] for an account being deleted.
    pub async fn reserve_storage_object(
        &self,
        account: &AccountId,
        id: &[u8; 32],
        max: u64,
    ) -> Result<(), RegistryError> {
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF account:[$a].deleting != false { THROW 'songbird:gone' };
                 IF count(SELECT id FROM sobj WHERE account = $a) >= $max {
                   THROW 'songbird:full' };
                 CREATE sobj:[$i] SET account = $a RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("i", bytes(id)),
                    var("max", int(max)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k == "Thrown:full" => Err(RegistryError::Full),
            Err(DbError::Statement(k)) if k == "Thrown:gone" => Err(RegistryError::NotFound),
            Err(DbError::Statement(k)) if k == db::TRANSACTION_CONFLICT => Err(RegistryError::Busy),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether a storage object belongs to the account.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn storage_object_of(
        &self,
        account: &AccountId,
        id: &[u8; 32],
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN sobj:[$i].account = $a;",
                vec![var("a", bytes(account.as_bytes())), var("i", bytes(id))],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
    }

    /// Removes a storage object's record (after its object is deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_storage_object(&self, id: &[u8; 32]) -> Result<(), RegistryError> {
        self.db
            .query("DELETE sobj:[$i] RETURN NONE;", vec![var("i", bytes(id))])
            .await?;
        Ok(())
    }

    /// Every storage object of an account (for its deletion and export).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn storage_objects_of(
        &self,
        account: &AccountId,
    ) -> Result<Vec<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM sobj WHERE account = $a;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|x| id32(x).ok_or(RegistryError::Shape))
            .collect()
    }
}
