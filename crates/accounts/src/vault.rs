//! The Songbird vault's rows (Prompt 10, M2, D-0121; `docs/PROTOCOL.md` §11.8).
//!
//! A vault holds one backup's objects. The server never sees its ID: rows are keyed by
//! `HMAC(server key, vault ID)` (32 bytes, "the vault key" below), computed in `api`.
//!
//! | Table | Key | Holds |
//! | --- | --- | --- |
//! | `vault` | vault key | the access hash, a random epoch (its objects' prefix), the manifest's generation and object suffix, bytes and chunk counts |
//! | `vault_owner` | vault key | the owning account (a separate table, so Prompt 11 can unlink vaults without a migration of `vault`) |
//! | `vchunk` | `[vault key, name]` | the chunk's object size |
//! | `vault_gone` | epoch | a turned-off vault's key, until the worker has deleted its objects |
//!
//! Turning a vault off ([`Registry::vault_retire`]) deletes its rows at once and leaves only a
//! `vault_gone` row naming its objects' prefix (`<vault key>/<epoch>/`), so the same recovery
//! key can open a new vault at once without ever mixing objects. No time is stored. Counts move
//! in the same transaction as the rows they count.

use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::{self, DbError};
use crate::{Registry, RegistryError, bytes, first_int, id32, int, rows, var};

/// A vault as the server knows it.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultRow {
    /// `SHA-256("songbird.v1/vault-access\0" || access secret)`.
    pub access: [u8; 32],
    /// The current manifest's generation (0: none yet).
    pub generation: u64,
    /// The current manifest object's suffix (random, so racing writers never share a name).
    pub manifest: Option<[u8; 16]>,
    /// Chunk object bytes plus the manifest's.
    pub bytes: u64,
    /// Chunks.
    pub chunks: u64,
    /// The random epoch naming this vault's objects (`<vault key>/<epoch>/…`).
    pub epoch: [u8; 16],
    /// The owning account.
    pub owner: Option<AccountId>,
}

impl std::fmt::Debug for VaultRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultRow")
            .field("generation", &self.generation)
            .field("bytes", &self.bytes)
            .field("chunks", &self.chunks)
            .finish_non_exhaustive()
    }
}

/// A vault's quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultQuota {
    /// Object bytes (chunks and the manifest).
    pub bytes: u64,
    /// Chunks.
    pub chunks: u64,
}

/// Why a vault write did not apply.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// No such vault (or turned off).
    #[error("gone")]
    Gone,
    /// The quota would be passed.
    #[error("full")]
    Full,
    /// Another manifest write won: the current generation.
    #[error("generation moved on")]
    Generation(u64),
    /// The account has as many vaults as allowed, or the ID is another account's.
    #[error("exists")]
    Exists,
    /// The registry failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

fn u(v: Option<&Value>) -> u64 {
    v.and_then(Value::as_i64)
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0)
}

fn conflict(k: &str) -> bool {
    k == db::TRANSACTION_CONFLICT
}

/// Retries a closure on transaction conflicts (many chunks of one vault are written at once,
/// and each moves the vault's counters): jittered, at most ten tries.
async fn retrying<T, F, Fut>(mut f: F) -> Result<T, VaultError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, DbError>>,
{
    let mut delay_us = 500u64;
    for _ in 0..10 {
        match f().await {
            Err(DbError::Statement(k)) if conflict(&k) => {
                let mut j = [0u8; 2];
                let _ = getrandom::fill(&mut j);
                let jitter = u64::from(u16::from_be_bytes(j)) % delay_us.max(1);
                tokio::time::sleep(std::time::Duration::from_micros(delay_us + jitter)).await;
                delay_us = (delay_us * 2).min(50_000);
            }
            Err(DbError::Statement(k)) => {
                return Err(match k.as_str() {
                    "Thrown:gone" => VaultError::Gone,
                    "Thrown:full" => VaultError::Full,
                    "Thrown:exists" => VaultError::Exists,
                    _ => RegistryError::from(DbError::Statement(k)).into(),
                });
            }
            Err(e) => return Err(RegistryError::from(e).into()),
            Ok(v) => return Ok(v),
        }
    }
    Err(RegistryError::Busy.into())
}

impl Registry {
    /// Creates a vault owned by `account`, or returns `Ok(false)` if this account already owns
    /// it (the same ID and access hash). At most `max_per_account` vaults per account, so a new
    /// recovery key's vault can be filled before the old one is deleted.
    ///
    /// # Errors
    /// [`VaultError::Exists`] (the cap, or the ID taken), [`VaultError::Gone`] for an account
    /// being deleted.
    pub async fn vault_create(
        &self,
        account: &AccountId,
        key: &[u8; 32],
        access: &[u8; 32],
        epoch: &[u8; 16],
        max_per_account: u64,
    ) -> Result<bool, VaultError> {
        let v = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 IF account:[$a].deleting != false { THROW 'songbird:gone' };
                 LET $row = (SELECT access FROM ONLY vault:[$k]);
                 LET $own = (SELECT VALUE account FROM ONLY vault_owner:[$k]);
                 IF $row != NONE AND ($own != $a OR $row.access != $h) {
                   THROW 'songbird:exists' };
                 IF $row = NONE AND count(SELECT id FROM vault_owner WHERE account = $a) >= $max {
                   THROW 'songbird:exists' };
                 IF $row = NONE {
                   CREATE vault:[$k] SET access = $h, epoch = $ep, gen = 0, bytes = 0,
                     chunks = 0 RETURN NONE;
                   CREATE vault_owner:[$k] SET account = $a RETURN NONE;
                 };
                 RETURN $row = NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("k", bytes(key)),
                    var("h", bytes(access)),
                    var("ep", bytes(epoch)),
                    var("max", int(max_per_account)),
                ],
            )
        })
        .await?;
        Ok(v.iter().rev().any(|x| matches!(x, Value::Bool(true))))
    }

    /// A vault's row, if it exists.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault(&self, key: &[u8; 32]) -> Result<Option<VaultRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT access, epoch, gen, man, bytes, chunks,
                   (SELECT VALUE account FROM ONLY vault_owner:[$k]) AS owner
                 FROM ONLY vault:[$k];",
                vec![var("k", bytes(key))],
            )
            .await?;
        if matches!(v, Value::Null) || v.get("access").is_none() {
            return Ok(None);
        }
        Ok(Some(VaultRow {
            access: v.get("access").and_then(id32).ok_or(RegistryError::Shape)?,
            generation: u(v.get("gen")),
            manifest: v
                .get("man")
                .and_then(Value::as_bytes)
                .and_then(|b| b.as_ref().try_into().ok()),
            bytes: u(v.get("bytes")),
            chunks: u(v.get("chunks")),
            epoch: v
                .get("epoch")
                .and_then(Value::as_bytes)
                .and_then(|b| b.as_ref().try_into().ok())
                .ok_or(RegistryError::Shape)?,
            owner: v
                .get("owner")
                .and_then(Value::as_bytes)
                .and_then(|b| AccountId::from_slice(b).ok()),
        }))
    }

    /// Records a chunk **before** its object is uploaded, so an upload that never completes is
    /// still deleted with the vault. Returns whether it was new (an existing name is left
    /// alone: same name, same plaintext).
    ///
    /// # Errors
    /// [`VaultError::Full`], [`VaultError::Gone`].
    pub async fn vault_reserve_chunk(
        &self,
        key: &[u8; 32],
        name: &[u8; 32],
        size: u64,
        quota: VaultQuota,
    ) -> Result<bool, VaultError> {
        let v = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $row = (SELECT bytes, chunks FROM ONLY vault:[$k]);
                 IF $row = NONE { THROW 'songbird:gone' };
                 LET $new = (SELECT id FROM ONLY vchunk:[$k, $n]) = NONE;
                 IF $new {
                   IF $row.bytes + $s > $maxb OR $row.chunks + 1 > $maxc { THROW 'songbird:full' };
                   CREATE vchunk:[$k, $n] SET vault = $k, name = $n, size = $s RETURN NONE;
                   UPDATE vault:[$k] SET bytes += $s, chunks += 1 RETURN NONE;
                 };
                 RETURN $new;
                 COMMIT TRANSACTION;",
                vec![
                    var("k", bytes(key)),
                    var("n", bytes(name)),
                    var("s", int(size)),
                    var("maxb", int(quota.bytes)),
                    var("maxc", int(quota.chunks)),
                ],
            )
        })
        .await?;
        Ok(v.iter().rev().any(|x| matches!(x, Value::Bool(true))))
    }

    /// Whether a chunk is recorded.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault_has_chunk(
        &self,
        key: &[u8; 32],
        name: &[u8; 32],
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN (SELECT id FROM ONLY vchunk:[$k, $n]) != NONE;",
                vec![var("k", bytes(key)), var("n", bytes(name))],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
    }

    /// Up to `limit` chunk names after `after`, in order.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault_chunks(
        &self,
        key: &[u8; 32],
        after: Option<&[u8; 32]>,
        limit: u64,
    ) -> Result<Vec<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE name FROM vchunk WHERE vault = $k AND name > $after
                   ORDER BY name LIMIT $l;",
                vec![
                    var("k", bytes(key)),
                    var("after", bytes(after.unwrap_or(&[0; 32]))),
                    var("l", int(limit)),
                ],
            )
            .await?;
        let mut out: Vec<[u8; 32]> = rows(v)
            .iter()
            .map(|x| id32(x).ok_or(RegistryError::Shape))
            .collect::<Result<_, _>>()?;
        // `name > [0; 32]` skips an all-zero name; include it when listing from the start.
        if after.is_none() && self.vault_has_chunk(key, &[0; 32]).await? {
            out.insert(0, [0; 32]);
            out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        Ok(out)
    }

    /// Forgets chunks (their objects are deleted after); returns how many existed.
    ///
    /// # Errors
    /// [`VaultError::Gone`].
    pub async fn vault_forget_chunks(
        &self,
        key: &[u8; 32],
        names: &[[u8; 32]],
    ) -> Result<u64, VaultError> {
        let ns: Vec<Value> = names.iter().map(|n| bytes(n)).collect();
        let v = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 IF (SELECT id FROM ONLY vault:[$k]) = NONE { THROW 'songbird:gone' };
                 LET $gone = (DELETE vchunk WHERE vault = $k AND name INSIDE $ns RETURN BEFORE);
                 UPDATE vault:[$k] SET bytes -= math::sum($gone.size), chunks -= count($gone)
                   RETURN NONE;
                 RETURN count($gone);
                 COMMIT TRANSACTION;",
                vec![var("k", bytes(key)), var("ns", Value::Array(ns.clone()))],
            )
        })
        .await?;
        Ok(v.iter()
            .rev()
            .find_map(first_int)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0))
    }

    /// Moves the manifest from generation `expected` to `next` (with its object suffix and
    /// size) if no other write did first; returns the previous suffix (to delete its object).
    ///
    /// # Errors
    /// [`VaultError::Generation`] with the current one, [`VaultError::Full`],
    /// [`VaultError::Gone`].
    pub async fn vault_swap_manifest(
        &self,
        key: &[u8; 32],
        expected: u64,
        next: u64,
        suffix: &[u8; 16],
        size: u64,
        quota: VaultQuota,
    ) -> Result<Option<[u8; 16]>, VaultError> {
        let r = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $row = (SELECT gen, man, mbytes, bytes FROM ONLY vault:[$k]);
                 IF $row = NONE { THROW 'songbird:gone' };
                 IF $row.gen != $e { THROW 'songbird:generation' };
                 IF $row.bytes - ($row.mbytes ?? 0) + $s > $maxb { THROW 'songbird:full' };
                 UPDATE vault:[$k] SET gen = $next, man = $m, mbytes = $s,
                   bytes = bytes - (mbytes ?? 0) + $s RETURN NONE;
                 RETURN $row.man;
                 COMMIT TRANSACTION;",
                vec![
                    var("k", bytes(key)),
                    var("e", int(expected)),
                    var("next", int(next)),
                    var("m", bytes(suffix)),
                    var("s", int(size)),
                    var("maxb", int(quota.bytes)),
                ],
            )
        })
        .await;
        match r {
            Ok(v) => Ok(v
                .iter()
                .rev()
                .find_map(|x| x.as_bytes().and_then(|b| b.as_ref().try_into().ok()))),
            Err(VaultError::Registry(RegistryError::Db(DbError::Statement(k))))
                if k == "Thrown:generation" =>
            {
                let current = self.vault(key).await?.map_or(0, |r| r.generation);
                Err(VaultError::Generation(current))
            }
            Err(e) => Err(e),
        }
    }

    /// Turns a vault off: its rows go at once (it answers as gone, and the same key may open a
    /// new vault), leaving a `vault_gone` row for the worker to delete its objects. Returns the
    /// epoch of its objects, or `None` if there was no such vault.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault_retire(&self, key: &[u8; 32]) -> Result<Option<[u8; 16]>, RegistryError> {
        let r = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $ep = (SELECT VALUE epoch FROM ONLY vault:[$k]);
                 IF $ep != NONE {
                   CREATE vault_gone:[$ep] SET vault = $k RETURN NONE;
                   DELETE vchunk WHERE vault = $k RETURN NONE;
                   DELETE vault_owner:[$k] RETURN NONE;
                   DELETE vault:[$k] RETURN NONE;
                 };
                 RETURN $ep;
                 COMMIT TRANSACTION;",
                vec![var("k", bytes(key))],
            )
        })
        .await
        .map_err(|e| match e {
            VaultError::Registry(r) => r,
            _ => RegistryError::Shape,
        })?;
        Ok(r.iter()
            .rev()
            .find_map(|x| x.as_bytes().and_then(|b| b.as_ref().try_into().ok())))
    }

    /// Turned-off vaults whose objects are still to delete: `(vault key, epoch)`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vaults_gone(
        &self,
        limit: u64,
    ) -> Result<Vec<([u8; 32], [u8; 16])>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT vault, meta::id(id)[0] AS ep FROM vault_gone LIMIT $l;",
                vec![var("l", int(limit))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| {
                Ok((
                    r.get("vault").and_then(id32).ok_or(RegistryError::Shape)?,
                    r.get("ep")
                        .and_then(Value::as_bytes)
                        .and_then(|b| b.as_ref().try_into().ok())
                        .ok_or(RegistryError::Shape)?,
                ))
            })
            .collect()
    }

    /// Forgets a turned-off vault once its objects are deleted.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault_gone_done(&self, epoch: &[u8; 16]) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE vault_gone:[$e] RETURN NONE;",
                vec![var("e", bytes(epoch))],
            )
            .await?;
        Ok(())
    }

    /// The vaults an account owns (for its deletion and export).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vaults_of(&self, account: &AccountId) -> Result<Vec<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM vault_owner WHERE account = $a;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|x| id32(x).ok_or(RegistryError::Shape))
            .collect()
    }
}
