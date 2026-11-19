//! The Songbird vault's rows (Prompt 10, M2, D-0121; `docs/PROTOCOL.md` §11.8).
//!
//! A vault holds one backup's objects. The server never sees its ID: rows are keyed by
//! `HMAC(server key, vault ID)` (32 bytes, "the vault key" below), computed in `api`.
//!
//! | Table | Key | Holds |
//! | --- | --- | --- |
//! | `vault` | vault key | the access hash, a random epoch (its objects' prefix), the manifest's generation and object suffix, bytes and chunk counts; the level and UTC day of its latest day pass, and the last day it was used |
//! | `vcreate` | `[keyed tag of an account, 180-day window]` | how many vault creation tokens the account was issued in the window (Prompt 11) |
//! | `vchunk` | `[vault key, name]` | the chunk's object size |
//! | `vault_gone` | epoch | a turned-off vault's key, until the worker has deleted its objects |
//!
//! Turning a vault off ([`Registry::vault_retire`]) deletes its rows at once and leaves only a
//! `vault_gone` row naming its objects' prefix (`<vault key>/<epoch>/`), so the same recovery
//! key can open a new vault at once without ever mixing objects. No time is stored. Counts move
//! in the same transaction as the rows they count.
//!
//! **No vault names an account** (Prompt 11, M4, D-0130; D-0119 §3 re-decided): a vault is
//! created with an anonymous creation token and written under an anonymous day pass, both
//! issued blinded to the account's primary. Their nullifiers are burnt in the transaction that
//! uses them. A vault nobody uses for a year is retired by the worker.

use songbird_surreal::Value;

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
    /// The plan level of its latest day pass (its quota).
    pub level: u8,
    /// The UTC day of its latest day pass.
    pub pass: u32,
    /// The last UTC day it was used (a pass presented).
    pub seen: u32,
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
    /// The ID is taken with another access secret, or the account has as many creations as
    /// its window allows.
    #[error("exists")]
    Exists,
    /// The token was redeemed already.
    #[error("spent")]
    Spent,
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
                    "Thrown:spent" => VaultError::Spent,
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
    /// Creates a vault with a creation token: burns its nullifier (kept through `keep_until`)
    /// and creates the rows, in one transaction. Returns `Ok(false)` if the vault exists with
    /// this access hash (nothing is burnt: the token stays the client's).
    ///
    /// # Errors
    /// [`VaultError::Exists`] (the ID taken with another secret), [`VaultError::Spent`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the vault, its secret and epoch, the token's nullifier and life, the day"
    )]
    pub async fn vault_create(
        &self,
        key: &[u8; 32],
        access: &[u8; 32],
        epoch: &[u8; 16],
        nullifier: &[u8; 32],
        keep_until: u32,
        today: u32,
    ) -> Result<bool, VaultError> {
        let v = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $row = (SELECT access FROM ONLY vault:[$k]);
                 IF $row != NONE AND $row.access != $h { THROW 'songbird:exists' };
                 IF $row = NONE {
                   IF record::exists(tnull:[$n]) { THROW 'songbird:spent' };
                   CREATE tnull:[$n] SET until = $u RETURN NONE;
                   CREATE vault:[$k] SET access = $h, epoch = $ep, gen = 0, bytes = 0,
                     chunks = 0, level = 0, pass = 0, seen = $t RETURN NONE;
                 };
                 RETURN $row = NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("k", bytes(key)),
                    var("h", bytes(access)),
                    var("ep", bytes(epoch)),
                    var("n", bytes(nullifier)),
                    var("u", int(u64::from(keep_until))),
                    var("t", int(u64::from(today))),
                ],
            )
        })
        .await?;
        Ok(v.iter().rev().any(|x| matches!(x, Value::Bool(true))))
    }

    /// Presents a day pass for a vault's incarnation `epoch`: burns its nullifier, and moves the
    /// vault's pass to `day` at `level` (a later day's pass sets the level; an earlier one only
    /// counts as use), its last use to `today`.
    ///
    /// # Errors
    /// [`VaultError::Gone`], [`VaultError::Spent`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the vault and its incarnation, the token's nullifier, life, day and level"
    )]
    pub async fn vault_pass(
        &self,
        key: &[u8; 32],
        epoch: &[u8; 16],
        nullifier: &[u8; 32],
        keep_until: u32,
        day: u32,
        level: u8,
        today: u32,
    ) -> Result<(), VaultError> {
        retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 IF (SELECT VALUE epoch FROM ONLY vault:[$k]) != $ep { THROW 'songbird:gone' };
                 IF record::exists(tnull:[$n]) { THROW 'songbird:spent' };
                 CREATE tnull:[$n] SET until = $u RETURN NONE;
                 LET $p = (SELECT VALUE pass FROM ONLY vault:[$k]) ?? 0;
                 IF $d >= $p {
                   UPDATE vault:[$k] SET pass = $d, level = $l, seen = $t RETURN NONE;
                 } ELSE {
                   UPDATE vault:[$k] SET seen = $t RETURN NONE;
                 };
                 COMMIT TRANSACTION;",
                vec![
                    var("k", bytes(key)),
                    var("ep", bytes(epoch)),
                    var("n", bytes(nullifier)),
                    var("u", int(u64::from(keep_until))),
                    var("d", int(u64::from(day))),
                    var("l", int(u64::from(level))),
                    var("t", int(u64::from(today))),
                ],
            )
        })
        .await?;
        Ok(())
    }

    /// Spends one of an account's vault creations in a window (`tag`: a keyed hash of the
    /// account, never the account). At most `cap` per window.
    ///
    /// # Errors
    /// [`VaultError::Exists`] at the cap.
    pub async fn vault_creation_budget(
        &self,
        tag: &[u8; 16],
        window: u32,
        n: u32,
        cap: u32,
        keep_until: u32,
    ) -> Result<(), VaultError> {
        retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $c = (SELECT VALUE n FROM ONLY vcreate:[$g, $w]) ?? 0;
                 IF $c + $n > $cap { THROW 'songbird:exists' };
                 UPSERT vcreate:[$g, $w] SET n = $c + $n, until = $u RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("g", bytes(tag)),
                    var("w", int(u64::from(window))),
                    var("n", int(u64::from(n))),
                    var("cap", int(u64::from(cap))),
                    var("u", int(u64::from(keep_until))),
                ],
            )
        })
        .await?;
        Ok(())
    }

    /// A vault's row, if it exists.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault(&self, key: &[u8; 32]) -> Result<Option<VaultRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT access, epoch, gen, man, bytes, chunks, level, pass, seen
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
            level: u8::try_from(u(v.get("level"))).unwrap_or(0),
            pass: u32::try_from(u(v.get("pass"))).unwrap_or(0),
            seen: u32::try_from(u(v.get("seen"))).unwrap_or(0),
        }))
    }

    /// Records a chunk **before** its object is uploaded, so an upload that never completes is
    /// still deleted with the vault. Returns `None` if it was new, or the size recorded for it
    /// (an existing name is left alone: same name, same plaintext, so the same size; the caller
    /// refuses another size, which is what keeps the quota exact, D-0125). `epoch` is the
    /// incarnation the caller opened: a vault turned off (and perhaps opened again) since
    /// answers as gone.
    ///
    /// # Errors
    /// [`VaultError::Full`], [`VaultError::Gone`].
    pub async fn vault_reserve_chunk(
        &self,
        key: &[u8; 32],
        epoch: &[u8; 16],
        name: &[u8; 32],
        size: u64,
        quota: VaultQuota,
    ) -> Result<Option<u64>, VaultError> {
        let v = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $row = (SELECT bytes, chunks, epoch FROM ONLY vault:[$k]);
                 IF $row = NONE OR $row.epoch != $ep { THROW 'songbird:gone' };
                 LET $old = (SELECT VALUE size FROM ONLY vchunk:[$k, $n]);
                 IF $old = NONE {
                   IF $row.bytes + $s > $maxb OR $row.chunks + 1 > $maxc { THROW 'songbird:full' };
                   CREATE vchunk:[$k, $n] SET vault = $k, name = $n, size = $s RETURN NONE;
                   UPDATE vault:[$k] SET bytes += $s, chunks += 1 RETURN NONE;
                 };
                 RETURN $old;
                 COMMIT TRANSACTION;",
                vec![
                    var("k", bytes(key)),
                    var("ep", bytes(epoch)),
                    var("n", bytes(name)),
                    var("s", int(size)),
                    var("maxb", int(quota.bytes)),
                    var("maxc", int(quota.chunks)),
                ],
            )
        })
        .await?;
        Ok(v.iter()
            .rev()
            .find_map(first_int)
            .and_then(|n| u64::try_from(n).ok()))
    }

    /// Whether a chunk is still recorded in the incarnation `epoch` of a vault: checked after
    /// an upload, whose object is deleted again if the chunk was forgotten or the vault turned
    /// off while it was in flight (D-0125).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault_chunk_live(
        &self,
        key: &[u8; 32],
        epoch: &[u8; 16],
        name: &[u8; 32],
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN (SELECT VALUE epoch FROM ONLY vault:[$k]) = $ep
                   AND (SELECT id FROM ONLY vchunk:[$k, $n]) != NONE;",
                vec![
                    var("k", bytes(key)),
                    var("ep", bytes(epoch)),
                    var("n", bytes(name)),
                ],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
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
    #[allow(
        clippy::too_many_arguments,
        reason = "the vault, its incarnation, the swap and the quota"
    )]
    pub async fn vault_swap_manifest(
        &self,
        key: &[u8; 32],
        epoch: &[u8; 16],
        expected: u64,
        next: u64,
        suffix: &[u8; 16],
        size: u64,
        quota: VaultQuota,
    ) -> Result<Option<[u8; 16]>, VaultError> {
        let r = retrying(|| {
            self.db.query(
                "BEGIN TRANSACTION;
                 LET $row = (SELECT gen, man, mbytes, bytes, epoch FROM ONLY vault:[$k]);
                 IF $row = NONE OR $row.epoch != $ep { THROW 'songbird:gone' };
                 IF $row.gen != $e { THROW 'songbird:generation' };
                 IF $row.bytes - ($row.mbytes ?? 0) + $s > $maxb { THROW 'songbird:full' };
                 UPDATE vault:[$k] SET gen = $next, man = $m, mbytes = $s,
                   bytes = bytes - (mbytes ?? 0) + $s RETURN NONE;
                 RETURN $row.man;
                 COMMIT TRANSACTION;",
                vec![
                    var("k", bytes(key)),
                    var("ep", bytes(epoch)),
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
                   CREATE vault_gone:[$ep] SET vault = $k, at = time::now() RETURN NONE;
                   DELETE vchunk WHERE vault = $k RETURN NONE;
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

    /// Forgets a turned-off vault once its objects are deleted, but only once it has been off
    /// for `grace`: until then every sweep lists its prefix again, so an upload that was in
    /// flight when it was turned off, and landed after a sweep, is deleted too (D-0125).
    /// Returns whether it was forgotten.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vault_gone_done(
        &self,
        epoch: &[u8; 16],
        grace: std::time::Duration,
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN count(DELETE vault_gone:[$e]
                   WHERE at < time::now() - duration::from_secs($g) RETURN BEFORE);",
                vec![var("e", bytes(epoch)), var("g", int(grace.as_secs()))],
            )
            .await?;
        Ok(first_int(&v).is_some_and(|n| n > 0))
    }

    /// Vaults unused since before `before` (a UTC day), at most `limit`: the worker retires them
    /// (a year without a backup or a restore).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn vaults_unused(
        &self,
        before: u32,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM vault WHERE seen < $b LIMIT $n;",
                vec![
                    var("b", int(u64::from(before))),
                    var("n", int(u64::try_from(limit).unwrap_or(u64::MAX))),
                ],
            )
            .await?;
        rows(v)
            .iter()
            .map(|x| id32(x).ok_or(RegistryError::Shape))
            .collect()
    }

    /// Deletes vault creation counts past their window (the worker's sweep).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn sweep_vault_creations(&self, today: u32) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE vcreate WHERE until < $t RETURN NONE;",
                vec![var("t", int(u64::from(today)))],
            )
            .await?;
        Ok(())
    }
}
