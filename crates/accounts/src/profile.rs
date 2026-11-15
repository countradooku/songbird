//! Encrypted profiles, avatars and unidentified-access keys (Prompt 3, M5, D-0054).

use bytes::Bytes;
use songbird_surreal::Value;
use songbird_types::{AccountId, DeviceId};

use crate::db::DbError;
use crate::{Registry, RegistryError, bytes, id16, id32, int, rows, var};

/// A recipient account's sealed-sender settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKey {
    /// The account.
    pub account: AccountId,
    /// Its unidentified-access key, if it set a profile.
    pub key: Option<[u8; 16]>,
    /// Anyone may send to it sealed.
    pub open: bool,
}

impl Registry {
    /// Stores an account's encrypted profile, its access key and whether anyone may send to it
    /// sealed; the version must exceed the stored one.
    ///
    /// # Errors
    /// [`RegistryError::Rollback`].
    pub async fn put_profile(
        &self,
        account: &AccountId,
        version: u64,
        blob: &[u8],
        access_key: &[u8; 16],
        open: bool,
    ) -> Result<(), RegistryError> {
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF account:[$a].deleting != false { THROW 'songbird:rollback' };
                 IF (account:[$a].profile_v ?? -1) >= $v { THROW 'songbird:rollback' };
                 UPDATE account:[$a] SET profile = $p, profile_v = $v, uak = $k, uak_open = $o
                   RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("v", int(version)),
                    var("p", bytes(blob)),
                    var("k", bytes(access_key)),
                    var("o", Value::Bool(open)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k == "Thrown:rollback" => Err(RegistryError::Rollback),
            Err(DbError::Statement(k)) if k == crate::db::TRANSACTION_CONFLICT => {
                Err(RegistryError::Rollback)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// An account's encrypted profile and its version (none for an account being deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn profile(
        &self,
        account: &AccountId,
    ) -> Result<Option<(Bytes, u64)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT profile, profile_v FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let (Some(b), Some(n)) = (
            v.get("profile").and_then(|b| b.as_bytes().cloned()),
            v.get("profile_v")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok()),
        ) else {
            return Ok(None);
        };
        Ok(Some((b, n)))
    }

    /// Records an avatar object **before** it is uploaded, already marked replaced, so an upload
    /// that never completes (or a crash before [`Registry::make_avatar_current`]) is swept.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn reserve_avatar(
        &self,
        account: &AccountId,
        id: &[u8; 32],
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "CREATE avatar:[$i] SET account = $a, at = time::now(), replaced_at = time::now()
                   RETURN NONE;",
                vec![var("a", bytes(account.as_bytes())), var("i", bytes(id))],
            )
            .await?;
        Ok(())
    }

    /// Makes an uploaded avatar the account's current one; the previous one is marked replaced in
    /// the same transaction (the worker deletes replaced ones after an hour).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn make_avatar_current(
        &self,
        account: &AccountId,
        id: &[u8; 32],
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 IF account:[$a].deleting != false { THROW 'songbird:gone' };
                 IF avatar:[$i].account != $a { THROW 'songbird:gone' };
                 UPDATE avatar SET replaced_at = time::now()
                   WHERE account = $a AND replaced_at = NONE RETURN NONE;
                 UPDATE avatar:[$i] SET replaced_at = NONE RETURN NONE;
                 UPDATE account:[$a] SET avatar = $i RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![var("a", bytes(account.as_bytes())), var("i", bytes(id))],
            )
            .await?;
        Ok(())
    }

    /// [`Registry::reserve_avatar`] then [`Registry::make_avatar_current`] (tests, tools).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn add_avatar(
        &self,
        account: &AccountId,
        id: &[u8; 32],
    ) -> Result<(), RegistryError> {
        self.reserve_avatar(account, id).await?;
        self.make_avatar_current(account, id).await
    }

    /// Whether an avatar object is an account's current one (only those are served).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn avatar_current(&self, id: &[u8; 32]) -> Result<bool, RegistryError> {
        let all = self
            .db
            .query(
                "LET $acc = avatar:[$i].account;
                 RETURN $acc != NONE AND account:[$acc].avatar = $i
                   AND account:[$acc].deleting = false;",
                vec![var("i", bytes(id))],
            )
            .await?;
        Ok(matches!(all.last(), Some(Value::Bool(true))))
    }

    /// Every avatar object of an account (for its deletion).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn avatars_of(&self, account: &AccountId) -> Result<Vec<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM avatar WHERE account = $a;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|x| id32(x).ok_or(RegistryError::Shape))
            .collect()
    }

    /// Avatar objects replaced (or never completed) more than an hour ago.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn stale_avatars(&self, limit: usize) -> Result<Vec<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM avatar
                   WHERE replaced_at != NONE AND replaced_at < time::now() - 1h LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|x| id32(x).ok_or(RegistryError::Shape))
            .collect()
    }

    /// Removes an avatar record (after its object is deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_avatar(&self, id: &[u8; 32]) -> Result<(), RegistryError> {
        self.db
            .query("DELETE avatar:[$i] RETURN NONE;", vec![var("i", bytes(id))])
            .await?;
        Ok(())
    }

    /// The sealed-sender settings of the accounts that own `devices` (enabled, listed devices;
    /// accounts being deleted are left out).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn access_keys(&self, devices: &[DeviceId]) -> Result<Vec<AccessKey>, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let v = self
            .db
            .query1(
                "SELECT VALUE account FROM device
                   WHERE meta::id(id)[0] INSIDE $ds AND disabled = false AND pending != true;",
                vec![var("ds", Value::Array(ds))],
            )
            .await?;
        let mut accounts: Vec<[u8; 16]> = rows(v).iter().filter_map(id16).collect();
        accounts.sort_unstable();
        accounts.dedup();
        let mut out = Vec::with_capacity(accounts.len());
        for a in accounts {
            let r = self
                .db
                .query1(
                    "SELECT uak, uak_open FROM ONLY account:[$a] WHERE deleting = false;",
                    vec![var("a", bytes(&a))],
                )
                .await?;
            if r.is_absent() {
                continue;
            }
            out.push(AccessKey {
                account: AccountId::from_bytes(a),
                key: r
                    .get("uak")
                    .and_then(|b| b.as_bytes())
                    .and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok()),
                open: matches!(r.get("uak_open"), Some(Value::Bool(true))),
            });
        }
        Ok(out)
    }
}
