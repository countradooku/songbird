//! Devices (Prompt 3, M4, D-0052): link tokens, linking, the signed device list, removal.
//!
//! Every change to an account's set of devices writes its account row (`dgen`) in the same
//! transaction, so two concurrent changes to one account conflict in SurrealDB and one retries:
//! the device limit holds under races (the live tests race it).
//!
//! A linked device is **pending** until the account identity key vouches for it in a signed
//! list: it can authenticate (to finish setting up and upload its keys) but no one is asked to
//! encrypt to it and its keys are not served ([`Registry::pending_devices`]).

use std::time::Duration;

use bytes::Bytes;
use songbird_jobs::Job;
use songbird_surreal::Value;
use songbird_types::{AccountId, DeviceId};

use crate::db::{self, DbError};
use crate::{CONFLICT_RETRIES, Registry, RegistryError, bytes, id16, id32, int, rows, var};

/// One device of an account, as its own devices see it (`GET /v1/devices`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDevice {
    /// The device.
    pub device: DeviceId,
    /// Ed25519 authentication key.
    pub auth_key: [u8; 32],
    /// Identity key (`0x05 || u`); a primary that has not uploaded keys yet has none.
    pub identity: Option<[u8; 33]>,
    /// Holds the account identity key.
    pub primary: bool,
    /// Linked, not yet in a signed list.
    pub pending: bool,
    /// The link confirmation tag (a MAC the primary checks with the key it sent the new device);
    /// cleared once a list names the device.
    pub confirm: Option<[u8; 32]>,
}

/// A device entry of a list to store, already decoded and signature-checked by the caller.
#[derive(Debug, Clone)]
pub struct ListEntry {
    /// The device.
    pub device: DeviceId,
    /// Its authentication key.
    pub auth_key: [u8; 32],
    /// Its identity key.
    pub identity: [u8; 33],
    /// Whether it is the primary.
    pub primary: bool,
}

/// What [`Registry::put_device_list`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListChange {
    /// Devices the list left out, now disabled (their deletion job is in the outbox).
    pub removed: Vec<DeviceId>,
    /// The account's enabled devices after the change.
    pub remaining: Vec<DeviceId>,
}

impl Registry {
    async fn retry<T>(
        &self,
        sql: &str,
        vars: impl Fn() -> Vec<(String, Value)>,
        classify: impl Fn(&str) -> Option<RegistryError>,
        done: impl Fn(Vec<Value>) -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        let mut attempt = 0;
        loop {
            match self.db.query(sql, vars()).await {
                Ok(v) => return done(v),
                Err(DbError::Statement(kind)) => {
                    if let Some(e) = classify(&kind) {
                        return Err(e);
                    }
                    if kind == db::TRANSACTION_CONFLICT && attempt < CONFLICT_RETRIES {
                        attempt += 1;
                        tokio::time::sleep(Duration::from_millis(2u64 << attempt.min(6))).await;
                        continue;
                    }
                    return Err(DbError::Statement(kind).into());
                }
                Err(e) if crate::is_conflict(&e) && attempt < CONFLICT_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(2u64 << attempt.min(6))).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// A link token for a new device of `primary`'s account: stores the token's hash with the
    /// device ID it reserves, until `ttl`. Refused unless `primary` is the account's enabled
    /// primary; refused once enabled devices plus unexpired tokens reach `max`. Returns the
    /// account.
    ///
    /// # Errors
    /// [`RegistryError::NotPrimary`], [`RegistryError::DeviceLimit`],
    /// [`RegistryError::Exists`] (the device ID is taken; draw another).
    pub async fn create_link_token(
        &self,
        primary: &DeviceId,
        token_hash: &[u8; 32],
        device: &DeviceId,
        ttl: Duration,
        max: u32,
    ) -> Result<AccountId, RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $row = (SELECT account, disabled, prim FROM ONLY device:[$p]);
             IF $row = NONE OR $row.disabled OR $row.prim != true { THROW 'songbird:primary' };
             LET $a = $row.account;
             IF account:[$a].deleting != false { THROW 'songbird:primary' };
             UPDATE account:[$a] SET dgen = (dgen ?? 0) + 1 RETURN NONE;
             IF record::exists(device:[$d]) OR
               count(SELECT id FROM ltoken WHERE device = $d) > 0 { THROW 'songbird:exists' };
             IF count(SELECT id FROM device WHERE account = $a AND disabled = false)
               + count(SELECT id FROM ltoken WHERE account = $a AND expires > time::now()) >= $max
               { THROW 'songbird:limit' };
             CREATE ltoken:[$t] SET account = $a, device = $d,
               expires = time::now() + duration::from_secs($ttl) RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("p", bytes(primary.as_bytes())),
                    var("t", bytes(token_hash)),
                    var("d", bytes(device.as_bytes())),
                    var("ttl", int(ttl.as_secs())),
                    var("max", int(u64::from(max))),
                ]
            },
            |k| match k {
                "Thrown:primary" => Some(RegistryError::NotPrimary),
                "Thrown:limit" => Some(RegistryError::DeviceLimit),
                "Thrown:exists" => Some(RegistryError::Exists),
                k if k.contains("AlreadyExists") => Some(RegistryError::Exists),
                _ => None,
            },
            |_| Ok(()),
        )
        .await?;
        self.device(primary)
            .await?
            .map(|r| r.account)
            .ok_or(RegistryError::NotPrimary)
    }

    /// Links a device with a link token (its hash): in one transaction, the token is consumed
    /// (it must be unexpired and reserve `device`), and the device is created, enabled and
    /// pending, with its authentication and identity keys and its confirmation tag, unless the
    /// account is being deleted or already has `max` enabled devices. Returns the account.
    ///
    /// # Errors
    /// [`RegistryError::LinkToken`] (one answer for unknown, used, expired and another device),
    /// [`RegistryError::DeviceLimit`].
    pub async fn link_device(
        &self,
        token_hash: &[u8; 32],
        device: &DeviceId,
        auth_key: &[u8; 32],
        identity: &[u8; 33],
        confirm: &[u8; 32],
        max: u32,
    ) -> Result<AccountId, RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $tok = (DELETE ONLY ltoken:[$t] RETURN BEFORE);
             IF $tok = NONE OR $tok.expires <= time::now() OR $tok.device != $d
               { THROW 'songbird:token' };
             LET $a = $tok.account;
             IF account:[$a].deleting != false { THROW 'songbird:token' };
             UPDATE account:[$a] SET dgen = (dgen ?? 0) + 1 RETURN NONE;
             IF count(SELECT id FROM device WHERE account = $a AND disabled = false) >= $max
               { THROW 'songbird:limit' };
             CREATE device:[$d] SET account = $a, key = $k, ik = $ik, lconf = $c, prim = false,
               pending = true, disabled = false, at = time::now() RETURN NONE;
             UPDATE directory:v SET version += 1 RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("t", bytes(token_hash)),
                    var("d", bytes(device.as_bytes())),
                    var("k", bytes(auth_key)),
                    var("ik", bytes(identity)),
                    var("c", bytes(confirm)),
                    var("max", int(u64::from(max))),
                ]
            },
            |k| match k {
                "Thrown:token" => Some(RegistryError::LinkToken),
                "Thrown:limit" => Some(RegistryError::DeviceLimit),
                // The reserved ID was taken in between (128 random bits: not in practice).
                k if k.contains("AlreadyExists") => Some(RegistryError::LinkToken),
                _ => None,
            },
            |_| Ok(()),
        )
        .await?;
        self.device(device)
            .await?
            .map(|r| r.account)
            .ok_or(RegistryError::LinkToken)
    }

    /// The enabled devices of an account, with what their own devices need to sign a list.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn devices_of(
        &self,
        account: &AccountId,
    ) -> Result<Vec<AccountDevice>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d, key AS k, ik, prim, pending, lconf FROM device
                   WHERE account = $a AND disabled = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(device), Some(auth_key)) = (
                r.get("d").and_then(id16).map(DeviceId::from_bytes),
                r.get("k").and_then(id32),
            ) else {
                return Err(RegistryError::Shape);
            };
            let flag = |f: &str| matches!(r.get(f), Some(Value::Bool(true)));
            out.push(AccountDevice {
                device,
                auth_key,
                identity: r
                    .get("ik")
                    .and_then(|b| b.as_bytes())
                    .and_then(|b| <[u8; 33]>::try_from(b.as_ref()).ok()),
                primary: flag("prim"),
                pending: flag("pending"),
                confirm: r.get("lconf").and_then(id32),
            });
        }
        out.sort_by_key(|d| d.device);
        Ok(out)
    }

    /// Stores a signed device list (`encoded`, already verified with the account identity key
    /// by the caller) in one transaction: its version must exceed the stored one; every entry
    /// must be an enabled device of the account with exactly those keys, and the primary entry
    /// the account's primary; listed devices stop being pending; enabled devices it leaves out
    /// are disabled and `job` (a [`songbird_jobs::Work::DeleteDevices`]) goes to the outbox.
    ///
    /// # Errors
    /// [`RegistryError::Rollback`], [`RegistryError::ListMismatch`].
    pub async fn put_device_list(
        &self,
        account: &AccountId,
        version: u64,
        entries: &[ListEntry],
        encoded: &[u8],
        job: &Job,
    ) -> Result<ListChange, RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF account:[$a].deleting != false { THROW 'songbird:mismatch' };
             UPDATE account:[$a] SET dgen = (dgen ?? 0) + 1 RETURN NONE;
             IF (account:[$a].dlist_v ?? -1) >= $v { THROW 'songbird:rollback' };
             FOR $e IN $entries {
               LET $r = (SELECT account, key, ik, prim, disabled FROM ONLY device:[$e[0]]);
               IF $r = NONE OR $r.account != $a OR $r.disabled OR $r.key != $e[1]
                 OR $r.ik != $e[2] OR ($r.prim ?? false) != $e[3] { THROW 'songbird:mismatch' };
             };
             LET $removed = (SELECT VALUE meta::id(id)[0] FROM device
               WHERE account = $a AND disabled = false AND meta::id(id)[0] NOTINSIDE $ids);
             UPDATE device SET disabled = true, pending = NONE, lconf = NONE
               WHERE account = $a AND disabled = false AND meta::id(id)[0] NOTINSIDE $ids
               RETURN NONE;
             UPDATE device SET pending = NONE, lconf = NONE
               WHERE account = $a AND meta::id(id)[0] INSIDE $ids RETURN NONE;
             UPDATE account:[$a] SET dlist = $blob, dlist_v = $v, kt_gen = (kt_gen ?? 0) + 1
               RETURN NONE;
             IF array::len($removed) > 0 {
               UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;
             };
             UPDATE directory:v SET version += 1 RETURN NONE;
             RETURN $removed;
             COMMIT TRANSACTION;";
        let list: Vec<Value> = entries
            .iter()
            .map(|e| {
                Value::Array(vec![
                    bytes(e.device.as_bytes()),
                    bytes(&e.auth_key),
                    bytes(&e.identity),
                    Value::Bool(e.primary),
                ])
            })
            .collect();
        let ids: Vec<Value> = entries.iter().map(|e| bytes(e.device.as_bytes())).collect();
        let removed = self
            .retry(
                sql,
                || {
                    vec![
                        var("a", bytes(account.as_bytes())),
                        var("v", int(version)),
                        var("entries", Value::Array(list.clone())),
                        var("ids", Value::Array(ids.clone())),
                        var("blob", bytes(encoded)),
                        var("j", bytes(job.id.as_bytes())),
                        var("job", bytes(&job.to_bytes())),
                    ]
                },
                |k| match k {
                    "Thrown:rollback" => Some(RegistryError::Rollback),
                    "Thrown:mismatch" => Some(RegistryError::ListMismatch),
                    _ => None,
                },
                |v| {
                    // `RETURN $removed` is the last result that is an array of IDs.
                    let arr = v
                        .into_iter()
                        .rev()
                        .find_map(|x| match x {
                            Value::Array(a) if a.iter().all(|i| id16(i).is_some()) => Some(a),
                            _ => None,
                        })
                        .unwrap_or_default();
                    arr.iter()
                        .map(|d| {
                            id16(d)
                                .map(DeviceId::from_bytes)
                                .ok_or(RegistryError::Shape)
                        })
                        .collect::<Result<Vec<_>, _>>()
                },
            )
            .await?;
        let remaining = self
            .devices_of(account)
            .await?
            .into_iter()
            .map(|d| d.device)
            .collect();
        Ok(ListChange { removed, remaining })
    }

    /// The account's signed device list and its version, if one was stored.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn device_list(
        &self,
        account: &AccountId,
    ) -> Result<Option<(Bytes, u64)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT dlist, dlist_v FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let (Some(b), Some(n)) = (
            v.get("dlist").and_then(|b| b.as_bytes().cloned()),
            v.get("dlist_v")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok()),
        ) else {
            return Ok(None);
        };
        Ok(Some((b, n)))
    }

    /// A linked device removes itself: disabled, with `job` in the outbox, in one transaction.
    /// The primary cannot (it deletes the account instead). Returns the account and its enabled
    /// devices after the change.
    ///
    /// # Errors
    /// [`RegistryError::NotPrimary`] for the primary (the name is the closest refusal).
    pub async fn remove_device(
        &self,
        device: &DeviceId,
        job: &Job,
    ) -> Result<(AccountId, Vec<DeviceId>), RegistryError> {
        let Some(row) = self.device(device).await? else {
            return Err(RegistryError::Shape);
        };
        let sql = "BEGIN TRANSACTION;
             LET $row = (SELECT account, disabled, prim FROM ONLY device:[$d]);
             IF $row = NONE OR $row.disabled OR $row.prim != false { THROW 'songbird:primary' };
             UPDATE account:[$row.account] SET dgen = (dgen ?? 0) + 1 RETURN NONE;
             UPDATE device:[$d] SET disabled = true, pending = NONE, lconf = NONE RETURN NONE;
             UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;
             UPDATE directory:v SET version += 1 RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("d", bytes(device.as_bytes())),
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ]
            },
            |k| (k == "Thrown:primary").then_some(RegistryError::NotPrimary),
            |_| Ok(()),
        )
        .await?;
        let remaining = self
            .devices_of(&row.account)
            .await?
            .into_iter()
            .map(|d| d.device)
            .collect();
        Ok((row.account, remaining))
    }

    /// Enabled devices not yet in a signed list (delivery's directory lets them authenticate but
    /// asks no sender to encrypt to them).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn pending_devices(&self) -> Result<Vec<DeviceId>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM device WHERE disabled = false AND pending = true;",
                Vec::new(),
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

    /// Disabled devices of an account that is not being deleted: what a
    /// [`songbird_jobs::Work::DeleteDevices`] job removes.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn removed_devices(
        &self,
        account: &AccountId,
    ) -> Result<Vec<DeviceId>, RegistryError> {
        let v = self
            .db
            .query1(
                "IF account:[$a].deleting = false {
                   RETURN SELECT VALUE meta::id(id)[0] FROM device
                     WHERE account = $a AND disabled = true;
                 } ELSE { RETURN []; };",
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

    /// Deletes removed (disabled) devices' rows and their prekeys and KeyPackages; enabled devices
    /// are never touched.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_device_rows(&self, devices: &[DeviceId]) -> Result<(), RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        self.db
            .query(
                "BEGIN TRANSACTION;
                 LET $gone = (SELECT VALUE meta::id(id)[0] FROM device
                   WHERE meta::id(id)[0] INSIDE $ds AND disabled = true);
                 DELETE otpk WHERE device INSIDE $gone RETURN NONE;
                 DELETE otkem WHERE device INSIDE $gone RETURN NONE;
                 DELETE mlskp WHERE device INSIDE $gone RETURN NONE;
                 FOR $d IN $gone { DELETE device:[$d] RETURN NONE; };
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![var("ds", Value::Array(ds))],
            )
            .await?;
        Ok(())
    }

    /// How many of `devices` still have rows, prekeys or KeyPackages.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn device_remnants(&self, devices: &[DeviceId]) -> Result<u64, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let v = self
            .db
            .query1(
                "RETURN count(SELECT id FROM device WHERE meta::id(id)[0] INSIDE $ds)
                   + count(SELECT id FROM otpk WHERE device INSIDE $ds)
                   + count(SELECT id FROM otkem WHERE device INSIDE $ds)
                   + count(SELECT id FROM mlskp WHERE device INSIDE $ds);",
                vec![var("ds", Value::Array(ds))],
            )
            .await?;
        crate::first_int(&v)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Removes expired link tokens (they are refused already; this only stops them taking
    /// space and counting toward the limit's query).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_expired_link_tokens(&self, limit: usize) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE (SELECT VALUE id FROM ltoken WHERE expires <= time::now() LIMIT $n)
                   RETURN NONE;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        Ok(())
    }
}

// ----- second factors (Prompt 3, M4b, D-0053) -----

/// A PIN attempt could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRefusal {
    /// The account has no PIN.
    NoPin,
    /// Locked: retry after this many seconds (`None`: until the primary sets a new PIN).
    Locked(Option<u64>),
}

/// A registered passkey (stored form of `songbird_keys::webauthn::Credential`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPasskey {
    /// Credential ID.
    pub id: Vec<u8>,
    /// `CredentialKey::to_bytes`.
    pub key: Vec<u8>,
    /// Signature counter.
    pub count: u32,
}

/// The account's second factors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Factors {
    /// A PIN is set.
    pub pin: bool,
    /// Seconds the PIN stays locked, if it is.
    pub pin_locked: Option<u64>,
    /// PIN attempts spent since the last correct one.
    pub pin_tries: u32,
    /// Registered passkeys' credential IDs.
    pub passkeys: Vec<Vec<u8>>,
}

impl Factors {
    /// Whether linking needs a second factor.
    #[must_use]
    pub fn any(&self) -> bool {
        self.pin || !self.passkeys.is_empty()
    }
}

fn passkey_key(id: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, id).as_ref());
    out
}

impl Registry {
    /// The account an unexpired link token belongs to (the token is not consumed).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn link_token_account(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<AccountId>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE account FROM ONLY ltoken:[$t] WHERE expires > time::now();",
                vec![var("t", bytes(token_hash))],
            )
            .await?;
        Ok(id16(&v).map(AccountId::from_bytes))
    }

    /// Sets (or replaces) the account's PIN verifier and clears its attempts and lock.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn set_pin(
        &self,
        account: &AccountId,
        verifier: Option<&[u8]>,
    ) -> Result<(), RegistryError> {
        let sql = if verifier.is_some() {
            "UPDATE account:[$a] SET pin = $v, pin_tries = 0, pin_lock = NONE RETURN NONE;"
        } else {
            "UPDATE account:[$a] SET pin = NONE, pin_tries = NONE, pin_lock = NONE RETURN NONE;"
        };
        self.db
            .query(
                sql,
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("v", bytes(verifier.unwrap_or_default())),
                ],
            )
            .await?;
        Ok(())
    }

    /// Spends one PIN attempt **before** it is checked (so parallel guesses cannot exceed the
    /// limit), returning the verifier. The first `free` attempts are unthrottled; attempt
    /// `free + k` locks further ones for `base · 2^(k-1)` (at most a week); after `max`
    /// attempts the PIN is unusable until the primary sets a new one. A correct PIN resets the
    /// count ([`Registry::pin_ok`]).
    ///
    /// # Errors
    /// [`RegistryError`]; the refusal as `Ok(Err(..))`.
    pub async fn spend_pin_attempt(
        &self,
        account: &AccountId,
        free: u32,
        base: Duration,
        max: u32,
    ) -> Result<Result<Vec<u8>, PinRefusal>, RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $acc = (SELECT pin, pin_tries, pin_lock FROM ONLY account:[$a]);
             IF $acc = NONE OR $acc.pin = NONE { THROW 'songbird:nopin' };
             IF ($acc.pin_tries ?? 0) >= $max { THROW 'songbird:dead' };
             IF $acc.pin_lock != NONE AND $acc.pin_lock > time::now() { THROW 'songbird:locked' };
             LET $t = ($acc.pin_tries ?? 0) + 1;
             LET $wait = IF $t > $free {
               <int> math::min([$base * math::pow(2, $t - $free - 1), 604800])
             } ELSE { 0 };
             UPDATE account:[$a] SET pin_tries = $t,
               pin_lock = IF $wait > 0 { time::now() + duration::from_secs($wait) } ELSE { NONE }
               RETURN NONE;
             RETURN $acc.pin;
             COMMIT TRANSACTION;";
        let r = self
            .retry(
                sql,
                || {
                    vec![
                        var("a", bytes(account.as_bytes())),
                        var("free", int(u64::from(free))),
                        var("base", int(base.as_secs())),
                        var("max", int(u64::from(max))),
                    ]
                },
                |_| None,
                |v| {
                    Ok(v.into_iter()
                        .rev()
                        .find_map(|x| x.as_bytes().map(|b| b.to_vec())))
                },
            )
            .await;
        match r {
            Ok(Some(v)) => Ok(Ok(v)),
            Ok(None) => Err(RegistryError::Shape),
            Err(RegistryError::Db(DbError::Statement(k))) => match k.as_str() {
                "Thrown:nopin" => Ok(Err(PinRefusal::NoPin)),
                "Thrown:dead" => Ok(Err(PinRefusal::Locked(None))),
                "Thrown:locked" => {
                    let left = self.pin_lock_secs(account).await?;
                    Ok(Err(PinRefusal::Locked(Some(left.max(1)))))
                }
                _ => Err(RegistryError::Db(DbError::Statement(k))),
            },
            Err(e) => Err(e),
        }
    }

    async fn pin_lock_secs(&self, account: &AccountId) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN IF account:[$a].pin_lock > time::now()
                   { duration::secs(account:[$a].pin_lock - time::now()) } ELSE { 0 };",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(crate::first_int(&v)
            .and_then(|s| u64::try_from(s).ok())
            .unwrap_or(1))
    }

    /// A correct PIN: attempts and lock cleared.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn pin_ok(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPDATE account:[$a] SET pin_tries = 0, pin_lock = NONE RETURN NONE;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(())
    }

    /// The account's second factors.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn factors(&self, account: &AccountId) -> Result<Factors, RegistryError> {
        let v = self
            .db
            .query(
                "RETURN account:[$a].pin != NONE;
                 RETURN account:[$a].pin_tries ?? 0;
                 RETURN IF account:[$a].pin_lock > time::now() { true } ELSE { false };
                 SELECT VALUE cid FROM passkey WHERE account = $a ORDER BY at;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let b = |i: usize| matches!(v.get(i), Some(Value::Bool(true)));
        let tries = v.get(1).and_then(crate::first_int).unwrap_or(0);
        let passkeys = v
            .get(3)
            .cloned()
            .map(rows)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|x| x.as_bytes().map(|b| b.to_vec()))
            .collect();
        let locked = if b(2) {
            Some(self.pin_lock_secs(account).await?.max(1))
        } else {
            None
        };
        Ok(Factors {
            pin: b(0),
            pin_locked: locked,
            pin_tries: u32::try_from(tries).unwrap_or(u32::MAX),
            passkeys,
        })
    }

    /// Registers a passkey, at most `max` per account.
    ///
    /// # Errors
    /// [`RegistryError::Full`], [`RegistryError::Duplicate`].
    pub async fn add_passkey(
        &self,
        account: &AccountId,
        p: &StoredPasskey,
        max: u32,
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             UPDATE account:[$a] SET dgen = (dgen ?? 0) + 1 RETURN NONE;
             IF count(SELECT id FROM passkey WHERE account = $a) >= $max { THROW 'songbird:full' };
             CREATE passkey:[$a, $h] SET account = $a, cid = $cid, key = $k, count = $n,
               at = time::now() RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("h", bytes(&passkey_key(&p.id))),
                    var("cid", bytes(&p.id)),
                    var("k", bytes(&p.key)),
                    var("n", int(u64::from(p.count))),
                    var("max", int(u64::from(max))),
                ]
            },
            |k| match k {
                "Thrown:full" => Some(RegistryError::Full),
                k if k.contains("AlreadyExists") => Some(RegistryError::Duplicate),
                _ => None,
            },
            |_| Ok(()),
        )
        .await
    }

    /// One of the account's passkeys.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn passkey(
        &self,
        account: &AccountId,
        id: &[u8],
    ) -> Result<Option<StoredPasskey>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT cid, key, count FROM ONLY passkey:[$a, $h];",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("h", bytes(&passkey_key(id))),
                ],
            )
            .await?;
        let (Some(cid), Some(key), Some(n)) = (
            v.get("cid").and_then(|b| b.as_bytes()),
            v.get("key").and_then(|b| b.as_bytes()),
            v.get("count").and_then(Value::as_i64),
        ) else {
            return Ok(None);
        };
        Ok(Some(StoredPasskey {
            id: cid.to_vec(),
            key: key.to_vec(),
            count: u32::try_from(n).unwrap_or(u32::MAX),
        }))
    }

    /// Moves a passkey's counter from `old` to `new`; false if another assertion moved it first
    /// (so one assertion is accepted once).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn bump_passkey(
        &self,
        account: &AccountId,
        id: &[u8],
        old: u32,
        new: u32,
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "UPDATE passkey:[$a, $h] SET count = $new WHERE count = $old RETURN AFTER;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("h", bytes(&passkey_key(id))),
                    var("old", int(u64::from(old))),
                    var("new", int(u64::from(new))),
                ],
            )
            .await?;
        Ok(!rows(v).is_empty())
    }

    /// Removes one of the account's passkeys.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_passkey(
        &self,
        account: &AccountId,
        id: &[u8],
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE passkey:[$a, $h] RETURN NONE;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("h", bytes(&passkey_key(id))),
                ],
            )
            .await?;
        Ok(())
    }
}
