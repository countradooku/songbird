//! Account recovery and the hand-over to a new phone (Prompt 10, M4, D-0123; `docs/PROTOCOL.md`
//! §4.9).
//!
//! A **recovery token** is drawn for an account by anyone (the request is unsigned); a
//! **hand-over token** only by the account's enabled primary. Both are `ltoken` rows with a
//! `kind`, so a link (§4.6) never accepts them and a recovery never accepts a link token. Using
//! one, in one transaction: the token is consumed, every enabled device of the account is
//! disabled (and marked for removal from its groups), the new device is created as the enabled
//! primary, other outstanding tokens are dropped, and a `DeleteDevices` job goes to the outbox.
//! The caller has already checked the account identity key's signature and, for a recovery
//! token, the PIN or passkey.

use std::time::Duration;

use songbird_jobs::Job;
use songbird_types::{AccountId, DeviceId};

use crate::{Registry, RegistryError, bytes, id16, int, var};

/// What a recovery-kind token allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Drawn without a device: needs the account's second factor if it has one.
    Recovery,
    /// Drawn by the enabled primary for its own replacement: needs no second factor.
    Handover,
}

impl TokenKind {
    const fn code(self) -> u64 {
        match self {
            Self::Recovery => 1,
            Self::Handover => 2,
        }
    }
}

impl Registry {
    /// The account's identity key (Ed25519), if the account exists and is not being deleted.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn account_identity(
        &self,
        account: &AccountId,
    ) -> Result<Option<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE identity FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(v.as_bytes()
            .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok()))
    }

    /// Draws a recovery token (`issuer`: `None`) or a hand-over token (`issuer`: the enabled
    /// primary) for `account`, reserving `device`, until `ttl`.
    ///
    /// # Errors
    /// [`RegistryError::NotFound`] (no such account, or being deleted), [`RegistryError::NotPrimary`]
    /// (a hand-over not drawn by the primary), [`RegistryError::Exists`] (draw another device ID).
    pub async fn create_recovery_token(
        &self,
        account: &AccountId,
        issuer: Option<&DeviceId>,
        token_hash: &[u8; 32],
        device: &DeviceId,
        ttl: Duration,
    ) -> Result<(), RegistryError> {
        let kind = if issuer.is_some() {
            TokenKind::Handover
        } else {
            TokenKind::Recovery
        };
        let sql = "BEGIN TRANSACTION;
             IF account:[$a].deleting != false { THROW 'songbird:gone' };
             IF $p != NONE {
               LET $row = (SELECT account, disabled, prim FROM ONLY device:[$p]);
               IF $row = NONE OR $row.disabled OR $row.prim != true OR $row.account != $a
                 { THROW 'songbird:primary' };
             };
             IF record::exists(device:[$d]) OR
               count(SELECT id FROM ltoken WHERE device = $d) > 0 { THROW 'songbird:exists' };
             CREATE ltoken:[$t] SET account = $a, device = $d, kind = $kind,
               expires = time::now() + duration::from_secs($ttl) RETURN NONE;
             COMMIT TRANSACTION;";
        let issuer = issuer.map(|p| bytes(p.as_bytes()));
        self.retry(
            sql,
            || {
                vec![
                    var("a", bytes(account.as_bytes())),
                    var(
                        "p",
                        issuer.clone().unwrap_or_else(songbird_surreal::Value::none),
                    ),
                    var("t", bytes(token_hash)),
                    var("d", bytes(device.as_bytes())),
                    var("kind", int(kind.code())),
                    var("ttl", int(ttl.as_secs())),
                ]
            },
            |k| match k {
                "Thrown:gone" => Some(RegistryError::NotFound),
                "Thrown:primary" => Some(RegistryError::NotPrimary),
                "Thrown:exists" => Some(RegistryError::Exists),
                k if k.contains("AlreadyExists") => Some(RegistryError::Exists),
                _ => None,
            },
            |_| Ok(()),
        )
        .await
    }

    /// The account and kind of an unexpired recovery or hand-over token (not consumed).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn recovery_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<(AccountId, TokenKind)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT account, kind FROM ONLY ltoken:[$t] WHERE expires > time::now()
                   AND kind != NONE;",
                vec![var("t", bytes(token_hash))],
            )
            .await?;
        let Some(account) = v.get("account").and_then(id16).map(AccountId::from_bytes) else {
            return Ok(None);
        };
        let kind = match v.get("kind").and_then(songbird_surreal::Value::as_i64) {
            Some(1) => TokenKind::Recovery,
            Some(2) => TokenKind::Handover,
            _ => return Ok(None),
        };
        Ok(Some((account, kind)))
    }

    /// Recovers the account onto a new primary (see the module documentation). Returns the
    /// account and the devices it disabled.
    ///
    /// # Errors
    /// [`RegistryError::LinkToken`] (one answer for unknown, used, expired, another device or
    /// another account).
    pub async fn recover_account(
        &self,
        token_hash: &[u8; 32],
        account: &AccountId,
        device: &DeviceId,
        auth_key: &[u8; 32],
        identity: &[u8; 33],
        job: &Job,
    ) -> Result<Vec<DeviceId>, RegistryError> {
        let sql = concat!(
            "BEGIN TRANSACTION;
             LET $tok = (DELETE ONLY ltoken:[$t] RETURN BEFORE);
             IF $tok = NONE OR $tok.expires <= time::now() OR $tok.device != $d
               OR $tok.account != $a OR $tok.kind = NONE { THROW 'songbird:token' };
             IF account:[$a].deleting != false { THROW 'songbird:token' };
             UPDATE account:[$a] SET dgen = (dgen ?? 0) + 1 RETURN NONE;
             LET $gone = (SELECT VALUE meta::id(id)[0] FROM device
               WHERE account = $a AND disabled = false);
             UPDATE device SET disabled = true, prim = false, pending = NONE, lconf = NONE
               WHERE account = $a AND disabled = false RETURN NONE;",
            mark_prune!(),
            "DELETE ltoken WHERE account = $a RETURN NONE;
             CREATE device:[$d] SET account = $a, key = $k, ik = $ik, prim = true,
               disabled = false, at = time::now() RETURN NONE;
             UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;
             UPDATE directory:v SET version += 1 RETURN NONE;
             RETURN $gone;
             COMMIT TRANSACTION;"
        );
        self.retry(
            sql,
            || {
                vec![
                    var("t", bytes(token_hash)),
                    var("a", bytes(account.as_bytes())),
                    var("d", bytes(device.as_bytes())),
                    var("k", bytes(auth_key)),
                    var("ik", bytes(identity)),
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ]
            },
            |k| match k {
                "Thrown:token" => Some(RegistryError::LinkToken),
                k if k.contains("AlreadyExists") => Some(RegistryError::LinkToken),
                _ => None,
            },
            |v| {
                let arr = v
                    .into_iter()
                    .rev()
                    .find_map(|x| match x {
                        songbird_surreal::Value::Array(a)
                            if a.iter().all(|i| id16(i).is_some()) =>
                        {
                            Some(a)
                        }
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
        .await
    }
}
