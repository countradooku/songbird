//! Entitlements (Prompt 11, M1; `docs/PROTOCOL.md` §12; D-0127).
//!
//! **What the server keeps:** per account that is not on the default plan, one row `ent:[account]`
//! with its level, the last day (UTC, days since the Unix epoch) it holds and where it came from
//! (`grant` by an operator, `token` from an anonymous redemption, later `org`). Nothing about a
//! payment: payments live in billing's own database and share no identifier with this one
//! (D-0126 §2). Every change bumps `entver:v`, which every service polls to reload its snapshot.
//!
//! Redeemed tokens leave only their **nullifier** (`tnull:[hash]`, a SHA-256 the token's nonce
//! went into) until the token could no longer be redeemed: no account, no time. Redemption and
//! the entitlement it buys are one transaction, so a token is never spent without its effect.
//!
//! A row past its last day is ignored by every reader (they compare with the clock) and deleted
//! by the worker's sweep, so a stopped worker can never extend an entitlement.

use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::DbError;
use crate::{Registry, RegistryError, bytes, first_int, id16, int, rows, var};

/// Where an entitlement came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// An operator's grant (`songbird-admin plans grant`: staff, testers, goodwill).
    Grant,
    /// An anonymous token redeemed by the account (D-0126 §2).
    Token,
}

impl Source {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Token => "token",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "grant" => Some(Self::Grant),
            "token" => Some(Self::Token),
            _ => None,
        }
    }
}

/// One account's entitlement row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntRow {
    /// The account.
    pub account: AccountId,
    /// The level (0 is the default plan and never stored).
    pub level: u8,
    /// The last day it holds (UTC days since the Unix epoch, inclusive).
    pub last_day: u32,
    /// Where it came from.
    pub source: Source,
}

fn ent_row(v: &Value) -> Option<EntRow> {
    let account = AccountId::from_bytes(id16(v.get("a")?)?);
    let level = u8::try_from(v.get("level")?.as_i64()?).ok()?;
    let last_day = u32::try_from(v.get("last")?.as_i64()?).ok()?;
    let source = Source::parse(v.get("source")?.as_text()?)?;
    (level > 0).then_some(EntRow {
        account,
        level,
        last_day,
        source,
    })
}

impl Registry {
    /// The entitlements version: bumped by every change to `ent`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn entitlements_version(&self) -> Result<i64, RegistryError> {
        let v = self
            .db
            .query1("SELECT VALUE version FROM ONLY entver:v;", Vec::new())
            .await?;
        first_int(&v).ok_or(RegistryError::Shape)
    }

    /// Every entitlement still held on `today` (UTC days since the epoch).
    ///
    /// # Errors
    /// [`RegistryError`]; a malformed row as [`RegistryError::Shape`].
    pub async fn entitlements(&self, today: u32) -> Result<Vec<EntRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, level, last, source FROM ent WHERE last >= $t;",
                vec![var("t", int(u64::from(today)))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| ent_row(r).ok_or(RegistryError::Shape))
            .collect()
    }

    /// One account's entitlement row, held or not (export, `songbird-admin plans show`).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn entitlement_of(
        &self,
        account: &AccountId,
    ) -> Result<Option<EntRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, level, last, source FROM ent:[$a];",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(rows(v).first().and_then(ent_row))
    }

    /// Sets an account's entitlement exactly (an operator's grant, or its correction). The
    /// account must exist and not be deleting.
    ///
    /// # Errors
    /// [`RegistryError::NotFound`] for no such account; [`RegistryError::Shape`] for level 0
    /// (revoke instead).
    pub async fn set_entitlement(
        &self,
        account: &AccountId,
        level: u8,
        last_day: u32,
        source: Source,
    ) -> Result<(), RegistryError> {
        if level == 0 {
            return Err(RegistryError::Shape);
        }
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) OR account:[$a].deleting { THROW 'songbird:none' };
                 UPSERT ent:[$a] SET level = $l, last = $d, source = $s, at = time::now() RETURN NONE;
                 UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("l", int(u64::from(level))),
                    var("d", int(u64::from(last_day))),
                    var("s", Value::Text(source.as_str().to_owned())),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k == "Thrown:none" => Err(RegistryError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Extends an account's entitlement (a redeemed token): the level becomes the higher of the
    /// two, the last day the later, unless the held row has already lapsed (`last < today`), in
    /// which case the new one replaces it. Returns the row as stored.
    ///
    /// # Errors
    /// As [`Registry::set_entitlement`].
    pub async fn extend_entitlement(
        &self,
        account: &AccountId,
        level: u8,
        last_day: u32,
        today: u32,
        source: Source,
    ) -> Result<EntRow, RegistryError> {
        if level == 0 {
            return Err(RegistryError::Shape);
        }
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) OR account:[$a].deleting { THROW 'songbird:none' };
                 LET $h = (SELECT level, last FROM ONLY ent:[$a]);
                 LET $live = $h != NONE AND $h.last >= $t;
                 LET $nl = IF $live { math::max([$h.level, $l]) } ELSE { $l };
                 LET $nd = IF $live { math::max([$h.last, $d]) } ELSE { $d };
                 UPSERT ent:[$a] SET level = $nl, last = $nd, source = $s, at = time::now() RETURN NONE;
                 UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE;
                 RETURN { a: $ab, level: $nl, last: $nd, source: $s };
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("ab", bytes(account.as_bytes())),
                    var("l", int(u64::from(level))),
                    var("d", int(u64::from(last_day))),
                    var("t", int(u64::from(today))),
                    var("s", Value::Text(source.as_str().to_owned())),
                ],
            )
            .await;
        match r {
            Ok(v) => v
                .into_iter()
                .rev()
                .find_map(|x| ent_row(&x))
                .ok_or(RegistryError::Shape),
            Err(DbError::Statement(k)) if k == "Thrown:none" => Err(RegistryError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes an account's entitlement (back to the default plan). Idempotent.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn revoke_entitlement(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 IF record::exists(ent:[$a]) {
                   DELETE ent:[$a] RETURN NONE;
                   UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE;
                 };
                 COMMIT TRANSACTION;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(())
    }

    /// Deletes rows past their last day (the worker's sweep); returns how many. Readers already
    /// ignore them: this only keeps the table and the snapshot small.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn sweep_entitlements(&self, today: u32) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 LET $gone = (DELETE ent WHERE last < $t RETURN BEFORE);
                 IF count($gone) > 0 { UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE; };
                 RETURN count($gone);
                 COMMIT TRANSACTION;",
                vec![var("t", int(u64::from(today)))],
            )
            .await?;
        Ok(v.iter()
            .rev()
            .find_map(first_int)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0))
    }

    /// Redeems a plan token: burns its nullifier (kept through `keep_until`, a UTC day) and
    /// extends the account's entitlement as [`Registry::extend_entitlement`], in one transaction.
    ///
    /// # Errors
    /// [`RegistryError::Spent`] for a nullifier already held (nothing changes);
    /// [`RegistryError::NotFound`] for no such account.
    #[allow(
        clippy::too_many_arguments,
        reason = "the token's nullifier and life, and the entitlement it buys"
    )]
    pub async fn redeem_plan_token(
        &self,
        nullifier: &[u8; 32],
        keep_until: u32,
        account: &AccountId,
        level: u8,
        last_day: u32,
        today: u32,
    ) -> Result<EntRow, RegistryError> {
        if level == 0 {
            return Err(RegistryError::Shape);
        }
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) OR account:[$a].deleting { THROW 'songbird:none' };
                 IF record::exists(tnull:[$n]) { THROW 'songbird:spent' };
                 CREATE tnull:[$n] SET until = $u RETURN NONE;
                 LET $h = (SELECT level, last FROM ONLY ent:[$a]);
                 LET $live = $h != NONE AND $h.last >= $t;
                 LET $nl = IF $live { math::max([$h.level, $l]) } ELSE { $l };
                 LET $nd = IF $live { math::max([$h.last, $d]) } ELSE { $d };
                 UPSERT ent:[$a] SET level = $nl, last = $nd, source = 'token', at = time::now()
                   RETURN NONE;
                 UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE;
                 RETURN { a: $ab, level: $nl, last: $nd, source: 'token' };
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("ab", bytes(account.as_bytes())),
                    var("n", bytes(nullifier)),
                    var("u", int(u64::from(keep_until))),
                    var("l", int(u64::from(level))),
                    var("d", int(u64::from(last_day))),
                    var("t", int(u64::from(today))),
                ],
            )
            .await;
        match r {
            Ok(v) => v
                .into_iter()
                .rev()
                .find_map(|x| ent_row(&x))
                .ok_or(RegistryError::Shape),
            Err(DbError::Statement(k)) if k == "Thrown:none" => Err(RegistryError::NotFound),
            Err(DbError::Statement(k)) if k == "Thrown:spent" => Err(RegistryError::Spent),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether a nullifier is held (tests, and the vault's token sessions in M4).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn nullifier_held(&self, nullifier: &[u8; 32]) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN record::exists(tnull:[$n]);",
                vec![var("n", bytes(nullifier))],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
    }

    /// Deletes nullifiers past their day (the worker's sweep); returns how many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn sweep_nullifiers(&self, today: u32) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query(
                "RETURN count((DELETE tnull WHERE until < $t RETURN BEFORE));",
                vec![var("t", int(u64::from(today)))],
            )
            .await?;
        Ok(v.iter()
            .rev()
            .find_map(first_int)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0))
    }
}
