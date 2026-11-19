//! Standings (Prompt 11, M5; `docs/PROTOCOL.md` §14.7; D-0126 §7–§8, D-0131).
//!
//! An account in good standing has no row. A **limited** account (set automatically from
//! metadata-only signals, lifting by itself after a quiet week) gets tighter budgets for new
//! conversations; a **suspended** account (set only by a moderator) cannot send or call but
//! still receives, exports, deletes and appeals. Every change bumps `entver:v`, so the services
//! that enforce standings reload them with the entitlements snapshot.
//!
//! Signals are counted under **keyed tags** of accounts (never an ID): verified reports of the
//! account's distinct messages per day (`rsig`), blocks it received per day (`bsig`). The
//! thresholds are evaluated at the moment a signal arrives, by the service that knows the
//! account then.

use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::{Registry, RegistryError, bytes, first_int, id16, int, rows, var};

/// A standing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingRow {
    /// The account.
    pub account: AccountId,
    /// `limited` or `suspended`.
    pub kind: String,
    /// The last UTC day it holds (`None`: until a moderator lifts it).
    pub until: Option<u32>,
    /// A reason category (`reports`, `blocks`, `spam`, `abuse`, …): never free text.
    pub reason: String,
    /// `auto` or `moderator`.
    pub source: String,
}

fn standing_row(v: &Value) -> Option<StandingRow> {
    let t = |k: &str| v.get(k).and_then(Value::as_text).map(str::to_owned);
    Some(StandingRow {
        account: AccountId::from_bytes(id16(v.get("a")?)?),
        kind: t("kind")?,
        until: v
            .get("until")
            .and_then(Value::as_i64)
            .and_then(|n| u32::try_from(n).ok()),
        reason: t("reason")?,
        source: t("source")?,
    })
}

impl Registry {
    /// Sets an account's standing. A `limited` from `auto` never overrides a moderator's row,
    /// and never shortens one; a moderator's row replaces whatever was there.
    ///
    /// # Errors
    /// [`RegistryError::NotFound`] for no such account.
    pub async fn set_standing(
        &self,
        account: &AccountId,
        kind: &str,
        until: Option<u32>,
        reason: &str,
        source: &str,
    ) -> Result<(), RegistryError> {
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) { THROW 'songbird:none' };
                 LET $h = (SELECT kind, until, source FROM ONLY standing:[$a]);
                 LET $keep = $src = 'auto' AND $h != NONE AND ($h.source = 'moderator'
                   OR $h.until = NONE OR ($u != NONE AND $h.until >= $u));
                 IF !$keep {
                   UPSERT standing:[$a] SET kind = $k, until = $u, reason = $r, source = $src,
                     at = time::now() RETURN NONE;
                   UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE;
                 };
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("k", Value::Text(kind.to_owned())),
                    var("u", until.map_or(Value::none(), |d| int(u64::from(d)))),
                    var("r", Value::Text(reason.to_owned())),
                    var("src", Value::Text(source.to_owned())),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(crate::DbError::Statement(k)) if k == "Thrown:none" => Err(RegistryError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Lifts an account's standing (a moderator, after an appeal). Idempotent.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn lift_standing(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 IF record::exists(standing:[$a]) {
                   DELETE standing:[$a] RETURN NONE;
                   UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE;
                 };
                 COMMIT TRANSACTION;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(())
    }

    /// Every standing still held on `today`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn standings(&self, today: u32) -> Result<Vec<StandingRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, kind, until, reason, source FROM standing
                   WHERE until = NONE OR until >= $t;",
                vec![var("t", int(u64::from(today)))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| standing_row(r).ok_or(RegistryError::Shape))
            .collect()
    }

    /// One account's standing row, held or not.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn standing_of(
        &self,
        account: &AccountId,
    ) -> Result<Option<StandingRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, kind, until, reason, source FROM standing:[$a];",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(rows(v).first().and_then(standing_row))
    }

    /// The UTC day an account was created (`None`: no such account).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn account_created_day(
        &self,
        account: &AccountId,
    ) -> Result<Option<u32>, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN math::floor(time::unix(account:[$a].at) / 86400);",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(first_int(&v).and_then(|d| u32::try_from(d).ok()))
    }

    /// Counts one signal (`rsig`: a distinct reported message; `bsig`: a block received) for the
    /// keyed tag of an account on `day`, kept 31 days; returns the sum over the last `window`
    /// days.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn count_signal(
        &self,
        table: Signal,
        tag: &[u8; 16],
        day: u32,
        window: u32,
    ) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query(
                &format!(
                    "BEGIN TRANSACTION;
                     UPSERT {t}:[$g, $d] SET tag = $g, day = $d, n = (n ?? 0) + 1, until = $u
                       RETURN NONE;
                     RETURN math::sum(SELECT VALUE n FROM {t} WHERE tag = $g AND day >= $from);
                     COMMIT TRANSACTION;",
                    t = table.name()
                ),
                vec![
                    var("g", bytes(tag)),
                    var("d", int(u64::from(day))),
                    var(
                        "from",
                        int(u64::from(day.saturating_sub(window.saturating_sub(1)))),
                    ),
                    var("u", int(u64::from(day) + 31)),
                ],
            )
            .await?;
        Ok(v.iter()
            .rev()
            .find_map(first_int)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0))
    }

    /// Deletes signal counts past their day and standings past theirs.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn sweep_signals(&self, today: u32) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE rsig WHERE until < $t RETURN NONE;
                 DELETE bsig WHERE until < $t RETURN NONE;
                 LET $gone = (DELETE standing WHERE until != NONE AND until < $t RETURN BEFORE);
                 IF count($gone) > 0 { UPSERT entver:v SET version = (version ?? 1) + 1 RETURN NONE; };",
                vec![var("t", int(u64::from(today)))],
            )
            .await?;
        Ok(())
    }
}

/// A signal's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// A distinct message of the account reported and verified.
    Report,
    /// A block of the account.
    Block,
}

impl Signal {
    const fn name(self) -> &'static str {
        match self {
            Self::Report => "rsig",
            Self::Block => "bsig",
        }
    }
}
