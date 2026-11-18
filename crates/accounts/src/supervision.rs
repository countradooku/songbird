//! Parental supervision (Prompt 9, M4, D-0105; PROTOCOL §10.6).
//!
//! The row `superv:[child]` holds the signed policy as sent (so the child's app can show and check
//! it), the parent's policy key for this child, its version and the day it ends. **No parent
//! account, device or birth date is stored**: the policy key is all the server knows of the
//! parent.
//!
//! The account row carries what the send path and the API enforce: `sv_requests`, `sv_hidden`,
//! `sv_groups` (the rules in force, which no device of the child may loosen) and `grp_approval`
//! (the policy key that signs group-add approvals). Applying a policy also sets the matching
//! settings (`requests_off`, `hidden`, `grp_contacts`); ending supervision lifts the locks and
//! leaves the settings as they are, for the child to change.

use bytes::Bytes;
use songbird_proto::supervision::{GROUP_APPROVAL, HIDDEN, NO_REQUESTS, Policy, UNLINK};
use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::{self, DbError};
use crate::{Registry, RegistryError, bytes, id16, int, rows, var};

/// A child's supervision as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supervision {
    /// The parent's policy key for this child.
    pub key: [u8; 32],
    /// The policy version.
    pub version: u64,
    /// The policy's flags.
    pub flags: u8,
    /// The signed policy, as sent.
    pub policy: Bytes,
}

impl Registry {
    /// A child's supervision, if any.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn supervision(
        &self,
        child: &AccountId,
    ) -> Result<Option<Supervision>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT pkey, pv, flags, policy FROM ONLY superv:[$a];",
                vec![var("a", bytes(child.as_bytes()))],
            )
            .await?;
        if v.is_absent() {
            return Ok(None);
        }
        let key = v
            .get("pkey")
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok())
            .ok_or(RegistryError::Shape)?;
        let int_of = |k: &str| {
            v.get(k)
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(RegistryError::Shape)
        };
        Ok(Some(Supervision {
            key,
            version: int_of("pv")?,
            flags: u8::try_from(int_of("flags")?).map_err(|_| RegistryError::Shape)?,
            policy: v
                .get("policy")
                .and_then(|b| b.as_bytes().cloned())
                .ok_or(RegistryError::Shape)?,
        }))
    }

    /// Stores a policy whose signature the caller verified: the first one (`first`: there must be
    /// none yet), or a newer one under the same key. An [`UNLINK`] policy ends supervision.
    ///
    /// # Errors
    /// [`RegistryError::Exists`] for a first policy when one is in force; [`RegistryError::Rollback`]
    /// for a version that does not grow or another key; [`RegistryError::Later`] for an update
    /// that moves the unlink date later (it may only come earlier: supervision never outlives the
    /// date set at linking, D-0108); [`RegistryError::NotFound`] for an update
    /// with none in force, or an account being deleted.
    pub async fn put_supervision(
        &self,
        policy: &Policy,
        raw: &[u8],
        first: bool,
    ) -> Result<(), RegistryError> {
        let unlink = policy.flags & UNLINK != 0;
        let has = |f: u8| Value::Bool(policy.flags & f != 0 && !unlink);
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF account:[$a].deleting != false { THROW 'songbird:gone' };
                 LET $cur = superv:[$a];
                 IF $first AND $cur.pkey != NONE { THROW 'songbird:exists' };
                 IF !$first AND $cur.pkey = NONE { THROW 'songbird:gone' };
                 IF !$first AND ($cur.pkey != $k OR $cur.pv >= $v) { THROW 'songbird:rollback' };
                 IF !$first AND !$unlink AND time::from_secs($until) > $cur.unlink_at {
                   THROW 'songbird:later' };
                 IF $unlink {
                   DELETE superv:[$a] RETURN NONE;
                 } ELSE {
                   UPSERT superv:[$a] SET pkey = $k, pv = $v, flags = $f, policy = $p,
                     unlink_at = time::from_secs($until) RETURN NONE;
                 };
                 UPDATE account:[$a] SET sv_requests = $req, sv_hidden = $hid, sv_groups = $grp,
                   grp_approval = IF $grp { $k } ELSE { NONE } RETURN NONE;
                 IF $req { UPDATE account:[$a] SET requests_off = true, uak_open = false
                   RETURN NONE; };
                 IF $hid { UPDATE account:[$a] SET hidden = true RETURN NONE; };
                 IF $grp { UPDATE account:[$a] SET grp_contacts = true RETURN NONE; };
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(policy.child.as_bytes())),
                    var("first", Value::Bool(first)),
                    var("k", bytes(&policy.policy_key)),
                    var("v", int(policy.policy_version)),
                    var("f", int(u64::from(policy.flags))),
                    var("p", bytes(raw)),
                    var("until", int(policy.unlink_at_s)),
                    var("unlink", Value::Bool(unlink)),
                    var("req", has(NO_REQUESTS)),
                    var("hid", has(HIDDEN)),
                    var("grp", has(GROUP_APPROVAL)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) => match k.as_str() {
                "Thrown:exists" => Err(RegistryError::Exists),
                "Thrown:rollback" => Err(RegistryError::Rollback),
                "Thrown:later" => Err(RegistryError::Later),
                "Thrown:gone" => Err(RegistryError::NotFound),
                k if k == db::TRANSACTION_CONFLICT => Err(RegistryError::Busy),
                _ => Err(DbError::Statement(k).into()),
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Children whose supervision ended by date (the worker unlinks them).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn supervisions_due(&self, limit: usize) -> Result<Vec<AccountId>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM superv WHERE unlink_at < time::now() LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        Ok(rows(v)
            .iter()
            .filter_map(id16)
            .map(AccountId::from_bytes)
            .collect())
    }

    /// Ends a child's supervision on its date: the row goes and the locks lift; the settings stay
    /// as they are, for the child to change.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn end_supervision(&self, child: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 DELETE superv:[$a] WHERE unlink_at < time::now() RETURN NONE;
                 IF superv:[$a].pkey = NONE {
                   UPDATE account:[$a] SET sv_requests = false, sv_hidden = false,
                     sv_groups = false, grp_approval = NONE RETURN NONE;
                 };
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![var("a", bytes(child.as_bytes()))],
            )
            .await?;
        Ok(())
    }
}
