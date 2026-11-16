//! MLS groups in the registry (Prompt 5, M1; D-0066, D-0067).
//!
//! `grp:[group]` is the one authority for a group's epoch:
//! - `state`: the delivery service's record (`songbird_groups::Record`, postcard), opaque here;
//! - `roster`: the member devices, 16 bytes each, sorted (what the send path fans out to);
//! - `last`: SHA-256 of the commit that made the current epoch, so a retried commit is
//!   recognised.
//!
//! A commit replaces all three only if the stored epoch is the one the commit was made from,
//! in one transaction that also writes the commit's fan-out to `grp_fanout:[group, epoch]`. The
//! fan-out row is deleted once every recipient's mailbox has stored it; `api` re-drives rows a
//! crash left behind. So of several concurrent commits exactly one wins, and an accepted commit
//! always reaches every member.

use songbird_surreal::Value;

use crate::{Registry, RegistryError, bytes, int, rows, var};

/// A group as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub epoch: u64,
    pub state: bytes::Bytes,
    pub roster: bytes::Bytes,
    pub last: bytes::Bytes,
}

/// A fan-out left to deliver: `(group, from_epoch, encoded plan)`.
pub type Fanout = ([u8; 16], u64, bytes::Bytes);

fn u64_of(v: &Value) -> Option<u64> {
    v.as_i64().and_then(|n| u64::try_from(n).ok())
}

fn bytes_of(v: &Value, key: &str) -> Option<bytes::Bytes> {
    v.get(key).and_then(|b| b.as_bytes().cloned())
}

impl Registry {
    /// Records a new group at epoch 0.
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the group ID is taken; [`RegistryError`] otherwise.
    pub async fn create_group(
        &self,
        group: &[u8; 16],
        state: &[u8],
        roster: &[u8],
    ) -> Result<(), RegistryError> {
        let sql = "CREATE grp:[$g] SET epoch = 0, state = $s, roster = $r, last = $z RETURN NONE;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("s", bytes(state)),
                    var("r", bytes(roster)),
                    var("z", bytes(&[])),
                ]
            },
            |k| k.contains("AlreadyExists").then_some(RegistryError::Exists),
            |_| Ok(()),
        )
        .await
    }

    /// The whole stored group.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group(&self, group: &[u8; 16]) -> Result<Option<GroupRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT epoch, state, roster, last FROM ONLY grp:[$g];",
                vec![var("g", bytes(group))],
            )
            .await?;
        if matches!(v, Value::Null) {
            return Ok(None);
        }
        let (Some(epoch), Some(state), Some(roster), Some(last)) = (
            v.get("epoch").and_then(u64_of),
            bytes_of(&v, "state"),
            bytes_of(&v, "roster"),
            bytes_of(&v, "last"),
        ) else {
            return Ok(None);
        };
        Ok(Some(GroupRow {
            epoch,
            state,
            roster,
            last,
        }))
    }

    /// The epoch and roster only (the send path's view; never the state blob).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_roster(
        &self,
        group: &[u8; 16],
    ) -> Result<Option<(u64, bytes::Bytes)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT epoch, roster FROM ONLY grp:[$g];",
                vec![var("g", bytes(group))],
            )
            .await?;
        Ok(v.get("epoch").and_then(u64_of).zip(bytes_of(&v, "roster")))
    }

    /// Advances a group from `from_epoch` with a validated commit, and records its fan-out, in
    /// one transaction.
    ///
    /// # Errors
    /// [`RegistryError::StaleEpoch`] if the group is no longer at `from_epoch` (another commit
    /// won) or does not exist; [`RegistryError`] otherwise.
    pub async fn commit_group(
        &self,
        group: &[u8; 16],
        from_epoch: u64,
        state: &[u8],
        roster: &[u8],
        last: &[u8; 32],
        fanout: &[u8],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF ((SELECT VALUE epoch FROM ONLY grp:[$g]) ?? -1) != $e { THROW 'songbird:stale' };
             UPDATE grp:[$g] SET epoch = $e + 1, state = $s, roster = $r, last = $l RETURN NONE;
             UPSERT grp_fanout:[$g, $e] SET body = $f, at = time::now() RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("e", int(from_epoch)),
                    var("s", bytes(state)),
                    var("r", bytes(roster)),
                    var("l", bytes(last)),
                    var("f", bytes(fanout)),
                ]
            },
            |k| (k == "Thrown:stale").then_some(RegistryError::StaleEpoch),
            |_| Ok(()),
        )
        .await
    }

    /// The fan-out a commit from `from_epoch` recorded, if still pending.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_fanout(
        &self,
        group: &[u8; 16],
        from_epoch: u64,
    ) -> Result<Option<bytes::Bytes>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT body FROM ONLY grp_fanout:[$g, $e];",
                vec![var("g", bytes(group)), var("e", int(from_epoch))],
            )
            .await?;
        Ok(bytes_of(&v, "body"))
    }

    /// Forgets a fan-out every recipient has stored.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_fanout_done(
        &self,
        group: &[u8; 16],
        from_epoch: u64,
    ) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE grp_fanout:[$g, $e];",
                vec![var("g", bytes(group)), var("e", int(from_epoch))],
            )
            .await?;
        Ok(())
    }

    /// Fan-outs older than `age_secs` (a crash interrupted them), oldest first.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn stale_group_fanouts(
        &self,
        age_secs: u64,
        limit: u64,
    ) -> Result<Vec<Fanout>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id) AS k, body FROM grp_fanout
                   WHERE at < time::now() - duration::from_secs($d) ORDER BY at LIMIT $n;",
                vec![var("d", int(age_secs)), var("n", int(limit))],
            )
            .await?;
        let mut out = Vec::new();
        for row in rows(v) {
            let k = row
                .get("k")
                .and_then(Value::as_array)
                .ok_or(RegistryError::Shape)?;
            let group: [u8; 16] = k
                .first()
                .and_then(Value::as_bytes)
                .and_then(|b| b.as_ref().try_into().ok())
                .ok_or(RegistryError::Shape)?;
            let epoch = k.get(1).and_then(u64_of).ok_or(RegistryError::Shape)?;
            let body = bytes_of(&row, "body").ok_or(RegistryError::Shape)?;
            out.push((group, epoch, body));
        }
        Ok(out)
    }
}
