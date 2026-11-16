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

/// What a validated commit writes (`Registry::commit_group`).
#[derive(Debug, Clone, Copy)]
pub struct GroupCommit<'a> {
    /// The new state (`songbird_groups::Record`).
    pub state: &'a [u8],
    /// The new roster (format 2, with roles).
    pub roster: &'a [u8],
    /// SHA-256 of the commit message.
    pub last: &'a [u8; 32],
    /// Its fan-out plan.
    pub fanout: &'a [u8],
    /// Its change-log entry, if any.
    pub log: Option<&'a [u8]>,
}

/// A group as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub epoch: u64,
    /// Bumped by every write of `state` (commits and queued proposals), so two writers of one
    /// epoch cannot overwrite each other.
    pub rev: u64,
    pub state: bytes::Bytes,
    pub roster: bytes::Bytes,
    pub last: bytes::Bytes,
    /// The encrypted group metadata (name, description, avatar pointer, settings; D-0070) and
    /// its version; the server never reads it.
    pub meta: bytes::Bytes,
    pub meta_v: u64,
}

/// Change-log entries kept per group (the newest).
pub const MAX_LOG_ENTRIES: u64 = 1_000;
/// Longest encrypted metadata.
pub const MAX_META: usize = 16 * 1024;

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
        let sql = "CREATE grp:[$g] SET epoch = 0, rev = 0, state = $s, roster = $r, last = $z,
                   meta = $z, meta_v = 0 RETURN NONE;";
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
                "SELECT epoch, rev, state, roster, last, meta, meta_v FROM ONLY grp:[$g];",
                vec![var("g", bytes(group))],
            )
            .await?;
        if matches!(v, Value::Null) {
            return Ok(None);
        }
        let (
            Some(epoch),
            Some(rev),
            Some(state),
            Some(roster),
            Some(last),
            Some(meta),
            Some(meta_v),
        ) = (
            v.get("epoch").and_then(u64_of),
            v.get("rev").and_then(u64_of),
            bytes_of(&v, "state"),
            bytes_of(&v, "roster"),
            bytes_of(&v, "last"),
            bytes_of(&v, "meta"),
            v.get("meta_v").and_then(u64_of),
        )
        else {
            return Ok(None);
        };
        Ok(Some(GroupRow {
            epoch,
            rev,
            state,
            roster,
            last,
            meta,
            meta_v,
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
        commit: &GroupCommit<'_>,
    ) -> Result<(), RegistryError> {
        // The change log keeps the newest `MAX_LOG_ENTRIES`: each entry written drops the one
        // that many epochs older.
        let sql = "BEGIN TRANSACTION;
             IF ((SELECT VALUE epoch FROM ONLY grp:[$g]) ?? -1) != $e { THROW 'songbird:stale' };
             UPDATE grp:[$g] SET epoch = $e + 1, rev += 1, state = $s, roster = $r, last = $l
               RETURN NONE;
             UPSERT grp_fanout:[$g, $e] SET body = $f, at = time::now() RETURN NONE;
             IF $has_log {
               UPSERT grp_log:[$g, $e] SET entry = $log, at = time::now() RETURN NONE;
               IF $e >= $keep { DELETE grp_log:[$g, $e - $keep] };
             };
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("e", int(from_epoch)),
                    var("s", bytes(commit.state)),
                    var("r", bytes(commit.roster)),
                    var("l", bytes(commit.last)),
                    var("f", bytes(commit.fanout)),
                    var("has_log", Value::Bool(commit.log.is_some())),
                    var("log", bytes(commit.log.unwrap_or_default())),
                    var("keep", int(MAX_LOG_ENTRIES)),
                ]
            },
            |k| (k == "Thrown:stale").then_some(RegistryError::StaleEpoch),
            |_| Ok(()),
        )
        .await
    }

    /// Writes a group's state after a queued proposal (D-0070), only if the group is still at
    /// `epoch` and revision `rev` (no commit or other proposal came in between).
    ///
    /// # Errors
    /// [`RegistryError::StaleEpoch`] if either moved; [`RegistryError`] otherwise.
    pub async fn propose_group(
        &self,
        group: &[u8; 16],
        epoch: u64,
        rev: u64,
        state: &[u8],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $row = (SELECT epoch, rev FROM ONLY grp:[$g]);
             IF $row = NONE OR $row.epoch != $e OR $row.rev != $v { THROW 'songbird:stale' };
             UPDATE grp:[$g] SET rev += 1, state = $s RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("e", int(epoch)),
                    var("v", int(rev)),
                    var("s", bytes(state)),
                ]
            },
            |k| (k == "Thrown:stale").then_some(RegistryError::StaleEpoch),
            |_| Ok(()),
        )
        .await
    }

    /// Replaces the encrypted metadata if its version is still `expected` (the caller checked
    /// the role). Returns the new version.
    ///
    /// # Errors
    /// [`RegistryError::StaleEpoch`] if another write came first; [`RegistryError`] otherwise.
    pub async fn put_group_meta(
        &self,
        group: &[u8; 16],
        expected: u64,
        meta: &[u8],
    ) -> Result<u64, RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF ((SELECT VALUE meta_v FROM ONLY grp:[$g]) ?? -1) != $v { THROW 'songbird:stale' };
             UPDATE grp:[$g] SET meta = $m, meta_v = $v + 1 RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("v", int(expected)),
                    var("m", bytes(meta)),
                ]
            },
            |k| (k == "Thrown:stale").then_some(RegistryError::StaleEpoch),
            |_| Ok(()),
        )
        .await?;
        Ok(expected + 1)
    }

    /// Change-log entries after `after_epoch` (exclusive), oldest first, at most `limit`:
    /// `(the epoch its commit was made from, entry)`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_log(
        &self,
        group: &[u8; 16],
        after_epoch: Option<u64>,
        limit: u64,
    ) -> Result<Vec<(u64, bytes::Bytes)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[1] AS e, entry FROM grp_log
                   WHERE meta::id(id)[0] = $g AND meta::id(id)[1] > $a
                   ORDER BY e LIMIT $n;",
                vec![
                    var("g", bytes(group)),
                    var("a", after_epoch.map_or(Value::Int(-1), int)),
                    var("n", int(limit)),
                ],
            )
            .await?;
        rows(v)
            .into_iter()
            .map(|r| {
                let e = r.get("e").and_then(u64_of).ok_or(RegistryError::Shape)?;
                let entry = bytes_of(&r, "entry").ok_or(RegistryError::Shape)?;
                Ok((e, entry))
            })
            .collect()
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
