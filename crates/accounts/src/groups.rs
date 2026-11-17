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
    /// The invite link a join by link spends (M3): checked and counted in the same transaction.
    pub link: Option<&'a [u8; 16]>,
    /// Accounts the commit added: their pending join requests are settled.
    pub joined: &'a [[u8; 16]],
    /// Devices still in the group that left the directory (D-0075): the group is marked so
    /// `api` proposes their removal again at the new epoch (proposals do not outlive one). The
    /// mark names only those whose device rows still exist: a deleted device's ID never comes
    /// back into a mark after its deletion stripped it (D-0078); the prune pass finds those
    /// through the directory.
    pub prune: &'a [[u8; 16]],
}

/// A group marked for server-proposed removals (D-0075): its ID, the mark's counter (to forget
/// it only if no later mark came) and the departed devices it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneMark {
    pub group: [u8; 16],
    pub n: u64,
    pub gone: Vec<songbird_types::DeviceId>,
}

/// An invite link (M3, D-0071).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLink {
    pub group: [u8; 16],
    /// SHA-256 of the link's secret (the secret itself never reaches the server's store).
    pub secret_hash: [u8; 32],
    /// Joining by this link needs an admin's approval.
    pub approval: bool,
    /// Still usable: not expired and not used up.
    pub usable: bool,
}

/// Most invite links per group.
pub const MAX_LINKS: u64 = 16;
/// Most pending join requests per group.
pub const MAX_REQUESTS: u64 = 256;
/// Pending join requests are dropped after this many days.
pub const REQUEST_DAYS: u64 = 7;

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

pub(crate) fn u64_of(v: &Value) -> Option<u64> {
    v.as_i64().and_then(|n| u64::try_from(n).ok())
}

pub(crate) fn bytes_of(v: &Value, key: &str) -> Option<bytes::Bytes> {
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
        let sql = "CREATE grp:[$g] SET epoch = 0, rev = 0, state = $s, roster = $r, devs = $d,
                   last = $z, meta = $z, meta_v = 0 RETURN NONE;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("s", bytes(state)),
                    var("r", bytes(roster)),
                    var("d", roster_devices(roster)),
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
             UPDATE grp:[$g] SET epoch = $e + 1, rev += 1, state = $s, roster = $r, devs = $d,
               last = $l
               RETURN NONE;
             UPSERT grp_fanout:[$g, $e] SET body = $f, at = time::now() RETURN NONE;
             IF $has_log {
               UPSERT grp_log:[$g, $e] SET grp = $g, entry = $log, at = time::now() RETURN NONE;
               IF $e >= $keep { DELETE grp_log:[$g, $e - $keep] };
             };
             IF $has_link {
               LET $k = (SELECT grp, max, uses, expires FROM ONLY grp_link:[$h]);
               IF $k = NONE OR $k.grp != $g OR ($k.max > 0 AND $k.uses >= $k.max)
                 OR ($k.expires != NONE AND $k.expires < time::now()) {
                 THROW 'songbird:link'
               };
               UPDATE grp_link:[$h] SET uses += 1 RETURN NONE;
             };
             FOR $a IN $joined { DELETE grp_req:[$g, $a] };
             IF array::len($prune) > 0 {
               UPSERT grp_prune:[$g] SET n = (n ?? 0) + 1, at = time::now(), gone = gone ?? []
                 RETURN NONE;
               FOR $pd IN $prune {
                 IF record::exists(device:[$pd]) {
                   UPDATE grp_prune:[$g] SET gone = array::union(gone, [$pd]) RETURN NONE;
                 };
               };
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
                    var("d", roster_devices(commit.roster)),
                    var("l", bytes(commit.last)),
                    var("f", bytes(commit.fanout)),
                    var("has_log", Value::Bool(commit.log.is_some())),
                    var("log", bytes(commit.log.unwrap_or_default())),
                    var("keep", int(MAX_LOG_ENTRIES)),
                    var("has_link", Value::Bool(commit.link.is_some())),
                    var("h", bytes(commit.link.map_or(&[][..], |h| &h[..]))),
                    var(
                        "joined",
                        Value::Array(commit.joined.iter().map(|a| bytes(a)).collect()),
                    ),
                    var(
                        "prune",
                        Value::Array(commit.prune.iter().map(|d| bytes(d)).collect()),
                    ),
                ]
            },
            |k| match k {
                "Thrown:stale" => Some(RegistryError::StaleEpoch),
                "Thrown:link" => Some(RegistryError::GroupLink),
                _ => None,
            },
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
                   WHERE grp = $g AND meta::id(id)[1] > $a
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

/// Server-proposed removals (D-0075): groups holding devices that left the directory.
impl Registry {
    /// Groups marked for pruning, oldest mark first, at most `limit`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn groups_to_prune(&self, limit: u64) -> Result<Vec<PruneMark>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS g, n, gone, at FROM grp_prune ORDER BY at LIMIT $n;",
                vec![var("n", int(limit))],
            )
            .await?;
        rows(v)
            .into_iter()
            .map(|r| {
                let group = r
                    .get("g")
                    .and_then(Value::as_bytes)
                    .and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok())
                    .ok_or(RegistryError::Shape)?;
                let n = r.get("n").and_then(u64_of).ok_or(RegistryError::Shape)?;
                let gone = r
                    .get("gone")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_bytes)
                            .filter_map(|b| songbird_types::DeviceId::from_slice(b).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(PruneMark { group, n, gone })
            })
            .collect()
    }

    /// Moves a mark that could not be handled to the back of the queue (unless a later mark
    /// came), so a group that keeps failing never holds up the others (D-0078).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_prune_later(&self, group: &[u8; 16], n: u64) -> Result<(), RegistryError> {
        self.db
            .exec(
                "UPDATE grp_prune:[$g] SET at = time::now() WHERE n = $n RETURN NONE;",
                vec![var("g", bytes(group)), var("n", int(n))],
            )
            .await?;
        Ok(())
    }

    /// Forgets a group's prune mark, unless a later mark came since it was read (`n` moved).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_pruned(&self, group: &[u8; 16], n: u64) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE grp_prune:[$g] WHERE n = $n;",
                vec![var("g", bytes(group)), var("n", int(n))],
            )
            .await?;
        Ok(())
    }
}

/// Invite links and join requests (Prompt 5, M3; D-0071).
impl Registry {
    /// Records an invite link under its random `handle`, first forgetting the group's spent and
    /// expired links. The caller checked the role.
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the handle is taken; [`RegistryError::Full`] at
    /// [`MAX_LINKS`] for the group; [`RegistryError`] otherwise.
    pub async fn create_group_link(
        &self,
        handle: &[u8; 16],
        group: &[u8; 16],
        secret_hash: &[u8; 32],
        expires_secs: Option<u64>,
        max_uses: u32,
        approval: bool,
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             DELETE grp_link WHERE grp = $g AND ((max > 0 AND uses >= max)
               OR (expires != NONE AND expires < time::now()));
             IF count((SELECT VALUE id FROM grp_link WHERE grp = $g)) >= $most {
               THROW 'songbird:full'
             };
             CREATE grp_link:[$h] SET grp = $g, sha = $sha, max = $max, uses = 0,
               approval = $appr,
               expires = IF $ttl > 0 { time::now() + duration::from_secs($ttl) } ELSE { NONE }
               RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("h", bytes(handle)),
                    var("g", bytes(group)),
                    var("sha", bytes(secret_hash)),
                    var("max", int(u64::from(max_uses))),
                    var("appr", Value::Bool(approval)),
                    var("ttl", int(expires_secs.unwrap_or(0))),
                    var("most", int(MAX_LINKS)),
                ]
            },
            |k| match k {
                "Thrown:full" => Some(RegistryError::Full),
                k if k.contains("AlreadyExists") => Some(RegistryError::Exists),
                _ => None,
            },
            |_| Ok(()),
        )
        .await
    }

    /// Revokes a link of `group` (nothing if it is another group's or gone).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn revoke_group_link(
        &self,
        group: &[u8; 16],
        handle: &[u8; 16],
    ) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE grp_link:[$h] WHERE grp = $g;",
                vec![var("h", bytes(handle)), var("g", bytes(group))],
            )
            .await?;
        Ok(())
    }

    /// A link by its handle.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_link(&self, handle: &[u8; 16]) -> Result<Option<GroupLink>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT grp, sha, approval,
                   (max = 0 OR uses < max) AND (expires = NONE OR expires > time::now()) AS usable
                 FROM ONLY grp_link:[$h];",
                vec![var("h", bytes(handle))],
            )
            .await?;
        if matches!(v, Value::Null) {
            return Ok(None);
        }
        let group = bytes_of(&v, "grp").and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok());
        let sha = bytes_of(&v, "sha").and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok());
        let (Some(group), Some(secret_hash)) = (group, sha) else {
            return Ok(None);
        };
        let flag = |k: &str| matches!(v.get(k), Some(Value::Bool(true)));
        Ok(Some(GroupLink {
            group,
            secret_hash,
            approval: flag("approval"),
            usable: flag("usable"),
        }))
    }

    /// Records `account`'s request to join `group` (idempotent: asking again keeps the first
    /// request's time, so it keeps its place and does not outlive [`REQUEST_DAYS`]).
    ///
    /// # Errors
    /// [`RegistryError::Full`] at [`MAX_REQUESTS`] pending; [`RegistryError`] otherwise.
    pub async fn add_group_request(
        &self,
        group: &[u8; 16],
        account: &[u8; 16],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             DELETE grp_req WHERE grp = $g
               AND at < time::now() - duration::from_days($days);
             IF !record::exists(grp_req:[$g, $a])
               AND count((SELECT VALUE id FROM grp_req WHERE grp = $g)) >= $most {
               THROW 'songbird:full'
             };
             IF !record::exists(grp_req:[$g, $a]) {
               CREATE grp_req:[$g, $a] SET grp = $g, acct = $a, at = time::now() RETURN NONE
             };
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("g", bytes(group)),
                    var("a", bytes(account)),
                    var("days", int(REQUEST_DAYS)),
                    var("most", int(MAX_REQUESTS)),
                ]
            },
            |k| (k == "Thrown:full").then_some(RegistryError::Full),
            |_| Ok(()),
        )
        .await
    }

    /// Pending join requests: `(account, seconds since the request)`, oldest first.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn group_requests(
        &self,
        group: &[u8; 16],
    ) -> Result<Vec<([u8; 16], u64)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[1] AS a, at, duration::secs(time::now() - at) AS age FROM grp_req
                   WHERE grp = $g AND at > time::now() - duration::from_days($days)
                   ORDER BY at LIMIT $most;",
                vec![
                    var("g", bytes(group)),
                    var("days", int(REQUEST_DAYS)),
                    var("most", int(MAX_REQUESTS)),
                ],
            )
            .await?;
        rows(v)
            .into_iter()
            .map(|r| {
                let a = r
                    .get("a")
                    .and_then(Value::as_bytes)
                    .and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok())
                    .ok_or(RegistryError::Shape)?;
                Ok((a, r.get("age").and_then(u64_of).unwrap_or(0)))
            })
            .collect()
    }

    /// Declines (forgets) a join request.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_group_request(
        &self,
        group: &[u8; 16],
        account: &[u8; 16],
    ) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE grp_req:[$g, $a];",
                vec![var("g", bytes(group)), var("a", bytes(account))],
            )
            .await?;
        Ok(())
    }
}

impl Registry {
    /// Forgets join requests older than [`REQUEST_DAYS`] and expired invite links, everywhere
    /// (a periodic sweep; both are also ignored when read).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn purge_group_invites(&self) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE grp_req WHERE at < time::now() - duration::from_days($days);
                 DELETE grp_link WHERE expires != NONE AND expires < time::now();",
                vec![var("days", int(REQUEST_DAYS))],
            )
            .await?;
        Ok(())
    }
}

/// The devices of a registry roster (format 2, `version 2 | policy [7] | n × (device [16] | role
/// u8)`, written by `songbird_groups`), as an indexed array: an account's groups are found by
/// its devices (GDPR export, D-0073). An unreadable roster names nobody.
fn roster_devices(roster: &[u8]) -> Value {
    let devices = roster
        .split_first()
        .filter(|(v, _)| **v == 2)
        .and_then(|(_, rest)| rest.get(7..))
        .map(|rest| {
            rest.as_chunks::<17>()
                .0
                .iter()
                .map(|c| bytes(&c[..16]))
                .collect()
        })
        .unwrap_or_default();
    Value::Array(devices)
}

impl Registry {
    /// Whether every `(device, KeyPackageRef)` names a package that device published: a
    /// single-use one claimed from the key directory (until it expires), or its last-resort
    /// one (D-0074). A commit may add only such packages, so a member cannot add a leaf it made
    /// up for someone else's device.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn key_packages_published(
        &self,
        packages: &[(songbird_types::DeviceId, [u8; 32])],
    ) -> Result<bool, RegistryError> {
        if packages.is_empty() {
            return Ok(true);
        }
        for (device, reference) in packages {
            let v = self
                .db
                .query1(
                    "RETURN record::exists(mlskp_used:[$d, $r])
                       OR ((SELECT VALUE mlslr_ref FROM ONLY device:[$d]) ?? NONE) = $r;",
                    vec![
                        var("d", bytes(device.as_bytes())),
                        var("r", bytes(reference)),
                    ],
                )
                .await?;
            if !matches!(v, Value::Bool(true)) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
