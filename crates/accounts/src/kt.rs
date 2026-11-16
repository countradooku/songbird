//! Key transparency storage (Prompt 3, M6, D-0055): the log's leaves and perfect-subtree hashes in
//! SurrealDB, appends serialized on the head row, and the reconcile pass that logs what changed.
//!
//! Changes to what the log records (registration's identity key, a new device list, a username
//! claimed or released) bump the account's `kt_gen` in their own transaction; the worker's
//! [`Registry::kt_reconcile`] appends a leaf for each value that differs from the last logged one
//! and records the generation it saw, so nothing is missed and a crash only delays logging.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

use songbird_kt::{Hash, Kind, Leaf, Store};
use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::{self, DbError};
use crate::{Registry, RegistryError, bytes, id16, id32, int, rows, var};

/// Appends race only on the head row; under contention each round lets one through, so the
/// bound is generous and the backoff jittered (the worker is the only appender in production).
const APPEND_ATTEMPTS: u32 = 200;

async fn backoff(attempt: u32) {
    let mut j = [0u8; 2];
    let _ = getrandom::fill(&mut j);
    let cap = 1u64 << attempt.min(6);
    let ms = 1 + u64::from(u16::from_be_bytes(j)) % cap;
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// A store that answers every node, recording the ones it did not have: the hashes a computation
/// needs depend only on indices, so one dry run lists them all.
struct Recording<'a> {
    known: &'a HashMap<(u32, u64), Hash>,
    missing: RefCell<Vec<(u32, u64)>>,
}

impl Store for Recording<'_> {
    fn node(&self, level: u32, index: u64) -> Option<Hash> {
        if let Some(h) = self.known.get(&(level, index)) {
            return Some(*h);
        }
        self.missing.borrow_mut().push((level, index));
        Some([0; 32])
    }
}

struct Known(HashMap<(u32, u64), Hash>);

impl Store for Known {
    fn node(&self, level: u32, index: u64) -> Option<Hash> {
        self.0.get(&(level, index)).copied()
    }
}

/// One of an account's log entries with its inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its index.
    pub index: u64,
    /// The leaf.
    pub leaf: Leaf,
    /// Its inclusion proof at the answer's size.
    pub proof: Vec<Hash>,
}

impl Registry {
    async fn kt_nodes(
        &self,
        want: &[(u32, u64)],
    ) -> Result<HashMap<(u32, u64), Hash>, RegistryError> {
        let ids: Vec<Value> = want
            .iter()
            .map(|(l, i)| Value::Array(vec![int(u64::from(*l)), int(*i)]))
            .collect();
        let found = self
            .db
            .query1(
                "SELECT meta::id(id) AS k, h FROM ktnode WHERE meta::id(id) INSIDE $ids;",
                vec![var("ids", Value::Array(ids))],
            )
            .await?;
        let mut out = HashMap::new();
        for row in rows(found) {
            let key = row.get("k").cloned().map(rows).unwrap_or_default();
            let level = key
                .first()
                .and_then(Value::as_i64)
                .and_then(|x| u32::try_from(x).ok());
            let index = key
                .get(1)
                .and_then(Value::as_i64)
                .and_then(|x| u64::try_from(x).ok());
            let (Some(level), Some(index), Some(hash)) =
                (level, index, row.get("h").and_then(id32))
            else {
                return Err(RegistryError::Shape);
            };
            out.insert((level, index), hash);
        }
        Ok(out)
    }

    /// Runs `f` against the stored nodes, fetching every node it needs in one round.
    async fn kt_with<T>(
        &self,
        f: impl Fn(&dyn Store) -> Result<T, songbird_kt::KtError>,
    ) -> Result<T, RegistryError> {
        let empty = HashMap::new();
        let dry = Recording {
            known: &empty,
            missing: RefCell::new(Vec::new()),
        };
        let _ = f(&dry);
        let mut want = dry.missing.into_inner();
        want.sort_unstable();
        want.dedup();
        let known = Known(self.kt_nodes(&want).await?);
        f(&known).map_err(|_| RegistryError::Shape)
    }

    /// The log's size.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_size(&self) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1("RETURN kt:head.size ?? 0;", Vec::new())
            .await?;
        crate::first_int(&v)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)
    }

    /// The root of the log at `size`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_root(&self, size: u64) -> Result<Hash, RegistryError> {
        self.kt_with(|s| songbird_kt::root(&StoreRef(s), size))
            .await
    }

    /// The consistency proof between two sizes.
    ///
    /// # Errors
    /// [`RegistryError::Shape`] for sizes out of order.
    pub async fn kt_consistency(&self, old: u64, new: u64) -> Result<Vec<Hash>, RegistryError> {
        self.kt_with(|s| songbird_kt::consistency_proof(&StoreRef(s), old, new))
            .await
    }

    /// Appends a leaf; returns its index. Appends are serialized on the head row.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_append(&self, leaf: &Leaf) -> Result<u64, RegistryError> {
        let hash = leaf.hash();
        let mut attempt = 0;
        loop {
            let n = self.kt_size().await?;
            let nodes = self
                .kt_with(|s| songbird_kt::append_nodes(&StoreRef(s), n, hash))
                .await?;
            let list: Vec<Value> = nodes
                .iter()
                .map(|(l, i, h)| Value::Array(vec![int(u64::from(*l)), int(*i), bytes(h)]))
                .collect();
            let r = self
                .db
                .query(
                    "BEGIN TRANSACTION;
                     IF (kt:head.size ?? 0) != $n { THROW 'songbird:moved' };
                     CREATE ktleaf:[$n] SET leaf = $leaf, subject = $s RETURN NONE;
                     FOR $x IN $nodes { CREATE ktnode:[$x[0], $x[1]] SET h = $x[2] RETURN NONE; };
                     UPSERT kt:head SET size = $n + 1 RETURN NONE;
                     COMMIT TRANSACTION;",
                    vec![
                        var("n", int(n)),
                        var("leaf", bytes(&leaf.encode())),
                        var("s", bytes(&leaf.subject)),
                        var("nodes", Value::Array(list)),
                    ],
                )
                .await;
            match r {
                Ok(_) => return Ok(n),
                Err(DbError::Statement(k))
                    if (k == "Thrown:moved"
                        || k == db::TRANSACTION_CONFLICT
                        || k.contains("AlreadyExists"))
                        && attempt < APPEND_ATTEMPTS =>
                {
                    attempt += 1;
                    backoff(attempt).await;
                }
                Err(e) if crate::is_conflict(&e) && attempt < APPEND_ATTEMPTS => {
                    attempt += 1;
                    backoff(attempt).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// An account's salt (none until its first entry) and its entries (newest `limit`), each with
    /// its inclusion proof at `size`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_account(
        &self,
        account: &AccountId,
        size: u64,
        limit: usize,
    ) -> Result<Option<([u8; 32], Vec<Entry>)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE kt_salt FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let Some(salt) = id32(&v) else {
            return Ok(None);
        };
        let subject = songbird_kt::subject(&salt, account.as_bytes());
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS i, leaf FROM ktleaf WHERE subject = $s
                   AND meta::id(id)[0] < $size ORDER BY i DESC LIMIT $n;",
                vec![
                    var("s", bytes(&subject)),
                    var("size", int(size)),
                    var("n", int(u64::try_from(limit).unwrap_or(u64::MAX))),
                ],
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(i), Some(l)) = (
                r.get("i")
                    .and_then(Value::as_i64)
                    .and_then(|x| u64::try_from(x).ok()),
                r.get("leaf").and_then(|b| b.as_bytes()),
            ) else {
                return Err(RegistryError::Shape);
            };
            let leaf = Leaf::decode(l).map_err(|_| RegistryError::Shape)?;
            let proof = self
                .kt_with(|s| songbird_kt::inclusion_proof(&StoreRef(s), i, size))
                .await?;
            out.push(Entry {
                index: i,
                leaf,
                proof,
            });
        }
        out.reverse();
        Ok(Some((salt, out)))
    }

    /// Logs what changed for up to `limit` accounts (the worker's sweep); returns leaves appended.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_reconcile(&self, limit: usize, now_ms: u64) -> Result<usize, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, identity, dlist, username, kt_gen AS g, kt_salt AS s,
                   kt_v1, kt_v2, kt_v3 FROM account
                   WHERE (kt_gen ?? 0) > (kt_logged ?? 0) AND deleting = false LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        let mut appended = 0;
        for r in rows(v) {
            let (Some(a), Some(g)) = (
                r.get("a").and_then(id16),
                r.get("g").and_then(Value::as_i64),
            ) else {
                return Err(RegistryError::Shape);
            };
            // The salt is stored before anything is logged under it.
            let salt = if let Some(s) = r.get("s").and_then(id32) {
                s
            } else {
                let mut s = [0u8; 32];
                getrandom::fill(&mut s).map_err(|_| RegistryError::Shape)?;
                let set = self
                    .db
                    .query(
                        "UPDATE account:[$a] SET kt_salt = kt_salt ?? $s RETURN NONE;
                         RETURN account:[$a].kt_salt;",
                        vec![var("a", bytes(&a)), var("s", bytes(&s))],
                    )
                    .await?;
                set.last().and_then(id32).ok_or(RegistryError::Shape)?
            };
            let subject = songbird_kt::subject(&salt, &a);
            let hash_of = |f: &str| {
                r.get(f)
                    .and_then(|b| b.as_bytes())
                    .map(|b| songbird_kt::sha256(b))
            };
            let stored = |f: &str| r.get(f).and_then(id32);
            let username = r.get("username").and_then(id32);
            let mut values: Vec<(Kind, Hash, &str)> = Vec::new();
            if let Some(h) = hash_of("identity") {
                values.push((Kind::Identity, h, "kt_v1"));
            }
            if let Some(h) = hash_of("dlist") {
                values.push((Kind::DeviceList, h, "kt_v2"));
            }
            // A username, or its release once one was logged.
            match (username, stored("kt_v3")) {
                (Some(u), _) => values.push((Kind::Username, u, "kt_v3")),
                (None, Some(_)) => values.push((Kind::Username, [0; 32], "kt_v3")),
                (None, None) => {}
            }
            let mut sets = vec![
                var("a", bytes(&a)),
                var("g", Value::Int(g)),
                var("salt", bytes(&salt)),
            ];
            let mut set_sql = String::from("kt_logged = $g, kt_salt = $salt");
            for (kind, value, field) in values {
                if stored(field) == Some(value) {
                    continue;
                }
                self.kt_append(&Leaf {
                    kind,
                    subject,
                    value,
                    time_ms: now_ms,
                })
                .await?;
                appended += 1;
                set_sql.push_str(", ");
                set_sql.push_str(field);
                set_sql.push_str(" = $");
                set_sql.push_str(field);
                sets.push(var(field, bytes(&value)));
            }
            self.db
                .query(
                    &format!(
                        "UPDATE account:[$a] SET {set_sql} WHERE (kt_logged ?? 0) < $g RETURN NONE;"
                    ),
                    sets,
                )
                .await?;
        }
        Ok(appended)
    }
}

/// Adapts a `&dyn Store` to the generic functions.
struct StoreRef<'a>(&'a dyn Store);

impl Store for StoreRef<'_> {
    fn node(&self, level: u32, index: u64) -> Option<Hash> {
        self.0.node(level, index)
    }
}
