//! Push registrations in a SurrealDB database of their own (Prompt 8, D-0095).
//!
//! The rows are what D-0036 defined: a device's push token sealed to the push service's X25519
//! key, under a keyed hash of the device ID. They used to sit in the registry's database; they
//! now live apart, so:
//!
//! - a reader of the registry (a dump, the backup user, any service holding registry
//!   credentials) never holds them, not even sealed;
//! - each service that touches them does so with a credential for this database only: `api`
//!   (registers and removes), `push` (reads, deletes an unregistered token) and `worker` (deletes
//!   with a device or an account). `push` holds no registry credential at all;
//! - backups leave this database out: the app registers again at every start, so a restore
//!   loses nothing that matters.
//!
//! [`PushStore::move_from_registry`] moves rows a registry still holds (written before D-0095).

use bytes::Bytes;
use songbird_surreal::Value;

use crate::{Db, Registry, RegistryError, bytes, first_int, rows, var};

const SCHEMA: &str = "
DEFINE TABLE IF NOT EXISTS push_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS sealed ON push_token TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON push_token TYPE datetime;
";

/// Rows moved per round by [`PushStore::move_from_registry`].
const MOVE_BATCH: usize = 500;

/// The push registration store.
#[derive(Debug)]
pub struct PushStore {
    db: Db,
}

impl PushStore {
    /// Connects and creates the schema if missing.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn connect(db: Db) -> Result<Self, RegistryError> {
        db.exec(SCHEMA, Vec::new()).await?;
        Ok(Self { db })
    }

    /// A store beside `registry`'s database: the same server and credentials, the database
    /// `<registry's>_push`. For tests and development only; deployments give each service a
    /// credential for the push database alone ([`crate::SurrealSettings`]).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn beside(registry: &Registry) -> Result<Self, RegistryError> {
        let mut cfg = registry.db().config_clone()?;
        cfg.database = format!("{}_push", cfg.database);
        // Boxed: the connection future is large, and callers build it inside larger ones.
        Box::pin(async move { Self::connect(Db::connect(cfg).await?).await }).await
    }

    /// The database handle (for tests and verification).
    #[must_use]
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Stores (or replaces) a device's sealed push token under its keyed hash.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn put(&self, index: &[u8; 32], sealed: &[u8]) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPSERT push_token:[$p] SET sealed = $s, at = time::now() RETURN NONE;",
                vec![var("p", bytes(index)), var("s", bytes(sealed))],
            )
            .await?;
        Ok(())
    }

    /// A device's sealed push token.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn get(&self, index: &[u8; 32]) -> Result<Option<Bytes>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE sealed FROM ONLY push_token:[$p];",
                vec![var("p", bytes(index))],
            )
            .await?;
        Ok(v.as_bytes().cloned())
    }

    /// Deletes push tokens (unregistered, or their device deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete(&self, index: &[[u8; 32]]) -> Result<(), RegistryError> {
        let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
        self.db
            .query(
                "FOR $p IN $ps { DELETE push_token:[$p] RETURN NONE; };",
                vec![var("ps", Value::Array(ps))],
            )
            .await?;
        Ok(())
    }

    /// How many of `index` still have a row (deletion is verified with this).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn count(&self, index: &[[u8; 32]]) -> Result<u64, RegistryError> {
        let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
        let v = self
            .db
            .query1(
                "RETURN count(SELECT id FROM push_token WHERE meta::id(id)[0] IN $ps);",
                vec![var("ps", Value::Array(ps))],
            )
            .await?;
        first_int(&v)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Deletes push rows a registry may still hold from before D-0095 (with the device or account,
    /// alongside [`PushStore::delete`]): until every `api` has moved its rows, a deleted device's
    /// sealed token must not survive in the registry, nor be moved back later (D-0100).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_legacy(
        registry: &Registry,
        index: &[[u8; 32]],
    ) -> Result<(), RegistryError> {
        let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
        registry
            .db()
            .query(
                "FOR $p IN $ps { DELETE push_token:[$p] RETURN NONE; };",
                vec![var("ps", Value::Array(ps))],
            )
            .await?;
        Ok(())
    }

    /// How many of `index` a registry still holds from before D-0095 (verified zero with every
    /// deletion, as [`PushStore::count`]).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn count_legacy(
        registry: &Registry,
        index: &[[u8; 32]],
    ) -> Result<u64, RegistryError> {
        let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
        let v = registry
            .db()
            .query1(
                "RETURN count(SELECT id FROM push_token WHERE meta::id(id)[0] IN $ps);",
                vec![var("ps", Value::Array(ps))],
            )
            .await?;
        first_int(&v)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Moves the push rows `registry` still holds (written before D-0095) into this store, then
    /// drops them from the registry. Idempotent; a newer row here wins over a moved one. Returns
    /// how many rows moved.
    ///
    /// # Errors
    /// [`RegistryError`]: rows not yet moved stay in the registry for the next attempt.
    pub async fn move_from_registry(&self, registry: &Registry) -> Result<usize, RegistryError> {
        let mut moved = 0;
        loop {
            let v = registry
                .db()
                .query1(
                    "SELECT meta::id(id)[0] AS p, sealed FROM push_token LIMIT $n;",
                    vec![var(
                        "n",
                        Value::Int(i64::try_from(MOVE_BATCH).unwrap_or(i64::MAX)),
                    )],
                )
                .await?;
            let batch = rows(v);
            if batch.is_empty() {
                return Ok(moved);
            }
            let mut index = Vec::with_capacity(batch.len());
            for row in &batch {
                let (Some(p), Some(sealed)) = (
                    row.get("p").and_then(Value::as_bytes),
                    row.get("sealed").and_then(Value::as_bytes),
                ) else {
                    return Err(RegistryError::Shape);
                };
                let p: [u8; 32] = p.as_ref().try_into().map_err(|_| RegistryError::Shape)?;
                // Only where this store has nothing newer for the device: one statement, so two
                // `api` instances moving at once neither fail nor overwrite each other.
                self.db
                    .query(
                        "UPSERT push_token:[$p] SET sealed = sealed ?? $s, at = at ?? time::now()
                           RETURN NONE;",
                        vec![var("p", bytes(&p)), var("s", bytes(sealed))],
                    )
                    .await?;
                index.push(p);
            }
            let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
            registry
                .db()
                .query(
                    "FOR $p IN $ps { DELETE push_token:[$p] RETURN NONE; };",
                    vec![var("ps", Value::Array(ps))],
                )
                .await?;
            moved += index.len();
        }
    }
}
