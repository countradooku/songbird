//! The moderation queue (Prompt 4, M5; `docs/PROTOCOL.md` §5.14; D-0063).
//!
//! A verified report is stored **sealed to the moderation key**, which the servers never hold:
//! the registry, its backups and an operator without that key see only ciphertext, the time it
//! arrived and when it goes. Nothing names the reporter. The row is named by a keyed hash of the
//! franking stamp's tag, so the same message is reported once. Rows go after the retention period
//! (the worker's sweep), or when a moderator deletes them.

use bytes::Bytes;

use crate::db::DbError;
use crate::{Registry, RegistryError, bytes, id16, int, rows, var};

/// A queued report: its ID, when it arrived and the sealed body.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedReport {
    /// The row's ID (a keyed hash of the stamp).
    pub id: [u8; 16],
    /// When it arrived, as SurrealDB prints it.
    pub at: String,
    /// The report sealed to the moderation key.
    pub sealed: Bytes,
}

impl std::fmt::Debug for QueuedReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedReport")
            .field("at", &self.at)
            .field("len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// Queues a sealed report under `id`, kept `days` days.
    ///
    /// # Errors
    /// [`RegistryError::Duplicate`] if a report with this ID is already queued.
    pub async fn queue_report(
        &self,
        id: &[u8; 16],
        sealed: &[u8],
        days: u32,
    ) -> Result<(), RegistryError> {
        let r = self
            .db
            .query(
                "CREATE report:[$i] SET sealed = $s, at = time::now(),
                   expires = time::now() + duration::from_days($d) RETURN NONE;",
                vec![
                    var("i", bytes(id)),
                    var("s", bytes(sealed)),
                    var("d", int(u64::from(days))),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k == "AlreadyExists" => Err(RegistryError::Duplicate),
            Err(e) => Err(e.into()),
        }
    }

    /// The oldest queued reports, at most `limit`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn queued_reports(&self, limit: usize) -> Result<Vec<QueuedReport>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS i, <string> at AS at, sealed FROM report
                   ORDER BY at LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| {
                Some(QueuedReport {
                    id: r.get("i").and_then(id16)?,
                    at: r.get("at")?.as_text()?.to_owned(),
                    sealed: r.get("sealed")?.as_bytes()?.clone(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(RegistryError::Shape)
    }

    /// Deletes a report (a moderator dealt with it).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_report(&self, id: &[u8; 16]) -> Result<(), RegistryError> {
        self.db
            .query("DELETE report:[$i] RETURN NONE;", vec![var("i", bytes(id))])
            .await?;
        Ok(())
    }

    /// Deletes reports past their retention; returns how many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn sweep_reports(&self) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN array::len(DELETE report WHERE expires < time::now() RETURN BEFORE);",
                Vec::new(),
            )
            .await?;
        Ok(v.as_i64().and_then(|n| u64::try_from(n).ok()).unwrap_or(0))
    }

    /// How many reports are queued (diagnostics, tests).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn report_count(&self) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1("RETURN count(SELECT VALUE id FROM report);", Vec::new())
            .await?;
        Ok(v.as_i64().and_then(|n| u64::try_from(n).ok()).unwrap_or(0))
    }
}
