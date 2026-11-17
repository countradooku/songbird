//! Packs (Prompt 6, M4; D-0079 §3, D-0083): sticker packs, chat scenes, sound stickers and emoticon
//! packs, all alike to the server.
//!
//! `pack:[id]` holds the pack's object IDs and their exact (padded) sizes, the SHA-256 of its
//! management token, whether it is complete, when it was created and when it was last fetched (to
//! the day). While the creator uploads, it also names the creating device; completion removes
//! that, so a finished pack is linked to no account (D-0079 §3). The kind, title and content are
//! in the encrypted objects, under a key the server never sees.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use songbird_jobs::ObjectKey;
use songbird_surreal::Value;
use songbird_types::DeviceId;

use crate::{DbError, Registry, RegistryError, bytes, id16, int, rows, var};

/// Most objects in a pack: the manifest and 200 assets (D-0079 §3).
pub const MAX_PACK_OBJECTS: usize = 201;
/// An unfinished pack goes after this long.
pub const PACK_UPLOAD_TIME: std::time::Duration = std::time::Duration::from_hours(24);
/// A pack nobody fetched for this long goes (D-0079 §3).
pub const PACK_IDLE: std::time::Duration = std::time::Duration::from_hours(365 * 24);

/// A pack as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct PackRow {
    /// Object IDs, the manifest first.
    pub objects: Vec<ObjectKey>,
    /// Their exact ciphertext sizes.
    pub sizes: Vec<u64>,
    /// The creating device, until the pack is complete.
    pub device: Option<DeviceId>,
    /// Complete: fetchable, and linked to no device.
    pub done: bool,
}

impl std::fmt::Debug for PackRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackRow")
            .field("objects", &self.objects.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

fn id32(v: &Value) -> Option<[u8; 32]> {
    v.as_bytes()
        .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok())
}

fn pack_of(v: &Value) -> Option<([u8; 16], Vec<ObjectKey>)> {
    let id = v.get("id").and_then(id16)?;
    let objects = v
        .get("objects")?
        .as_array()?
        .iter()
        .map(|o| id32(o).map(ObjectKey))
        .collect::<Option<Vec<_>>>()?;
    Some((id, objects))
}

impl Registry {
    /// Creates a pack being uploaded by `device`.
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the ID is taken; [`RegistryError`].
    pub async fn create_pack(
        &self,
        pack: &[u8; 16],
        objects: &[ObjectKey],
        sizes: &[u64],
        device: &DeviceId,
        token_hash: &[u8; 32],
    ) -> Result<(), RegistryError> {
        if objects.len() != sizes.len() || objects.is_empty() || objects.len() > MAX_PACK_OBJECTS {
            return Err(RegistryError::Shape);
        }
        let r = self
            .db
            .query(
                "CREATE pack:[$p] SET objects = $o, sizes = $s, device = $d, token = $t,
                   done = false, created = time::now(), used = time::now() RETURN NONE;",
                vec![
                    var("p", bytes(pack)),
                    var(
                        "o",
                        Value::Array(objects.iter().map(|o| bytes(&o.0)).collect()),
                    ),
                    var("s", Value::Array(sizes.iter().map(|s| int(*s)).collect())),
                    var("d", bytes(device.as_bytes())),
                    var("t", bytes(token_hash)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k.contains("AlreadyExists") => Err(RegistryError::Exists),
            Err(e) => Err(e.into()),
        }
    }

    /// A pack, if it exists (an unfinished one past its upload time is gone).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn pack(&self, pack: &[u8; 16]) -> Result<Option<PackRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT objects, sizes, device, done FROM ONLY pack:[$p]
                   WHERE done OR created > time::now() - duration::from_secs($up);",
                vec![
                    var("p", bytes(pack)),
                    var("up", int(PACK_UPLOAD_TIME.as_secs())),
                ],
            )
            .await?;
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.swap_remove(0),
            Value::Array(_) => return Ok(None),
            other => other,
        };
        if v.is_absent() {
            return Ok(None);
        }
        let objects = v
            .get("objects")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|o| id32(o).map(ObjectKey))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(RegistryError::Shape)?
            .ok_or(RegistryError::Shape)?;
        let sizes = v
            .get("sizes")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|s| s.as_i64().and_then(|n| u64::try_from(n).ok()))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(RegistryError::Shape)?
            .ok_or(RegistryError::Shape)?;
        let device = v.get("device").and_then(id16).map(DeviceId::from_bytes);
        let done = matches!(v.get("done"), Some(Value::Bool(true)));
        if objects.len() != sizes.len() {
            return Err(RegistryError::Shape);
        }
        Ok(Some(PackRow {
            objects,
            sizes,
            device,
            done,
        }))
    }

    /// Marks an unfinished pack complete and forgets its creating device. False if it was not
    /// unfinished (already complete, expired or gone).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn complete_pack(&self, pack: &[u8; 16]) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "UPDATE pack:[$p] SET done = true, device = NONE, used = time::now()
                   WHERE done = false AND created > time::now() - duration::from_secs($up)
                   RETURN VALUE done;",
                vec![
                    var("p", bytes(pack)),
                    var("up", int(PACK_UPLOAD_TIME.as_secs())),
                ],
            )
            .await?;
        Ok(!rows(v).is_empty())
    }

    /// Records that a complete pack was fetched, at most once a day (only the day is kept).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn touch_pack(&self, pack: &[u8; 16]) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPDATE pack:[$p] SET used = time::now()
                   WHERE done AND used < time::now() - 1d RETURN NONE;",
                vec![var("p", bytes(pack))],
            )
            .await?;
        Ok(())
    }

    /// Deletes a pack whose management token hashes to `token_hash` (compared in constant
    /// time) and returns its objects, for deletion from the store. `None` if there is no such
    /// pack or the token is wrong (the two look the same).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_pack(
        &self,
        pack: &[u8; 16],
        token_hash: &[u8; 32],
    ) -> Result<Option<Vec<ObjectKey>>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT token, objects FROM ONLY pack:[$p];",
                vec![var("p", bytes(pack))],
            )
            .await?;
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.swap_remove(0),
            Value::Array(_) => return Ok(None),
            other => other,
        };
        let Some(stored) = v.get("token").and_then(id32) else {
            return Ok(None);
        };
        if verify_slices_are_equal(&stored, token_hash).is_err() {
            return Ok(None);
        }
        let objects = v
            .get("objects")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|o| id32(o).map(ObjectKey))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(RegistryError::Shape)?
            .ok_or(RegistryError::Shape)?;
        self.delete_pack_row(pack).await?;
        Ok(Some(objects))
    }

    /// Deletes a pack's row.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_pack_row(&self, pack: &[u8; 16]) -> Result<(), RegistryError> {
        self.db
            .query("DELETE pack:[$p] RETURN NONE;", vec![var("p", bytes(pack))])
            .await?;
        Ok(())
    }

    /// Up to `limit` packs to delete: unfinished past their upload time, or unfetched for
    /// [`PACK_IDLE`]; with their objects.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn expired_packs(
        &self,
        limit: usize,
    ) -> Result<Vec<([u8; 16], Vec<ObjectKey>)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS id, objects FROM pack
                   WHERE (done = false AND created <= time::now() - duration::from_secs($up))
                      OR used <= time::now() - duration::from_secs($idle)
                   LIMIT $n;",
                vec![
                    var("up", int(PACK_UPLOAD_TIME.as_secs())),
                    var("idle", int(PACK_IDLE.as_secs())),
                    var("n", int(u64::try_from(limit).unwrap_or(u64::MAX))),
                ],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| pack_of(r).ok_or(RegistryError::Shape))
            .collect()
    }

    /// Unfinished packs some devices are uploading (account or device deletion), with their
    /// objects.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn packs_of(
        &self,
        devices: &[DeviceId],
    ) -> Result<Vec<([u8; 16], Vec<ObjectKey>)>, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS id, objects FROM pack WHERE device IN $ds;",
                vec![var("ds", Value::Array(ds))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|r| pack_of(r).ok_or(RegistryError::Shape))
            .collect()
    }
}
