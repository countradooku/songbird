//! Family mailboxes (Prompt 11, M4; `docs/PROTOCOL.md` §14.6; D-0126 §5, D-0130).
//!
//! A Family subscription's owner hands each member a month's plan token without the server
//! learning who is in whose family. A mailbox is a random family ID with up to five slots; each
//! slot holds one sealed box (the token, encrypted to a key only the member's invite link
//! carries). **No row names an account**: a family is managed by the hash of a management token
//! the owner's app keeps, a slot is opened by the hash of a slot secret its member's app keeps.
//!
//! | Table | Key | Holds |
//! | --- | --- | --- |
//! | `fam` | family ID (16 random bytes) | `SHA-256` of the management token; the last UTC day it was used |
//! | `fam_slot` | `[family, slot ID]` | `SHA-256` of the slot secret; the sealed box (at most [`MAX_BOX`] bytes), if any |

use bytes::Bytes;
use songbird_surreal::Value;

use crate::db::DbError;
use crate::{Registry, RegistryError, bytes, int, var};

/// Most slots in a family: the owner and five members, and the owner needs none.
pub const MAX_SLOTS: u64 = 5;
/// Largest sealed box.
pub const MAX_BOX: usize = 4_096;

/// Why a family operation did not apply.
#[derive(Debug, thiserror::Error)]
pub enum FamilyError {
    /// No such family or slot, or a wrong token or secret (one answer for all).
    #[error("not found")]
    NotFound,
    /// The family has [`MAX_SLOTS`] slots.
    #[error("full")]
    Full,
    /// The registry failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

fn thrown(e: DbError) -> FamilyError {
    match e {
        DbError::Statement(k) if k == "Thrown:none" => FamilyError::NotFound,
        DbError::Statement(k) if k == "Thrown:full" => FamilyError::Full,
        e => FamilyError::Registry(e.into()),
    }
}

impl Registry {
    /// Creates a family managed by `mgmt` (`SHA-256` of the management token).
    ///
    /// # Errors
    /// [`RegistryError::Exists`] for an ID taken (the caller draws another).
    pub async fn family_create(
        &self,
        id: &[u8; 16],
        mgmt: &[u8; 32],
        today: u32,
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "CREATE fam:[$f] SET mgmt = $m, seen = $t RETURN NONE;",
                vec![
                    var("f", bytes(id)),
                    var("m", bytes(mgmt)),
                    var("t", int(u64::from(today))),
                ],
            )
            .await
            .map_err(|e| match e {
                DbError::Statement(k) if k == "AlreadyExists" => RegistryError::Exists,
                e => e.into(),
            })?;
        Ok(())
    }

    /// Puts a sealed box in a slot (the management token's hash must match): creates the slot
    /// with `auth` (`SHA-256` of its secret) if new and the family has room, else replaces the box
    /// if `auth` matches.
    ///
    /// # Errors
    /// [`FamilyError::NotFound`] (no family, a wrong token, a slot with another secret),
    /// [`FamilyError::Full`].
    pub async fn family_put(
        &self,
        id: &[u8; 16],
        mgmt: &[u8; 32],
        slot: &[u8; 16],
        auth: &[u8; 32],
        sealed: &[u8],
        today: u32,
    ) -> Result<(), FamilyError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 LET $fm = (SELECT VALUE mgmt FROM ONLY fam:[$f]);
                 IF $fm = NONE OR $fm != $m { THROW 'songbird:none' };
                 LET $row = (SELECT auth FROM ONLY fam_slot:[$f, $s]);
                 IF $row = NONE {
                   IF count(SELECT id FROM fam_slot WHERE fam = $f) >= $max { THROW 'songbird:full' };
                   CREATE fam_slot:[$f, $s] SET fam = $f, auth = $a, sealed = $b RETURN NONE;
                 } ELSE {
                   IF $row.auth != $a { THROW 'songbird:none' };
                   UPDATE fam_slot:[$f, $s] SET sealed = $b RETURN NONE;
                 };
                 UPDATE fam:[$f] SET seen = $t RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("f", bytes(id)),
                    var("m", bytes(mgmt)),
                    var("s", bytes(slot)),
                    var("a", bytes(auth)),
                    var("b", Value::Bytes(Bytes::copy_from_slice(sealed))),
                    var("max", int(MAX_SLOTS)),
                    var("t", int(u64::from(today))),
                ],
            )
            .await
            .map_err(thrown)?;
        Ok(())
    }

    /// A slot's sealed box, for its secret's hash (`None`: the slot holds none yet).
    ///
    /// # Errors
    /// [`FamilyError::NotFound`] for any miss.
    pub async fn family_get(
        &self,
        id: &[u8; 16],
        slot: &[u8; 16],
        auth: &[u8; 32],
        today: u32,
    ) -> Result<Option<Bytes>, FamilyError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 LET $row = (SELECT auth, sealed FROM ONLY fam_slot:[$f, $s]);
                 IF $row = NONE OR $row.auth != $a { THROW 'songbird:none' };
                 UPDATE fam:[$f] SET seen = $t RETURN NONE;
                 RETURN $row.sealed;
                 COMMIT TRANSACTION;",
                vec![
                    var("f", bytes(id)),
                    var("s", bytes(slot)),
                    var("a", bytes(auth)),
                    var("t", int(u64::from(today))),
                ],
            )
            .await
            .map_err(thrown)?;
        Ok(v.into_iter().rev().find_map(|x| x.as_bytes().cloned()))
    }

    /// Deletes a slot: by the owner (the management token's hash) or by its member (the slot
    /// secret's hash).
    ///
    /// # Errors
    /// [`FamilyError::NotFound`] for any miss.
    pub async fn family_remove(
        &self,
        id: &[u8; 16],
        slot: &[u8; 16],
        mgmt_or_auth: &[u8; 32],
    ) -> Result<(), FamilyError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 LET $fm = (SELECT VALUE mgmt FROM ONLY fam:[$f]);
                 LET $row = (SELECT auth FROM ONLY fam_slot:[$f, $s]);
                 IF $row = NONE OR ($fm != $h AND $row.auth != $h) { THROW 'songbird:none' };
                 DELETE fam_slot:[$f, $s] RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("f", bytes(id)),
                    var("s", bytes(slot)),
                    var("h", bytes(mgmt_or_auth)),
                ],
            )
            .await
            .map_err(thrown)?;
        Ok(())
    }

    /// Deletes a family and its slots (the owner).
    ///
    /// # Errors
    /// [`FamilyError::NotFound`].
    pub async fn family_delete(&self, id: &[u8; 16], mgmt: &[u8; 32]) -> Result<(), FamilyError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 LET $fm = (SELECT VALUE mgmt FROM ONLY fam:[$f]);
                 IF $fm = NONE OR $fm != $m { THROW 'songbird:none' };
                 DELETE fam_slot WHERE fam = $f RETURN NONE;
                 DELETE fam:[$f] RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![var("f", bytes(id)), var("m", bytes(mgmt))],
            )
            .await
            .map_err(thrown)?;
        Ok(())
    }

    /// Deletes families unused since before `before` (a UTC day), with their slots.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn sweep_families(&self, before: u32) -> Result<(), RegistryError> {
        self.db
            .query(
                "LET $gone = (SELECT VALUE meta::id(id)[0] FROM fam WHERE seen < $b);
                 DELETE fam_slot WHERE fam IN $gone RETURN NONE;
                 DELETE fam WHERE seen < $b RETURN NONE;",
                vec![var("b", int(u64::from(before)))],
            )
            .await?;
        Ok(())
    }
}
