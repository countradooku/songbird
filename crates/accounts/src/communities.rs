//! Communities (Prompt 5, M4; D-0072): opaque links between IDs, and an encrypted blob.
//!
//! - `cmty:[community]`: its announcement group (`ann`), its encrypted info (`meta`) and that
//!   info's version (`meta_v`).
//! - `cmty_grp:[group]`: the community a group belongs to (`cmty`), and whether it is the
//!   announcement group. Keyed by group, so a group is in at most one community.
//!
//! Names, descriptions and pictures are in `meta`, ciphertext under a key the members share. Who
//! may change a community is decided by the caller, from the announcement group's roles.

use crate::groups::{bytes_of, u64_of};
use crate::{Registry, RegistryError, bytes, int, rows, var};

/// Most groups in a community, besides its announcement group.
pub const MAX_COMMUNITY_GROUPS: u64 = 100;
/// Largest encrypted community info.
pub const MAX_COMMUNITY_META: usize = 16 * 1024;

/// A community as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityRow {
    /// Its announcement group.
    pub announcement: [u8; 16],
    /// Its groups, sorted (the announcement group not among them).
    pub groups: Vec<[u8; 16]>,
    /// Its encrypted info, empty until set.
    pub meta: bytes::Bytes,
    /// The info's version (0 until set).
    pub meta_v: u64,
}

fn id16(v: &songbird_surreal::Value) -> Option<[u8; 16]> {
    v.as_bytes()
        .and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok())
}

impl Registry {
    /// Creates a community around `announcement`, an existing group in no community.
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the community ID is taken or the group is already in a
    /// community; [`RegistryError`] otherwise.
    pub async fn create_community(
        &self,
        community: &[u8; 16],
        announcement: &[u8; 16],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF record::exists(cmty_grp:[$a]) { THROW 'songbird:exists' };
             CREATE cmty:[$c] SET ann = $a, meta = <bytes>'', meta_v = 0 RETURN NONE;
             CREATE cmty_grp:[$a] SET cmty = $c, ann = true RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || vec![var("c", bytes(community)), var("a", bytes(announcement))],
            |k| {
                (k == "Thrown:exists" || k.contains("AlreadyExists"))
                    .then_some(RegistryError::Exists)
            },
            |_| Ok(()),
        )
        .await
    }

    /// A community, with its groups.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn community(
        &self,
        community: &[u8; 16],
    ) -> Result<Option<CommunityRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT ann, meta, meta_v,
                   (SELECT VALUE meta::id(id)[0] FROM cmty_grp WHERE cmty = $c AND ann = false)
                     AS groups
                 FROM ONLY cmty:[$c];",
                vec![var("c", bytes(community))],
            )
            .await?;
        if matches!(v, songbird_surreal::Value::Null) {
            return Ok(None);
        }
        // A missing record comes back as NONE, or with only the computed fields.
        let Some(announcement) =
            bytes_of(&v, "ann").and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok())
        else {
            return Ok(None);
        };
        let mut groups = v
            .get("groups")
            .map(|g| rows(g.clone()))
            .unwrap_or_default()
            .iter()
            .map(|g| id16(g).ok_or(RegistryError::Shape))
            .collect::<Result<Vec<_>, _>>()?;
        groups.sort_unstable();
        Ok(Some(CommunityRow {
            announcement,
            groups,
            meta: bytes_of(&v, "meta").unwrap_or_default(),
            meta_v: v.get("meta_v").and_then(u64_of).unwrap_or(0),
        }))
    }

    /// The community a group belongs to (as a member group or its announcement group).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn community_of(&self, group: &[u8; 16]) -> Result<Option<[u8; 16]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE cmty FROM ONLY cmty_grp:[$g];",
                vec![var("g", bytes(group))],
            )
            .await?;
        Ok(id16(&v))
    }

    /// Links `group` into `community`.
    ///
    /// # Errors
    /// [`RegistryError::NotFound`] for no such community; [`RegistryError::Exists`] if the group
    /// is in a community (this one included); [`RegistryError::Full`] at
    /// [`MAX_COMMUNITY_GROUPS`]; [`RegistryError`] otherwise.
    pub async fn add_community_group(
        &self,
        community: &[u8; 16],
        group: &[u8; 16],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF !record::exists(cmty:[$c]) { THROW 'songbird:none' };
             IF record::exists(cmty_grp:[$g]) { THROW 'songbird:exists' };
             IF count((SELECT VALUE id FROM cmty_grp WHERE cmty = $c AND ann = false)) >= $most {
               THROW 'songbird:full'
             };
             CREATE cmty_grp:[$g] SET cmty = $c, ann = false RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("c", bytes(community)),
                    var("g", bytes(group)),
                    var("most", int(MAX_COMMUNITY_GROUPS)),
                ]
            },
            |k| match k {
                "Thrown:none" => Some(RegistryError::NotFound),
                "Thrown:exists" => Some(RegistryError::Exists),
                "Thrown:full" => Some(RegistryError::Full),
                k if k.contains("AlreadyExists") => Some(RegistryError::Exists),
                _ => None,
            },
            |_| Ok(()),
        )
        .await
    }

    /// Unlinks `group` from `community` (nothing if it is not there; never the announcement
    /// group).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn remove_community_group(
        &self,
        community: &[u8; 16],
        group: &[u8; 16],
    ) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE cmty_grp:[$g] WHERE cmty = $c AND ann = false;",
                vec![var("c", bytes(community)), var("g", bytes(group))],
            )
            .await?;
        Ok(())
    }

    /// Replaces the community's encrypted info if its version is still `expected`; returns the
    /// new version.
    ///
    /// # Errors
    /// [`RegistryError::StaleEpoch`] if the version moved (or no such community);
    /// [`RegistryError`] otherwise.
    pub async fn put_community_meta(
        &self,
        community: &[u8; 16],
        expected: u64,
        meta: &[u8],
    ) -> Result<u64, RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF ((SELECT VALUE meta_v FROM ONLY cmty:[$c]) ?? -1) != $v { THROW 'songbird:stale' };
             UPDATE cmty:[$c] SET meta = $m, meta_v = $v + 1 RETURN NONE;
             COMMIT TRANSACTION;";
        self.retry(
            sql,
            || {
                vec![
                    var("c", bytes(community)),
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

    /// Deletes a community and its links (the groups themselves stay).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_community(&self, community: &[u8; 16]) -> Result<(), RegistryError> {
        self.db
            .exec(
                "BEGIN TRANSACTION;
                 DELETE cmty_grp WHERE cmty = $c;
                 DELETE cmty:[$c];
                 COMMIT TRANSACTION;",
                vec![var("c", bytes(community))],
            )
            .await?;
        Ok(())
    }
}
