//! Call links (Prompt 7, M3; PROTOCOL §8.7; D-0085 §2, D-0088).
//!
//! `call_link:[hash]` is named by `SHA-256("songbird.v1/call-link-hash\0" ‖ link ID)`: the server
//! never holds the link ID itself, nor the root in the link's fragment that the ID and the
//! participants' card key come from. It keeps the link's room, the SHA-256 of its admin token,
//! audio or video, whether a lobby is on, and its expiry. **No account**: the creator holds the
//! admin token, and deleting an account cannot find its links; they go at their expiry (at most
//! 30 days).

use songbird_surreal::Value;

use crate::groups::u64_of;
use crate::{Registry, RegistryError, bytes, id16, int, rows, var};

/// The longest a link lives (D-0088).
pub const MAX_CALL_LINK_TTL: std::time::Duration = std::time::Duration::from_hours(30 * 24);

/// A call link as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct CallLinkRow {
    /// Its room.
    pub room: [u8; 16],
    /// SHA-256 of its admin token.
    pub admin: [u8; 32],
    /// 1 audio, 2 video.
    pub media: u8,
    /// Joiners wait until an admin admits them.
    pub lobby: bool,
}

impl std::fmt::Debug for CallLinkRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallLinkRow")
            .field("media", &self.media)
            .field("lobby", &self.lobby)
            .finish_non_exhaustive()
    }
}

fn id32(v: &Value) -> Option<[u8; 32]> {
    v.as_bytes()
        .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok())
}

impl Registry {
    /// Creates a link valid `ttl_secs` (at most [`MAX_CALL_LINK_TTL`]).
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the hash is taken; [`RegistryError::Shape`] for a bad TTL or
    /// media; [`RegistryError`].
    pub async fn create_call_link(
        &self,
        hash: &[u8; 32],
        row: &CallLinkRow,
        ttl_secs: u64,
    ) -> Result<(), RegistryError> {
        if ttl_secs == 0 || ttl_secs > MAX_CALL_LINK_TTL.as_secs() || !(1..=2).contains(&row.media)
        {
            return Err(RegistryError::Shape);
        }
        let r = self
            .db
            .query(
                "CREATE call_link:[$h] SET room = $r, admin = $a, media = $m, lobby = $l,
                   expires = time::now() + duration::from_secs($t) RETURN NONE;",
                vec![
                    var("h", bytes(hash)),
                    var("r", bytes(&row.room)),
                    var("a", bytes(&row.admin)),
                    var("m", int(u64::from(row.media))),
                    var("l", Value::Bool(row.lobby)),
                    var("t", int(ttl_secs)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(crate::DbError::Statement(k)) if k.contains("AlreadyExists") => {
                Err(RegistryError::Exists)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// A link, if it exists and has not expired.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn call_link(&self, hash: &[u8; 32]) -> Result<Option<CallLinkRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT room, admin, media, lobby FROM ONLY call_link:[$h]
                   WHERE expires > time::now();",
                vec![var("h", bytes(hash))],
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
        let room = v.get("room").and_then(id16).ok_or(RegistryError::Shape)?;
        let admin = v.get("admin").and_then(id32).ok_or(RegistryError::Shape)?;
        let media = v
            .get("media")
            .and_then(u64_of)
            .and_then(|m| u8::try_from(m).ok())
            .ok_or(RegistryError::Shape)?;
        let lobby = matches!(v.get("lobby"), Some(Value::Bool(true)));
        Ok(Some(CallLinkRow {
            room,
            admin,
            media,
            lobby,
        }))
    }

    /// Deletes a link (revoked by its admin).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_call_link(&self, hash: &[u8; 32]) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE call_link:[$h] RETURN NONE;",
                vec![var("h", bytes(hash))],
            )
            .await?;
        Ok(())
    }

    /// Deletes up to `limit` expired links; returns how many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_expired_call_links(&self, limit: usize) -> Result<usize, RegistryError> {
        let v = self
            .db
            .query1(
                "DELETE (SELECT VALUE id FROM call_link WHERE expires <= time::now() LIMIT $n)
                   RETURN BEFORE;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        Ok(rows(v).len())
    }
}
