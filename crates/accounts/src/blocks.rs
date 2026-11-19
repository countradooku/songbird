//! Blocks and the message-request policy (Prompt 4, M4; `docs/PROTOCOL.md` §5.10–5.11; D-0062).
//!
//! **What the server keeps of a block list:** one row per (blocker, blocked) pair, named by a keyed
//! hash of the pair, with a keyed hash of the blocker for counting and deletion. No account ID is
//! stored; the keys come from the cluster secret (`songbird_send::gate::GateKeys`), so this
//! registry API takes the tags, never the accounts. The full block list (with groups) lives in the
//! user's encrypted sync messages; the server needs only "is this sender blocked by this
//! recipient?", and only for message requests (a contact who is blocked loses the access key when
//! the blocker rotates its profile key).
//!
//! **The request policy** is one flag on the account row, `requests_off`, that the send path reads
//! from the directory snapshot: with it on, message requests are dropped silently.

use aws_lc_rs::{hkdf, hmac};
use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::DbError;
use crate::{Registry, RegistryError, bytes, id16, int, rows, var};

/// Most blocks an account may hold (the server's rows; a client's list may be longer only in
/// groups, which need no server row).
pub const MAX_BLOCKS: u64 = 1_000;

/// An account's send settings as the directory snapshot holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRow {
    /// The account.
    pub account: AccountId,
    /// Its unidentified-access key, if it set a profile.
    pub key: Option<[u8; 16]>,
    /// Anyone may send to it (sealed or identified) without a request.
    pub open: bool,
    /// Message requests are refused (dropped silently).
    pub requests_off: bool,
    /// Group adds need the account's access key (Prompt 9, D-0103).
    pub groups_contacts: bool,
    /// Group adds need a parent's approval signed by this key (Prompt 9, D-0105).
    pub approval_key: Option<[u8; 32]>,
}

impl Registry {
    /// Records a block: `pair` is the keyed hash of (blocker, blocked), `owner` the keyed hash of
    /// the blocker. Idempotent. At most [`MAX_BLOCKS`] per owner: every change writes the owner's
    /// counter row in its transaction, so concurrent adds conflict instead of passing the limit
    /// together.
    ///
    /// Returns whether the block is new.
    ///
    /// # Errors
    /// [`RegistryError::Full`] at the limit; a transaction conflict as a database error (retry).
    pub async fn add_block(
        &self,
        owner: &[u8; 16],
        pair: &[u8; 16],
    ) -> Result<bool, RegistryError> {
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 LET $new = !record::exists(block:[$p]);
                 IF $new {
                   LET $n = (SELECT VALUE n FROM ONLY blockctr:[$o]) ?? 0;
                   IF $n >= $max { THROW 'songbird:full' };
                   UPSERT blockctr:[$o] SET n = $n + 1 RETURN NONE;
                   CREATE block:[$p] SET owner = $o, at = time::now() RETURN NONE;
                 };
                 RETURN $new;
                 COMMIT TRANSACTION;",
                vec![
                    var("p", bytes(pair)),
                    var("o", bytes(owner)),
                    var("max", int(MAX_BLOCKS)),
                ],
            )
            .await;
        match r {
            Ok(v) => Ok(v.iter().rev().any(|x| matches!(x, Value::Bool(true)))),
            Err(DbError::Statement(k)) if k == "Thrown:full" => Err(RegistryError::Full),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes a block (idempotent).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn remove_block(
        &self,
        owner: &[u8; 16],
        pair: &[u8; 16],
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 IF record::exists(block:[$p]) {
                   DELETE block:[$p] RETURN NONE;
                   UPSERT blockctr:[$o] SET n = math::max([(n ?? 1) - 1, 0]) RETURN NONE;
                 };
                 COMMIT TRANSACTION;",
                vec![var("p", bytes(pair)), var("o", bytes(owner))],
            )
            .await?;
        Ok(())
    }

    /// Whether the pair is blocked.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn is_blocked(&self, pair: &[u8; 16]) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN record::exists(block:[$p]);",
                vec![var("p", bytes(pair))],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
    }

    /// How many blocks an owner holds (export).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn block_count(&self, owner: &[u8; 16]) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN count(SELECT VALUE id FROM block WHERE owner = $o);",
                vec![var("o", bytes(owner))],
            )
            .await?;
        v.as_i64()
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Deletes every block an owner holds (account deletion); returns how many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_blocks(&self, owner: &[u8; 16]) -> Result<u64, RegistryError> {
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 LET $gone = DELETE block WHERE owner = $o RETURN BEFORE;
                 DELETE blockctr:[$o] RETURN NONE;
                 RETURN array::len($gone);
                 COMMIT TRANSACTION;",
                vec![var("o", bytes(owner))],
            )
            .await?;
        // The count is the transaction's last value (after its `LET` and `DELETE`).
        r.iter()
            .rev()
            .find_map(Value::as_i64)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Sets whether an account refuses message requests; bumps the directory version so every
    /// node's snapshot follows.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn set_requests_off(
        &self,
        account: &AccountId,
        off: bool,
    ) -> Result<(), RegistryError> {
        // Accepting requests again is refused while a parent's policy refuses them (D-0105).
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !$off AND (account:[$a].sv_requests ?? false) { THROW 'songbird:supervised' };
                 UPDATE account:[$a] SET requests_off = $off WHERE deleting = false RETURN NONE;
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("off", Value::Bool(off)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k == "Thrown:supervised" => {
                Err(RegistryError::Supervised)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Whether an account refuses message requests.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn requests_off(&self, account: &AccountId) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN (SELECT VALUE requests_off FROM ONLY account:[$a]) ?? false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
    }

    /// Pins `value` under `name` the first time, then answers whether it matches (configuration
    /// fingerprints shared by every node, such as [`GateKeys::fingerprint`]).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn pin_fingerprint(
        &self,
        name: &str,
        value: &[u8; 16],
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(pin:[$n]) { CREATE pin:[$n] SET v = $v RETURN NONE };
                 RETURN (SELECT VALUE v FROM ONLY pin:[$n]);
                 COMMIT TRANSACTION;",
                vec![var("n", Value::from(name)), var("v", bytes(value))],
            )
            .await?;
        Ok(v.iter()
            .rev()
            .find_map(Value::as_bytes)
            .is_some_and(|b| b.as_ref() == value))
    }

    /// Every account's send settings (accounts being deleted left out): the directory snapshot's
    /// access part.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn load_access(&self) -> Result<Vec<AccessRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, uak, uak_open, requests_off, grp_contacts, grp_approval
                   FROM account
                   WHERE deleting = false;",
                Vec::new(),
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let Some(a) = r.get("a").and_then(id16) else {
                return Err(RegistryError::Shape);
            };
            out.push(AccessRow {
                account: AccountId::from_bytes(a),
                key: r
                    .get("uak")
                    .and_then(|b| b.as_bytes())
                    .and_then(|b| <[u8; 16]>::try_from(b.as_ref()).ok()),
                open: matches!(r.get("uak_open"), Some(Value::Bool(true))),
                requests_off: matches!(r.get("requests_off"), Some(Value::Bool(true))),
                groups_contacts: matches!(r.get("grp_contacts"), Some(Value::Bool(true))),
                approval_key: r
                    .get("grp_approval")
                    .and_then(|b| b.as_bytes())
                    .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok()),
            });
        }
        Ok(out)
    }
}

/// The keys of block rows and request budgets (Prompt 4, D-0062), from the requests secret
/// every `api`, delivery and worker node holds: Valkey and SurrealDB see only these HMACs.
#[derive(Clone)]
pub struct GateKeys {
    throttle: hmac::Key,
    pair: hmac::Key,
    owner: hmac::Key,
}

impl std::fmt::Debug for GateKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GateKeys { .. }")
    }
}

fn derive(secret: &[u8; 32], label: &[u8]) -> Result<hmac::Key, aws_lc_rs::error::Unspecified> {
    let mut k = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1/gate")
        .extract(secret)
        .expand(&[label], hkdf::HKDF_SHA256)?
        .fill(&mut k)?;
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &k))
}

impl GateKeys {
    /// Derived from the router's cluster secret (HKDF, one label per use).
    ///
    /// # Errors
    /// Only if HKDF refuses the length (never for 32 bytes).
    pub fn from_cluster_secret(secret: &[u8; 32]) -> Result<Self, aws_lc_rs::error::Unspecified> {
        Ok(Self {
            throttle: derive(secret, b"request-throttle")?,
            pair: derive(secret, b"block-pair")?,
            owner: derive(secret, b"block-owner")?,
        })
    }

    /// The block row of (blocker, the account it blocks).
    #[must_use]
    pub fn pair(&self, blocker: &AccountId, target: &AccountId) -> [u8; 16] {
        let mut ctx = hmac::Context::with_key(&self.pair);
        ctx.update(blocker.as_bytes());
        ctx.update(target.as_bytes());
        first16(ctx.sign().as_ref())
    }

    /// The owner tag of `blocker`'s rows.
    #[must_use]
    pub fn owner(&self, blocker: &AccountId) -> [u8; 16] {
        first16(hmac::sign(&self.owner, blocker.as_bytes()).as_ref())
    }

    /// A keyed tag of `subject` for `kind` (throttle records, report IDs). Every part is length
    /// framed, so no two (kind, subject) lists share a tag.
    #[must_use]
    pub fn tag(&self, kind: &str, subject: &[&[u8]]) -> [u8; 16] {
        let mut ctx = hmac::Context::with_key(&self.throttle);
        for part in std::iter::once(kind.as_bytes()).chain(subject.iter().copied()) {
            ctx.update(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            ctx.update(part);
        }
        first16(ctx.sign().as_ref())
    }

    /// A public fingerprint of these keys (a keyed tag of nothing): pinned in the registry so a
    /// node configured with another requests secret refuses to start, instead of, for a worker,
    /// silently missing an account's block rows at deletion.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 16] {
        self.tag("fingerprint", &[])
    }

    /// A throttle record name in `valkey-hot`: `q:<kind>:<keyed hash>`.
    #[must_use]
    pub fn record(&self, kind: &str, subject: &[&[u8]]) -> String {
        format!("q:{kind}:{}", hex::encode(self.tag(kind, subject)))
    }
}

fn first16(b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(b.get(..16).unwrap_or(&[0; 16]));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn records_and_tags_are_keyed_and_reveal_no_account() {
        let k = GateKeys::from_cluster_secret(&[1; 32]).unwrap();
        let a = AccountId::from_bytes([0xAB; 16]);
        let b = AccountId::from_bytes([0xCD; 16]);
        let r = k.record("s", &[a.as_bytes()]);
        assert!(r.starts_with("q:s:") && r.len() == 4 + 32);
        assert!(!r.contains("abab"));
        assert_ne!(k.pair(&a, &b), k.pair(&b, &a), "direction matters");
        assert_ne!(k.owner(&a), k.owner(&b));
        let other = GateKeys::from_cluster_secret(&[2; 32]).unwrap();
        assert_ne!(k.pair(&a, &b), other.pair(&a, &b));
        assert_ne!(r, other.record("s", &[a.as_bytes()]));
    }
}
