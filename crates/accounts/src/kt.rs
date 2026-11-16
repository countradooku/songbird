//! What key transparency must log (Prompt 3, M6 and D-0057): the changes waiting to be
//! published to `akd`, and the per-account salt its published values are keyed with.
//!
//! Changes to what the directory records (registration's identity key, a new device list, a
//! username claimed or released) bump the account's `kt_gen` in their own transaction. The worker
//! takes [`Registry::kt_pending`], publishes one `akd` epoch with the values that changed, then
//! [`Registry::kt_logged`] records the generation it saw: nothing is missed, and a crash only
//! delays publishing (republishing an unchanged value is skipped by comparing with the last
//! logged one).

use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::{Registry, RegistryError, bytes, id16, id32, int, rows, var};

/// What a directory entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KtKind {
    /// The account identity key (value: its SHA-256).
    Identity,
    /// The signed device list (value: its SHA-256).
    DeviceList,
    /// The username hash (value: the hash; 32 zero bytes once released).
    Username,
}

impl KtKind {
    fn field(self) -> &'static str {
        match self {
            Self::Identity => "kt_v1",
            Self::DeviceList => "kt_v2",
            Self::Username => "kt_v3",
        }
    }
}

/// An account's changes waiting to be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtPending {
    /// The account.
    pub account: AccountId,
    /// Its salt (stored before anything is published under it).
    pub salt: [u8; 32],
    /// The generation these values were read at.
    pub generation: i64,
    /// The values that differ from the last published ones.
    pub changes: Vec<(KtKind, [u8; 32])>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref());
    out
}

impl Registry {
    /// Accounts whose recorded values changed since they were last published (at most `limit`).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_pending(&self, limit: usize) -> Result<Vec<KtPending>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS a, identity, dlist, username, kt_gen AS g, kt_salt AS s,
                   kt_v1, kt_v2, kt_v3 FROM account
                   WHERE (kt_gen ?? 0) > (kt_logged ?? 0) AND deleting = false LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(a), Some(g)) = (
                r.get("a").and_then(id16),
                r.get("g").and_then(Value::as_i64),
            ) else {
                return Err(RegistryError::Shape);
            };
            let salt = if let Some(s) = r.get("s").and_then(id32) {
                s
            } else {
                // Stored first, so nothing is ever published under a salt that was then lost.
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
            let hash_of = |f: &str| r.get(f).and_then(|b| b.as_bytes()).map(|b| sha256(b));
            let stored = |k: KtKind| r.get(k.field()).and_then(id32);
            let mut values: Vec<(KtKind, [u8; 32])> = Vec::new();
            if let Some(h) = hash_of("identity") {
                values.push((KtKind::Identity, h));
            }
            if let Some(h) = hash_of("dlist") {
                values.push((KtKind::DeviceList, h));
            }
            match (r.get("username").and_then(id32), stored(KtKind::Username)) {
                (Some(u), _) => values.push((KtKind::Username, u)),
                (None, Some(_)) => values.push((KtKind::Username, [0; 32])),
                (None, None) => {}
            }
            let changes = values
                .into_iter()
                .filter(|(k, v)| stored(*k) != Some(*v))
                .collect();
            out.push(KtPending {
                account: AccountId::from_bytes(a),
                salt,
                generation: g,
                changes,
            });
        }
        Ok(out)
    }

    /// Records that an account's changes were published at `generation`.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_logged(&self, p: &KtPending) -> Result<(), RegistryError> {
        let mut sql = String::from("kt_logged = $g");
        let mut vars = vec![
            var("a", bytes(p.account.as_bytes())),
            var("g", Value::Int(p.generation)),
        ];
        for (kind, value) in &p.changes {
            // Static field names only.
            let f = kind.field();
            sql.push_str(", ");
            sql.push_str(f);
            sql.push_str(" = $");
            sql.push_str(f);
            vars.push(var(f, bytes(value)));
        }
        self.db
            .query(
                &format!("UPDATE account:[$a] SET {sql} WHERE (kt_logged ?? 0) < $g RETURN NONE;"),
                vars,
            )
            .await?;
        Ok(())
    }

    /// The salt an account's published values are keyed with (none until something was
    /// published, none for an account being deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn kt_salt(&self, account: &AccountId) -> Result<Option<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE kt_salt FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(id32(&v))
    }
}
