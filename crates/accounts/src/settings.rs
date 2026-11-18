//! Server-enforced settings (Prompt 9, M2, D-0103; `docs/THREAT_MODEL.md` §4): the few an account's
//! server must see to enforce. Everything else is an encrypted record (§10).
//!
//! - **Discoverable by username** (`account.hidden`): off, a lookup by username answers as for
//!   an unknown one, except through one of the account's own username links (which it handed
//!   out on purpose).
//! - **Who may add me to groups** (`account.grp_contacts`): "contacts" means a commit adding
//!   the account's devices must carry its access key (the server compares it in constant time),
//!   unless the account asked to join.
//!
//! Tightening is any listed device's; loosening is the primary's, checked in the same
//! transaction (as for message requests, D-0058). Both change the directory version, so the send
//! path's snapshot follows.

use songbird_surreal::Value;
use songbird_types::AccountId;

use crate::db::DbError;
use crate::{Registry, RegistryError, bytes, var};

/// What the server enforces for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSettings {
    /// Found by username lookups.
    pub discoverable: bool,
    /// Group adds need the account's access key (a contact).
    pub groups_contacts: bool,
    /// Message requests are refused.
    pub requests_off: bool,
    /// Inactivity period (months).
    pub inactivity_months: u32,
}

impl Registry {
    /// The account's server-enforced settings.
    ///
    /// # Errors
    /// [`RegistryError::NotFound`] for an account that does not exist or is being deleted.
    pub async fn server_settings(
        &self,
        account: &AccountId,
    ) -> Result<ServerSettings, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT hidden, grp_contacts, requests_off, inactive_months ?? 12 AS months
                   FROM ONLY account:[$a] WHERE deleting = false;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        if v.is_absent() {
            return Err(RegistryError::NotFound);
        }
        let flag = |k: &str| matches!(v.get(k), Some(Value::Bool(true)));
        Ok(ServerSettings {
            discoverable: !flag("hidden"),
            groups_contacts: flag("grp_contacts"),
            requests_off: flag("requests_off"),
            inactivity_months: v
                .get("months")
                .and_then(Value::as_i64)
                .and_then(|m| u32::try_from(m).ok())
                .unwrap_or(12),
        })
    }

    /// Sets whether the account is found by username. Turning it on (loosening) needs the
    /// primary.
    ///
    /// # Errors
    /// [`RegistryError::NotPrimary`]; [`RegistryError::NotFound`].
    pub async fn set_discoverable(
        &self,
        account: &AccountId,
        on: bool,
        primary: bool,
    ) -> Result<(), RegistryError> {
        self.set_flag(account, "hidden", !on, on, primary).await
    }

    /// Sets whether group adds need the account's access key. Turning it off (loosening) needs
    /// the primary.
    ///
    /// # Errors
    /// [`RegistryError::NotPrimary`]; [`RegistryError::NotFound`].
    pub async fn set_groups_contacts(
        &self,
        account: &AccountId,
        contacts: bool,
        primary: bool,
    ) -> Result<(), RegistryError> {
        self.set_flag(account, "grp_contacts", contacts, !contacts, primary)
            .await
    }

    /// Writes a boolean field; `loosens` is checked against `primary` in the transaction, and
    /// only when the value actually changes (re-sending the current value is anyone's).
    async fn set_flag(
        &self,
        account: &AccountId,
        field: &'static str,
        value: bool,
        loosens: bool,
        primary: bool,
    ) -> Result<(), RegistryError> {
        // `field` is one of this module's constants, never input.
        let sql = format!(
            "BEGIN TRANSACTION;
             IF account:[$a].deleting != false {{ THROW 'songbird:gone' }};
             IF $loosens AND !$primary AND (account:[$a].{field} ?? false) != $v {{
               THROW 'songbird:primary' }};
             UPDATE account:[$a] SET {field} = $v RETURN NONE;
             UPDATE directory:v SET version += 1 RETURN NONE;
             COMMIT TRANSACTION;"
        );
        let r = self
            .db
            .query(
                &sql,
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("v", Value::Bool(value)),
                    var("loosens", Value::Bool(loosens)),
                    var("primary", Value::Bool(primary)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(k)) if k == "Thrown:primary" => Err(RegistryError::NotPrimary),
            Err(DbError::Statement(k)) if k == "Thrown:gone" => Err(RegistryError::NotFound),
            Err(DbError::Statement(k)) if k == crate::db::TRANSACTION_CONFLICT => {
                Err(RegistryError::Busy)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Whether the account has a pending request to join the group (its devices may then be
    /// added whatever its group setting: it asked).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn has_join_request(
        &self,
        group: &[u8; 16],
        account: &AccountId,
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN grp_req:[$g, $a].acct != NONE;",
                vec![var("g", bytes(group)), var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(matches!(v, Value::Bool(true)))
    }
}
