//! GDPR (Prompt 3, M7, D-0056): the account export and inactivity deletion.

use songbird_surreal::Value;
use songbird_types::{AccountId, DeviceId};

use crate::{Registry, RegistryError, bytes, id16, int, rows, var};

/// Inactivity periods an account may choose (months); the default is 12 (owner, D-0047).
pub const INACTIVITY_CHOICES: [u32; 3] = [6, 12, 24];
/// The default.
pub const DEFAULT_INACTIVITY: u32 = 12;

/// What the inactivity sweep found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inactive {
    /// Accounts a month from deletion, not yet warned: (account, its enabled devices).
    pub warn_month: Vec<(AccountId, Vec<DeviceId>)>,
    /// Accounts a week from deletion, warned once: (account, its enabled devices).
    pub warn_week: Vec<(AccountId, Vec<DeviceId>)>,
    /// Accounts past their period: to delete.
    pub expired: Vec<AccountId>,
}

/// What the server holds that cannot be attributed to the account (the export says so).
fn not_attributable() -> serde_json::Value {
    serde_json::json!([
        "Messages waiting in the mailbox: end-to-end encrypted, delivered to your devices, deleted on acknowledgement or after 30 days.",
        "Sent attachments: not linked to your account once uploaded (random IDs inside your messages).",
        "Throttle and nonce records in valkey-hot: keyed hashes that cannot be traced back to you; expire within hours.",
        "Key transparency leaves: name your account only through the salt above, deleted with your account.",
        "Encrypted backups: the same registry data as above, kept up to 93 days.",
        "Groups: each group's end-to-end encrypted state names its members' devices (device IDs and public keys) and the accounts holding a role. After your account is deleted these stay in the groups listed above until a member's app commits your removal (the server cannot change a group without its members); they no longer lead to you on the server, and nothing is delivered to your deleted devices.",
        "Group change logs and invite links: ciphertext only the members can read, and hashes; not linked to your account.",
        "Attachments you received: fetched without naming your account or device (the object ID inside the message is enough); the server sees only the address a download came from, and keeps no record of it.",
        "Packs you made (stickers, scenes, sounds, emoticons): once complete, not linked to your account; your devices keep the token that deletes them, and a pack nobody fetches for a year is deleted. Packs still being uploaded are listed with your devices.",
        "Upload budgets: two keyed records per account in valkey-hot (counts, no files), expiring within 24 hours.",
        "GIF searches: held in memory for minutes to answer and cache them, never stored or logged, and sent to the GIF provider without anything identifying you.",
    ])
}

impl Registry {
    /// Records that the account was used now (at most daily, by the caller) and clears any
    /// inactivity warning.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn touch(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPDATE account:[$a] SET last_seen = time::now(), inact_warned = 0
                   WHERE deleting = false RETURN NONE;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(())
    }

    /// Sets the account's inactivity period (6, 12 or 24 months).
    ///
    /// # Errors
    /// [`RegistryError::Shape`] for another value.
    pub async fn set_inactivity(
        &self,
        account: &AccountId,
        months: u32,
    ) -> Result<(), RegistryError> {
        if !INACTIVITY_CHOICES.contains(&months) {
            return Err(RegistryError::Shape);
        }
        self.db
            .query(
                "UPDATE account:[$a] SET inactive_months = $m RETURN NONE;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("m", int(u64::from(months))),
                ],
            )
            .await?;
        Ok(())
    }

    async fn inactive_ids(&self, sql: &str, limit: usize) -> Result<Vec<AccountId>, RegistryError> {
        let v = self
            .db
            .query1(
                sql,
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|a| {
                id16(a)
                    .map(AccountId::from_bytes)
                    .ok_or(RegistryError::Shape)
            })
            .collect()
    }

    async fn enabled_devices(&self, account: &AccountId) -> Result<Vec<DeviceId>, RegistryError> {
        Ok(self
            .devices_of(account)
            .await?
            .into_iter()
            .map(|d| d.device)
            .collect())
    }

    /// Accounts to warn (a month and a week before) or delete for inactivity; the warnings are
    /// marked sent. A month is 30 days.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn inactive(&self, limit: usize) -> Result<Inactive, RegistryError> {
        let base = "SELECT VALUE meta::id(id)[0] FROM account
               WHERE deleting = false AND last_seen != NONE AND last_seen < time::now()
                 - duration::from_days((inactive_months ?? 12) * 30";
        let expired = self
            .inactive_ids(&format!("{base}) LIMIT $n;"), limit)
            .await?;
        let mut out = Inactive {
            expired,
            ..Inactive::default()
        };
        let week = self
            .inactive_ids(
                &format!("{base} - 7) AND (inact_warned ?? 0) < 2 LIMIT $n;"),
                limit,
            )
            .await?;
        for a in week {
            if out.expired.contains(&a) {
                continue;
            }
            out.warn_week.push((a, self.enabled_devices(&a).await?));
        }
        let month = self
            .inactive_ids(
                &format!("{base} - 30) AND (inact_warned ?? 0) < 1 LIMIT $n;"),
                limit,
            )
            .await?;
        for a in month {
            if out.expired.contains(&a) || out.warn_week.iter().any(|(x, _)| *x == a) {
                continue;
            }
            out.warn_month.push((a, self.enabled_devices(&a).await?));
        }
        Ok(out)
    }

    /// Marks an inactivity warning as sent (1: the month's, 2: the week's).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn mark_warned(&self, account: &AccountId, level: u8) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPDATE account:[$a] SET inact_warned = $l RETURN NONE;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("l", int(u64::from(level))),
                ],
            )
            .await?;
        Ok(())
    }

    /// Everything the registry holds about an account, as JSON (GDPR export). Secrets derived
    /// from what the user knows (the PIN and username-key verifiers) are reported as present,
    /// not given out; sealed push registrations as present (only the push service can open
    /// them). Push registrations live in their own store (D-0095): give it, with the push-index
    /// secret, to report them; without it the field is left out.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn export(
        &self,
        account: &AccountId,
        push: Option<(&crate::PushStore, &[u8; 32])>,
    ) -> Result<serde_json::Value, RegistryError> {
        let a = vec![var("a", bytes(account.as_bytes()))];
        let acc = self
            .db
            .query1(
                "SELECT
                   <string> at AS created, deleting, invites, identity, username,
                   ukey != NONE AS username_key, dlist, dlist_v, profile, profile_v, uak, uak_open,
                   avatar, pin != NONE AS pin, pin_tries, <string> pin_lock AS pin_lock,
                   kt_salt, kt_logged, <string> last_seen AS last_seen,
                   inactive_months ?? 12 AS inactive_months
                 FROM ONLY account:[$a];",
                a.clone(),
            )
            .await?;
        if acc.is_absent() {
            return Err(RegistryError::Shape);
        }
        let hex = |v: Option<&Value>| v.and_then(|b| b.as_bytes()).map(hex::encode);
        let mut out = serde_json::Map::new();
        let mut account_json = serde_json::Map::new();
        account_json.insert("id".into(), account.to_hex_unredacted().into());
        for (k, v) in [
            (
                "created",
                acc.get("created")
                    .and_then(Value::as_text)
                    .map(str::to_owned)
                    .into(),
            ),
            (
                "deleting",
                serde_json::Value::from(matches!(acc.get("deleting"), Some(Value::Bool(true)))),
            ),
            (
                "invites_left",
                acc.get("invites").and_then(Value::as_i64).into(),
            ),
            ("identity_key", hex(acc.get("identity")).into()),
            ("username_hash", hex(acc.get("username")).into()),
            (
                "username_key_set",
                matches!(acc.get("username_key"), Some(Value::Bool(true))).into(),
            ),
            ("device_list", hex(acc.get("dlist")).into()),
            (
                "device_list_version",
                acc.get("dlist_v").and_then(Value::as_i64).into(),
            ),
            ("profile", hex(acc.get("profile")).into()),
            (
                "profile_version",
                acc.get("profile_v").and_then(Value::as_i64).into(),
            ),
            ("unidentified_access_key", hex(acc.get("uak")).into()),
            (
                "sealed_open",
                matches!(acc.get("uak_open"), Some(Value::Bool(true))).into(),
            ),
            (
                "pin_set",
                matches!(acc.get("pin"), Some(Value::Bool(true))).into(),
            ),
            (
                "pin_attempts",
                acc.get("pin_tries").and_then(Value::as_i64).into(),
            ),
            (
                "pin_locked_until",
                acc.get("pin_lock")
                    .and_then(Value::as_text)
                    .map(str::to_owned)
                    .into(),
            ),
            ("transparency_salt", hex(acc.get("kt_salt")).into()),
            (
                "last_seen",
                acc.get("last_seen")
                    .and_then(Value::as_text)
                    .map(str::to_owned)
                    .into(),
            ),
            (
                "inactivity_months",
                acc.get("inactive_months").and_then(Value::as_i64).into(),
            ),
        ] {
            account_json.insert(k.into(), v);
        }
        out.insert("account".into(), account_json.into());
        self.export_lists(account, &mut out).await?;
        out.insert(
            "devices".into(),
            self.export_devices(account, push)
                .await?
                .into(),
        );
        out.insert("not_attributable".into(), not_attributable());
        Ok(serde_json::Value::Object(out))
    }

    async fn export_devices(
        &self,
        account: &AccountId,
        push: Option<(&crate::PushStore, &[u8; 32])>,
    ) -> Result<Vec<serde_json::Value>, RegistryError> {
        let hex = |v: Option<&Value>| v.and_then(|b| b.as_bytes()).map(hex::encode);
        // Devices, each with its keys, counts, push registration and pending uploads.
        let devs = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d, key, ik, prim, pending, disabled, <string> at AS at
                   FROM device WHERE account = $a;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let mut devices = Vec::new();
        for d in rows(devs) {
            let Some(id) = d.get("d").and_then(id16).map(DeviceId::from_bytes) else {
                return Err(RegistryError::Shape);
            };
            let (ec, kem) = self.prekey_counts(&id).await?;
            let (kp, lr) = self.key_package_counts(&id).await?;
            let registration = match push {
                Some((store, secret)) => Some(
                    store
                        .get(&crate::push_index(secret, &id))
                        .await?
                        .map_or("none", |_| "present, sealed to the push service"),
                ),
                None => None,
            };
            let grants = self.grants_of(&[id]).await?;
            let packs = self.packs_of(&[id]).await?;
            devices.push(serde_json::json!({
                "id": id.to_hex_unredacted(),
                "auth_key": hex(d.get("key")),
                "identity_key": hex(d.get("ik")),
                "primary": matches!(d.get("prim"), Some(Value::Bool(true))),
                "pending": matches!(d.get("pending"), Some(Value::Bool(true))),
                "disabled": matches!(d.get("disabled"), Some(Value::Bool(true))),
                "created": d.get("at").and_then(Value::as_text),
                "one_time_prekeys": {"x25519": ec, "ml_kem_1024": kem},
                "key_packages": {"single_use": kp, "last_resort": lr},
                "push_registration": registration,
                "pending_uploads": grants.iter().map(songbird_jobs::ObjectKey::to_hex_unredacted).collect::<Vec<_>>(),
                "packs_being_uploaded": packs.iter().map(|(p, _)| hex::encode(p)).collect::<Vec<_>>(),
            }));
        }
        Ok(devices)
    }

    async fn export_lists(
        &self,
        account: &AccountId,
        out: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), RegistryError> {
        let hex = |v: Option<&Value>| v.and_then(|b| b.as_bytes()).map(hex::encode);
        let a = vec![var("a", bytes(account.as_bytes()))];
        // Username link handle, passkeys, avatars.
        let more = self
            .db
            .query(
                "SELECT VALUE meta::id(id)[0] FROM ulink WHERE account = $a;
                 SELECT cid, count, <string> at AS at FROM passkey WHERE account = $a;
                 SELECT VALUE meta::id(id)[0] FROM avatar WHERE account = $a;",
                a,
            )
            .await?;
        let list = |i: usize| more.get(i).cloned().map(rows).unwrap_or_default();
        out.insert(
            "username_links".into(),
            list(0)
                .iter()
                .filter_map(|x| x.as_bytes().map(hex::encode))
                .collect::<Vec<_>>()
                .into(),
        );
        out.insert(
            "passkeys".into(),
            list(1)
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "credential_id": hex(p.get("cid")),
                        "counter": p.get("count").and_then(Value::as_i64),
                        "registered": p.get("at").and_then(Value::as_text),
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        );
        out.insert(
            "avatars".into(),
            list(2)
                .iter()
                .filter_map(|x| x.as_bytes().map(hex::encode))
                .collect::<Vec<_>>()
                .into(),
        );
        self.export_groups(account, out).await
    }

    /// The groups the account's devices are in, with their roles and communities, and its
    /// pending requests to join groups (Prompt 5, D-0073).
    async fn export_groups(
        &self,
        account: &AccountId,
        out: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), RegistryError> {
        const ROLES: [&str; 5] = ["read_only", "member", "moderator", "admin", "owner"];
        let a = vec![var("a", bytes(account.as_bytes()))];
        let ds = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM device WHERE account = $a;",
                a.clone(),
            )
            .await?;
        let mine: Vec<[u8; 16]> = rows(ds.clone()).iter().filter_map(id16).collect();
        let v = self
            .db
            .query(
                "SELECT meta::id(id)[0] AS g, epoch, roster FROM grp WHERE devs CONTAINSANY $ds;
                 SELECT meta::id(id)[0] AS g, <string> at AS at FROM grp_req WHERE acct = $a;",
                vec![var("ds", ds), var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let list = |i: usize| v.get(i).cloned().map(rows).unwrap_or_default();
        let mut groups = Vec::new();
        for g in list(0) {
            let Some(id) = g.get("g").and_then(id16) else {
                return Err(RegistryError::Shape);
            };
            let roster = g
                .get("roster")
                .and_then(Value::as_bytes)
                .cloned()
                .unwrap_or_default();
            // `version 2 | policy [7] | n × (device [16] | role u8)`.
            let devices: Vec<serde_json::Value> = roster
                .get(8..)
                .unwrap_or_default()
                .as_chunks::<17>()
                .0
                .iter()
                .filter(|c| mine.iter().any(|d| c[..16] == d[..]))
                .map(|c| {
                    serde_json::json!({
                        "id": hex::encode(&c[..16]),
                        "role": ROLES.get(usize::from(c[16])).copied(),
                    })
                })
                .collect();
            let community = self.community_of(&id).await?.map(hex::encode);
            groups.push(serde_json::json!({
                "group": hex::encode(id),
                "epoch": g.get("epoch").and_then(Value::as_i64),
                "devices": devices,
                "community": community,
            }));
        }
        out.insert("groups".into(), groups.into());
        out.insert(
            "group_requests".into(),
            list(1)
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "group": r.get("g").and_then(id16).map(hex::encode),
                        "asked": r.get("at").and_then(Value::as_text),
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        );
        Ok(())
    }
}
