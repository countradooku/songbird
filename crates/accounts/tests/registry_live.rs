//! The registry against a real SurrealDB. Runs when `SONGBIRD_TEST_SURREALDB` (`host:port`) and
//! `SONGBIRD_TEST_SURREALDB_PASS` are set; with `SONGBIRD_REQUIRE_SURREALDB=1` a missing server
//! fails instead of skipping. Every test uses a database of its own.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names,
    reason = "tests"
)]

use std::time::Duration;

use songbird_accounts::{Db, Grant, PushStore, Registry, RegistryError, push_index};
use songbird_jobs::{Job, ObjectKey, Outbox as _, Work};
use songbird_types::{AccountId, DeviceId};

async fn registry() -> Option<Registry> {
    Some(
        Registry::connect(Db::connect(db_config("accounts")?).await.unwrap())
            .await
            .unwrap(),
    )
}

/// A push registration store in a database of its own (D-0095).
async fn push_store() -> Option<PushStore> {
    Some(
        PushStore::connect(Db::connect(db_config("push")?).await.unwrap())
            .await
            .unwrap(),
    )
}

fn db_config(prefix: &str) -> Option<songbird_surreal::Config> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_SURREALDB") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
            "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
        );
        return None;
    };
    let cfg = songbird_surreal::Config {
        addr,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").expect("SONGBIRD_TEST_SURREALDB_PASS"),
        namespace: "test".into(),
        database: format!(
            "{prefix}_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
        // Generous: CI's shared SurrealDB also serves the prekey gate's 400 concurrent claims.
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    Some(cfg)
}

fn dev(b: u8) -> (DeviceId, [u8; 32]) {
    (DeviceId::random().unwrap(), [b; 32])
}

#[tokio::test]
async fn accounts_devices_and_the_directory() {
    let Some(r) = registry().await else { return };
    let v0 = r.directory_version().await.unwrap();
    let a = AccountId::random().unwrap();
    let (d1, d2) = (dev(1), dev(2));
    r.create_account(&a, &[d1, d2]).await.unwrap();
    assert!(r.directory_version().await.unwrap() > v0);
    // Neither the account nor a device can be created twice.
    assert!(matches!(
        r.create_account(&a, &[dev(3)]).await,
        Err(RegistryError::Exists)
    ));
    let b = AccountId::random().unwrap();
    assert!(matches!(
        r.create_account(&b, &[d1]).await,
        Err(RegistryError::Exists)
    ));
    // The failed transaction left nothing behind.
    assert!(r.account_devices(&b).await.unwrap().is_empty());

    let row = r.device(&d1.0).await.unwrap().unwrap();
    assert_eq!(row.account, a);
    assert_eq!(row.key, [1; 32]);
    assert!(!row.disabled);
    assert!(
        r.device(&DeviceId::random().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let mut dir = r.load_directory().await.unwrap();
    dir.sort_by_key(|(d, _, _)| *d.as_bytes());
    assert_eq!(dir.len(), 2);
    let mut devs = r.account_devices(&a).await.unwrap();
    devs.sort_by_key(|d| *d.as_bytes());
    let mut want = vec![d1.0, d2.0];
    want.sort_by_key(|d| *d.as_bytes());
    assert_eq!(devs, want);
}

#[tokio::test]
async fn deletion_disables_writes_the_outbox_and_leaves_nothing() {
    let Some(r) = registry().await else { return };
    let Some(p) = push_store().await else { return };
    let secret = [7u8; 32];
    let a = AccountId::random().unwrap();
    let (d1, d2) = (dev(1), dev(2));
    r.create_account(&a, &[d1, d2]).await.unwrap();
    let other = AccountId::random().unwrap();
    let d3 = dev(3);
    r.create_account(&other, &[d3]).await.unwrap();
    for d in [d1.0, d2.0, d3.0] {
        p.put(&push_index(&secret, &d), b"sealed").await.unwrap();
    }
    let obj = ObjectKey::random().unwrap();
    r.create_grant(
        &obj,
        &Grant {
            device: d1.0,
            size: 4096,
            fetches: 2,
        },
        Duration::from_secs(3600),
    )
    .await
    .unwrap();

    let v = r.directory_version().await.unwrap();
    let job = Job::new(Work::DeleteAccount { account: a }).unwrap();
    assert!(r.begin_account_deletion(&a, &job).await.unwrap());
    assert!(r.directory_version().await.unwrap() > v);
    assert!(r.device(&d1.0).await.unwrap().unwrap().disabled);
    // Disabled devices leave the directory at once; the other account stays.
    let dir = r.load_directory().await.unwrap();
    assert_eq!(dir.len(), 1);
    assert_eq!(dir[0].0, d3.0);
    // The job is in the outbox, exactly once even if deletion is asked twice.
    assert!(r.begin_account_deletion(&a, &job).await.unwrap());
    let jobs = r.take(10).await.unwrap();
    assert_eq!(jobs, vec![job.clone()]);
    r.remove(&[job.id]).await.unwrap();
    assert!(r.take(10).await.unwrap().is_empty());
    assert!(
        !r.begin_account_deletion(&AccountId::random().unwrap(), &job)
            .await
            .unwrap()
    );

    // The worker's steps.
    let devices = r.account_devices(&a).await.unwrap();
    let index: Vec<[u8; 32]> = devices.iter().map(|d| push_index(&secret, d)).collect();
    let before = r.remnants(&a, &devices).await.unwrap();
    assert_eq!(before.account, 1);
    assert_eq!(before.devices, 2);
    assert_eq!(p.count(&index).await.unwrap(), 2);
    assert_eq!(before.grants, 1);
    p.delete(&index).await.unwrap();
    for g in r.grants_of(&devices).await.unwrap() {
        r.delete_grant(&g).await.unwrap();
    }
    r.delete_account_rows(&a).await.unwrap();
    assert!(r.remnants(&a, &devices).await.unwrap().is_empty());
    assert_eq!(p.count(&index).await.unwrap(), 0);
    // The other account is untouched.
    assert!(r.device(&d3.0).await.unwrap().is_some());
    assert!(p.get(&push_index(&secret, &d3.0)).await.unwrap().is_some());
}

/// Push registrations live in their own database (D-0095): the registry's database holds none,
/// and rows a registry still holds from before are moved once, never over a newer registration.
#[tokio::test]
async fn push_registrations_live_apart_and_old_rows_move_once() {
    let Some(r) = registry().await else { return };
    let Some(p) = push_store().await else { return };
    // Rows written by the registry before D-0095 (same table name, in the registry database).
    let (old, newer) = ([0x0a; 32], [0x0b; 32]);
    for (i, sealed) in [(old, b"old-a".as_slice()), (newer, b"old-b")] {
        r.db()
            .query(
                "UPSERT push_token:[$p] SET sealed = $s, at = time::now() RETURN NONE;",
                vec![
                    (
                        "p".into(),
                        songbird_surreal::Value::Bytes(i.to_vec().into()),
                    ),
                    (
                        "s".into(),
                        songbird_surreal::Value::Bytes(sealed.to_vec().into()),
                    ),
                ],
            )
            .await
            .unwrap();
    }
    // The device behind `newer` registered again since, in the new store.
    p.put(&newer, b"new-b").await.unwrap();
    // Until moved, a deletion finds and removes rows in the registry too (D-0100).
    assert_eq!(PushStore::count_legacy(&r, &[old, newer]).await.unwrap(), 2);
    // Two `api` instances moving at once: both succeed, neither overwrites the newer row.
    let q = PushStore::connect(Db::connect(p.db().config_clone().unwrap()).await.unwrap())
        .await
        .unwrap();
    let (a, b) = tokio::join!(p.move_from_registry(&r), q.move_from_registry(&r));
    assert!(a.unwrap() + b.unwrap() >= 2);
    assert_eq!(
        p.get(&old).await.unwrap().as_deref(),
        Some(b"old-a".as_slice())
    );
    assert_eq!(
        p.get(&newer).await.unwrap().as_deref(),
        Some(b"new-b".as_slice())
    );
    // Nothing is left in the registry's database, and a second run moves nothing.
    let left = r
        .db()
        .query1("RETURN count(SELECT id FROM push_token);", Vec::new())
        .await
        .unwrap();
    assert_eq!(left, songbird_surreal::Value::Int(0));
    assert_eq!(p.move_from_registry(&r).await.unwrap(), 0);
    assert_eq!(PushStore::count_legacy(&r, &[old, newer]).await.unwrap(), 0);
    // A legacy row deleted with its device is gone and never moved back.
    r.db()
        .query(
            "UPSERT push_token:[$p] SET sealed = $s, at = time::now() RETURN NONE;",
            vec![
                (
                    "p".into(),
                    songbird_surreal::Value::Bytes([0x0c; 32].to_vec().into()),
                ),
                (
                    "s".into(),
                    songbird_surreal::Value::Bytes(b"gone".to_vec().into()),
                ),
            ],
        )
        .await
        .unwrap();
    PushStore::delete_legacy(&r, &[[0x0c; 32]]).await.unwrap();
    assert_eq!(p.move_from_registry(&r).await.unwrap(), 0);
    assert!(p.get(&[0x0c; 32]).await.unwrap().is_none());
}

#[tokio::test]
async fn grants_become_attachments_and_fetches_count_down() {
    let Some(r) = registry().await else { return };
    let d = DeviceId::random().unwrap();
    let obj = ObjectKey::random().unwrap();
    let g = Grant {
        device: d,
        size: 1 << 20,
        fetches: 2,
    };
    r.create_grant(&obj, &g, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(r.grant(&obj).await.unwrap(), Some(g));
    assert!(r.attachment(&obj).await.unwrap().is_none());
    assert!(r.complete_upload(&obj).await.unwrap());
    // A grant is used once.
    assert!(!r.complete_upload(&obj).await.unwrap());
    assert!(r.grant(&obj).await.unwrap().is_none());
    let at = r.attachment(&obj).await.unwrap().unwrap();
    assert_eq!((at.size, at.left), (1 << 20, 2));
    assert_eq!(r.count_fetch(&obj).await.unwrap(), Some(1));
    assert_eq!(r.count_fetch(&obj).await.unwrap(), Some(0));
    assert_eq!(r.count_fetch(&obj).await.unwrap(), None);
    assert!(r.attachment(&obj).await.unwrap().is_none());
    // Fully fetched attachments are swept.
    assert_eq!(r.expired_attachments(10).await.unwrap(), vec![obj]);
    r.delete_attachment(&obj).await.unwrap();
    assert!(r.expired_attachments(10).await.unwrap().is_empty());

    // Expired grants are listed and refused.
    let old = ObjectKey::random().unwrap();
    r.create_grant(&old, &g, Duration::ZERO).await.unwrap();
    assert!(r.grant(&old).await.unwrap().is_none());
    assert_eq!(r.expired_grants(10).await.unwrap(), vec![old]);
}

#[tokio::test]
async fn store_generation_only_grows_past_anything_issued() {
    let Some(r) = registry().await else { return };
    assert_eq!(r.store_generation().await.unwrap(), 1);
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let g1 = r.bump_store_generation().await.unwrap();
    assert!(g1 >= now, "jumps to at least the current time");
    let g2 = r.bump_store_generation().await.unwrap();
    assert!(g2 > g1);
    assert_eq!(r.store_generation().await.unwrap(), g2);
    // A restore (later than a millisecond) brings back an older value; the next bump still
    // passes every value issued.
    tokio::time::sleep(Duration::from_millis(5)).await;
    r.db()
        .exec("UPDATE store:g SET generation = 5 RETURN NONE;", Vec::new())
        .await
        .unwrap();
    assert!(r.bump_store_generation().await.unwrap() > g2);
}

// ----- Prompt 3, M1: registration and invites -----

use songbird_accounts::NewAccount;

fn new_account(allowance: u32) -> NewAccount {
    NewAccount {
        account: AccountId::random().unwrap(),
        identity: [9; 32],
        device: DeviceId::random().unwrap(),
        auth_key: [10; 32],
        allowance,
    }
}

fn code() -> [u8; 32] {
    let mut c = [0u8; 32];
    getrandom::fill(&mut c).unwrap();
    c
}

#[tokio::test]
async fn registration_creates_the_account_its_device_and_bumps_the_directory() {
    let Some(r) = registry().await else { return };
    let v0 = r.directory_version().await.unwrap();
    let n = new_account(5);
    r.register(&n, None).await.unwrap();
    assert!(r.directory_version().await.unwrap() > v0);
    let d = r.device(&n.device).await.unwrap().unwrap();
    assert_eq!(
        (d.account, d.key, d.disabled),
        (n.account, n.auth_key, false)
    );
    assert_eq!(r.identity_key(&n.account).await.unwrap(), Some(n.identity));
    assert_eq!(r.invite_allowance(&n.account).await.unwrap(), 5);
    // Taken IDs are refused, so the caller draws new ones.
    assert!(matches!(
        r.register(&n, None).await,
        Err(RegistryError::Exists)
    ));
}

#[tokio::test]
async fn invites_valid_expired_used_up_unknown_and_revoked() {
    let Some(r) = registry().await else { return };
    let (single, multi, short, revoked) = (code(), code(), code(), code());
    r.create_invites(&[single], 1, Duration::from_secs(3600))
        .await
        .unwrap();
    r.create_invites(&[multi], 3, Duration::from_secs(3600))
        .await
        .unwrap();
    r.create_invites(&[short], 1, Duration::from_secs(1))
        .await
        .unwrap();
    r.create_invites(&[revoked], 1, Duration::from_secs(3600))
        .await
        .unwrap();
    // A hash already stored is refused (a collision of 256-bit hashes means a reused code).
    assert!(matches!(
        r.create_invites(&[single], 1, Duration::from_secs(3600))
            .await,
        Err(RegistryError::Exists)
    ));

    // Valid, then reused.
    r.register(&new_account(0), Some(&single)).await.unwrap();
    assert_eq!(r.invite_uses(&single).await.unwrap(), None);
    assert!(matches!(
        r.register(&new_account(0), Some(&single)).await,
        Err(RegistryError::Invite)
    ));
    // Multi-use: exactly three.
    for left in [2, 1] {
        r.register(&new_account(0), Some(&multi)).await.unwrap();
        assert_eq!(r.invite_uses(&multi).await.unwrap(), Some(left));
    }
    r.register(&new_account(0), Some(&multi)).await.unwrap();
    assert!(matches!(
        r.register(&new_account(0), Some(&multi)).await,
        Err(RegistryError::Invite)
    ));
    // Expired (the row is still there until the sweep).
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let refused = new_account(0);
    assert!(matches!(
        r.register(&refused, Some(&short)).await,
        Err(RegistryError::Invite)
    ));
    // A refused registration creates nothing.
    assert_eq!(r.device(&refused.device).await.unwrap(), None);
    // Unknown, and revoked.
    assert!(matches!(
        r.register(&new_account(0), Some(&code())).await,
        Err(RegistryError::Invite)
    ));
    r.revoke_invite(&revoked).await.unwrap();
    assert!(matches!(
        r.register(&new_account(0), Some(&revoked)).await,
        Err(RegistryError::Invite)
    ));
    // The sweep removes the expired row.
    assert!(r.delete_expired_invites(100).await.unwrap() >= 1);
    let v = r
        .db()
        .query1("SELECT VALUE count() FROM invite GROUP ALL;", Vec::new())
        .await
        .unwrap();
    let left = match v {
        songbird_surreal::Value::Array(a) => a
            .first()
            .and_then(songbird_surreal::Value::as_i64)
            .unwrap_or(0),
        other => panic!("{other:?}"),
    };
    assert_eq!(left, 0);
}

/// Codes are redeemed atomically: of many registrations racing for one code, exactly as many
/// succeed as it has uses.
#[tokio::test]
async fn racing_registrations_never_exceed_a_codes_uses() {
    let Some(r) = registry().await else { return };
    let r = std::sync::Arc::new(r);
    for uses in [1u32, 5] {
        let c = code();
        r.create_invites(&[c], uses, Duration::from_secs(3600))
            .await
            .unwrap();
        let tasks: Vec<_> = (0..24)
            .map(|_| {
                let r = std::sync::Arc::clone(&r);
                tokio::spawn(async move { r.register(&new_account(0), Some(&c)).await })
            })
            .collect();
        let mut ok = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(()) => ok += 1,
                Err(RegistryError::Invite) => {}
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        assert_eq!(ok, uses, "uses {uses}");
        assert_eq!(r.invite_uses(&c).await.unwrap(), None);
    }
}

#[tokio::test]
async fn user_invites_spend_the_allowance_and_record_no_issuer() {
    let Some(r) = registry().await else { return };
    let n = new_account(2);
    r.register(&n, None).await.unwrap();
    let (a, b) = (code(), code());
    r.create_user_invite(&n.account, &a, Duration::from_secs(3600))
        .await
        .unwrap();
    r.create_user_invite(&n.account, &b, Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(matches!(
        r.create_user_invite(&n.account, &code(), Duration::from_secs(3600))
            .await,
        Err(RegistryError::Allowance)
    ));
    assert_eq!(r.invite_allowance(&n.account).await.unwrap(), 0);
    // An account the admin link created has no allowance.
    let legacy = AccountId::random().unwrap();
    r.create_account(&legacy, &[dev(3)]).await.unwrap();
    assert!(matches!(
        r.create_user_invite(&legacy, &code(), Duration::from_secs(3600))
            .await,
        Err(RegistryError::Allowance)
    ));
    assert!(r.add_invite_allowance(&legacy, 1).await.unwrap());
    r.create_user_invite(&legacy, &code(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(
        !r.add_invite_allowance(&AccountId::random().unwrap(), 1)
            .await
            .unwrap()
    );
    // The invite row holds only uses and expiry: nothing names the account that made it.
    let row = r
        .db()
        .query1(
            "SELECT * FROM ONLY invite:[$c];",
            vec![(
                "c".into(),
                songbird_surreal::Value::Bytes(bytes::Bytes::copy_from_slice(&a)),
            )],
        )
        .await
        .unwrap();
    let mut fields: Vec<String> = match row {
        songbird_surreal::Value::Map(m) => m.into_iter().map(|(k, _)| k).collect(),
        other => panic!("{other:?}"),
    };
    fields.sort();
    assert_eq!(fields, ["expires", "id", "uses"]);
    // Its single use, by someone else; then the inviter's account is deleted and nothing of the
    // invitee changes.
    let invitee = new_account(0);
    r.register(&invitee, Some(&a)).await.unwrap();
    r.delete_account_rows(&n.account).await.unwrap();
    assert!(r.device(&invitee.device).await.unwrap().is_some());
}

// ----- Prompt 3, M2: usernames -----

fn uname() -> [u8; 32] {
    code()
}

async fn registered(r: &Registry) -> NewAccount {
    let n = new_account(0);
    r.register(&n, None).await.unwrap();
    n
}

#[tokio::test]
async fn usernames_are_unique_held_after_release_and_swept() {
    let Some(r) = registry().await else { return };
    let (a, b) = (registered(&r).await, registered(&r).await);
    let (h1, h2) = (uname(), uname());
    assert_eq!(r.lookup_username(&h1).await.unwrap(), None);
    r.set_username(&a.account, &h1).await.unwrap();
    // Setting it again changes nothing; another account cannot take it.
    r.set_username(&a.account, &h1).await.unwrap();
    assert!(matches!(
        r.set_username(&b.account, &h1).await,
        Err(RegistryError::Taken)
    ));
    let row = r.lookup_username(&h1).await.unwrap().unwrap();
    assert_eq!((row.account, row.key), (a.account, None));
    assert_eq!(r.username_of(&a.account).await.unwrap(), Some(h1));
    // A changes to h2: h1 is held, for everyone (A included) and found by nobody.
    r.set_username(&a.account, &h2).await.unwrap();
    assert_eq!(r.lookup_username(&h1).await.unwrap(), None);
    assert!(matches!(
        r.set_username(&b.account, &h1).await,
        Err(RegistryError::Taken)
    ));
    assert!(matches!(
        r.set_username(&a.account, &h1).await,
        Err(RegistryError::Taken)
    ));
    // The held row names nobody.
    let held = r
        .db()
        .query1(
            "SELECT VALUE account FROM ONLY username:[$h];",
            vec![(
                "h".into(),
                songbird_surreal::Value::Bytes(bytes::Bytes::copy_from_slice(&h1)),
            )],
        )
        .await
        .unwrap();
    assert!(
        held.is_absent() || matches!(held, songbird_surreal::Value::Null),
        "{held:?}"
    );
    // Once the hold ends, B may take it, and the sweep removes ended holds.
    r.db()
        .exec(
            "UPDATE username:[$h] SET held_until = time::now() - 1s RETURN NONE;",
            vec![(
                "h".into(),
                songbird_surreal::Value::Bytes(bytes::Bytes::copy_from_slice(&h1)),
            )],
        )
        .await
        .unwrap();
    r.set_username(&b.account, &h1).await.unwrap();
    assert_eq!(
        r.lookup_username(&h1).await.unwrap().unwrap().account,
        b.account
    );
    // Delete: held again, then swept once ended.
    r.delete_username(&b.account).await.unwrap();
    assert_eq!(r.lookup_username(&h1).await.unwrap(), None);
    assert_eq!(r.username_of(&b.account).await.unwrap(), None);
    r.db()
        .exec(
            "UPDATE username SET held_until = time::now() - 1s WHERE account = NONE RETURN NONE;",
            Vec::new(),
        )
        .await
        .unwrap();
    // h1 (released by B) is the only held username; h2 is still A's.
    assert_eq!(r.delete_released_usernames(100).await.unwrap(), 1);
    assert_eq!(
        r.lookup_username(&h2).await.unwrap().unwrap().account,
        a.account
    );
}

#[tokio::test]
async fn racing_claims_for_one_username_give_it_to_one_account() {
    let Some(r) = registry().await else { return };
    let r = std::sync::Arc::new(r);
    let mut accounts = Vec::new();
    for _ in 0..16 {
        accounts.push(registered(&r).await.account);
    }
    let h = uname();
    let tasks: Vec<_> = accounts
        .iter()
        .map(|a| {
            let (r, a) = (std::sync::Arc::clone(&r), *a);
            tokio::spawn(async move { r.set_username(&a, &h).await.map(|()| a) })
        })
        .collect();
    let mut winners = Vec::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok(a) => winners.push(a),
            Err(RegistryError::Taken) => {}
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(
        r.lookup_username(&h).await.unwrap().unwrap().account,
        winners[0]
    );
}

#[tokio::test]
async fn keys_links_and_deletion() {
    let Some(r) = registry().await else { return };
    let a = registered(&r).await;
    // A link needs a username.
    assert!(matches!(
        r.put_username_link(&a.account, &[1; 16], b"ciphertext")
            .await,
        Err(RegistryError::NoUsername)
    ));
    let h = uname();
    r.set_username(&a.account, &h).await.unwrap();
    r.set_username_key(&a.account, Some(b"salt-and-verifier"))
        .await
        .unwrap();
    assert_eq!(
        r.lookup_username(&h).await.unwrap().unwrap().key.as_deref(),
        Some(&b"salt-and-verifier"[..])
    );
    r.put_username_link(&a.account, &[1; 16], b"first")
        .await
        .unwrap();
    assert_eq!(
        r.username_link(&[1; 16]).await.unwrap().as_deref(),
        Some(&b"first"[..])
    );
    // A reset: the old handle stops working.
    r.put_username_link(&a.account, &[2; 16], b"second")
        .await
        .unwrap();
    assert_eq!(r.username_link(&[1; 16]).await.unwrap(), None);
    assert_eq!(
        r.username_link(&[2; 16]).await.unwrap().as_deref(),
        Some(&b"second"[..])
    );
    // A username change drops the link (its ciphertext names the old username).
    r.set_username(&a.account, &uname()).await.unwrap();
    assert_eq!(r.username_link(&[2; 16]).await.unwrap(), None);
    r.put_username_link(&a.account, &[3; 16], b"third")
        .await
        .unwrap();
    r.set_username_key(&a.account, None).await.unwrap();
    // Once deletion starts, nobody finds the account by its username.
    let current = r.username_of(&a.account).await.unwrap().unwrap();
    assert!(r.lookup_username(&current).await.unwrap().is_some());
    let job = Job::new(Work::DeleteAccount { account: a.account }).unwrap();
    assert!(r.begin_account_deletion(&a.account, &job).await.unwrap());
    assert_eq!(r.lookup_username(&current).await.unwrap(), None);
    // Deletion: nothing names the account any more.
    r.delete_account_rows(&a.account).await.unwrap();
    let left = r.remnants(&a.account, &[a.device]).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(r.username_link(&[3; 16]).await.unwrap(), None);
}

// ----- Prompt 3, M3: the key directory -----

use songbird_accounts::KeysUpdate;

fn blob(tag: u8, id: u32, len: usize) -> Vec<u8> {
    let mut b = id.to_be_bytes().to_vec();
    b.resize(len, tag);
    b
}

fn full_update(ik: [u8; 33], first_id: u32, n: u32) -> KeysUpdate {
    KeysUpdate {
        identity: Some(ik),
        signed: Some(blob(1, 1, 101)),
        last_resort: Some(blob(2, 2, 1637)),
        one_time_ec: (first_id..first_id + n)
            .map(|i| (i, blob(3, i, 37)))
            .collect(),
        one_time_kem: (first_id..first_id + n)
            .map(|i| (i, blob(4, i, 1637)))
            .collect(),
    }
}

#[tokio::test]
async fn uploads_keep_the_identity_bound_the_store_and_refuse_duplicates() {
    let Some(r) = registry().await else { return };
    let a = registered(&r).await;
    // A first upload without its identity key and prekeys is incomplete.
    let partial = KeysUpdate {
        one_time_ec: vec![(1, blob(3, 1, 37))],
        ..KeysUpdate::default()
    };
    assert!(matches!(
        r.put_keys(&a.device, &partial, 200).await,
        Err(RegistryError::Incomplete)
    ));
    r.put_keys(&a.device, &full_update([5; 33], 0, 10), 200)
        .await
        .unwrap();
    assert_eq!(r.prekey_counts(&a.device).await.unwrap(), (10, 10));
    let keys = r.device_keys(&a.device).await.unwrap();
    assert_eq!(keys.identity, Some([5; 33]));
    // The identity key is never replaced; the same one is accepted.
    assert!(matches!(
        r.put_keys(&a.device, &full_update([6; 33], 100, 1), 200)
            .await,
        Err(RegistryError::IdentityMismatch)
    ));
    r.put_keys(&a.device, &full_update([5; 33], 100, 1), 200)
        .await
        .unwrap();
    // A duplicate ID; the bound per kind.
    assert!(matches!(
        r.put_keys(&a.device, &full_update([5; 33], 100, 1), 200)
            .await,
        Err(RegistryError::Duplicate)
    ));
    assert!(matches!(
        r.put_keys(&a.device, &full_update([5; 33], 1000, 190), 200)
            .await,
        Err(RegistryError::Full)
    ));
    // A refused upload changes nothing.
    assert_eq!(r.prekey_counts(&a.device).await.unwrap(), (11, 11));
    // Prekeys alone (no identity) once the device is complete.
    let more = KeysUpdate {
        one_time_ec: vec![(500, blob(3, 500, 37))],
        ..KeysUpdate::default()
    };
    r.put_keys(&a.device, &more, 200).await.unwrap();
    assert_eq!(r.prekey_counts(&a.device).await.unwrap(), (12, 11));
}

#[tokio::test]
async fn bundles_claim_one_time_keys_skip_the_requester_and_fall_back_to_last_resort() {
    let Some(r) = registry().await else { return };
    let alice = registered(&r).await;
    let bob = registered(&r).await;
    r.put_keys(&alice.device, &full_update([5; 33], 0, 1), 200)
        .await
        .unwrap();
    // Alice's own device is skipped.
    assert!(
        r.claim_bundles(&alice.account, None, &alice.device, true)
            .await
            .unwrap()
            .is_empty()
    );
    let b = r
        .claim_bundles(&alice.account, None, &bob.device, true)
        .await
        .unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].one_time_ec.as_deref(), Some(&blob(3, 0, 37)[..]));
    assert!(b[0].kem_one_time);
    // Nothing one-time left: no X25519 one, the last-resort ML-KEM one.
    let b = r
        .claim_bundles(&alice.account, None, &bob.device, true)
        .await
        .unwrap();
    assert_eq!(b[0].one_time_ec, None);
    assert!(!b[0].kem_one_time);
    assert_eq!(&b[0].kem[..], &blob(2, 2, 1637)[..]);
    // `one_time = false` (the target's budget spent) claims nothing.
    r.put_keys(&alice.device, &full_update([5; 33], 10, 1), 200)
        .await
        .unwrap();
    let b = r
        .claim_bundles(&alice.account, None, &bob.device, false)
        .await
        .unwrap();
    assert!(b[0].one_time_ec.is_none() && !b[0].kem_one_time);
    assert_eq!(r.prekey_counts(&alice.device).await.unwrap(), (1, 1));
    // Deletion leaves no prekey behind.
    r.delete_account_rows(&alice.account).await.unwrap();
    let left = r.remnants(&alice.account, &[alice.device]).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
}

/// **Prompt 3's gate**: no one-time prekey is ever served twice under parallel claims. 400
/// claims at once, from eight independent database connections, against 200 one-time keys of
/// each kind, three rounds: every served key is distinct, and served plus still stored is
/// always exactly what was uploaded (nothing served twice, nothing lost).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn no_one_time_prekey_is_ever_served_twice_under_parallel_claims() {
    let Some(first) = registry().await else {
        return;
    };
    let target = registered(&first).await;
    let requester = registered(&first).await;
    // Eight registries on eight connections to the same database.
    let mut conns = vec![std::sync::Arc::new(first)];
    for _ in 1..8 {
        let db = conns[0].db().config_clone().unwrap();
        conns.push(std::sync::Arc::new(
            Registry::connect(Db::connect(db).await.unwrap())
                .await
                .unwrap(),
        ));
    }
    let mut next_id = 0u32;
    for round in 0..3 {
        // 200 of each kind, in two uploads of 100.
        for _ in 0..2 {
            conns[0]
                .put_keys(&target.device, &full_update([5; 33], next_id, 100), 200)
                .await
                .unwrap();
            next_id += 100;
        }
        let tasks: Vec<_> = (0..400)
            .map(|i| {
                let r = std::sync::Arc::clone(&conns[i % conns.len()]);
                let (account, device) = (target.account, requester.device);
                tokio::spawn(async move {
                    r.claim_bundles(&account, None, &device, true)
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut ec = std::collections::HashSet::new();
        let mut kem = std::collections::HashSet::new();
        let (mut ec_served, mut kem_served) = (0u64, 0u64);
        for t in tasks {
            for b in t.await.unwrap() {
                if let Some(k) = b.one_time_ec {
                    ec_served += 1;
                    assert!(ec.insert(k), "round {round}: an X25519 prekey served twice");
                }
                if b.kem_one_time {
                    kem_served += 1;
                    assert!(
                        kem.insert(b.kem),
                        "round {round}: an ML-KEM prekey served twice"
                    );
                }
            }
        }
        let (ec_left, kem_left) = conns[0].prekey_counts(&target.device).await.unwrap();
        println!(
            "round {round}: served {ec_served} X25519 and {kem_served} ML-KEM one-time prekeys of 200 each; {ec_left} and {kem_left} left"
        );
        assert_eq!(
            ec_served + ec_left,
            200,
            "round {round}: X25519 conservation"
        );
        assert_eq!(
            kem_served + kem_left,
            200,
            "round {round}: ML-KEM conservation"
        );
        // 400 claims for 200 keys: under contention a claim may give up and serve none, but
        // nearly all keys go out.
        assert!(
            ec_served >= 190 && kem_served >= 190,
            "round {round}: too few served"
        );
        // Drain what is left so the next round starts from 200.
        while conns[0]
            .claim_bundles(&target.account, None, &requester.device, true)
            .await
            .unwrap()
            .iter()
            .any(|b| b.one_time_ec.is_some() || b.kem_one_time)
        {}
    }
}

// ----- Prompt 3, M3b: MLS KeyPackages -----

use songbird_accounts::StoredKeyPackage;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn kp(tag: u32, valid_for: i64) -> StoredKeyPackage {
    let mut reference = [0u8; 32];
    reference[..4].copy_from_slice(&tag.to_be_bytes());
    reference[4] = 0xAB;
    StoredKeyPackage {
        reference,
        package: blob(9, tag, 300),
        not_after: now_secs().checked_add_signed(valid_for).unwrap(),
    }
}

#[tokio::test]
async fn key_packages_are_single_use_expire_and_fall_back_to_last_resort() {
    let Some(r) = registry().await else { return };
    let alice = registered(&r).await;
    let bob = registered(&r).await;
    // Nothing yet: Alice's device is left out.
    assert!(
        r.claim_key_packages(&alice.account, None, &bob.device, true)
            .await
            .unwrap()
            .is_empty()
    );
    r.put_key_packages(
        &alice.device,
        &[kp(1, 3600), kp(2, -10)],
        Some(&kp(100, 3600)),
        10,
    )
    .await
    .unwrap();
    // The expired one is never served or counted.
    assert_eq!(
        r.key_package_counts(&alice.device).await.unwrap(),
        (1, true)
    );
    let c = r
        .claim_key_packages(&alice.account, None, &bob.device, true)
        .await
        .unwrap();
    assert_eq!((c.len(), c[0].one_time), (1, true));
    assert_eq!(&c[0].package[..], &kp(1, 0).package[..]);
    // Then the last-resort one, again and again.
    for _ in 0..2 {
        let c = r
            .claim_key_packages(&alice.account, None, &bob.device, true)
            .await
            .unwrap();
        assert!(!c[0].one_time);
        assert_eq!(&c[0].package[..], &kp(100, 0).package[..]);
    }
    // Duplicates by reference; the bound.
    r.put_key_packages(&alice.device, &[kp(3, 3600)], None, 10)
        .await
        .unwrap();
    assert!(matches!(
        r.put_key_packages(&alice.device, &[kp(3, 3600)], None, 10)
            .await,
        Err(RegistryError::Duplicate)
    ));
    let many: Vec<_> = (10..20).map(|i| kp(i, 3600)).collect();
    assert!(matches!(
        r.put_key_packages(&alice.device, &many, None, 10).await,
        Err(RegistryError::Full)
    ));
    // `one_time = false`: the last-resort one even with single-use ones left.
    let c = r
        .claim_key_packages(&alice.account, None, &bob.device, false)
        .await
        .unwrap();
    assert!(!c[0].one_time);
    // The sweep removes the expired row; deletion removes the rest.
    assert!(r.delete_expired_key_packages(100).await.unwrap() >= 1);
    r.delete_account_rows(&alice.account).await.unwrap();
    let left = r.remnants(&alice.account, &[alice.device]).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
}

/// The same gate for KeyPackages: 400 concurrent claims over eight connections against 200
/// single-use packages, two rounds: each served once, none twice, none lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn no_key_package_is_ever_served_twice_under_parallel_claims() {
    let Some(first) = registry().await else {
        return;
    };
    let target = registered(&first).await;
    let requester = registered(&first).await;
    let mut conns = vec![std::sync::Arc::new(first)];
    for _ in 1..8 {
        let db = conns[0].db().config_clone().unwrap();
        conns.push(std::sync::Arc::new(
            Registry::connect(Db::connect(db).await.unwrap())
                .await
                .unwrap(),
        ));
    }
    conns[0]
        .put_key_packages(&target.device, &[], Some(&kp(0, 3600)), 200)
        .await
        .unwrap();
    let mut next = 1u32;
    for round in 0..2 {
        for _ in 0..2 {
            let batch: Vec<_> = (next..next + 100).map(|i| kp(i, 3600)).collect();
            conns[0]
                .put_key_packages(&target.device, &batch, None, 200)
                .await
                .unwrap();
            next += 100;
        }
        let tasks: Vec<_> = (0..400)
            .map(|i| {
                let r = std::sync::Arc::clone(&conns[i % conns.len()]);
                let (account, device) = (target.account, requester.device);
                tokio::spawn(async move {
                    r.claim_key_packages(&account, None, &device, true)
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut seen = std::collections::HashSet::new();
        let mut served = 0u64;
        for t in tasks {
            for c in t.await.unwrap() {
                if c.one_time {
                    served += 1;
                    assert!(
                        seen.insert(c.package),
                        "round {round}: a KeyPackage served twice"
                    );
                }
            }
        }
        let (left, _) = conns[0].key_package_counts(&target.device).await.unwrap();
        println!("round {round}: served {served} single-use KeyPackages of 200; {left} left");
        assert_eq!(served + left, 200, "round {round}: conservation");
        assert!(served >= 190, "round {round}: too few served");
        while conns[0]
            .claim_key_packages(&target.account, None, &requester.device, true)
            .await
            .unwrap()
            .iter()
            .any(|c| c.one_time)
        {}
    }
}

/// Resumable grants (Prompt 6, M2, D-0081): two racing first parts record one multipart upload;
/// parts keep the grant alive, but never past its deadline; completion still uses it once.
#[tokio::test]
async fn resumable_grants_record_one_upload_and_slide_to_a_deadline() {
    let Some(r) = registry().await else { return };
    let obj = ObjectKey::random().unwrap();
    let g = Grant {
        device: DeviceId::random().unwrap(),
        size: 20 << 20,
        fetches: 1,
    };
    r.create_grant(&obj, &g, Duration::from_secs(2))
        .await
        .unwrap();
    let p = r.pending_upload(&obj).await.unwrap().unwrap();
    assert_eq!((p.grant, p.upload.clone()), (g, None));
    assert!(!format!("{p:?}").contains("upload-"));
    let (a, b) = tokio::join!(
        r.set_grant_upload(&obj, "upload-a"),
        r.set_grant_upload(&obj, "upload-b")
    );
    let (a, b) = (a.unwrap().unwrap(), b.unwrap().unwrap());
    assert_eq!(a, b, "one upload wins and both see it");
    assert_eq!(
        r.pending_upload(&obj)
            .await
            .unwrap()
            .unwrap()
            .upload
            .as_deref(),
        Some(a.as_str())
    );
    // Sliding: touched past its first expiry, the grant lives on.
    r.touch_grant(&obj, Duration::from_secs(60)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(r.grant(&obj).await.unwrap().is_some());
    // An expired grant cannot be touched back to life or given an upload.
    let gone = ObjectKey::random().unwrap();
    r.create_grant(&gone, &g, Duration::ZERO).await.unwrap();
    r.touch_grant(&gone, Duration::from_secs(60)).await.unwrap();
    assert!(r.grant(&gone).await.unwrap().is_none());
    assert_eq!(r.set_grant_upload(&gone, "x").await.unwrap(), None);
    assert!(r.complete_upload(&obj).await.unwrap());
    assert!(r.pending_upload(&obj).await.unwrap().is_none());
    // A retried completion finds the attachment: never "gone", so the caller keeps the object
    // (D-0084); an expired grant cannot complete.
    assert_eq!(
        r.finish_upload(&obj).await.unwrap(),
        songbird_accounts::UploadEnd::Attached
    );
    let late = ObjectKey::random().unwrap();
    r.create_grant(&late, &g, Duration::ZERO).await.unwrap();
    assert_eq!(
        r.finish_upload(&late).await.unwrap(),
        songbird_accounts::UploadEnd::Gone
    );
    // Part writes are counted: retries allowed, endless rewrites not.
    let counted = ObjectKey::random().unwrap();
    r.create_grant(&counted, &g, Duration::from_secs(60))
        .await
        .unwrap();
    for _ in 0..3 {
        assert!(r.spend_part(&counted, 3).await.unwrap());
    }
    assert!(!r.spend_part(&counted, 3).await.unwrap());
    assert!(!r.spend_part(&late, 3).await.unwrap(), "expired");
}
