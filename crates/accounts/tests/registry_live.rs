//! The registry against a real SurrealDB. Runs when `SONGBIRD_TEST_SURREALDB` (`host:port`) and
//! `SONGBIRD_TEST_SURREALDB_PASS` are set; with `SONGBIRD_REQUIRE_SURREALDB=1` a missing server
//! fails instead of skipping. Every test uses a database of its own.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    reason = "tests"
)]

use std::time::Duration;

use songbird_accounts::{Db, Grant, Registry, RegistryError, push_index};
use songbird_jobs::{Job, ObjectKey, Outbox as _, Work};
use songbird_types::{AccountId, DeviceId};

async fn registry() -> Option<Registry> {
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
            "accounts_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    };
    Some(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    )
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
    let secret = [7u8; 32];
    let a = AccountId::random().unwrap();
    let (d1, d2) = (dev(1), dev(2));
    r.create_account(&a, &[d1, d2]).await.unwrap();
    let other = AccountId::random().unwrap();
    let d3 = dev(3);
    r.create_account(&other, &[d3]).await.unwrap();
    for d in [d1.0, d2.0, d3.0] {
        r.put_push_token(&push_index(&secret, &d), b"sealed")
            .await
            .unwrap();
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
    let before = r.remnants(&a, &devices, &index).await.unwrap();
    assert_eq!(before.account, 1);
    assert_eq!(before.devices, 2);
    assert_eq!(before.push_tokens, 2);
    assert_eq!(before.grants, 1);
    r.delete_push_tokens(&index).await.unwrap();
    for g in r.grants_of(&devices).await.unwrap() {
        r.delete_grant(&g).await.unwrap();
    }
    r.delete_account_rows(&a).await.unwrap();
    assert!(r.remnants(&a, &devices, &index).await.unwrap().is_empty());
    // The other account is untouched.
    assert!(r.device(&d3.0).await.unwrap().is_some());
    assert!(
        r.push_token(&push_index(&secret, &d3.0))
            .await
            .unwrap()
            .is_some()
    );
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
