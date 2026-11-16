//! What key transparency must publish (Prompt 3, D-0057) against a real SurrealDB: each change
//! reported once, under a salt stored first, and nothing once published; deletion removes the salt.
//! (Publishing to akd and its proofs: `songbird-akd` `akd_live`.) Runs as `registry_live` does.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::time::Duration;

use songbird_accounts::devices::ListEntry;
use songbird_accounts::kt::KtKind;
use songbird_accounts::{Db, KeysUpdate, NewAccount, Registry};
use songbird_jobs::{Job, Work};
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
        database: format!("kt_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    Some(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    )
}

fn sha(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref());
    out
}

async fn publish_all(r: &Registry) -> Vec<(KtKind, [u8; 32])> {
    let mut out = Vec::new();
    for p in r.kt_pending(100).await.unwrap() {
        out.extend(p.changes.iter().copied());
        r.kt_logged(&p).await.unwrap();
    }
    out
}

#[tokio::test]
async fn each_change_is_reported_once_under_a_stored_salt_and_deletion_unlinks() {
    let Some(r) = registry().await else { return };
    let n = NewAccount {
        account: AccountId::random().unwrap(),
        identity: [9; 32],
        device: DeviceId::random().unwrap(),
        auth_key: [3; 32],
        allowance: 0,
    };
    r.register(&n, None).await.unwrap();
    assert!(r.kt_salt(&n.account).await.unwrap().is_none());
    // The registration's identity key; the salt is stored before it is reported.
    let pending = r.kt_pending(100).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].changes, vec![(KtKind::Identity, sha(&[9; 32]))]);
    assert_eq!(r.kt_salt(&n.account).await.unwrap(), Some(pending[0].salt));
    // Reported again until marked, with the same salt.
    let again = r.kt_pending(100).await.unwrap();
    assert_eq!(again[0].salt, pending[0].salt);
    r.kt_logged(&pending[0]).await.unwrap();
    assert!(r.kt_pending(100).await.unwrap().is_empty(), "nothing new");
    // A username, then a device list and the username's release: only what changed.
    r.set_username(&n.account, &[7; 32]).await.unwrap();
    assert_eq!(publish_all(&r).await, vec![(KtKind::Username, [7; 32])]);
    let mut ik = [1u8; 33];
    ik[0] = 5;
    r.put_keys(
        &n.device,
        &KeysUpdate {
            identity: Some(ik),
            signed: Some(vec![1]),
            last_resort: Some(vec![2]),
            ..KeysUpdate::default()
        },
        10,
    )
    .await
    .unwrap();
    let entry = ListEntry {
        device: n.device,
        auth_key: n.auth_key,
        identity: ik,
        primary: true,
    };
    let job = Job::new(Work::DeleteDevices { account: n.account }).unwrap();
    r.put_device_list(&n.account, 1, &[entry], b"list-v1", &job)
        .await
        .unwrap();
    r.delete_username(&n.account).await.unwrap();
    let mut got = publish_all(&r).await;
    got.sort_by_key(|(k, _)| format!("{k:?}"));
    assert_eq!(
        got,
        vec![
            (KtKind::DeviceList, sha(b"list-v1")),
            (KtKind::Username, [0; 32])
        ]
    );
    // A change made while a pass is publishing is not lost: the generation moved on.
    r.set_username(&n.account, &[8; 32]).await.unwrap();
    let racing = r.kt_pending(100).await.unwrap();
    r.set_username(&n.account, &[6; 32]).await.unwrap();
    r.kt_logged(&racing[0]).await.unwrap();
    assert_eq!(publish_all(&r).await, vec![(KtKind::Username, [6; 32])]);
    // Deleting the account deletes its salt: its directory entries name no one.
    let del = Job::new(Work::DeleteAccount { account: n.account }).unwrap();
    r.begin_account_deletion(&n.account, &del).await.unwrap();
    assert!(r.kt_salt(&n.account).await.unwrap().is_none());
    r.delete_account_rows(&n.account).await.unwrap();
    assert!(r.kt_salt(&n.account).await.unwrap().is_none());
}
