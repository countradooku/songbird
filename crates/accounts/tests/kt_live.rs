//! Key transparency storage (Prompt 3, M6, D-0055) against a real SurrealDB: changes are logged
//! once, proofs verify against the stored tree, concurrent appends keep one consistent log, and a
//! deleted account's entries become unlinkable. Runs as `registry_live` does.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use songbird_accounts::devices::ListEntry;
use songbird_accounts::{Db, KeysUpdate, NewAccount, Registry};
use songbird_jobs::{Job, Work};
use songbird_kt::{Kind, Leaf, MemoryStore, verify_consistency, verify_inclusion};
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

async fn check_entries(r: &Registry, a: &AccountId, kinds: &[Kind]) {
    let size = r.kt_size().await.unwrap();
    let root = r.kt_root(size).await.unwrap();
    let (salt, entries) = r.kt_account(a, size, 100).await.unwrap().unwrap();
    let subject = songbird_kt::subject(&salt, a.as_bytes());
    assert_eq!(
        entries.iter().map(|e| e.leaf.kind).collect::<Vec<_>>(),
        kinds
    );
    for e in &entries {
        assert_eq!(e.leaf.subject, subject);
        assert_eq!(
            verify_inclusion(&e.leaf.hash(), e.index, size, &e.proof, &root),
            Ok(())
        );
    }
}

#[tokio::test]
async fn changes_are_logged_once_with_proofs_and_deletion_unlinks() {
    let Some(r) = registry().await else { return };
    let n = NewAccount {
        account: AccountId::random().unwrap(),
        identity: [9; 32],
        device: DeviceId::random().unwrap(),
        auth_key: [3; 32],
        allowance: 0,
    };
    r.register(&n, None).await.unwrap();
    assert_eq!(r.kt_reconcile(100, 1).await.unwrap(), 1);
    assert_eq!(r.kt_reconcile(100, 2).await.unwrap(), 0, "nothing new");
    check_entries(&r, &n.account, &[Kind::Identity]).await;
    let (_, e) = r
        .kt_account(&n.account, r.kt_size().await.unwrap(), 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e[0].leaf.value, songbird_kt::sha256(&[9; 32]));
    let old = (
        r.kt_size().await.unwrap(),
        r.kt_root(r.kt_size().await.unwrap()).await.unwrap(),
    );
    // A username, then a device list, then the username released.
    r.set_username(&n.account, &[7; 32]).await.unwrap();
    assert_eq!(r.kt_reconcile(100, 3).await.unwrap(), 1);
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
    // Both changes since the last pass: the list and the release, once each.
    assert_eq!(r.kt_reconcile(100, 4).await.unwrap(), 2);
    check_entries(
        &r,
        &n.account,
        &[
            Kind::Identity,
            Kind::Username,
            Kind::DeviceList,
            Kind::Username,
        ],
    )
    .await;
    // The log only grew: the old head is consistent with the new one.
    let size = r.kt_size().await.unwrap();
    let p = r.kt_consistency(old.0, size).await.unwrap();
    assert_eq!(
        verify_consistency(old.0, size, &old.1, &r.kt_root(size).await.unwrap(), &p),
        Ok(())
    );
    // Deleting the account deletes its salt: its entries stay in the log but name no one.
    let del = Job::new(Work::DeleteAccount { account: n.account }).unwrap();
    r.begin_account_deletion(&n.account, &del).await.unwrap();
    assert!(r.kt_account(&n.account, size, 10).await.unwrap().is_none());
    r.delete_account_rows(&n.account).await.unwrap();
    assert!(r.kt_account(&n.account, size, 10).await.unwrap().is_none());
    assert_eq!(r.kt_size().await.unwrap(), size, "the log is append-only");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_appends_keep_one_consistent_log() {
    let Some(first) = registry().await else {
        return;
    };
    let mut conns = vec![Arc::new(first)];
    for _ in 1..8 {
        let cfg = conns[0].db().config_clone().unwrap();
        conns.push(Arc::new(
            Registry::connect(Db::connect(cfg).await.unwrap())
                .await
                .unwrap(),
        ));
    }
    let tasks: Vec<_> = (0..160u64)
        .map(|i| {
            let r = Arc::clone(&conns[usize::try_from(i).unwrap() % conns.len()]);
            tokio::spawn(async move {
                let leaf = Leaf {
                    kind: Kind::Identity,
                    subject: [u8::try_from(i % 256).unwrap(); 32],
                    value: songbird_kt::sha256(&i.to_be_bytes()),
                    time_ms: i,
                };
                (r.kt_append(&leaf).await.unwrap(), leaf)
            })
        })
        .collect();
    let mut placed = Vec::new();
    for t in tasks {
        placed.push(t.await.unwrap());
    }
    placed.sort_by_key(|p| p.0);
    // Every append got its own index, 0..160 with no gap or repeat.
    assert_eq!(
        placed.iter().map(|p| p.0).collect::<Vec<_>>(),
        (0..160).collect::<Vec<_>>()
    );
    let r = &conns[0];
    assert_eq!(r.kt_size().await.unwrap(), 160);
    // The stored tree equals the tree of those leaves in that order.
    let mut mem = MemoryStore::default();
    for (_, l) in &placed {
        mem.append(l.hash()).unwrap();
    }
    assert_eq!(
        r.kt_root(160).await.unwrap(),
        songbird_kt::root(&mem, 160).unwrap()
    );
    for m in [1, 7, 64, 100, 159] {
        let p = r.kt_consistency(m, 160).await.unwrap();
        assert_eq!(
            verify_consistency(
                m,
                160,
                &songbird_kt::root(&mem, m).unwrap(),
                &r.kt_root(160).await.unwrap(),
                &p
            ),
            Ok(())
        );
    }
}
