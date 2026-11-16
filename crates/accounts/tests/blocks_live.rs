//! Blocks and the message-request policy (Prompt 4, M4, D-0062) against a real SurrealDB. Runs
//! as `registry_live` does.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::time::Duration;

use songbird_accounts::blocks::{GateKeys, MAX_BLOCKS};
use songbird_accounts::{Db, NewAccount, Registry, RegistryError};
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
        database: format!("blocks_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    Some(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    )
}

async fn account(r: &Registry) -> NewAccount {
    let n = NewAccount {
        account: AccountId::random().unwrap(),
        identity: [9; 32],
        device: DeviceId::random().unwrap(),
        auth_key: [3; 32],
        allowance: 0,
    };
    r.register(&n, None).await.unwrap();
    n
}

#[tokio::test]
async fn blocks_are_keyed_pairs_bounded_per_owner_and_deleted_with_it() {
    let Some(r) = registry().await else { return };
    let keys = GateKeys::from_cluster_secret(&[5; 32]).unwrap();
    let a = account(&r).await.account;
    let b = account(&r).await.account;
    let owner = keys.owner(&a);
    let pair = keys.pair(&a, &b);
    assert!(!r.is_blocked(&pair).await.unwrap());
    r.add_block(&owner, &pair).await.unwrap();
    // Idempotent; the reverse pair is another row.
    r.add_block(&owner, &pair).await.unwrap();
    assert!(r.is_blocked(&pair).await.unwrap());
    assert!(!r.is_blocked(&keys.pair(&b, &a)).await.unwrap());
    assert_eq!(r.block_count(&owner).await.unwrap(), 1);
    r.remove_block(&owner, &pair).await.unwrap();
    assert!(!r.is_blocked(&pair).await.unwrap());
    // The limit per owner, under concurrency: never more than MAX_BLOCKS.
    let mut tasks = Vec::new();
    let r = std::sync::Arc::new(r);
    for i in 0..MAX_BLOCKS + 20 {
        let (r, keys) = (std::sync::Arc::clone(&r), keys.clone());
        tasks.push(tokio::spawn(async move {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            let target = AccountId::from_bytes(id);
            r.add_block(&owner, &keys.pair(&a, &target)).await
        }));
    }
    let mut full = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(()) => {}
            Err(RegistryError::Full | RegistryError::Db(_)) => full += 1,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(full >= 20);
    let n = r.block_count(&owner).await.unwrap();
    assert!(n <= MAX_BLOCKS, "{n}");
    // Deleting the owner's rows (account deletion) leaves none, and nobody else's.
    let other = keys.owner(&b);
    r.add_block(&other, &keys.pair(&b, &a)).await.unwrap();
    assert_eq!(r.delete_blocks(&owner).await.unwrap(), n);
    assert_eq!(r.block_count(&owner).await.unwrap(), 0);
    assert_eq!(r.block_count(&other).await.unwrap(), 1);
}

#[tokio::test]
async fn the_request_policy_and_profiles_reach_the_directory_snapshot() {
    let Some(r) = registry().await else { return };
    let a = account(&r).await.account;
    let v0 = r.directory_version().await.unwrap();
    assert!(!r.requests_off(&a).await.unwrap());
    r.set_requests_off(&a, true).await.unwrap();
    assert!(r.requests_off(&a).await.unwrap());
    let v1 = r.directory_version().await.unwrap();
    assert!(v1 > v0, "a policy change reloads every node's directory");
    r.put_profile(&a, 1, b"p", &[7; 16], true).await.unwrap();
    assert!(
        r.directory_version().await.unwrap() > v1,
        "so does a profile"
    );
    let row = r
        .load_access()
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.account == a)
        .unwrap();
    assert_eq!(row.key, Some([7; 16]));
    assert!(row.open && row.requests_off);
}

#[tokio::test]
async fn only_the_primary_opens_an_account_to_anyone() {
    let Some(r) = registry().await else { return };
    let a = account(&r).await.account;
    // A linked device may set a closed profile...
    r.put_profile_as(&a, 1, b"p", &[1; 16], false, false)
        .await
        .unwrap();
    // ...but not open the account (loosening is the primary's, D-0058).
    assert!(matches!(
        r.put_profile_as(&a, 2, b"p", &[1; 16], true, false).await,
        Err(RegistryError::NotPrimary)
    ));
    r.put_profile_as(&a, 2, b"p", &[1; 16], true, true)
        .await
        .unwrap();
    // Once open, a linked device may keep it open or close it.
    r.put_profile_as(&a, 3, b"p", &[1; 16], true, false)
        .await
        .unwrap();
    r.put_profile_as(&a, 4, b"p", &[1; 16], false, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_node_with_another_requests_secret_is_detected() {
    let Some(r) = registry().await else { return };
    let ours = GateKeys::from_cluster_secret(&[5; 32])
        .unwrap()
        .fingerprint();
    let theirs = GateKeys::from_cluster_secret(&[6; 32])
        .unwrap()
        .fingerprint();
    assert!(r.pin_fingerprint("requests", &ours).await.unwrap());
    assert!(r.pin_fingerprint("requests", &ours).await.unwrap());
    assert!(!r.pin_fingerprint("requests", &theirs).await.unwrap());
}
