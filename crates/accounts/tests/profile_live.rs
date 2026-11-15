//! Profiles, avatars and access keys (Prompt 3, M5, D-0054) against a real SurrealDB. Runs as
//! `registry_live` does.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::time::Duration;

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
        database: format!(
            "profile_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
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
async fn profiles_only_grow_and_access_keys_follow_devices() {
    let Some(r) = registry().await else { return };
    let a = account(&r).await;
    let b = account(&r).await;
    assert!(r.profile(&a.account).await.unwrap().is_none());
    r.put_profile(&a.account, 1, b"one", &[1; 16], false)
        .await
        .unwrap();
    for v in [0, 1] {
        assert!(matches!(
            r.put_profile(&a.account, v, b"old", &[2; 16], false).await,
            Err(RegistryError::Rollback)
        ));
    }
    r.put_profile(&a.account, 5, b"five", &[5; 16], true)
        .await
        .unwrap();
    assert_eq!(
        r.profile(&a.account).await.unwrap(),
        Some((b"five".to_vec().into(), 5))
    );
    // Access keys by device: each account once; an account without a profile has none.
    let keys = r
        .access_keys(&[a.device, b.device, DeviceId::random().unwrap(), a.device])
        .await
        .unwrap();
    assert_eq!(keys.len(), 2);
    let ka = keys.iter().find(|k| k.account == a.account).unwrap();
    assert_eq!((ka.key, ka.open), (Some([5; 16]), true));
    let kb = keys.iter().find(|k| k.account == b.account).unwrap();
    assert_eq!((kb.key, kb.open), (None, false));
    // Avatars: only the current one is served; replaced ones become stale after an hour.
    r.add_avatar(&a.account, &[1; 32]).await.unwrap();
    r.add_avatar(&a.account, &[2; 32]).await.unwrap();
    assert!(!r.avatar_current(&[1; 32]).await.unwrap());
    assert!(r.avatar_current(&[2; 32]).await.unwrap());
    assert_eq!(r.stale_avatars(10).await.unwrap(), Vec::<[u8; 32]>::new());
    r.db()
        .exec(
            "UPDATE avatar SET at = time::now() - 2h RETURN NONE;",
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(r.stale_avatars(10).await.unwrap(), vec![[1; 32]]);
    r.delete_avatar(&[1; 32]).await.unwrap();
    let mut all = r.avatars_of(&a.account).await.unwrap();
    all.sort_unstable();
    assert_eq!(all, vec![[2; 32]]);
}

#[tokio::test]
async fn admin_created_accounts_take_profiles_too() {
    let Some(r) = registry().await else { return };
    let a = AccountId::random().unwrap();
    let d = DeviceId::random().unwrap();
    r.create_account(&a, &[(d, [4; 32])]).await.unwrap();
    let res = r.put_profile(&a, 1, b"x", &[1; 16], false).await;
    assert!(res.is_ok(), "{res:?}");
}
