//! Entitlements in the registry (Prompt 11, M1, D-0127) against a real SurrealDB. Runs when
//! `SONGBIRD_TEST_SURREALDB` and `SONGBIRD_TEST_SURREALDB_PASS` are set; with
//! `SONGBIRD_REQUIRE_SURREALDB=1` a missing server fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::time::Duration;

use songbird_accounts::entitlements::Source;
use songbird_accounts::{Db, Registry, RegistryError};
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
        database: format!("ent_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    Some(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    )
}

async fn account(r: &Registry) -> AccountId {
    let a = AccountId::random().unwrap();
    r.create_account(&a, &[(DeviceId::random().unwrap(), [7; 32])])
        .await
        .unwrap();
    a
}

#[tokio::test]
async fn entitlements_are_set_extended_revoked_and_swept_with_the_version() {
    let Some(r) = registry().await else { return };
    let today = 20_000;
    let a = account(&r).await;
    let b = account(&r).await;
    let v0 = r.entitlements_version().await.unwrap();
    assert_eq!(r.entitlements(today).await.unwrap(), Vec::new());

    // A grant sets the row exactly and bumps the version.
    r.set_entitlement(&a, 1, today + 30, Source::Grant)
        .await
        .unwrap();
    let v1 = r.entitlements_version().await.unwrap();
    assert!(v1 > v0);
    let rows = r.entitlements(today).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].account, rows[0].level, rows[0].last_day),
        (a, 1, today + 30)
    );
    assert_eq!(rows[0].source, Source::Grant);

    // An extension keeps the later day and the higher level while the row is held.
    let e = r
        .extend_entitlement(&a, 1, today + 10, today, Source::Token)
        .await
        .unwrap();
    assert_eq!((e.level, e.last_day), (1, today + 30), "never shortened");
    let e = r
        .extend_entitlement(&a, 1, today + 60, today, Source::Token)
        .await
        .unwrap();
    assert_eq!(e.last_day, today + 60);
    assert_eq!(e.source, Source::Token);
    // ... and replaces a lapsed one.
    r.set_entitlement(&b, 1, today - 5, Source::Grant)
        .await
        .unwrap();
    assert!(
        r.entitlements(today)
            .await
            .unwrap()
            .iter()
            .all(|x| x.account != b)
    );
    let e = r
        .extend_entitlement(&b, 1, today + 3, today, Source::Token)
        .await
        .unwrap();
    assert_eq!(e.last_day, today + 3);

    // Level 0 is never stored; an unknown account is refused.
    assert!(matches!(
        r.set_entitlement(&a, 0, today, Source::Grant).await,
        Err(RegistryError::Shape)
    ));
    assert!(matches!(
        r.set_entitlement(&AccountId::random().unwrap(), 1, today, Source::Grant)
            .await,
        Err(RegistryError::NotFound)
    ));

    // Revocation and the sweep bump the version; the sweep removes only lapsed rows.
    let v2 = r.entitlements_version().await.unwrap();
    r.revoke_entitlement(&a).await.unwrap();
    assert!(r.entitlements_version().await.unwrap() > v2);
    assert!(r.entitlement_of(&a).await.unwrap().is_none());
    r.revoke_entitlement(&a).await.unwrap();
    assert_eq!(r.sweep_entitlements(today).await.unwrap(), 0);
    let v3 = r.entitlements_version().await.unwrap();
    assert_eq!(
        r.sweep_entitlements(today + 4).await.unwrap(),
        1,
        "b lapsed"
    );
    assert!(r.entitlements_version().await.unwrap() > v3);
    assert!(r.entitlement_of(&b).await.unwrap().is_none());
}

#[tokio::test]
async fn deleting_the_account_deletes_its_entitlement() {
    let Some(r) = registry().await else { return };
    let a = account(&r).await;
    r.set_entitlement(&a, 1, 30_000, Source::Grant)
        .await
        .unwrap();
    let export = r.export(&a, None).await.unwrap();
    assert_eq!(export["plan"]["level"], 1);
    assert_eq!(export["plan"]["source"], "grant");
    r.delete_account_rows(&a).await.unwrap();
    assert!(r.entitlement_of(&a).await.unwrap().is_none());
    assert_eq!(r.remnants(&a, &[]).await.unwrap().entitlements, 0);
}
