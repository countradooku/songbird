//! Support tickets and legal counts (Prompt 11, M6, D-0132) against a real SurrealDB. Runs when
//! `SONGBIRD_TEST_SURREALDB` and `SONGBIRD_TEST_SURREALDB_PASS` are set; with
//! `SONGBIRD_REQUIRE_SURREALDB=1` a missing server fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::time::Duration;

use songbird_accounts::support::MAX_MESSAGES;
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
        database: format!("sup_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    Some(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn a_ticket_is_read_only_with_its_bearer_and_goes_entirely_at_close() {
    let Some(r) = registry().await else { return };
    let today = 20_000;
    let acct = AccountId::random().unwrap();
    let (id, bearer, reply) = ([1u8; 16], [2u8; 32], [3u8; 32]);
    r.ticket_open(
        &id,
        "appeal",
        &bearer,
        &reply,
        Some(&acct),
        true,
        b"sealed-1",
        today,
    )
    .await
    .unwrap();
    assert!(matches!(
        r.ticket_open(&id, "help", &bearer, &reply, None, false, b"x", today)
            .await,
        Err(RegistryError::Exists)
    ));
    // A wrong bearer reads nothing and writes nothing; the same as no ticket at all.
    for wrong in [[9u8; 32], [0u8; 32]] {
        assert!(matches!(
            r.ticket_read(&id, Some(&wrong)).await,
            Err(RegistryError::NotFound)
        ));
        assert!(matches!(
            r.ticket_post(&id, Some(&wrong), b"x", today).await,
            Err(RegistryError::NotFound)
        ));
        assert!(matches!(
            r.ticket_close(&id, Some(&wrong)).await,
            Err(RegistryError::NotFound)
        ));
    }
    assert!(matches!(
        r.ticket_read(&[7; 16], Some(&bearer)).await,
        Err(RegistryError::NotFound)
    ));
    r.ticket_post(&id, None, b"staff-1", today + 1)
        .await
        .unwrap();
    r.ticket_post(&id, Some(&bearer), b"sealed-2", today + 2)
        .await
        .unwrap();
    let (kind, msgs) = r.ticket_read(&id, Some(&bearer)).await.unwrap();
    assert_eq!(kind, "appeal");
    let seen: Vec<_> = msgs
        .iter()
        .map(|m| (m.from.as_str(), m.sealed.as_ref(), m.day))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("user", b"sealed-1".as_slice(), today),
            ("staff", b"staff-1".as_slice(), today + 1),
            ("user", b"sealed-2".as_slice(), today + 2)
        ]
    );
    // Staff list it, priority first.
    r.ticket_open(
        &[4; 16], "help", &[5; 32], &[6; 32], None, false, b"anon", today,
    )
    .await
    .unwrap();
    let list = r.tickets(10).await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, id);
    assert_eq!(list[0].account, Some(acct));
    assert!(list[0].priority);
    assert_eq!(list[0].messages, 3);
    assert_eq!(list[0].touched, today + 2);
    assert_eq!(list[0].reply_key, reply);
    assert_eq!(list[1].account, None);
    // Closed by its user: ticket and messages gone.
    r.ticket_close(&id, Some(&bearer)).await.unwrap();
    assert!(matches!(
        r.ticket_read(&id, None).await,
        Err(RegistryError::NotFound)
    ));
    assert_eq!(r.tickets(10).await.unwrap().len(), 1);
    // The sweep takes the untouched one.
    r.sweep_tickets(today).await.unwrap();
    assert_eq!(r.tickets(10).await.unwrap().len(), 1);
    r.sweep_tickets(today + 1).await.unwrap();
    assert_eq!(r.tickets(10).await.unwrap().len(), 0);
    assert!(matches!(
        r.ticket_read(&[4; 16], None).await,
        Err(RegistryError::NotFound)
    ));
}

#[tokio::test]
async fn a_ticket_holds_a_bounded_number_of_messages() {
    let Some(r) = registry().await else { return };
    let (id, bearer) = ([8u8; 16], [8u8; 32]);
    r.ticket_open(&id, "help", &bearer, &[1; 32], None, false, b"0", 1)
        .await
        .unwrap();
    for _ in 1..MAX_MESSAGES {
        r.ticket_post(&id, Some(&bearer), b"m", 1).await.unwrap();
    }
    assert!(matches!(
        r.ticket_post(&id, None, b"m", 1).await,
        Err(RegistryError::Full)
    ));
    assert_eq!(
        r.ticket_read(&id, None).await.unwrap().1.len(),
        usize::try_from(MAX_MESSAGES).unwrap()
    );
}

#[tokio::test]
async fn legal_requests_leave_counts_only() {
    let Some(r) = registry().await else { return };
    for _ in 0..3 {
        r.count_legal("2026-H2", "DE", "data", "rejected")
            .await
            .unwrap();
    }
    r.count_legal("2026-H2", "NL", "data", "disclosed")
        .await
        .unwrap();
    r.count_legal("2026-H1", "DE", "data", "rejected")
        .await
        .unwrap();
    let mut c = r.legal_counts("2026-H2").await.unwrap();
    c.sort();
    assert_eq!(
        c,
        vec![
            ("DE".into(), "data".into(), "rejected".into(), 3),
            ("NL".into(), "data".into(), "disclosed".into(), 1)
        ]
    );
    assert_eq!(r.legal_counts("2025-H1").await.unwrap().len(), 0);
}

#[tokio::test]
async fn the_export_lists_attached_tickets_and_deletion_unlinks_them() {
    let Some(r) = registry().await else { return };
    let a = AccountId::random().unwrap();
    r.create_account(&a, &[(DeviceId::random().unwrap(), [7; 32])])
        .await
        .unwrap();
    r.set_standing(&a, "limited", Some(20_007), "reports", "auto")
        .await
        .unwrap();
    r.ticket_open(
        &[1; 16],
        "appeal",
        &[2; 32],
        &[3; 32],
        Some(&a),
        false,
        b"s",
        20_000,
    )
    .await
    .unwrap();
    r.ticket_open(
        &[4; 16], "help", &[5; 32], &[6; 32], None, false, b"s", 20_000,
    )
    .await
    .unwrap();
    let e = r.export(&a, None).await.unwrap();
    assert_eq!(e["standing"]["kind"], "limited");
    assert_eq!(e["standing"]["reason"], "reports");
    let t = e["support_tickets"].as_array().unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0]["id"], hex::encode([1u8; 16]));
    assert_eq!(t[0]["kind"], "appeal");
    // The export never carries a bearer, a reply key or a message.
    let text = e.to_string();
    for secret in [hex::encode([2u8; 32]), hex::encode([3u8; 32])] {
        assert!(!text.contains(&secret));
    }
    r.delete_account_rows(&a).await.unwrap();
    assert_eq!(r.tickets_of(&a).await.unwrap().len(), 0);
    assert_eq!(r.tickets(10).await.unwrap().len(), 2);
}
