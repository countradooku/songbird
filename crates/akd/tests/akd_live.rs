//! akd on SurrealDB (Prompt 3, D-0057): epochs published by the writer, read by a separate
//! reader, every proof checked with akd's own client verification (lookup, key history, audit),
//! and the store's semantics. Runs when `SONGBIRD_TEST_SURREALDB` is set, like `registry_live`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use akd::storage::Database;
use akd::storage::types::{DbRecord, ValueStateRetrievalFlag};
use akd::verify::history::{HistoryParams, HistoryVerificationParams};
use akd::{AkdLabel, AkdValue};
use songbird_accounts::Db;
use songbird_akd::{Config, Kind, SecretVrf, SurrealStore, label, value};
use songbird_types::DeviceId;

/// A second connection to the same database (another writer process).
async fn store_same_db(cfg: &songbird_surreal::Config) -> SurrealStore {
    SurrealStore::connect(Arc::new(Db::connect(cfg.clone()).await.unwrap()))
        .await
        .unwrap()
}

async fn store() -> Option<SurrealStore> {
    store_cfg().await.map(|(s, _)| s)
}

async fn store_cfg() -> Option<(SurrealStore, songbird_surreal::Config)> {
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
        database: format!("akd_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    let db = Db::connect(cfg.clone()).await.unwrap();
    Some((SurrealStore::connect(Arc::new(db)).await.unwrap(), cfg))
}

fn account(b: u8) -> [u8; 16] {
    [b; 16]
}

const SALT: [u8; 32] = [0x5a; 32];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn published_epochs_verify_with_akds_own_client_checks() {
    let Some(s) = store().await else { return };
    let vrf = SecretVrf::new(&[0x71; 32]);
    let writer = songbird_akd::writer(s.clone(), vrf.clone()).await.unwrap();
    let vrf_public = writer.get_public_key().await.unwrap();
    let vpk = vrf_public.as_bytes().to_vec();
    // Epoch 1: two accounts' identity keys; epoch 2: a device list and a key change.
    let alice = label(Kind::Identity, &account(1));
    let bob = label(Kind::Identity, &account(2));
    let alice_list = label(Kind::DeviceList, &account(1));
    let e1 = writer
        .publish(vec![
            (alice.clone(), value(&SALT, Kind::Identity, &[0xA1; 32])),
            (bob.clone(), value(&SALT, Kind::Identity, &[0xB1; 32])),
        ])
        .await
        .unwrap();
    let e2 = writer
        .publish(vec![
            (
                alice_list.clone(),
                value(&SALT, Kind::Identity, &[0xA2; 32]),
            ),
            (bob.clone(), value(&SALT, Kind::Identity, &[0xB2; 32])),
        ])
        .await
        .unwrap();
    assert_eq!((e1.epoch(), e2.epoch()), (1, 2));

    // A separate reader (another api node) sees epoch 2 and serves proofs.
    let reader = songbird_akd::reader(s.clone(), vrf.clone()).await.unwrap();
    let (proof, head) = reader.lookup(bob.clone()).await.unwrap();
    assert_eq!(head.epoch(), 2);
    let r = akd::client::lookup_verify::<Config>(
        &vpk,
        head.hash(),
        head.epoch(),
        bob.clone(),
        proof.clone(),
    )
    .unwrap();
    assert_eq!(r.value, value(&SALT, Kind::Identity, &[0xB2; 32]));
    assert_eq!(r.version, 2);
    // The same proof for another label, against another root, or for a later epoch fails.
    assert!(
        akd::client::lookup_verify::<Config>(
            &vpk,
            head.hash(),
            head.epoch(),
            alice.clone(),
            proof.clone()
        )
        .is_err()
    );
    assert!(
        akd::client::lookup_verify::<Config>(
            &vpk,
            e1.hash(),
            head.epoch(),
            bob.clone(),
            proof.clone()
        )
        .is_err()
    );
    let other_vrf = SecretVrf::new(&[0x72; 32]);
    let other_writer = songbird_akd::writer(store().await.unwrap(), other_vrf)
        .await
        .unwrap();
    let other_vpk = other_writer
        .get_public_key()
        .await
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(
        akd::client::lookup_verify::<Config>(
            &other_vpk,
            head.hash(),
            head.epoch(),
            bob.clone(),
            proof
        )
        .is_err()
    );
    // Bob's key history shows both keys, newest first.
    let (hist, hhead) = reader
        .key_history(&bob, HistoryParams::Complete)
        .await
        .unwrap();
    let results = akd::client::key_history_verify::<Config>(
        &vpk,
        hhead.hash(),
        hhead.epoch(),
        bob.clone(),
        hist,
        HistoryVerificationParams::default(),
    )
    .unwrap();
    let values: Vec<AkdValue> = results.iter().map(|r| r.value.clone()).collect();
    assert_eq!(
        values,
        vec![
            value(&SALT, Kind::Identity, &[0xB2; 32]),
            value(&SALT, Kind::Identity, &[0xB1; 32])
        ]
    );
    // A label never published: lookup refuses (non-membership is akd's to prove in history).
    assert!(
        reader
            .lookup(label(Kind::Username, &account(9)))
            .await
            .is_err()
    );
    // The directory only grew: an audit proof from epoch 1 to 2 verifies against both roots.
    let audit = reader.audit(1, 2).await.unwrap();
    akd::auditor::audit_verify::<Config>(vec![e1.hash(), e2.hash()], audit.clone())
        .await
        .unwrap();
    // A rewritten history (another root for epoch 1) fails the audit.
    assert!(
        akd::auditor::audit_verify::<Config>(vec![e2.hash(), e2.hash()], audit)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_keeps_akds_semantics() {
    let Some(s) = store().await else { return };
    let vrf = SecretVrf::new(&[0x73; 32]);
    let writer = songbird_akd::writer(s.clone(), vrf).await.unwrap();
    let l = label(Kind::DeviceList, &account(3));
    for i in 1..=3u8 {
        writer
            .publish(vec![(l.clone(), value(&SALT, Kind::Identity, &[i; 32]))])
            .await
            .unwrap();
    }
    // Versions 1..3 at epochs 1..3.
    let data = s.get_user_data(&l).await.unwrap();
    assert_eq!(
        data.states
            .iter()
            .map(|st| (st.version, st.epoch))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 2), (3, 3)]
    );
    let at = |f| {
        let s = s.clone();
        let l = l.clone();
        async move { s.get_user_state(&l, f).await.map(|st| st.version) }
    };
    assert_eq!(at(ValueStateRetrievalFlag::MaxEpoch).await.unwrap(), 3);
    assert_eq!(at(ValueStateRetrievalFlag::MinEpoch).await.unwrap(), 1);
    assert_eq!(
        at(ValueStateRetrievalFlag::SpecificVersion(2))
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        at(ValueStateRetrievalFlag::SpecificEpoch(3)).await.unwrap(),
        3
    );
    assert_eq!(at(ValueStateRetrievalFlag::LeqEpoch(2)).await.unwrap(), 2);
    assert!(
        at(ValueStateRetrievalFlag::SpecificVersion(9))
            .await
            .is_err()
    );
    let versions = s
        .get_user_state_versions(
            &[l.clone(), AkdLabel(vec![9; 33])],
            ValueStateRetrievalFlag::MaxEpoch,
        )
        .await
        .unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[&l].0, 3);
    assert!(s.get_user_data(&AkdLabel(vec![8; 33])).await.is_err());
    // Records round-trip through the store unchanged.
    let st = s
        .get_user_state(&l, ValueStateRetrievalFlag::MaxEpoch)
        .await
        .unwrap();
    s.set(DbRecord::ValueState(st.clone())).await.unwrap();
    assert_eq!(
        s.get_user_state(&l, ValueStateRetrievalFlag::MaxEpoch)
            .await
            .unwrap(),
        st
    );
}

/// Regression (security review): one label per account and kind, so everyone is shown one value;
/// a server handing someone another salt cannot make that value match another key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_salt_never_matches_the_published_value() {
    let Some(s) = store().await else { return };
    let vrf = SecretVrf::new(&[0x74; 32]);
    let writer = songbird_akd::writer(s.clone(), vrf.clone()).await.unwrap();
    let vpk = writer.get_public_key().await.unwrap().as_bytes().to_vec();
    let x = label(Kind::Identity, &account(5));
    writer
        .publish(vec![(x.clone(), value(&SALT, Kind::Identity, &[0x11; 32]))])
        .await
        .unwrap();
    let reader = songbird_akd::reader(s, vrf).await.unwrap();
    let (proof, head) = reader.lookup(x.clone()).await.unwrap();
    let r =
        akd::client::lookup_verify::<Config>(&vpk, head.hash(), head.epoch(), x, proof).unwrap();
    // The owner's salt and key match; any other salt with an attacker's key does not.
    assert_eq!(r.value, value(&SALT, Kind::Identity, &[0x11; 32]));
    for other in [[0u8; 32], [1; 32], [0x5b; 32]] {
        assert_ne!(r.value, value(&other, Kind::Identity, &[0x66; 32]));
    }
    // The value is bound to its kind too.
    assert_ne!(r.value, value(&SALT, Kind::DeviceList, &[0x11; 32]));
}

/// Regression (security review): one writer, enforced. An epoch cannot be rewritten, and two
/// writers racing from the same epoch never both commit it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn epochs_cannot_be_rewritten_and_racing_writers_never_both_commit() {
    let Some((s, cfg)) = store_cfg().await else {
        return;
    };
    let vrf = SecretVrf::new(&[0x75; 32]);
    let a = songbird_akd::writer(s.clone(), vrf.clone()).await.unwrap();
    a.publish(vec![(
        label(Kind::Identity, &account(1)),
        value(&SALT, Kind::Identity, &[1; 32]),
    )])
    .await
    .unwrap();
    // Rewriting epoch 1 (or jumping to 9) is refused by the store.
    for epoch in [1, 9] {
        let azks = akd::append_only_zks::Azks {
            latest_epoch: epoch,
            num_nodes: 1,
        };
        assert!(s.set(DbRecord::Azks(azks)).await.is_err(), "epoch {epoch}");
    }
    // Two writers on separate connections publish at once, several rounds.
    let s2 = store_same_db(&cfg).await;
    let b = songbird_akd::writer(s2, vrf.clone()).await.unwrap();
    let (a, b) = (Arc::new(a), Arc::new(b));
    let mut committed = Vec::new();
    for round in 0..6u8 {
        let la = label(Kind::Identity, &account(100 + round));
        let lb = label(Kind::Identity, &account(150 + round));
        let (ra, rb) = tokio::join!(
            {
                let a = Arc::clone(&a);
                let la = la.clone();
                async move {
                    a.publish(vec![(la, value(&SALT, Kind::Identity, &[2; 32]))])
                        .await
                }
            },
            {
                let b = Arc::clone(&b);
                let lb = lb.clone();
                async move {
                    b.publish(vec![(lb, value(&SALT, Kind::Identity, &[3; 32]))])
                        .await
                }
            }
        );
        if let (Ok(ea), Ok(eb)) = (&ra, &rb) {
            assert_ne!(ea.epoch(), eb.epoch(), "two writers committed one epoch");
        }
        if ra.is_ok() {
            committed.push(la);
        }
        if rb.is_ok() {
            committed.push(lb);
        }
    }
    // Everything that was committed is still verifiable.
    let reader = songbird_akd::reader(s, vrf.clone()).await.unwrap();
    let vpk = reader.get_public_key().await.unwrap().as_bytes().to_vec();
    for l in committed {
        let (proof, head) = reader.lookup(l.clone()).await.unwrap();
        akd::client::lookup_verify::<Config>(&vpk, head.hash(), head.epoch(), l, proof).unwrap();
    }
}
