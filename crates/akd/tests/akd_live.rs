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

async fn store() -> Option<SurrealStore> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_SURREALDB") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
            "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
        );
        return None;
    };
    let db = Db::connect(songbird_surreal::Config {
        addr,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").expect("SONGBIRD_TEST_SURREALDB_PASS"),
        namespace: "test".into(),
        database: format!("akd_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    Some(SurrealStore::connect(Arc::new(db)).await.unwrap())
}

fn subject(b: u8) -> [u8; 32] {
    [b; 32]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn published_epochs_verify_with_akds_own_client_checks() {
    let Some(s) = store().await else { return };
    let vrf = SecretVrf::new(&[0x71; 32]);
    let writer = songbird_akd::writer(s.clone(), vrf.clone()).await.unwrap();
    let vrf_public = writer.get_public_key().await.unwrap();
    let vpk = vrf_public.as_bytes().to_vec();
    // Epoch 1: two accounts' identity keys; epoch 2: a device list and a key change.
    let alice = label(Kind::Identity, &subject(1));
    let bob = label(Kind::Identity, &subject(2));
    let alice_list = label(Kind::DeviceList, &subject(1));
    let e1 = writer
        .publish(vec![
            (alice.clone(), value(&[0xA1; 32])),
            (bob.clone(), value(&[0xB1; 32])),
        ])
        .await
        .unwrap();
    let e2 = writer
        .publish(vec![
            (alice_list.clone(), value(&[0xA2; 32])),
            (bob.clone(), value(&[0xB2; 32])),
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
    assert_eq!(r.value, AkdValue(vec![0xB2; 32]));
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
        vec![AkdValue(vec![0xB2; 32]), AkdValue(vec![0xB1; 32])]
    );
    // A label never published: lookup refuses (non-membership is akd's to prove in history).
    assert!(
        reader
            .lookup(label(Kind::Username, &subject(9)))
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
    let l = label(Kind::DeviceList, &subject(3));
    for i in 1..=3u8 {
        writer
            .publish(vec![(l.clone(), value(&[i; 32]))])
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
