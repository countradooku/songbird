//! The Iggy mailbox in cluster mode (D-0034): two nodes sharing a topic, leases in Valkey, node
//! links with test certificates. Runs when `SONGBIRD_TEST_IGGY` (+ `_PASS`) and
//! `SONGBIRD_TEST_VALKEY` are set; with `SONGBIRD_REQUIRE_IGGY=1` a missing server fails.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    reason = "tests"
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use songbird_link::LinkTls;
use songbird_mailbox::iggy::{ClusterConfig, IggyConfig, IggyConnection, IggyMailbox};
use songbird_mailbox::{Mailbox, NewEnvelope, Payload, StoreRequest};
use songbird_types::DeviceId;

struct Env {
    iggy: IggyConnection,
    valkey: String,
    stream: String,
    master: [u8; 32],
    ca: Issuer<'static, KeyPair>,
    ca_pem: String,
}

fn env(name: &str) -> Option<Env> {
    let (Ok(addr), Ok(valkey)) = (
        std::env::var("SONGBIRD_TEST_IGGY"),
        std::env::var("SONGBIRD_TEST_VALKEY"),
    ) else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_IGGY").is_err(),
            "SONGBIRD_REQUIRE_IGGY is set but SONGBIRD_TEST_IGGY or SONGBIRD_TEST_VALKEY is not"
        );
        return None;
    };
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let ca_pem = p.self_signed(&key).unwrap().pem();
    let mut master = [0u8; 32];
    master.copy_from_slice(&DeviceId::random().unwrap().as_bytes().repeat(2));
    Some(Env {
        iggy: IggyConnection {
            addr,
            tls_domain: None,
            tls_ca_file: None,
            user: "iggy".into(),
            pass: std::env::var("SONGBIRD_TEST_IGGY_PASS").unwrap(),
        },
        valkey,
        stream: format!(
            "c_{name}_{}",
            &DeviceId::random().unwrap().to_hex_unredacted()[..8]
        ),
        master,
        ca: Issuer::new(p, key),
        ca_pem,
    })
}

fn private_dir(parent: &Path) -> PathBuf {
    std::fs::create_dir_all(parent).unwrap();
    let dir = parent.join(DeviceId::random().unwrap().to_hex_unredacted());
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir).unwrap();
    dir
}

fn free_port() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

/// One node of the test cluster (its own key directory and certificate).
async fn node(e: &Env, n: &str) -> IggyMailbox {
    let name = format!("delivery.{n}.songbird.internal");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![name.clone()]).unwrap();
    p.is_ca = IsCa::ExplicitNoCa;
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = p.signed_by(&key, &e.ca).unwrap();
    let tls = LinkTls::from_pem(
        cert.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        e.ca_pem.as_bytes(),
        &name,
    )
    .unwrap();
    let addr = free_port();
    let dir = private_dir(&Path::new(env!("CARGO_TARGET_TMPDIR")).join("cluster-keys"));
    let mut cfg = IggyConfig::new(e.iggy.clone(), [7; 32], dir, e.master);
    cfg.stream.clone_from(&e.stream);
    cfg.ack_interval = Duration::from_millis(20);
    cfg.key_interval = Duration::from_millis(50);
    cfg.idem_flush = Duration::from_millis(20);
    cfg.timeout = Duration::from_secs(10);
    cfg.compaction_interval = Duration::from_hours(1);
    cfg.cluster = Some(ClusterConfig {
        node_name: name,
        link_listen: addr,
        link_advertise: addr,
        link_tls: tls,
        valkey_url: e.valkey.clone(),
        valkey_tls_ca_pem: None,
        valkey_tls_client: None,
        lease_ttl: Duration::from_millis(900),
    });
    IggyMailbox::connect(cfg).await.unwrap()
}

fn to(d: DeviceId, body: &'static str) -> StoreRequest {
    StoreRequest {
        idempotency_key: None,
        mls: None,
        payload: Payload::PerDevice(vec![NewEnvelope {
            device: d,
            envelope: Bytes::from_static(body.as_bytes()),
        }]),
    }
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn fetch_ok(m: &IggyMailbox, d: &DeviceId, want: usize) -> Vec<(u64, Bytes)> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(got) = m.fetch_after(d, 0, 100).await
            && got.len() == want
        {
            return got.into_iter().map(|s| (s.seq, s.envelope)).collect();
        }
        assert!(
            Instant::now() < deadline,
            "fetch never returned {want} entries"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_reaches_partitions_owned_by_another() {
    let Some(e) = env("remote") else { return };
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    // Ownership is sticky: A keeps them; B reaches them over the link.
    assert_eq!(b.owned_partitions(), Vec::<u32>::new());
    let devs: Vec<DeviceId> = (0..8).map(|_| DeviceId::random().unwrap()).collect();
    for d in &devs {
        let out = b.store(to(*d, "via-b")).await.unwrap();
        assert_eq!(out.seqs, vec![1]);
    }
    for d in &devs {
        let got = fetch_ok(&b, d, 1).await;
        assert_eq!(got[0].1.as_ref(), b"via-b");
        assert_eq!(a.count_pending(d).await.unwrap(), 1);
        b.ack_up_to(d, 1).await.unwrap();
    }
    for d in &devs {
        let deadline = Instant::now() + Duration::from_secs(10);
        while b.count_pending(d).await.unwrap() != 0 {
            assert!(Instant::now() < deadline, "ack via B never applied on A");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    // A send across devices on several partitions, from B: one seq each.
    let out = b
        .store(StoreRequest {
            idempotency_key: Some([3; 16]),
            mls: None,
            payload: Payload::PerDevice(
                devs.iter()
                    .map(|d| NewEnvelope {
                        device: *d,
                        envelope: Bytes::from_static(b"multi"),
                    })
                    .collect(),
            ),
        })
        .await
        .unwrap();
    assert_eq!(out.seqs, vec![2; 8]);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_standby_takes_over_without_losing_anything() {
    let Some(e) = env("failover") else { return };
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    let devs: Vec<DeviceId> = (0..8).map(|_| DeviceId::random().unwrap()).collect();
    for d in &devs {
        b.store(to(*d, "before-crash")).await.unwrap();
    }
    // Every key store reaches B before A dies (the next key interval).
    tokio::time::sleep(Duration::from_millis(500)).await;
    // A dies without writing or releasing anything.
    a.crash();
    eventually("B takes every partition over", || {
        b.owned_partitions().len() == 4
    })
    .await;
    for d in &devs {
        let got = fetch_ok(&b, d, 1).await;
        assert_eq!(got[0], (1, Bytes::from_static(b"before-crash")));
        // No seq is reused after the takeover.
        assert_eq!(b.store(to(*d, "after")).await.unwrap().seqs, vec![2]);
    }
    assert_eq!(b.replica_failures(), 0);
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_graceful_shutdown_hands_partitions_over_at_once() {
    let Some(e) = env("handover") else { return };
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    let d = DeviceId::random().unwrap();
    a.store(to(d, "pending")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t = Instant::now();
    a.shutdown().await;
    eventually("B takes every partition over", || {
        b.owned_partitions().len() == 4
    })
    .await;
    // Released leases: no waiting for them to expire.
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(fetch_ok(&b, &d, 1).await[0].1.as_ref(), b"pending");
    b.shutdown().await;
}
