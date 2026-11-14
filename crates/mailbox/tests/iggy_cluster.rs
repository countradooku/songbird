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
use songbird_mailbox::iggy::{
    ClusterConfig, IggyConfig, IggyConnection, IggyMailbox, IggySender, IggySenderConfig,
};
use songbird_mailbox::{Mailbox, NewEnvelope, Payload, StoreRequest, StoreSend as _};
use songbird_types::DeviceId;

/// The test that drops every Valkey connection runs alone (write); the others share (read).
static VALKEY: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

struct Env {
    iggy: IggyConnection,
    valkey: String,
    stream: String,
    master: [u8; 32],
    ca: Issuer<'static, KeyPair>,
    ca_pem: String,
}

fn env(name: &str) -> Option<Env> {
    if std::env::var("SONGBIRD_TEST_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("songbird_mailbox=debug")
            .with_test_writer()
            .try_init();
    }
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

/// One node of the test cluster (its own key directory and certificate), four partitions.
async fn node(e: &Env, n: &str) -> IggyMailbox {
    node_with(e, n, 4, None).await
}

/// A node with `partitions` partitions and, if given, a key window that length.
async fn node_with(e: &Env, n: &str, partitions: u32, key_window: Option<Duration>) -> IggyMailbox {
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
    cfg.partitions = partitions;
    if let Some(w) = key_window {
        cfg.key_window = w;
    }
    cfg.cluster = Some(ClusterConfig {
        node_name: name,
        link_listen: addr,
        link_advertise: addr,
        link_tls: tls,
        valkey_url: e.valkey.clone(),
        valkey_tls_ca_pem: None,
        valkey_tls_client: None,
        lease_ttl: Duration::from_millis(900),
        zone: String::new(),
        senders: vec!["api.".into()],
    });
    IggyMailbox::connect(cfg).await.unwrap()
}

/// A link identity for `name`, signed by the test CA.
fn identity(e: &Env, name: &str) -> LinkTls {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![name.to_owned()]).unwrap();
    p.is_ca = IsCa::ExplicitNoCa;
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = p.signed_by(&key, &e.ca).unwrap();
    LinkTls::from_pem(
        cert.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        e.ca_pem.as_bytes(),
        name,
    )
    .unwrap()
}

/// A send-only node (`api`, D-0044) under certificate name `name`.
async fn sender(e: &Env, name: &str) -> IggySender {
    IggySender::connect(IggySenderConfig {
        stream: e.stream.clone(),
        topic: "mailbox".into(),
        partitions: 4,
        idempotency_secret: [7; 32],
        timeout: Duration::from_secs(10),
        link_tls: identity(e, name),
        valkey: redis::Client::open(e.valkey.as_str()).unwrap(),
        refresh: Duration::from_millis(300),
    })
    .await
    .unwrap()
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

/// Waits until `m` owns every partition; on failure says what it owns.
async fn takes_all(m: &IggyMailbox) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while m.owned_partitions().len() != 4 {
        assert!(
            Instant::now() < deadline,
            "never took every partition over: owns {:?}, partition starts {}",
            m.owned_partitions(),
            m.stats()
                .partition_starts
                .load(std::sync::atomic::Ordering::Relaxed)
        );
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
    let _shared = VALKEY.read().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    // A keeps them until B has been up two lease periods and holds copies; B reaches them over
    // the link.
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
    let _shared = VALKEY.read().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    let devs: Vec<DeviceId> = (0..8).map(|_| DeviceId::random().unwrap()).collect();
    for d in &devs {
        b.store(to(*d, "before-crash")).await.unwrap();
    }
    // A's key stores are on B (its standby) before A dies.
    eventually("A's key stores reach B", || {
        a.cluster_members() == 2 && a.standbys_synced()
    })
    .await;
    assert_eq!(a.replica_failures(), 0);
    // A dies without writing or releasing anything.
    a.crash();
    takes_all(&b).await;
    for d in &devs {
        let got = fetch_ok(&b, d, 1).await;
        assert_eq!(got[0], (1, Bytes::from_static(b"before-crash")));
        // No seq is reused after the takeover.
        assert_eq!(b.store(to(*d, "after")).await.unwrap().seqs, vec![2]);
    }
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_graceful_shutdown_hands_partitions_over_at_once() {
    let Some(e) = env("handover") else { return };
    let _shared = VALKEY.read().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    let d = DeviceId::random().unwrap();
    a.store(to(d, "pending")).await.unwrap();
    eventually("A's key stores reach B", || {
        a.cluster_members() == 2 && a.standbys_synced()
    })
    .await;
    let t = Instant::now();
    a.shutdown().await;
    takes_all(&b).await;
    // Released leases: no waiting for them to expire.
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(fetch_ok(&b, &d, 1).await[0].1.as_ref(), b"pending");
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_lost_with_valkey_are_taken_back_without_restarting() {
    let Some(e) = env("relet") else { return };
    let _shared = VALKEY.read().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let d = DeviceId::random().unwrap();
    a.store(to(d, "first")).await.unwrap();
    let starts = a
        .stats()
        .partition_starts
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(starts, 4);
    // Valkey loses everything (a restart without persistence): the lease keys are gone.
    let client = redis::Client::open(e.valkey.as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("songbird:{}:*", e.stream))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_ne!(keys.len(), 0);
    let _: i64 = redis::cmd("DEL")
        .arg(&keys)
        .query_async(&mut conn)
        .await
        .unwrap();
    // A keeps running every partition (no restart, no second writer) and takes the leases back.
    for _ in 0..30 {
        assert_eq!(a.owned_partitions().len(), 4);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let held: Vec<Option<String>> = redis::cmd("MGET")
        .arg(
            (0..4)
                .map(|p| format!("songbird:{}:mailbox:lease:{p}", e.stream))
                .collect::<Vec<_>>(),
        )
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(held.iter().all(Option::is_some), "{held:?}");
    assert_eq!(
        a.stats()
            .partition_starts
            .load(std::sync::atomic::Ordering::Relaxed),
        starts,
        "a partition was restarted"
    );
    assert_eq!(a.store(to(d, "second")).await.unwrap().seqs, vec![2]);
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_keep_renewing_after_valkey_drops_every_connection() {
    let Some(e) = env("reconnect") else { return };
    let _alone = VALKEY.write().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let starts = a
        .stats()
        .partition_starts
        .load(std::sync::atomic::Ordering::Relaxed);
    let client = redis::Client::open(e.valkey.as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let _: redis::RedisResult<i64> = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("normal")
        .query_async(&mut conn)
        .await;
    // Three lease periods later A still holds every lease (it reconnected and renewed them;
    // without that they would have expired) and restarted nothing.
    tokio::time::sleep(Duration::from_millis(2_700)).await;
    assert_eq!(a.owned_partitions().len(), 4);
    assert_eq!(
        a.stats()
            .partition_starts
            .load(std::sync::atomic::Ordering::Relaxed),
        starts
    );
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let held: Vec<Option<String>> = redis::cmd("MGET")
        .arg(
            (0..4)
                .map(|p| format!("songbird:{}:mailbox:lease:{p}", e.stream))
                .collect::<Vec<_>>(),
        )
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(held.iter().all(Option::is_some), "{held:?}");
    let d = DeviceId::random().unwrap();
    assert_eq!(a.store(to(d, "x")).await.unwrap().seqs, vec![1]);
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_joins_takes_its_share_without_losing_anything() {
    let Some(e) = env("rebalance") else { return };
    let _shared = VALKEY.read().await;
    // Sixteen partitions: a node ranks first for none of them with probability 2^-16.
    let a = node_with(&e, "a", 16, None).await;
    eventually("A owns every partition", || {
        a.owned_partitions().len() == 16
    })
    .await;
    let devs: Vec<DeviceId> = (0..32).map(|_| DeviceId::random().unwrap()).collect();
    for d in &devs {
        a.store(to(*d, "before")).await.unwrap();
    }
    let b = node_with(&e, "b", 16, None).await;
    // Partitions move one per round until each is with its preferred node, then nothing moves
    // (no ping-pong): the same split for three seconds.
    let deadline = Instant::now() + Duration::from_secs(40);
    let settled = loop {
        let before = (a.owned_partitions(), b.owned_partitions());
        tokio::time::sleep(Duration::from_millis(3_000)).await;
        let after = (a.owned_partitions(), b.owned_partitions());
        let whole = after.0.len() + after.1.len() == 16;
        if before == after && whole && !after.1.is_empty() {
            break after;
        }
        assert!(Instant::now() < deadline, "never settled: {after:?}");
    };
    assert!(!settled.0.is_empty(), "A kept nothing: {settled:?}");
    assert!(
        settled.0.iter().all(|p| !settled.1.contains(p)),
        "{settled:?}"
    );
    for d in &devs {
        assert_eq!(
            fetch_ok(&a, d, 1).await[0],
            (1, Bytes::from_static(b"before"))
        );
        assert_eq!(
            fetch_ok(&b, d, 1).await[0],
            (1, Bytes::from_static(b"before"))
        );
        assert_eq!(b.store(to(*d, "after")).await.unwrap().seqs, vec![2]);
    }
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_can_die_at_once() {
    let Some(e) = env("twodie") else { return };
    let _shared = VALKEY.read().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node(&e, "b").await;
    let c = node(&e, "c").await;
    let devs: Vec<DeviceId> = (0..8).map(|_| DeviceId::random().unwrap()).collect();
    for d in &devs {
        c.store(to(*d, "three-copies")).await.unwrap();
    }
    // Every owner's key stores are on both its standbys (with three nodes: on every node).
    eventually("every store on both standbys", || {
        [&a, &b, &c]
            .iter()
            .all(|m| m.cluster_members() == 3 && m.standbys_synced())
            && a.owned_partitions().len() + b.owned_partitions().len() + c.owned_partitions().len()
                == 4
    })
    .await;
    // Two nodes die at the same moment, whichever partitions they own.
    a.crash();
    b.crash();
    takes_all(&c).await;
    for d in &devs {
        assert_eq!(
            fetch_ok(&c, d, 1).await[0],
            (1, Bytes::from_static(b"three-copies"))
        );
        assert_eq!(c.store(to(*d, "after")).await.unwrap().seqs, vec![2]);
    }
    c.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_seals_nothing_before_a_standby_holds_its_keys() {
    let Some(e) = env("confirm") else { return };
    let _shared = VALKEY.read().await;
    // A new key window every 100 ms.
    let window = Some(Duration::from_millis(100));
    let a = node_with(&e, "a", 4, window).await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let b = node_with(&e, "b", 4, window).await;
    eventually("A's key stores reach B", || {
        a.cluster_members() == 2 && a.standbys_synced()
    })
    .await;
    // B dies while it still counts as a member (its registration lasts a lease period), before
    // anything is handed to it.
    b.crash();
    let d = DeviceId::random().unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    // A needs a new window, cannot get its keys onto a standby, and refuses to seal under it.
    assert!(a.store(to(d, "refused")).await.is_err());
    assert!(a.replica_failures() > 0);
    // Once B's registration expires A is alone (no node to copy to) and stores again.
    let deadline = Instant::now() + Duration::from_secs(10);
    let seqs = loop {
        if let Ok(out) = a.store(to(d, "alone")).await {
            break out.seqs;
        }
        assert!(Instant::now() < deadline, "A never stored alone");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(seqs, vec![1]);
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_only_node_stores_on_the_owners_and_may_do_nothing_else() {
    let Some(e) = env("sender") else { return };
    let _shared = VALKEY.read().await;
    let a = node(&e, "a").await;
    eventually("A owns every partition", || a.owned_partitions().len() == 4).await;
    let api = sender(&e, "api.x.songbird.internal").await;
    eventually("the sender knows every owner", || api.known() == 4).await;
    // Single-partition sends, stored on the owner over the node link.
    let devs: Vec<DeviceId> = (0..8).map(|_| DeviceId::random().unwrap()).collect();
    for d in &devs {
        assert_eq!(
            api.store_send(to(*d, "via-api")).await.unwrap().seqs,
            vec![1]
        );
        assert_eq!(fetch_ok(&a, d, 1).await[0].1.as_ref(), b"via-api");
    }
    // A send across partitions, then the same send through a delivery node: the sender computes
    // the same idempotency tag, so the retry is a replay (the WebSocket after HTTP).
    let multi = || StoreRequest {
        idempotency_key: Some([5; 16]),
        mls: None,
        payload: Payload::PerDevice(
            devs.iter()
                .map(|d| NewEnvelope {
                    device: *d,
                    envelope: Bytes::from_static(b"multi"),
                })
                .collect(),
        ),
    };
    let first = api.store_send(multi()).await.unwrap();
    assert_eq!(first.seqs, vec![2; 8]);
    assert!(!first.replayed);
    // The sender may not mark the remote parts stored; the home partition's re-driver finds them
    // stored and completes the bookkeeping.
    eventually("the re-driver completes the sender's remote parts", || {
        a.stats()
            .redriven
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    })
    .await;
    let again = a.store(multi()).await.unwrap();
    assert_eq!(again.seqs, vec![2; 8]);
    assert!(again.replayed);
    for d in &devs {
        assert_eq!(a.count_pending(d).await.unwrap(), 2);
    }
    // Nothing but the store: fetch and ACK are refused and counted, and changed nothing.
    let (fetched, acked) = api.try_forbidden(&devs[0]).await;
    assert!(fetched.is_err());
    assert!(acked.is_err());
    assert!(a.sender_requests_refused() >= 2);
    assert_eq!(a.count_pending(&devs[0]).await.unwrap(), 2);
    // A certificate of a kind not admitted (push) cannot even store.
    let push = sender(&e, "push.x.songbird.internal").await;
    eventually("the push identity reads the owners", || push.known() == 4).await;
    assert!(push.store_send(to(devs[0], "never")).await.is_err());
    assert_eq!(a.count_pending(&devs[0]).await.unwrap(), 2);
    a.shutdown().await;
}
