//! The Valkey router against a real Valkey, two routers playing two nodes. Runs when
//! `SONGBIRD_TEST_VALKEY` (a `redis://` URL with credentials) is set; with
//! `SONGBIRD_REQUIRE_VALKEY=1` a missing server fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use songbird_router::valkey::{ValkeyRouter, ValkeyRouterConfig};
use songbird_router::{InboxSizes, Live, Routed, Router};
use songbird_types::DeviceId;

/// The tests share one Valkey and one of them drops every pub/sub connection: one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SIZES: InboxSizes = InboxSizes {
    live: 16,
    ephemeral: 4,
};

fn url() -> Option<String> {
    let url = std::env::var("SONGBIRD_TEST_VALKEY").ok();
    assert!(
        url.is_some() || std::env::var("SONGBIRD_REQUIRE_VALKEY").is_err(),
        "SONGBIRD_REQUIRE_VALKEY is set but SONGBIRD_TEST_VALKEY is not"
    );
    url
}

async fn node(url: &str, secret: [u8; 32], id: u64) -> ValkeyRouter {
    ValkeyRouter::connect(ValkeyRouterConfig {
        url: url.to_owned(),
        tls_ca_pem: None,
        tls_client: None,
        cluster_secret: secret,
        subscribers: 2,
        node_id: id,
    })
    .await
    .unwrap()
}

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..16].copy_from_slice(DeviceId::random().unwrap().as_bytes());
    s[16..].copy_from_slice(DeviceId::random().unwrap().as_bytes());
    s
}

fn live(seq: u64, body: &'static [u8]) -> Live {
    Live {
        seq,
        envelope: Bytes::from_static(body),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_across_nodes_and_reports_offline() {
    let Some(url) = url() else { return };
    let _one = SERIAL.lock().await;
    let s = secret();
    let (a, b) = (node(&url, s, 1).await, node(&url, s, 2).await);
    let dev = DeviceId::random().unwrap();
    let mut inbox = b.attach(dev, SIZES).await;
    // Held on B: A publishes, B receives.
    assert_eq!(a.route(&dev, live(7, b"sealed")).await, Routed::Queued);
    let got = tokio::time::timeout(Duration::from_secs(5), inbox.live.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((got.seq, got.envelope.as_ref()), (7, b"sealed".as_slice()));
    assert_eq!(
        a.route_ephemeral(&dev, Bytes::from_static(b"typing")).await,
        Routed::Queued
    );
    let e = tokio::time::timeout(Duration::from_secs(5), inbox.ephemeral.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e.as_ref(), b"typing");
    // Nobody holds this one: offline (zero receivers).
    let nobody = DeviceId::random().unwrap();
    assert_eq!(a.route(&nobody, live(1, b"x")).await, Routed::Offline);
    // After detaching, B no longer receives: offline again.
    b.detach(&dev, inbox.conn).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(a.route(&dev, live(8, b"later")).await, Routed::Offline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_connection_on_another_node_replaces_the_old_one() {
    let Some(url) = url() else { return };
    let _one = SERIAL.lock().await;
    let s = secret();
    let (a, b, c) = (
        node(&url, s, 11).await,
        node(&url, s, 12).await,
        node(&url, s, 13).await,
    );
    let dev = DeviceId::random().unwrap();
    let old = b.attach(dev, SIZES).await;
    let mut new = a.attach(dev, SIZES).await;
    // B's session is told it was replaced (invariant 4).
    tokio::time::timeout(Duration::from_secs(5), async {
        while !old.signals.is_replaced() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the old session was not replaced");
    assert_eq!(b.stats().evicted.load(Ordering::Relaxed), 1);
    // Routing now reaches A only.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(c.route(&dev, live(3, b"to-new")).await, Routed::Queued);
    let got = tokio::time::timeout(Duration::from_secs(5), new.live.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.seq, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_heal_after_the_connection_drops() {
    let Some(url) = url() else { return };
    let _one = SERIAL.lock().await;
    let s = secret();
    let (a, b) = (node(&url, s, 21).await, node(&url, s, 22).await);
    let dev = DeviceId::random().unwrap();
    let mut inbox = b.attach(dev, SIZES).await;
    // Valkey drops every pub/sub connection (as on a restart or failover).
    let admin = redis::Client::open(url.as_str()).unwrap();
    let mut conn = admin.get_multiplexed_async_connection().await.unwrap();
    let _: i64 = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("pubsub")
        .query_async(&mut conn)
        .await
        .unwrap();
    // The session is told to drain its mailbox (it may have missed notifications)...
    tokio::time::timeout(Duration::from_secs(10), async {
        while !inbox.signals.take_lagged() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("sessions were not marked lagged after the reconnect");
    // ...and routing works again without anyone re-attaching.
    let mut routed = Routed::Offline;
    for _ in 0..50 {
        routed = a.route(&dev, live(9, b"healed")).await;
        if routed == Routed::Queued {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(routed, Routed::Queued);
    let got = tokio::time::timeout(Duration::from_secs(5), inbox.live.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.seq, 9);
    assert!(b.stats().reconnects.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valkey_sees_neither_device_ids_nor_content() {
    let Some(url) = url() else { return };
    let _one = SERIAL.lock().await;
    let s = secret();
    let (a, b) = (node(&url, s, 31).await, node(&url, s, 32).await);
    let dev = DeviceId::random().unwrap();
    let hex = dev.to_hex_unredacted();
    let mut inbox = b.attach(dev, SIZES).await;
    // A spy subscribed to every channel sees what Valkey sees.
    let spy = redis::Client::open(url.as_str()).unwrap();
    let mut ps = spy.get_async_pubsub().await.unwrap();
    ps.psubscribe("*").await.unwrap();
    let names: Vec<String> = {
        let mut c = spy.get_multiplexed_async_connection().await.unwrap();
        redis::cmd("PUBSUB")
            .arg("CHANNELS")
            .query_async(&mut c)
            .await
            .unwrap()
    };
    assert_ne!(names.len(), 0);
    assert!(
        names
            .iter()
            .all(|n| n.starts_with("r:") && !n.contains(&hex[..8]))
    );
    assert_eq!(
        a.route(&dev, live(5, b"SECRET-MARKER")).await,
        Routed::Queued
    );
    let _ = inbox.live.recv().await;
    let mut stream = ps.on_message();
    let seen = tokio::time::timeout(
        Duration::from_secs(5),
        futures_util::StreamExt::next(&mut stream),
    )
    .await
    .unwrap()
    .unwrap();
    let payload: Vec<u8> = seen.get_payload_bytes().to_vec();
    assert!(!seen.get_channel_name().contains(&hex[..8]));
    assert!(!payload.windows(13).any(|w| w == b"SECRET-MARKER"));
    assert!(!payload.windows(16).any(|w| w == dev.as_bytes()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_cluster_secret_cannot_reach_or_read_devices() {
    let Some(url) = url() else { return };
    let _one = SERIAL.lock().await;
    let (a, b) = (
        node(&url, secret(), 41).await,
        node(&url, secret(), 42).await,
    );
    let dev = DeviceId::random().unwrap();
    let _inbox = b.attach(dev, SIZES).await;
    // Another secret, another channel name: nobody listens there.
    assert_eq!(a.route(&dev, live(1, b"x")).await, Routed::Offline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishing_heals_after_valkey_drops_every_connection() {
    let Some(url) = url() else { return };
    let _one = SERIAL.lock().await;
    let s = secret();
    let (a, b) = (node(&url, s, 51).await, node(&url, s, 52).await);
    let dev = DeviceId::random().unwrap();
    let mut inbox = b.attach(dev, SIZES).await;
    assert_eq!(a.route(&dev, live(1, b"before")).await, Routed::Queued);
    let _ = inbox.live.recv().await;
    // A Valkey restart drops every connection: commands and subscriptions alike.
    let admin = redis::Client::open(url.as_str()).unwrap();
    let mut conn = admin.get_multiplexed_async_connection().await.unwrap();
    for kind in ["normal", "pubsub"] {
        let _: redis::RedisResult<i64> = redis::cmd("CLIENT")
            .arg("KILL")
            .arg("TYPE")
            .arg(kind)
            .query_async(&mut conn)
            .await;
    }
    // Publishing works again without anyone reconnecting by hand.
    let mut routed = Routed::Offline;
    for _ in 0..100 {
        routed = a.route(&dev, live(2, b"after")).await;
        if routed == Routed::Queued {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(routed, Routed::Queued);
}
