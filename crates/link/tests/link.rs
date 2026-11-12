//! Node links end to end on loopback, with certificates from a test CA laid out like the
//! internal CA's (D-0012).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use songbird_link::{Handler, LinkClient, LinkError, LinkStats, LinkTls, serve};
use tokio::sync::watch;

struct Ca {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn ca() -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let cert = p.self_signed(&key).unwrap();
    Ca {
        pem: cert.pem(),
        issuer: Issuer::new(p, key),
    }
}

/// A leaf for `name` (server and client auth), as `LinkTls` presenting `as_name`.
fn leaf(ca: &Ca, trust: &Ca, name: &str, as_name: &str) -> LinkTls {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![name.to_owned()]).unwrap();
    p.is_ca = IsCa::ExplicitNoCa;
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    LinkTls::from_pem(
        cert.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        trust.pem.as_bytes(),
        as_name,
    )
    .unwrap()
}

const A: &str = "delivery.a.songbird.internal";
const B: &str = "delivery.b.songbird.internal";

async fn server(tls: LinkTls) -> (std::net::SocketAddr, Arc<LinkStats>, watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler: Handler = Arc::new(|req: Bytes| {
        Box::pin(async move {
            // Slower for "slow", so answers arrive out of order.
            if req.as_ref() == b"slow" {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let mut v = req.to_vec();
            v.reverse();
            Bytes::from(v)
        })
    });
    let stats = Arc::new(LinkStats::default());
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(
        listener,
        tls,
        "delivery.".into(),
        handler,
        Arc::clone(&stats),
        rx,
    ));
    (addr, stats, stop)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_are_multiplexed_and_answered_out_of_order() {
    let ca = ca();
    let (addr, stats, _stop) = server(leaf(&ca, &ca, B, B)).await;
    let client = Arc::new(LinkClient::new(addr, B, leaf(&ca, &ca, A, A)));
    let slow = {
        let c = Arc::clone(&client);
        tokio::spawn(async move { c.call(b"slow", Duration::from_secs(5)).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut fast = Vec::new();
    for i in 0..200u32 {
        let c = Arc::clone(&client);
        fast.push(tokio::spawn(async move {
            let req = format!("req-{i}");
            let resp = c
                .call(req.as_bytes(), Duration::from_secs(5))
                .await
                .unwrap();
            let mut want = req.into_bytes();
            want.reverse();
            assert_eq!(resp.as_ref(), want.as_slice());
        }));
    }
    for f in fast {
        f.await.unwrap();
    }
    // The slow request did not hold the fast ones, and is answered too.
    assert_eq!(slow.await.unwrap().unwrap().as_ref(), b"wols");
    assert_eq!(stats.served.load(Ordering::Relaxed), 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_components_and_other_cas_are_refused() {
    let ca = ca();
    let (addr, stats, _stop) = server(leaf(&ca, &ca, B, B)).await;
    // Same CA, but an API certificate: not a delivery node.
    let api = LinkClient::new(
        addr,
        B,
        leaf(
            &ca,
            &ca,
            "api.x.songbird.internal",
            "api.x.songbird.internal",
        ),
    );
    assert!(api.call(b"x", Duration::from_secs(2)).await.is_err());
    // Same CA, claiming a delivery name its certificate is not for.
    let liar = LinkClient::new(addr, B, leaf(&ca, &ca, "api.x.songbird.internal", A));
    assert!(liar.call(b"x", Duration::from_secs(2)).await.is_err());
    // Another CA altogether (it trusts our CA, we do not trust it).
    let other = ca_other();
    let stranger = LinkClient::new(addr, B, leaf(&other, &ca, A, A));
    assert!(stranger.call(b"x", Duration::from_secs(2)).await.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stats.served.load(Ordering::Relaxed), 0);
    assert!(stats.refused.load(Ordering::Relaxed) >= 3);
}

fn ca_other() -> Ca {
    ca()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_refuses_a_server_with_another_name() {
    let ca = ca();
    // The listener is node B, the client expects node C there.
    let (addr, _, _stop) = server(leaf(&ca, &ca, B, B)).await;
    let c = LinkClient::new(addr, "delivery.c.songbird.internal", leaf(&ca, &ca, A, A));
    assert!(matches!(
        c.call(b"x", Duration::from_secs(2)).await,
        Err(LinkError::Connect)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_the_listener_keeps_open_connections_served() {
    let ca = ca();
    let (addr, _, stop) = server(leaf(&ca, &ca, B, B)).await;
    let c = LinkClient::new(addr, B, leaf(&ca, &ca, A, A));
    assert!(c.call(b"ab", Duration::from_secs(2)).await.is_ok());
    // Stop accepting new connections: the open one stays served (a drain).
    let _ = stop.send(true);
    assert!(c.call(b"cd", Duration::from_secs(2)).await.is_ok());
}
