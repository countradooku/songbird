//! APNs client against the mock APNs (HTTP/2 over TLS).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::BTreeSet;
use std::time::Duration;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use serde_json::Value;
use songbird_push_providers::apns::{Apns, ApnsConfig};
use songbird_push_providers::b64::decode_url;
use songbird_push_providers::test_support::{
    Behaviour, MockServer, RecordedRequest, TestCa, p256_pkcs8,
};
use songbird_push_providers::{BreakerConfig, BreakerState, Outcome, Provider, Target};

const TOKEN: [u8; 32] = [0xab; 32];

struct Fixture {
    mock: MockServer,
    apns: Apns,
    public: Vec<u8>,
}

async fn fixture(tweak: impl FnOnce(&mut ApnsConfig)) -> Fixture {
    let ca = TestCa::new();
    let mock = MockServer::apns(&ca).await;
    let key = p256_pkcs8();
    let public = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let mut cfg = ApnsConfig::new("TEAM123456", "KEYID12345", "eu.songbird.app");
    cfg.base_url = mock.url();
    cfg.http = ca.http_config();
    tweak(&mut cfg);
    let apns = Apns::with_pkcs8_der(cfg, &key).unwrap();
    Fixture { mock, apns, public }
}

fn alert() -> Target {
    Target::Apns {
        token: TOKEN.to_vec(),
        voip: false,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Verifies the provider token's signature and returns its header and claims.
fn verify_jwt(auth: &str, public: &[u8]) -> (Value, Value) {
    let jwt = auth.strip_prefix("bearer ").expect("bearer scheme");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let sig = decode_url(parts[2]).unwrap();
    assert_eq!(sig.len(), 64, "ES256 signatures are fixed-length r||s");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .expect("signature verifies");
    (
        serde_json::from_slice(&decode_url(parts[0]).unwrap()).unwrap(),
        serde_json::from_slice(&decode_url(parts[1]).unwrap()).unwrap(),
    )
}

fn header_names(r: &RecordedRequest) -> BTreeSet<String> {
    r.headers.iter().map(|(k, _)| k.clone()).collect()
}

#[tokio::test]
async fn delivered_with_only_the_constant_payload() {
    let f = fixture(|_| {}).await;
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);

    let reqs = f.mock.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert!(r.http2);
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, format!("/3/device/{}", hex::encode(TOKEN)));
    assert_eq!(r.header("apns-topic"), Some("eu.songbird.app"));
    assert_eq!(r.header("apns-push-type"), Some("alert"));
    assert_eq!(r.header("apns-priority"), Some("10"));
    assert_eq!(r.header("apns-collapse-id"), Some("sb"));
    assert_eq!(r.header("content-type"), Some("application/json"));
    let exp: u64 = r.header("apns-expiration").unwrap().parse().unwrap();
    assert!(exp.abs_diff(now() + 24 * 3600) < 60);
    assert_eq!(
        r.body,
        br#"{"aps":{"alert":{"body":"New message","title":"Songbird"},"mutable-content":1}}"#
    );
    // Nothing else travels: no identifiers, no user agent, no extra headers.
    let allowed: BTreeSet<String> = [
        "authorization",
        "apns-topic",
        "apns-push-type",
        "apns-priority",
        "apns-collapse-id",
        "apns-expiration",
        "content-type",
        "content-length",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert!(header_names(r).is_subset(&allowed), "{:?}", header_names(r));

    let (h, c) = verify_jwt(r.header("authorization").unwrap(), &f.public);
    assert_eq!(h, serde_json::json!({"alg": "ES256", "kid": "KEYID12345"}));
    assert_eq!(c["iss"], "TEAM123456");
    assert!(c["iat"].as_u64().unwrap().abs_diff(now()) < 60);
    assert_eq!(c.as_object().unwrap().len(), 2);
}

#[tokio::test]
async fn every_alert_push_is_identical_but_for_the_token() {
    let f = fixture(|_| {}).await;
    let other = Target::Apns {
        token: vec![0x01; 32],
        voip: false,
    };
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
    assert_eq!(f.apns.send(&other).await, Outcome::Delivered);
    let reqs = f.mock.requests();
    assert_eq!(reqs[0].body, reqs[1].body);
    for name in [
        "apns-topic",
        "apns-push-type",
        "apns-priority",
        "apns-collapse-id",
        "authorization",
    ] {
        assert_eq!(reqs[0].header(name), reqs[1].header(name), "{name}");
    }
}

#[tokio::test]
async fn voip_goes_on_its_own_topic_with_no_payload_and_no_storage() {
    let f = fixture(|_| {}).await;
    let t = Target::Apns {
        token: TOKEN.to_vec(),
        voip: true,
    };
    assert_eq!(f.apns.send(&t).await, Outcome::Delivered);
    let r = &f.mock.requests()[0];
    assert_eq!(r.header("apns-topic"), Some("eu.songbird.app.voip"));
    assert_eq!(r.header("apns-push-type"), Some("voip"));
    assert_eq!(r.header("apns-priority"), Some("10"));
    assert_eq!(r.header("apns-expiration"), Some("0"));
    assert_eq!(r.body, b"{}");
}

#[tokio::test]
async fn provider_token_is_cached() {
    let f = fixture(|_| {}).await;
    for _ in 0..3 {
        assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
    }
    let reqs = f.mock.requests();
    let auths: BTreeSet<_> = reqs
        .iter()
        .map(|r| r.header("authorization").unwrap())
        .collect();
    assert_eq!(auths.len(), 1);
}

#[tokio::test]
async fn expired_provider_token_is_refreshed_and_the_push_retried_once() {
    let f = fixture(|_| {}).await;
    f.mock.push(Behaviour::ExpiredAuth);
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
    let reqs = f.mock.requests();
    assert_eq!(reqs.len(), 2);
    let (a, b) = (
        reqs[0].header("authorization").unwrap(),
        reqs[1].header("authorization").unwrap(),
    );
    assert_ne!(a, b, "a new provider token was minted");
    verify_jwt(b, &f.public);

    // Expired twice in a row: our problem (clock, key), not a retry loop.
    f.mock.push(Behaviour::ExpiredAuth);
    f.mock.push(Behaviour::ExpiredAuth);
    assert_eq!(f.apns.send(&alert()).await, Outcome::Failed);
    assert_eq!(f.mock.requests().len(), 4);
}

#[tokio::test]
async fn provider_answers_map_to_outcomes() {
    let f = fixture(|_| {}).await;
    f.mock.push(Behaviour::Unregistered);
    assert_eq!(f.apns.send(&alert()).await, Outcome::Unregistered);
    f.mock.push(Behaviour::RateLimited {
        retry_after: Some(7),
    });
    assert_eq!(
        f.apns.send(&alert()).await,
        Outcome::Retry {
            after: Some(Duration::from_secs(7))
        }
    );
    f.mock.push(Behaviour::RateLimited { retry_after: None });
    assert_eq!(f.apns.send(&alert()).await, Outcome::Retry { after: None });
    f.mock.push(Behaviour::ServerError);
    assert_eq!(f.apns.send(&alert()).await, Outcome::Retry { after: None });
    f.mock.push(Behaviour::Unavailable);
    assert_eq!(f.apns.send(&alert()).await, Outcome::Retry { after: None });
    // Wrong kind of target, empty token: never sent.
    let n = f.mock.requests().len();
    assert_eq!(
        f.apns.send(&Target::Fcm { token: "x".into() }).await,
        Outcome::Failed
    );
    assert_eq!(
        f.apns
            .send(&Target::Apns {
                token: vec![],
                voip: false
            })
            .await,
        Outcome::Unregistered
    );
    assert_eq!(f.mock.requests().len(), n);
}

#[tokio::test]
async fn a_slow_provider_times_out_as_retry() {
    let f = fixture(|c| c.http.request_timeout = Duration::from_millis(300)).await;
    f.mock.push(Behaviour::Slow(Duration::from_secs(2)));
    assert_eq!(f.apns.send(&alert()).await, Outcome::Retry { after: None });
    // The connection is still good for the next push.
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
}

/// A black-holed APNs (accepts, never answers) costs each push its timeout, opens the breaker,
/// and after its cooldown a probe finds the recovered provider (Prompt 8, D-0095).
#[tokio::test]
async fn a_black_holed_provider_times_out_opens_the_breaker_and_recovers() {
    let f = fixture(|c| {
        c.http.request_timeout = Duration::from_millis(200);
        c.breaker = BreakerConfig {
            failures: 3,
            window: Duration::from_secs(60),
            cooldown: Duration::from_millis(300),
        };
    })
    .await;
    f.mock.outage(Behaviour::Hang);
    for _ in 0..3 {
        let t = tokio::time::Instant::now();
        assert_eq!(f.apns.send(&alert()).await, Outcome::Retry { after: None });
        assert!(t.elapsed() < Duration::from_secs(1), "bounded by the timeout");
    }
    assert_eq!(f.apns.breaker_state(), BreakerState::Open);
    let sent = f.mock.requests().len();
    assert!(matches!(f.apns.send(&alert()).await, Outcome::Retry { after: Some(_) }));
    assert_eq!(f.mock.requests().len(), sent, "no request while open");
    f.mock.recover();
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
    assert_eq!(f.apns.breaker_state(), BreakerState::Closed);
}

/// A stream reset mid-request is transient: retried, and the connection serves the next push.
#[tokio::test]
async fn a_reset_stream_is_retried() {
    let f = fixture(|_| {}).await;
    f.mock.push(Behaviour::Reset);
    assert!(matches!(f.apns.send(&alert()).await, Outcome::Retry { .. }));
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
}

#[tokio::test]
async fn breaker_opens_and_answers_without_the_network() {
    let f = fixture(|c| {
        c.breaker = BreakerConfig {
            failures: 2,
            window: Duration::from_secs(60),
            cooldown: Duration::from_millis(300),
        };
    })
    .await;
    f.mock.push(Behaviour::ServerError);
    f.mock.push(Behaviour::ServerError);
    assert!(matches!(f.apns.send(&alert()).await, Outcome::Retry { .. }));
    assert!(matches!(f.apns.send(&alert()).await, Outcome::Retry { .. }));
    assert_eq!(f.apns.breaker_state(), BreakerState::Open);
    match f.apns.send(&alert()).await {
        Outcome::Retry { after: Some(d) } => assert!(d <= Duration::from_millis(300)),
        o => panic!("{o:?}"),
    }
    assert_eq!(f.mock.requests().len(), 2, "no request while open");

    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
    assert_eq!(f.apns.breaker_state(), BreakerState::Closed);
}

#[tokio::test]
async fn reconnects_after_goaway_and_multiplexes_on_one_connection() {
    let f = fixture(|_| {}).await;
    let target = alert();
    let sends = (0..20).map(|_| f.apns.send(&target));
    for o in futures_join_all(sends).await {
        assert_eq!(o, Outcome::Delivered);
    }
    assert_eq!(f.mock.connections(), 1, "one multiplexed connection");

    f.mock.goaway_all();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.apns.send(&alert()).await, Outcome::Delivered);
    assert_eq!(f.mock.connections(), 2, "reconnected after GOAWAY");
}

#[tokio::test]
async fn unreachable_provider_is_retry() {
    let ca = TestCa::new();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cfg = ApnsConfig::new("TEAM123456", "KEYID12345", "eu.songbird.app");
    cfg.base_url = format!("https://localhost:{port}");
    cfg.http = ca.http_config();
    let apns = Apns::with_pkcs8_der(cfg, &p256_pkcs8()).unwrap();
    assert_eq!(apns.send(&alert()).await, Outcome::Retry { after: None });
}

#[tokio::test]
async fn untrusted_certificate_is_refused() {
    let ca = TestCa::new();
    let mock = MockServer::apns(&ca).await;
    let mut cfg = ApnsConfig::new("TEAM123456", "KEYID12345", "eu.songbird.app");
    cfg.base_url = mock.url();
    cfg.http = TestCa::new().http_config(); // another CA
    let apns = Apns::with_pkcs8_der(cfg, &p256_pkcs8()).unwrap();
    assert_eq!(apns.send(&alert()).await, Outcome::Retry { after: None });
    assert!(mock.requests().is_empty());
}

/// Runs futures concurrently on this task (no extra dependency).
async fn futures_join_all<F: Future>(fs: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for f in fs {
        set.push(Box::pin(f));
    }
    let mut out: Vec<Option<F::Output>> = (0..set.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in set.iter_mut().enumerate() {
            if out[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => out[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().map(Option::unwrap).collect()
}
