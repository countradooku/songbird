//! Web Push client against the mock push endpoint (HTTP/1.1 over TLS).
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
use songbird_push_providers::b64::{decode_url, encode_url};
use songbird_push_providers::test_support::{
    Behaviour, MockServer, TestCa, TestSubscription, p256_pkcs8,
};
use songbird_push_providers::webpush::{PADDED_LEN, PLAINTEXT, WebPush, WebPushConfig};
use songbird_push_providers::{Outcome, Provider};

const SUBJECT: &str = "mailto:push-ops@songbird.example";

struct Fixture {
    mock: MockServer,
    wp: WebPush,
    sub: TestSubscription,
    vapid_public: Vec<u8>,
}

async fn fixture(insecure: bool) -> Fixture {
    let ca = TestCa::new();
    let mock = MockServer::web_push(&ca).await;
    let key = p256_pkcs8();
    let vapid_public = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let mut cfg = WebPushConfig::new(SUBJECT);
    cfg.http = ca.http_config();
    cfg.allow_insecure_for_tests = insecure;
    let wp = WebPush::with_pkcs8_der(cfg, &key).unwrap();
    Fixture {
        mock,
        wp,
        sub: TestSubscription::generate(),
        vapid_public,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn delivered_encrypted_constant_payload_with_vapid() {
    let f = fixture(true).await;
    let endpoint = format!("{}/wpush/v2/opaque-subscription-id", f.mock.url());
    assert_eq!(f.wp.send(&f.sub.target(endpoint)).await, Outcome::Delivered);

    let reqs = f.mock.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert!(!r.http2);
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/wpush/v2/opaque-subscription-id");
    assert_eq!(r.header("ttl"), Some("86400"));
    assert_eq!(r.header("urgency"), Some("high"));
    assert_eq!(r.header("topic"), Some("sb"));
    assert_eq!(r.header("content-encoding"), Some("aes128gcm"));
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(
        r.header("host"),
        Some(format!("localhost:{}", f.mock.addr().port()).as_str())
    );
    let names: BTreeSet<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
    let allowed: BTreeSet<&str> = [
        "host",
        "authorization",
        "ttl",
        "urgency",
        "topic",
        "content-encoding",
        "content-type",
        "content-length",
    ]
    .into_iter()
    .collect();
    assert!(names.is_subset(&allowed), "{names:?}");

    // Body: RFC 8291, constant size, and opens to the constant plaintext only.
    assert_eq!(r.body.len(), 86 + PADDED_LEN + 16);
    assert_eq!(&r.body[16..20], &4096u32.to_be_bytes());
    assert_eq!(r.body[20], 65);
    assert_eq!(f.sub.decrypt(&r.body).unwrap(), PLAINTEXT);

    // VAPID (RFC 8292).
    let auth = r.header("authorization").unwrap();
    let rest = auth.strip_prefix("vapid t=").expect("vapid scheme");
    let (jwt, k) = rest.split_once(", k=").unwrap();
    assert_eq!(k, encode_url(&f.vapid_public));
    assert_eq!(k, f.wp.vapid_public_key());
    let parts: Vec<&str> = jwt.split('.').collect();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &f.vapid_public)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &decode_url(parts[2]).unwrap(),
        )
        .expect("VAPID signature verifies");
    let header: Value = serde_json::from_slice(&decode_url(parts[0]).unwrap()).unwrap();
    assert_eq!(header, serde_json::json!({"typ": "JWT", "alg": "ES256"}));
    let claims: Value = serde_json::from_slice(&decode_url(parts[1]).unwrap()).unwrap();
    assert_eq!(
        claims["aud"],
        format!("https://localhost:{}", f.mock.addr().port())
    );
    assert_eq!(claims["sub"], SUBJECT);
    let exp = claims["exp"].as_u64().unwrap();
    assert!(exp > now() && exp <= now() + 24 * 3600);
    assert_eq!(claims.as_object().unwrap().len(), 3);
}

#[tokio::test]
async fn every_push_has_the_same_shape_but_fresh_keys() {
    let f = fixture(true).await;
    let t = f.sub.target(format!("{}/p", f.mock.url()));
    assert_eq!(f.wp.send(&t).await, Outcome::Delivered);
    assert_eq!(f.wp.send(&t).await, Outcome::Delivered);
    let reqs = f.mock.requests();
    assert_eq!(reqs[0].body.len(), reqs[1].body.len());
    assert_ne!(reqs[0].body[..16], reqs[1].body[..16], "fresh salt");
    assert_ne!(
        reqs[0].body[21..86],
        reqs[1].body[21..86],
        "fresh ephemeral key"
    );
    assert_eq!(f.sub.decrypt(&reqs[1].body).unwrap(), PLAINTEXT);
}

#[tokio::test]
async fn endpoint_answers_map_to_outcomes() {
    let f = fixture(true).await;
    let t = f.sub.target(format!("{}/p", f.mock.url()));
    f.mock.push(Behaviour::Unregistered);
    assert_eq!(f.wp.send(&t).await, Outcome::Unregistered);
    f.mock.push(Behaviour::RateLimited {
        retry_after: Some(12),
    });
    assert_eq!(
        f.wp.send(&t).await,
        Outcome::Retry {
            after: Some(Duration::from_secs(12))
        }
    );
    f.mock.push(Behaviour::ServerError);
    assert_eq!(f.wp.send(&t).await, Outcome::Retry { after: None });
    f.mock.push(Behaviour::ExpiredAuth);
    assert_eq!(f.wp.send(&t).await, Outcome::Failed);
}

#[tokio::test]
async fn ssrf_targets_are_refused_before_any_connection() {
    // Production rules (no test escape hatch): the mock on loopback must be unreachable.
    let f = fixture(false).await;
    let port = f.mock.addr().port();
    for endpoint in [
        format!("https://127.0.0.1:{port}/p"),
        "https://127.0.0.1/p".to_owned(),
        format!("https://localhost:{port}/p"),
        "https://localhost/p".to_owned(),
        "https://[::1]/p".to_owned(),
        "https://169.254.169.254/latest/meta-data/".to_owned(),
        "https://10.0.0.1/p".to_owned(),
        format!("http://push.example.net:{port}/p"),
        "https://user@push.example.net/p".to_owned(),
    ] {
        assert!(!f.wp.endpoint_ok(&endpoint), "{endpoint}");
        assert_eq!(
            f.wp.send(&f.sub.target(endpoint.clone())).await,
            Outcome::Unregistered,
            "{endpoint}"
        );
    }
    assert!(f.mock.requests().is_empty());
    assert_eq!(f.mock.connections(), 0);
}

#[tokio::test]
async fn host_names_are_resolved_and_connected() {
    // The resolver path (name, then checked address). That a name resolving to a forbidden
    // address is refused is a unit test (`webpush::tests::resolution_to_loopback_is_refused`).
    let f = fixture(true).await;
    let t = f
        .sub
        .target(format!("https://localhost:{}/p", f.mock.addr().port()));
    assert_eq!(f.wp.send(&t).await, Outcome::Delivered);
}

#[tokio::test]
async fn invalid_subscription_key_is_unregistered() {
    let f = fixture(true).await;
    let mut bad = f.sub.target(format!("{}/p", f.mock.url()));
    if let songbird_push_providers::Target::WebPush { p256dh, .. } = &mut bad {
        p256dh[0] = 0x05; // not an uncompressed point
    }
    assert_eq!(f.wp.send(&bad).await, Outcome::Unregistered);
    assert!(f.mock.requests().is_empty());
}

#[tokio::test]
async fn a_slow_endpoint_times_out_as_retry() {
    let ca = TestCa::new();
    let mock = MockServer::web_push(&ca).await;
    let mut cfg = WebPushConfig::new(SUBJECT);
    cfg.http = ca.http_config();
    cfg.http.request_timeout = Duration::from_millis(300);
    cfg.allow_insecure_for_tests = true;
    let wp = WebPush::with_pkcs8_der(cfg, &p256_pkcs8()).unwrap();
    let sub = TestSubscription::generate();
    mock.push(Behaviour::Slow(Duration::from_secs(2)));
    assert_eq!(
        wp.send(&sub.target(format!("{}/p", mock.url()))).await,
        Outcome::Retry { after: None }
    );
}

/// A black-holed provider ends at the request timeout (2 s here) as a retry, and a reset
/// stream is a retry too; the client keeps working once the provider answers (D-0095).
#[tokio::test]
async fn hanging_and_reset_requests_are_retries() {
    let f = fixture(true).await;
    f.mock.push(Behaviour::Hang);
    let t = tokio::time::Instant::now();
    assert_eq!(f.wp.send(&f.sub.target(format!("{}/wpush/v2/x", f.mock.url()))).await, Outcome::Retry { after: None });
    assert!(t.elapsed() < Duration::from_secs(4), "bounded by the timeout");
    f.mock.push(Behaviour::Reset);
    assert!(matches!(f.wp.send(&f.sub.target(format!("{}/wpush/v2/x", f.mock.url()))).await, Outcome::Retry { .. }));
    assert_eq!(f.wp.send(&f.sub.target(format!("{}/wpush/v2/x", f.mock.url()))).await, Outcome::Delivered);
}
