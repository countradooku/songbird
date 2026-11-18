//! FCM HTTP v1 client against the mock FCM and its OAuth token endpoint (HTTP/2 over TLS).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::BTreeSet;
use std::time::Duration;

use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde_json::Value;
use songbird_push_providers::b64::decode_url;
use songbird_push_providers::fcm::{Fcm, FcmConfig, SCOPE, ServiceAccount};
use songbird_push_providers::test_support::{Behaviour, MockServer, TestCa, rsa_pkcs8};
use songbird_push_providers::{Outcome, Provider, Target};

const PROJECT: &str = "songbird-test";
const EMAIL: &str = "push@songbird-test.iam.gserviceaccount.com";
const TOKEN: &str = "dGVzdC10b2tlbg:APA91bHun4MxP5egoKMwt2KZFBaFUH-1RYqx";

struct Fixture {
    mock: MockServer,
    fcm: Fcm,
    rsa_public: Vec<u8>,
    token_uri: String,
}

async fn fixture() -> Fixture {
    let ca = TestCa::new();
    let mock = MockServer::fcm(&ca).await;
    let key = rsa_pkcs8();
    let rsa_public = RsaKeyPair::from_pkcs8(&key)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let token_uri = format!("{}/token", mock.url());
    let account = ServiceAccount::with_pkcs8_der(PROJECT, EMAIL, &token_uri, &key).unwrap();
    let cfg = FcmConfig {
        base_url: mock.url(),
        http: ca.http_config(),
        ..FcmConfig::default()
    };
    let fcm = Fcm::new(&cfg, account).unwrap();
    Fixture {
        mock,
        fcm,
        rsa_public,
        token_uri,
    }
}

fn target() -> Target {
    Target::Fcm {
        token: TOKEN.to_owned(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn delivered_with_oauth_token_and_only_the_constant_message() {
    let f = fixture().await;
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);

    // The token exchange: a JWT-bearer grant whose assertion is signed by the service account.
    let toks = f.mock.token_requests();
    assert_eq!(toks.len(), 1);
    let t = &toks[0];
    assert!(t.http2);
    assert_eq!(t.method, "POST");
    assert_eq!(
        t.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let form = String::from_utf8(t.body.clone()).unwrap();
    let assertion = form
        .strip_prefix("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=")
        .expect("grant type first, then the assertion");
    let parts: Vec<&str> = assertion.split('.').collect();
    assert_eq!(parts.len(), 3);
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &f.rsa_public)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &decode_url(parts[2]).unwrap(),
        )
        .expect("RS256 signature verifies");
    let header: Value = serde_json::from_slice(&decode_url(parts[0]).unwrap()).unwrap();
    assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
    let claims: Value = serde_json::from_slice(&decode_url(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], EMAIL);
    assert_eq!(claims["scope"], SCOPE);
    assert_eq!(claims["aud"], f.token_uri.as_str());
    let iat = claims["iat"].as_u64().unwrap();
    assert!(iat.abs_diff(now()) < 60);
    assert_eq!(claims["exp"].as_u64().unwrap(), iat + 3600);
    assert_eq!(claims.as_object().unwrap().len(), 5);

    // The push.
    let reqs = f.mock.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert!(r.http2);
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, format!("/v1/projects/{PROJECT}/messages:send"));
    assert_eq!(r.header("authorization"), Some("Bearer mock-access-0"));
    assert_eq!(r.header("content-type"), Some("application/json"));
    let body: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "message": {
                "token": TOKEN,
                "android": { "priority": "HIGH", "collapse_key": "sb", "ttl": "86400s" }
            }
        })
    );
    let names: BTreeSet<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
    let allowed: BTreeSet<&str> = ["authorization", "content-type", "content-length"]
        .into_iter()
        .collect();
    assert!(names.is_subset(&allowed), "{names:?}");
}

#[tokio::test]
async fn access_token_is_cached() {
    let f = fixture().await;
    for _ in 0..5 {
        assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
    }
    assert_eq!(f.mock.token_requests().len(), 1);
    assert_eq!(f.mock.requests().len(), 5);
}

#[tokio::test]
async fn concurrent_sends_share_one_token_fetch() {
    let fx = fixture().await;
    let tgt = target();
    let outcomes = tokio::join!(fx.fcm.send(&tgt), fx.fcm.send(&tgt), fx.fcm.send(&tgt));
    assert_eq!(<[Outcome; 3]>::from(outcomes), [Outcome::Delivered; 3]);
    assert_eq!(fx.mock.token_requests().len(), 1);
}

#[tokio::test]
async fn access_token_is_refreshed_before_it_expires() {
    let f = fixture().await;
    // Short-lived tokens are refreshed half-way through their life.
    f.mock.set_token_lifetime(2);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
    assert_eq!(f.mock.token_requests().len(), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
    assert_eq!(f.mock.token_requests().len(), 2);
    assert_eq!(
        f.mock.requests()[2].header("authorization"),
        Some("Bearer mock-access-1")
    );
}

#[tokio::test]
async fn unauthenticated_refreshes_the_token_once() {
    let f = fixture().await;
    f.mock.push(Behaviour::ExpiredAuth);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
    assert_eq!(f.mock.token_requests().len(), 2);
    let reqs = f.mock.requests();
    assert_eq!(
        reqs[0].header("authorization"),
        Some("Bearer mock-access-0")
    );
    assert_eq!(
        reqs[1].header("authorization"),
        Some("Bearer mock-access-1")
    );

    f.mock.push(Behaviour::ExpiredAuth);
    f.mock.push(Behaviour::ExpiredAuth);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Failed);
}

#[tokio::test]
async fn provider_answers_map_to_outcomes() {
    let f = fixture().await;
    f.mock.push(Behaviour::Unregistered);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Unregistered);
    f.mock.push(Behaviour::RateLimited {
        retry_after: Some(30),
    });
    assert_eq!(
        f.fcm.send(&target()).await,
        Outcome::Retry {
            after: Some(Duration::from_secs(30))
        }
    );
    f.mock.push(Behaviour::ServerError);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Retry { after: None });
    f.mock.push(Behaviour::Unavailable);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Retry { after: None });
    // A malformed token is never sent.
    let n = f.mock.requests().len();
    let bad = Target::Fcm {
        token: "bad token\"}".into(),
    };
    assert_eq!(f.fcm.send(&bad).await, Outcome::Unregistered);
    assert_eq!(f.mock.requests().len(), n);
}

#[tokio::test]
async fn token_endpoint_failures() {
    let f = fixture().await;
    f.mock.push_token(Behaviour::ServerError);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Retry { after: None });
    f.mock.push_token(Behaviour::RateLimited {
        retry_after: Some(5),
    });
    assert_eq!(
        f.fcm.send(&target()).await,
        Outcome::Retry {
            after: Some(Duration::from_secs(5))
        }
    );
    // A refused grant (revoked key): permanent until someone fixes the credentials.
    f.mock.push_token(Behaviour::ExpiredAuth);
    assert_eq!(f.fcm.send(&target()).await, Outcome::Failed);
    assert!(f.mock.requests().is_empty(), "no push without a token");
    // And it recovers.
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
}

#[tokio::test]
async fn a_slow_provider_times_out_as_retry() {
    let ca = TestCa::new();
    let mock = MockServer::fcm(&ca).await;
    let account = ServiceAccount::with_pkcs8_der(
        PROJECT,
        EMAIL,
        &format!("{}/token", mock.url()),
        &rsa_pkcs8(),
    )
    .unwrap();
    let mut http = ca.http_config();
    http.request_timeout = Duration::from_millis(300);
    let cfg = FcmConfig {
        base_url: mock.url(),
        http,
        ..FcmConfig::default()
    };
    let fcm = Fcm::new(&cfg, account).unwrap();
    mock.push(Behaviour::Slow(Duration::from_secs(2)));
    assert_eq!(fcm.send(&target()).await, Outcome::Retry { after: None });
}

/// A black-holed provider ends at the request timeout (2 s here) as a retry, and a reset
/// stream is a retry too; the client keeps working once the provider answers (D-0095).
#[tokio::test]
async fn hanging_and_reset_requests_are_retries() {
    let f = fixture().await;
    f.mock.push(Behaviour::Hang);
    let t = tokio::time::Instant::now();
    assert_eq!(f.fcm.send(&target()).await, Outcome::Retry { after: None });
    assert!(t.elapsed() < Duration::from_secs(4), "bounded by the timeout");
    f.mock.push(Behaviour::Reset);
    assert!(matches!(f.fcm.send(&target()).await, Outcome::Retry { .. }));
    assert_eq!(f.fcm.send(&target()).await, Outcome::Delivered);
}
