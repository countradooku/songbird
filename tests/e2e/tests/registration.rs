//! Prompt 3, M1 (D-0048): accounts registered through `api` (proof of work, invite) can connect
//! to `delivery` and talk, with no operator step in between: `delivery` follows the registry.
//! Runs against SurrealDB and `valkey-hot` (`SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`),
//! `SONGBIRD_TEST_VALKEY`); with `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of
//! skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::Ed25519KeyPair;
use songbird_accounts::{Db, Registry, invite_hash};
use songbird_api::client::{ApiClient, Registered, Registrar};
use songbird_api::config::{PowSettings, RegistrationSettings, ThrottleSettings};
use songbird_api::registration::{Registration, RegistrationMetrics};
use songbird_api::{ApiMetrics, App};
use songbird_client::{ClientConfig, DeviceKey, ResumeState, State};
use songbird_delivery::{DeliveryMetrics, Directory, Shared, server};
use songbird_e2e::{SERVER_NAME, key, next_delivery, settings, test_mailbox, to};
use songbird_jobs::{Queue, QueueConfig};
use songbird_proto::frame::{Recipient, RejectReason, SendHints, SendStatus};
use songbird_proto::registration::{INVITE_LEN, invite};
use songbird_router::LocalRouter;
use songbird_types::{DeviceId, Secret, SecretRef};

const API: &str = "api.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

/// A person's app: an identity key, an authentication key seed, and after registration its IDs.
struct Person {
    identity: Ed25519KeyPair,
    seed: [u8; 32],
    device: Option<DeviceId>,
}

impl Person {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        aws_lc_rs::rand::fill(&mut seed).unwrap();
        Self {
            identity: Ed25519KeyPair::generate().unwrap(),
            seed,
            device: None,
        }
    }

    fn auth(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&self.seed).unwrap()
    }

    async fn register(&mut self, r: &Registrar, code: [u8; INVITE_LEN]) {
        match r
            .register(&self.identity, &self.auth(), Some(code))
            .await
            .unwrap()
        {
            Registered::Ok { device, .. } => self.device = Some(device),
            Registered::Refused(e) => panic!("refused {e:?}"),
        }
    }

    fn device_key(&self) -> DeviceKey {
        DeviceKey::from_seed(self.device.unwrap(), &self.seed).unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registered_accounts_connect_and_talk_without_an_operator() {
    let (Some(surreal), Some(hot)) = (env("SONGBIRD_TEST_SURREALDB"), env("SONGBIRD_TEST_VALKEY"))
    else {
        return;
    };
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("p03m1_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        // Generous: CI's shared SurrealDB also serves the prekey gate's 400 concurrent claims.
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());

    // Delivery, starting with an empty directory and following the registry.
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_accounts(Vec::new()),
        test_mailbox().await,
        LocalRouter::new(),
        DeliveryMetrics::default(),
    ));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(server::serve(
        listener,
        None,
        Arc::clone(&shared),
        stop_rx.clone(),
    ));
    tokio::spawn(songbird_delivery::directory::follow_registry(
        Arc::clone(&registry),
        Arc::clone(&shared.directory),
        Arc::clone(&shared.generation),
        registry.directory_version().await.unwrap(),
        Duration::from_millis(100),
        stop_rx.clone(),
    ));

    // api with invite-only registration.
    let mut secret = [0u8; 32];
    aws_lc_rs::rand::fill(&mut secret).unwrap();
    let reg = Registration::new(
        RegistrationSettings {
            secret: SecretRef::Env("UNUSED".into()),
            invite_only: true,
            allowance: 1,
            invite_ttl_days: 7,
            challenge_ttl_secs: 600,
            max_concurrent_verifications: 2,
            pow: PowSettings {
                memory_kib: 64,
                iterations: 1,
                bits: 3,
                solutions: 4,
            },
            throttle: ThrottleSettings::default(),
        },
        &secret,
        RegistrationMetrics::default(),
    )
    .unwrap();
    let app = Arc::new(App {
        plans: songbird_api::plans::Plans::default(),
        requests: None,
        reports: None,
        calls: None,
        server_name: API.into(),
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
        registry: Arc::clone(&registry),
        s3: songbird_s3::Client::new(songbird_s3::Config::new(
            "127.0.0.1:9".into(),
            "unused".into(),
            Secret::new("unused".into()),
            Secret::new("unused-secret".into()),
        ))
        .unwrap(),
        queue: Arc::new(
            Queue::connect(
                redis::Client::open(hot.as_str()).unwrap(),
                &[3; 32],
                QueueConfig::new("p03m1".into()),
            )
            .await
            .unwrap(),
        ),
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public: [0; 32],
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: Some(reg),
        usernames: None,
        keys: None,
        storage: None,
        vault: None,
        kt: None,
        profiles: None,
        devices: None,
    });
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    tokio::spawn(songbird_api::server::serve(
        api_listener,
        None,
        Arc::clone(&app),
        64,
        stop_rx.clone(),
    ));
    let registrar = Registrar::new(api_addr, API);

    // An early tester gets an operator's code; she invites Bob with her own allowance.
    let mut operator_code = [0u8; INVITE_LEN];
    aws_lc_rs::rand::fill(&mut operator_code).unwrap();
    registry
        .create_invites(&[invite_hash(&operator_code)], 1, Duration::from_secs(3600))
        .await
        .unwrap();
    let mut alice = Person::new();
    alice.register(&registrar, operator_code).await;
    let alice_api = ApiClient::new(api_addr, API, alice.device.unwrap(), alice.auth());
    let (status, body) = alice_api.send("POST", "/v1/invites", None).await.unwrap();
    assert_eq!(status, 201);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let bob_code = invite::parse(v["code"].as_str().unwrap()).unwrap();
    let mut bob = Person::new();
    bob.register(&registrar, bob_code).await;

    // Without the grace period, a client that beats the directory reload stops for good: the
    // server answers an unknown device exactly like a wrong key (4000, do not reconnect).
    // With it, both connect once the directory has them, and exchange messages.
    let client = |p: &Person| {
        let mut c = ClientConfig::new(addr.to_string(), SERVER_NAME);
        c.backoff.initial = Duration::from_millis(20);
        c.backoff.max = Duration::from_millis(200);
        // Connecting right after registering: the directory may not hold the device yet.
        c.new_device_grace = Duration::from_secs(10);
        songbird_client::Client::start(c, p.device_key(), ResumeState::default())
    };
    let (mut a, mut a_ev) = client(&alice);
    let (mut b, mut b_ev) = client(&bob);
    tokio::time::timeout(Duration::from_secs(10), a.wait_for(State::Connected))
        .await
        .expect("alice connects");
    tokio::time::timeout(Duration::from_secs(10), b.wait_for(State::Connected))
        .await
        .expect("bob connects");
    // Prompt 4 (D-0062): strangers cannot simply write to each other. Without a profile (and
    // its access key) Bob is reachable by a message request only.
    let r = a
        .send(key(), vec![to(bob.device.unwrap(), "no key")])
        .await
        .unwrap();
    assert_eq!(
        r,
        SendStatus::Rejected {
            reason: RejectReason::AccessRequired,
            retry_after_ms: 0
        }
    );
    // Each publishes a profile with its access key, and they exchange profile keys (out of band
    // here): from then on each writes to the other as a contact.
    let account_of = async |d: DeviceId| registry.device(&d).await.unwrap().unwrap().account;
    let (alice_account, bob_account) = (
        account_of(alice.device.unwrap()).await,
        account_of(bob.device.unwrap()).await,
    );
    for (acct, k) in [(alice_account, [0xA1; 16]), (bob_account, [0xB1; 16])] {
        registry
            .put_profile(&acct, 1, b"profile", &k, false)
            .await
            .unwrap();
    }
    let r = send_as_contact(&a, [0xB1; 16], vec![to(bob.device.unwrap(), "hello bob")]).await;
    assert_eq!(r, SendStatus::Accepted);
    assert_eq!(&next_delivery(&mut b_ev).await.1[..], b"hello bob");
    let r = send_as_contact(
        &b,
        [0xA1; 16],
        vec![to(alice.device.unwrap(), "hello alice")],
    )
    .await;
    assert_eq!(r, SendStatus::Accepted);
    assert_eq!(&next_delivery(&mut a_ev).await.1[..], b"hello alice");

    // A device that never registered keeps getting 4000 and stops once the grace period ends.
    let stranger = Person {
        device: Some(DeviceId::random().unwrap()),
        ..Person::new()
    };
    let mut c = ClientConfig::new(addr.to_string(), SERVER_NAME);
    c.backoff.initial = Duration::from_millis(20);
    c.backoff.max = Duration::from_millis(100);
    c.new_device_grace = Duration::from_millis(500);
    let (mut s, _ev) =
        songbird_client::Client::start(c, stranger.device_key(), ResumeState::default());
    let state = tokio::time::timeout(Duration::from_secs(10), s.wait_for(State::Failed))
        .await
        .expect("the stranger gives up");
    assert_eq!(state, State::Failed);
}

/// Sends as a contact (with the recipient's access key), waiting for the directory to follow a
/// profile just published: until then the send is refused as access required and stores nothing.
async fn send_as_contact(
    c: &songbird_client::Client,
    access: [u8; 16],
    recipients: Vec<Recipient>,
) -> SendStatus {
    let k = key();
    for _ in 0..200 {
        let hints = SendHints {
            access: Some(access),
            ..SendHints::default()
        };
        let st = c.send_hinted(k, hints, recipients.clone()).await.unwrap();
        if !matches!(
            st,
            SendStatus::Rejected {
                reason: RejectReason::AccessRequired,
                ..
            }
        ) {
            return st;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the directory never followed the profiles")
}
