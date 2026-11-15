//! Devices over HTTP against SurrealDB and `valkey-hot` (Prompt 3, M4, D-0052): the whole QR
//! linking flow as two clients run it, the signed list's refusals, removal and the limits. Runs
//! when `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`) and `SONGBIRD_TEST_VALKEY` are set; with
//! `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use songbird_accounts::{Db, KeysUpdate, NewAccount, Registry};
use songbird_api::client::{ApiClient, unsigned};
use songbird_api::config::{DeviceSettings, KeyThrottle};
use songbird_api::devices::{DeviceMetrics, Devices};
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{Queue, QueueConfig};
use songbird_keys::provisioning::{self, ProvisioningKey};
use songbird_keys::xeddsa::Signer;
use songbird_proto::devices::{
    self as wire, DeviceList, IDENTITY_LEN, LINK_AUTH_CONTEXT, LINK_IDENTITY_CONTEXT, LinkRequest,
    ListedDevice, Provision,
};
use songbird_types::{AccountId, DeviceId, Secret};

const SERVER: &str = "api.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

struct Stack {
    app: Arc<App>,
    addr: std::net::SocketAddr,
    _stop: tokio::sync::watch::Sender<bool>,
}

fn settings() -> DeviceSettings {
    DeviceSettings {
        long_poll_secs: 1,
        token_burst: 50,
        ..DeviceSettings::default()
    }
}

async fn stack(d: DeviceSettings) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!(
            "devices_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    // A secret of its own per test: throttle records never meet.
    let devices = Devices::new(
        d,
        &KeyThrottle::default(),
        &rand32(),
        None,
        DeviceMetrics::default(),
    )
    .unwrap();
    let app = Arc::new(App {
        server_name: SERVER.into(),
        registry,
        s3: songbird_s3::Client::new(songbird_s3::Config::new(
            "127.0.0.1:9".into(),
            "unused".into(),
            Secret::new("unused".into()),
            Secret::new("unused-secret".into()),
        ))
        .unwrap(),
        queue: Arc::new(
            Queue::connect(
                redis::Client::open(hot.clone()).unwrap(),
                &[3; 32],
                QueueConfig::new(format!("devices-test-{}", hex::encode(rand32()))),
            )
            .await
            .unwrap(),
        ),
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
            .await
            .unwrap(),
        push_public: [0; 32],
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        devices: Some(devices),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(songbird_api::server::serve(
        listener,
        None,
        Arc::clone(&app),
        64,
        rx,
    ));
    Some(Stack {
        app,
        addr,
        _stop: stop,
    })
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn pk(k: &Ed25519KeyPair) -> [u8; 32] {
    k.public_key().as_ref().try_into().unwrap()
}

fn ec(s: &Signer) -> [u8; IDENTITY_LEN] {
    let mut k = [0u8; IDENTITY_LEN];
    k[0] = 5;
    k[1..].copy_from_slice(&s.public());
    k
}

/// A registered account's primary: account identity key, device identity key (uploaded), client.
struct Primary {
    account: AccountId,
    device: DeviceId,
    account_key: Ed25519KeyPair,
    auth_key: [u8; 32],
    identity: Signer,
    client: ApiClient,
}

async fn primary(s: &Stack) -> Primary {
    let account_key = Ed25519KeyPair::generate().unwrap();
    let auth = Ed25519KeyPair::generate().unwrap();
    let identity = Signer::new(&rand32());
    let n = NewAccount {
        account: AccountId::random().unwrap(),
        identity: pk(&account_key),
        device: DeviceId::random().unwrap(),
        auth_key: pk(&auth),
        allowance: 0,
    };
    s.app.registry.register(&n, None).await.unwrap();
    s.app
        .registry
        .put_keys(
            &n.device,
            &KeysUpdate {
                identity: Some(ec(&identity)),
                signed: Some(vec![1]),
                last_resort: Some(vec![2]),
                ..KeysUpdate::default()
            },
            10,
        )
        .await
        .unwrap();
    Primary {
        account: n.account,
        device: n.device,
        account_key,
        auth_key: pk(&auth),
        identity,
        client: ApiClient::new(s.addr, SERVER, n.device, auth),
    }
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

fn hex16(v: &serde_json::Value) -> [u8; 16] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// What the new device ends with.
struct Linked {
    device: DeviceId,
    auth_key: [u8; 32],
    identity: [u8; IDENTITY_LEN],
    client: ApiClient,
    confirm_key: [u8; 32],
}

/// The whole QR flow; the new device's link request goes through `tamper` first.
async fn link_flow(
    s: &Stack,
    p: &Primary,
    tamper: impl Fn(&mut LinkRequest),
) -> (u16, Option<Linked>) {
    // New device: a provisioning key and a channel (the QR code shows both).
    let qr = ProvisioningKey::generate().unwrap();
    let (st, b) = unsigned(s.addr, SERVER, "POST", "/v1/provisioning", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    let channel = json(&b)["channel"].as_str().unwrap().to_owned();
    let path = format!("/v1/provisioning/{channel}");
    // Primary: a link token, sealed to the QR key with the account and a confirmation key.
    let (st, b) = p
        .client
        .send("POST", "/v1/devices/link-token", None)
        .await
        .unwrap();
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let t = json(&b);
    let token: [u8; 32] = hex::decode(t["token"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let device = DeviceId::from_bytes(hex16(&t["device"]));
    let confirm_key = rand32();
    let msg = Provision {
        account: p.account,
        account_identity: pk(&p.account_key),
        token,
        device,
        confirm_key,
        server_name: SERVER.into(),
    };
    let sealed = provisioning::seal(&qr.public(), &msg.encode().unwrap()).unwrap();
    assert_eq!(
        p.client.send("PUT", &path, Some(&sealed)).await.unwrap().0,
        204
    );
    // A channel holds one message.
    assert_eq!(
        p.client.send("PUT", &path, Some(&sealed)).await.unwrap().0,
        404
    );
    // New device: reads it once, opens it.
    let (st, b) = unsigned(s.addr, SERVER, "GET", &path, None).await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(b.as_ref(), sealed.as_slice());
    assert_eq!(
        unsigned(s.addr, SERVER, "GET", &path, None)
            .await
            .unwrap()
            .0,
        404
    );
    let got = Provision::decode(&provisioning::open(&qr, &b).unwrap()).unwrap();
    assert_eq!(got, msg);
    // Its keys, both proven over the transcript, and the confirmation tag for the primary.
    let auth = Ed25519KeyPair::generate().unwrap();
    let ident = Signer::new(&rand32());
    let mut r = LinkRequest {
        token: got.token,
        device: got.device,
        auth_key: pk(&auth),
        identity_key: ec(&ident),
        auth_sig: [0; 64],
        identity_sig: [0; 64],
        confirm: [0; 32],
    };
    let tr = |c, r: &LinkRequest| {
        wire::link_transcript(c, SERVER, &r.token, &r.device, &r.auth_key, &r.identity_key).unwrap()
    };
    let sig = auth.sign(&tr(LINK_AUTH_CONTEXT, &r));
    r.auth_sig.copy_from_slice(sig.as_ref());
    r.identity_sig = ident.sign(&tr(LINK_IDENTITY_CONTEXT, &r), &[1; 64]);
    r.confirm = provisioning::confirm_tag(&got.confirm_key, &tr(LINK_IDENTITY_CONTEXT, &r));
    tamper(&mut r);
    let (st, b) = unsigned(
        s.addr,
        SERVER,
        "POST",
        "/v1/devices/link",
        Some(&r.encode()),
    )
    .await
    .unwrap();
    if st != 200 {
        return (st, None);
    }
    let v = json(&b);
    assert_eq!(AccountId::from_bytes(hex16(&v["account"])), p.account);
    // Replaying the same request: the token is spent.
    let (again, _) = unsigned(
        s.addr,
        SERVER,
        "POST",
        "/v1/devices/link",
        Some(&r.encode()),
    )
    .await
    .unwrap();
    assert_eq!(again, 409);
    (
        st,
        Some(Linked {
            device: r.device,
            auth_key: r.auth_key,
            identity: r.identity_key,
            client: ApiClient::new(s.addr, SERVER, r.device, auth),
            confirm_key: got.confirm_key,
        }),
    )
}

fn signed_list(p: &Primary, version: u64, others: &[&Linked], key: &Ed25519KeyPair) -> DeviceList {
    let mut devices = vec![ListedDevice {
        device: p.device,
        auth_key: p.auth_key,
        identity_key: ec(&p.identity),
        primary: true,
    }];
    devices.extend(others.iter().map(|l| ListedDevice {
        device: l.device,
        auth_key: l.auth_key,
        identity_key: l.identity,
        primary: false,
    }));
    let mut l = DeviceList {
        account: p.account,
        list_version: version,
        issued_ms: 0,
        devices,
        signature: [0; 64],
    };
    let sig = key.sign(&l.signed_bytes());
    l.signature.copy_from_slice(sig.as_ref());
    l
}

async fn put_list(p: &Primary, l: &DeviceList) -> (u16, String) {
    let (st, b) = p
        .client
        .send("PUT", "/v1/devices/list", Some(&l.encode()))
        .await
        .unwrap();
    (st, String::from_utf8_lossy(&b).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_links_through_the_qr_flow_and_joins_only_through_a_signed_list() {
    let Some(s) = stack(settings()).await else {
        return;
    };
    let p = primary(&s).await;
    // Reading an empty channel waits, then answers 204 (ask again).
    let (_, b) = unsigned(s.addr, SERVER, "POST", "/v1/provisioning", None)
        .await
        .unwrap();
    let ch = json(&b)["channel"].as_str().unwrap().to_owned();
    let started = std::time::Instant::now();
    let (st, _) = unsigned(
        s.addr,
        SERVER,
        "GET",
        &format!("/v1/provisioning/{ch}"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(st, 204);
    assert!(started.elapsed() >= Duration::from_millis(900));
    // An unknown channel, an oversized message, a message without a signature.
    let unknown = format!("/v1/provisioning/{}", hex::encode([7u8; 16]));
    assert_eq!(
        p.client.send("PUT", &unknown, Some(b"x")).await.unwrap().0,
        404
    );
    let big = vec![0u8; wire::MAX_PROVISIONING_LEN + 1];
    let path = format!("/v1/provisioning/{ch}");
    assert_eq!(
        p.client.send("PUT", &path, Some(&big)).await.unwrap().0,
        413
    );
    assert_eq!(
        unsigned(s.addr, SERVER, "PUT", &path, Some(b"x"))
            .await
            .unwrap()
            .0,
        401
    );

    let (st, linked) = link_flow(&s, &p, |_| {}).await;
    assert_eq!(st, 200);
    let l = linked.unwrap();
    // The new device authenticates at once, and sees itself pending.
    let (st, b) = l.client.send("GET", "/v1/devices", None).await.unwrap();
    assert_eq!(st, 200);
    let v = json(&b);
    let _me = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["device"].as_str() == Some(&l.device.to_hex_unredacted()))
        .filter(|d| d["pending"] == true)
        .unwrap();
    assert!(v["list_version"].is_null());
    // (The primary checks the confirmation tag first: the next test.)
    // Lists signed by anything but the account identity key are refused.
    let device_key = Ed25519KeyPair::generate().unwrap();
    let (st, b) = put_list(&p, &signed_list(&p, 1, &[&l], &device_key)).await;
    assert_eq!((st, b.as_str()), (400, r#"{"error":"signature"}"#));
    // A list for another account.
    let other = primary(&s).await;
    let (st, _) = put_list(&p, &signed_list(&other, 1, &[], &other.account_key)).await;
    assert_eq!(st, 400);
    // The right list: accepted; the device is no longer pending.
    assert_eq!(
        put_list(&p, &signed_list(&p, 1, &[&l], &p.account_key))
            .await
            .0,
        204
    );
    let (_, b) = l.client.send("GET", "/v1/devices", None).await.unwrap();
    let v = json(&b);
    assert_eq!(v["list_version"], 1);
    assert!(
        v["devices"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["pending"] == false)
    );
    // Rollback: the same or a lower version.
    let (st, b) = put_list(&p, &signed_list(&p, 1, &[&l], &p.account_key)).await;
    assert_eq!((st, b.as_str()), (409, r#"{"error":"version"}"#));
    // Another account's device fetches the list and checks it as a client does.
    let body = format!(r#"{{"account":"{}"}}"#, p.account.to_hex_unredacted());
    let (st, b) = other
        .client
        .send("POST", "/v1/devices/list/fetch", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 200);
    let got = DeviceList::decode(&b).unwrap();
    assert!(songbird_keys::ed25519_verify(
        &pk(&p.account_key),
        &got.signed_bytes(),
        &got.signature
    ));
    assert_eq!(got.list_version, 1);
    assert_eq!(got.devices.len(), 2);
    // An account without a list.
    let body = format!(r#"{{"account":"{}"}}"#, other.account.to_hex_unredacted());
    assert_eq!(
        p.client
            .send("POST", "/v1/devices/list/fetch", Some(body.as_bytes()))
            .await
            .unwrap()
            .0,
        404
    );
    // Version 2 leaves the device out: removed, it can no longer authenticate.
    assert_eq!(
        put_list(&p, &signed_list(&p, 2, &[], &p.account_key))
            .await
            .0,
        204
    );
    assert_eq!(
        l.client.send("GET", "/v1/devices", None).await.unwrap().0,
        401
    );
    // And it cannot be named again.
    let (st, b) = put_list(&p, &signed_list(&p, 3, &[&l], &p.account_key)).await;
    assert_eq!((st, b.as_str()), (409, r#"{"error":"devices"}"#));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_confirmation_tag_verifies_with_the_real_transcript() {
    let Some(s) = stack(settings()).await else {
        return;
    };
    let p = primary(&s).await;
    // Keep the request the new device sent.
    let sent = std::sync::Mutex::new(None);
    let (st, linked) = link_flow(&s, &p, |r| {
        *sent.lock().unwrap() = Some(r.clone());
    })
    .await;
    assert_eq!(st, 200);
    let l = linked.unwrap();
    let r = sent.lock().unwrap().clone().unwrap();
    let (_, b) = p.client.send("GET", "/v1/devices", None).await.unwrap();
    let v = json(&b);
    let row = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["pending"] == true)
        .unwrap()
        .clone();
    let tag: [u8; 32] = hex::decode(row["confirm"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let t = wire::link_transcript(
        LINK_IDENTITY_CONTEXT,
        SERVER,
        &r.token,
        &l.device,
        &l.auth_key,
        &l.identity,
    )
    .unwrap();
    assert!(provisioning::confirm_ok(&l.confirm_key, &t, &tag));
    // A server that swapped in keys of its own cannot produce it: another identity key fails.
    let mut other_identity = l.identity;
    other_identity[5] ^= 1;
    let t2 = wire::link_transcript(
        LINK_IDENTITY_CONTEXT,
        SERVER,
        &r.token,
        &l.device,
        &l.auth_key,
        &other_identity,
    )
    .unwrap();
    assert!(!provisioning::confirm_ok(&l.confirm_key, &t2, &tag));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_link_proofs_limits_and_self_removal() {
    let Some(s) = stack(DeviceSettings {
        max_devices: 2,
        ..settings()
    })
    .await
    else {
        return;
    };
    let p = primary(&s).await;
    // A tampered proof is refused and leaves the token unspent for the right device.
    let (st, _) = link_flow(&s, &p, |r| r.auth_sig[0] ^= 1).await;
    assert_eq!(st, 400);
    // That token still counts toward the limit until it expires: primary + 1 outstanding = 2.
    assert_eq!(
        p.client
            .send("POST", "/v1/devices/link-token", None)
            .await
            .unwrap()
            .0,
        409
    );
    // Expire it, then link for real.
    s.app
        .registry
        .db()
        .exec(
            "UPDATE ltoken SET expires = time::now() - 1s RETURN NONE;",
            Vec::new(),
        )
        .await
        .unwrap();
    let (st, linked) = link_flow(&s, &p, |_| {}).await;
    assert_eq!(st, 200);
    let l = linked.unwrap();
    // Full: no more tokens; a linked device may not ask for one either.
    let (st, b) = p
        .client
        .send("POST", "/v1/devices/link-token", None)
        .await
        .unwrap();
    assert_eq!((st, b.as_ref()), (409, br#"{"error":"limit"}"#.as_slice()));
    let (st, b) = l
        .client
        .send("POST", "/v1/devices/link-token", None)
        .await
        .unwrap();
    assert_eq!(
        (st, b.as_ref()),
        (409, br#"{"error":"primary"}"#.as_slice())
    );
    // A malformed link body.
    let (st, _) = unsigned(s.addr, SERVER, "POST", "/v1/devices/link", Some(&[1u8; 10]))
        .await
        .unwrap();
    assert_eq!(st, 400);
    // The primary cannot remove itself; the linked device can, and is gone.
    assert_eq!(
        p.client
            .send("DELETE", "/v1/devices/self", None)
            .await
            .unwrap()
            .0,
        409
    );
    assert_eq!(
        l.client
            .send("DELETE", "/v1/devices/self", None)
            .await
            .unwrap()
            .0,
        204
    );
    assert_eq!(
        l.client.send("GET", "/v1/devices", None).await.unwrap().0,
        401
    );
    // Room again.
    assert_eq!(
        p.client
            .send("POST", "/v1/devices/link-token", None)
            .await
            .unwrap()
            .0,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_and_links_are_throttled_per_range() {
    let Some(s) = stack(DeviceSettings {
        channels_per_hour: 1,
        channel_burst: 2,
        links_per_hour: 1,
        link_burst: 2,
        ..settings()
    })
    .await
    else {
        return;
    };
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            unsigned(s.addr, SERVER, "POST", "/v1/provisioning", None)
                .await
                .unwrap()
                .0,
        );
    }
    assert_eq!(statuses[..2], [200, 200]);
    assert_eq!(statuses[3], 429);
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            unsigned(
                s.addr,
                SERVER,
                "POST",
                "/v1/devices/link",
                Some(&[0u8; wire::LINK_LEN]),
            )
            .await
            .unwrap()
            .0,
        );
    }
    assert_eq!(statuses[..2], [400, 400]);
    assert_eq!(statuses[3], 429);
}
