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
    self as wire, DeviceList, Factor, IDENTITY_LEN, LINK_AUTH_CONTEXT, LINK_IDENTITY_CONTEXT,
    LinkRequest, ListedDevice, Provision,
};
use songbird_types::{AccountId, DeviceId, Secret};

const SERVER: &str = "api.test";
/// The transparency log key's seed in these tests.
const LOG_SEED: [u8; 32] = [0x61; 32];
/// The akd VRF key's seed in these tests.
const VRF_SEED: [u8; 32] = [0x62; 32];

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
    akd_store: songbird_akd::SurrealStore,
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
    let cfg = songbird_surreal::Config {
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
    };
    let akd_store =
        songbird_akd::SurrealStore::connect(Arc::new(Db::connect(cfg.clone()).await.unwrap()))
            .await
            .unwrap();
    let db = Db::connect(cfg).await.unwrap();
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
        requests: None,
        reports: None,
        calls: None,
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
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: Some(
            songbird_api::kt::Transparency::new(
                songbird_api::config::KtSettings {
                    secret: songbird_types::SecretRef::Env("UNUSED".into()),
                    log_key: songbird_types::SecretRef::Env("UNUSED".into()),
                    vrf_key: songbird_types::SecretRef::Env("UNUSED".into()),
                    fetches_per_hour: 600,
                    fetch_burst: 120,
                },
                &rand32(),
                &LOG_SEED,
                &VRF_SEED,
                akd_store.clone(),
            )
            .unwrap(),
        ),
        profiles: None,
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
        akd_store,
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
        factor: Factor::None,
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

// ----- Prompt 3, M4b (D-0053): second factors -----

mod authenticator {
    //! A software passkey (ES256) producing what a browser hands a relying party.
    use aws_lc_rs::digest::{SHA256, digest};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
    use songbird_keys::webauthn::base64url;

    pub(crate) struct Passkey {
        key: EcdsaKeyPair,
        pub(crate) id: Vec<u8>,
        rp_id: String,
        origin: String,
    }

    fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
        match b.len() {
            n @ 0..=23 => out.push(0x40 | u8::try_from(n).unwrap()),
            n @ 24..=255 => out.extend_from_slice(&[0x58, u8::try_from(n).unwrap()]),
            n => {
                out.push(0x59);
                out.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
            }
        }
        out.extend_from_slice(b);
    }

    fn cbor_text(out: &mut Vec<u8>, s: &str) {
        out.push(0x60 | u8::try_from(s.len()).unwrap());
        out.extend_from_slice(s.as_bytes());
    }

    impl Passkey {
        pub(crate) fn new(rp_id: &str, origin: &str) -> Self {
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                    .unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            let mut id = vec![0u8; 32];
            getrandom::fill(&mut id).unwrap();
            Self {
                key,
                id,
                rp_id: rp_id.into(),
                origin: origin.into(),
            }
        }

        fn client_data(&self, kind: &str, challenge: &[u8]) -> Vec<u8> {
            format!(
                r#"{{"type":"{kind}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
                base64url(challenge),
                self.origin
            )
            .into_bytes()
        }

        /// (clientDataJSON, attestationObject) for registration.
        pub(crate) fn register(&self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let public = self.key.public_key().as_ref();
            let mut ad = digest(&SHA256, self.rp_id.as_bytes()).as_ref().to_vec();
            ad.push(0x45); // UP | UV | AT
            ad.extend_from_slice(&[0; 4]);
            ad.extend_from_slice(&[0; 16]);
            ad.extend_from_slice(&u16::try_from(self.id.len()).unwrap().to_be_bytes());
            ad.extend_from_slice(&self.id);
            ad.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
            ad.extend_from_slice(&public[1..33]);
            ad.extend_from_slice(&[0x22, 0x58, 0x20]);
            ad.extend_from_slice(&public[33..]);
            let mut ao = vec![0xa3];
            cbor_text(&mut ao, "fmt");
            cbor_text(&mut ao, "none");
            cbor_text(&mut ao, "attStmt");
            ao.push(0xa0);
            cbor_text(&mut ao, "authData");
            cbor_bytes(&mut ao, &ad);
            (self.client_data("webauthn.create", challenge), ao)
        }

        /// (authenticatorData, clientDataJSON, signature) for an assertion.
        pub(crate) fn assert(&self, challenge: &[u8], count: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let mut ad = digest(&SHA256, self.rp_id.as_bytes()).as_ref().to_vec();
            ad.push(0x05); // UP | UV
            ad.extend_from_slice(&count.to_be_bytes());
            let cd = self.client_data("webauthn.get", challenge);
            let mut msg = ad.clone();
            msg.extend_from_slice(digest(&SHA256, &cd).as_ref());
            let sig = self.key.sign(&SystemRandom::new(), &msg).unwrap();
            (ad, cd, sig.as_ref().to_vec())
        }
    }
}

fn factor_settings() -> DeviceSettings {
    DeviceSettings {
        max_devices: 16,
        pin_cost: songbird_api::config::KeyCost {
            memory_kib: 64,
            iterations: 1,
        },
        pin_free_attempts: 2,
        pin_lock_base_secs: 1,
        pin_max_attempts: 5,
        channel_burst: 200,
        link_burst: 200,
        rp_id: Some("api.test".into()),
        origins: vec!["https://api.test".into()],
        ..settings()
    }
}

fn identity_transcript(r: &LinkRequest) -> Vec<u8> {
    wire::link_transcript(
        LINK_IDENTITY_CONTEXT,
        SERVER,
        &r.token,
        &r.device,
        &r.auth_key,
        &r.identity_key,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pin_gates_linking_with_attempt_limits_and_lockout() {
    let Some(s) = stack(factor_settings()).await else {
        return;
    };
    let p = primary(&s).await;
    let pin = |v: &str| format!(r#"{{"pin":"{v}"}}"#);
    // Shape: 6 to 12 digits.
    let (st, b) = p
        .client
        .send("PUT", "/v1/account/pin", Some(pin("12345").as_bytes()))
        .await
        .unwrap();
    assert_eq!((st, b.as_ref()), (400, br#"{"error":"pin"}"#.as_slice()));
    assert_eq!(
        p.client
            .send("PUT", "/v1/account/pin", Some(pin("246810").as_bytes()))
            .await
            .unwrap()
            .0,
        204
    );
    let with = |v: &'static str| move |r: &mut LinkRequest| r.factor = Factor::Pin(v.into());
    // No factor, then wrong PINs: refused; the third wrong one starts the lock.
    assert_eq!(link_flow(&s, &p, |_| {}).await.0, 403);
    assert_eq!(link_flow(&s, &p, with("111111")).await.0, 403);
    assert_eq!(link_flow(&s, &p, with("222222")).await.0, 403);
    assert_eq!(link_flow(&s, &p, with("333333")).await.0, 403);
    // Locked: even the right PIN is refused until the lock ends.
    assert_eq!(link_flow(&s, &p, with("246810")).await.0, 403);
    let (_, b) = p
        .client
        .send("GET", "/v1/account/factors", None)
        .await
        .unwrap();
    let f = json(&b);
    assert_eq!(f["pin"], true);
    assert!(f["pin_locked_secs"].as_u64().is_some(), "{f}");
    tokio::time::sleep(Duration::from_millis(2100)).await;
    // The right PIN links, and resets the count.
    let (st, linked) = link_flow(&s, &p, with("246810")).await;
    assert_eq!(st, 200);
    let l = linked.unwrap();
    let (_, b) = p
        .client
        .send("GET", "/v1/account/factors", None)
        .await
        .unwrap();
    assert!(json(&b)["pin_locked_secs"].is_null());
    // Only the primary changes factors.
    let (st, b) = l
        .client
        .send("DELETE", "/v1/account/pin", None)
        .await
        .unwrap();
    assert_eq!(
        (st, b.as_ref()),
        (403, br#"{"error":"primary"}"#.as_slice())
    );
    // Five wrong attempts in all make the PIN unusable until the primary sets a new one.
    for _ in 0..5 {
        let _ = link_flow(&s, &p, with("999999")).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        s.app
            .registry
            .db()
            .exec(
                "UPDATE account SET pin_lock = NONE RETURN NONE;",
                Vec::new(),
            )
            .await
            .unwrap();
    }
    let (_, b) = p
        .client
        .send("GET", "/v1/account/factors", None)
        .await
        .unwrap();
    assert_eq!(json(&b)["pin_unusable"], true);
    let (st, _) = link_flow(&s, &p, with("246810")).await;
    assert_eq!(st, 403);
    assert_eq!(
        p.client
            .send("PUT", "/v1/account/pin", Some(pin("135790").as_bytes()))
            .await
            .unwrap()
            .0,
        204
    );
    assert_eq!(link_flow(&s, &p, with("135790")).await.0, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_passkey_registers_and_approves_a_link_bound_to_its_transcript() {
    let Some(s) = stack(factor_settings()).await else {
        return;
    };
    let p = primary(&s).await;
    let pk = authenticator::Passkey::new("api.test", "https://api.test");
    // Registration: a challenge, used once.
    let (st, b) = p
        .client
        .send("POST", "/v1/account/passkeys/challenge", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    let challenge = hex::decode(json(&b)["challenge"].as_str().unwrap()).unwrap();
    let (cd, ao) = pk.register(&challenge);
    let body = serde_json::json!({
        "client_data_json": hex::encode(&cd),
        "attestation_object": hex::encode(&ao),
    })
    .to_string();
    let (st, b) = p
        .client
        .send("PUT", "/v1/account/passkeys", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let (st, _) = p
        .client
        .send("PUT", "/v1/account/passkeys", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 409, "the challenge is single use");
    // Registration for another origin is refused.
    let (_, b) = p
        .client
        .send("POST", "/v1/account/passkeys/challenge", None)
        .await
        .unwrap();
    let c2 = hex::decode(json(&b)["challenge"].as_str().unwrap()).unwrap();
    let other = authenticator::Passkey::new("api.test", "https://evil.test");
    let (cd2, ao2) = other.register(&c2);
    let body2 = serde_json::json!({
        "client_data_json": hex::encode(&cd2),
        "attestation_object": hex::encode(&ao2),
    })
    .to_string();
    assert_eq!(
        p.client
            .send("PUT", "/v1/account/passkeys", Some(body2.as_bytes()))
            .await
            .unwrap()
            .0,
        400
    );
    // Linking now needs the factor.
    assert_eq!(link_flow(&s, &p, |_| {}).await.0, 403);
    // An assertion over another challenge (another link's transcript) is refused.
    let id = pk.id.clone();
    let stale = {
        let pk = &pk;
        let id = id.clone();
        move |r: &mut LinkRequest| {
            let (ad, cd, sig) = pk.assert(&[7; 32], 1);
            r.factor = Factor::Passkey {
                credential_id: id.clone(),
                authenticator_data: ad,
                client_data_json: cd,
                signature: sig,
            };
        }
    };
    assert_eq!(link_flow(&s, &p, stale).await.0, 403);
    // An assertion over this link's own transcript approves it.
    let good = {
        let pk = &pk;
        move |r: &mut LinkRequest| {
            let c = songbird_keys::webauthn::link_challenge(&identity_transcript(r));
            let (ad, cd, sig) = pk.assert(&c, 1);
            r.factor = Factor::Passkey {
                credential_id: id.clone(),
                authenticator_data: ad,
                client_data_json: cd,
                signature: sig,
            };
        }
    };
    assert_eq!(link_flow(&s, &p, good).await.0, 200);
    // A counter that does not grow (a cloned authenticator) is refused.
    let id = pk.id.clone();
    let cloned = {
        let pk = &pk;
        move |r: &mut LinkRequest| {
            let c = songbird_keys::webauthn::link_challenge(&identity_transcript(r));
            let (ad, cd, sig) = pk.assert(&c, 1);
            r.factor = Factor::Passkey {
                credential_id: id.clone(),
                authenticator_data: ad,
                client_data_json: cd,
                signature: sig,
            };
        }
    };
    assert_eq!(link_flow(&s, &p, cloned).await.0, 403);
    let (_, b) = p
        .client
        .send("GET", "/v1/account/factors", None)
        .await
        .unwrap();
    assert_eq!(json(&b)["passkeys"].as_array().unwrap().len(), 1);
    // Removing it lifts the requirement.
    let del = serde_json::json!({ "id": hex::encode(&pk.id) }).to_string();
    assert_eq!(
        p.client
            .send("DELETE", "/v1/account/passkeys", Some(del.as_bytes()))
            .await
            .unwrap()
            .0,
        204
    );
    assert_eq!(link_flow(&s, &p, |_| {}).await.0, 200);
}

/// Prompt 3, M4b: several accounts on one installation are separate accounts on the server (own
/// device IDs, keys, mailboxes and push registrations); nothing one does reaches the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accounts_sharing_an_installation_stay_apart() {
    let Some(s) = stack(factor_settings()).await else {
        return;
    };
    let (work, home) = (primary(&s).await, primary(&s).await);
    let (_, l) = link_flow(&s, &work, |_| {}).await;
    let l = l.unwrap();
    // Each sees only its own devices.
    let (_, b) = home.client.send("GET", "/v1/devices", None).await.unwrap();
    let ids: Vec<String> = json(&b)["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec![home.device.to_hex_unredacted()]);
    // One account cannot list the other's device, nor sign for it, nor take its PIN.
    let mut list = signed_list(&home, 1, &[&l], &home.account_key);
    assert_eq!(put_list(&home, &list).await.0, 409);
    list = signed_list(&work, 1, &[&l], &work.account_key);
    assert_eq!(put_list(&home, &list).await.0, 400);
    assert_eq!(
        home.client
            .send("PUT", "/v1/account/pin", Some(br#"{"pin":"112233"}"#))
            .await
            .unwrap()
            .0,
        204
    );
    let (_, b) = work
        .client
        .send("GET", "/v1/account/factors", None)
        .await
        .unwrap();
    assert_eq!(json(&b)["pin"], false);
    // Linking to one account needs only that account's factors.
    assert_eq!(link_flow(&s, &work, |_| {}).await.0, 200);
    assert_eq!(link_flow(&s, &home, |_| {}).await.0, 403);
    // Their push registrations are separate rows under keyed, per-device indexes.
    assert_ne!(
        songbird_accounts::push_index(&[9; 32], &work.device),
        songbird_accounts::push_index(&[9; 32], &home.device)
    );
}

/// Prompt 3 (D-0057): what a client checks on akd. The signed head (log key); the account's
/// identity key and device list by lookup proofs against that head, under the label its salt
/// gives (VRF key); the identity key's history; and that the directory only grew between two
/// consecutive heads (audit).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_verify_the_transparency_log() {
    use akd::verify::history::{HistoryParams, HistoryVerificationParams};
    use songbird_akd::{Config, Kind, SignedHead, label, proofs};

    let Some(s) = stack(settings()).await else {
        return;
    };
    let log_public: [u8; 32] = pk(&Ed25519KeyPair::from_seed_unchecked(&LOG_SEED).unwrap());
    let p = primary(&s).await;
    let other = primary(&s).await;
    let reg = &s.app.registry;
    // The worker's publisher on the same database (the only writer).
    let publisher =
        songbird_akd::Publisher::open(s.akd_store.clone(), songbird_akd::SecretVrf::new(&VRF_SEED))
            .await
            .unwrap();
    publisher.publish_pending(reg, 100).await.unwrap();
    // The keys apps pin.
    let (st, b) = other.client.send("GET", "/v1/kt/keys", None).await.unwrap();
    assert_eq!(st, 200);
    let keys = json(&b);
    assert_eq!(keys["log"], hex::encode(log_public));
    let vrf = hex::decode(keys["vrf"].as_str().unwrap()).unwrap();
    let head = |b: &[u8]| {
        let h = SignedHead::decode(b).unwrap();
        assert!(songbird_keys::ed25519_verify(
            &log_public,
            &h.signed_bytes(),
            &h.signature
        ));
        h
    };
    let verify = |v: &serde_json::Value, account: AccountId, kind: Kind| {
        let salt: [u8; 32] = hex::decode(v["salt"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let h = head(&hex::decode(v["head"].as_str().unwrap()).unwrap());
        let proof =
            proofs::decode_lookup(&hex::decode(v["proof"].as_str().unwrap()).unwrap()).unwrap();
        let l = label(kind, account.as_bytes());
        let r = akd::client::lookup_verify::<Config>(&vrf, h.root, h.epoch, l, proof).unwrap();
        (h, salt, r.value.0)
    };
    // Another account's device verifies p's identity key.
    let (st, v) = kt_lookup(&other.client, p.account, "identity").await;
    assert_eq!(st, 200);
    let v = v.unwrap();
    let (h1, salt, value) = verify(&v, p.account, Kind::Identity);
    assert_eq!(
        value,
        songbird_akd::value(&salt, Kind::Identity, &sha(&pk(&p.account_key))).0
    );
    // The proof does not hold for another account's label, nor against another root.
    let proof =
        || proofs::decode_lookup(&hex::decode(v["proof"].as_str().unwrap()).unwrap()).unwrap();
    let wrong = label(Kind::Identity, other.account.as_bytes());
    assert!(akd::client::lookup_verify::<Config>(&vrf, h1.root, h1.epoch, wrong, proof()).is_err());
    let right = label(Kind::Identity, p.account.as_bytes());
    assert!(akd::client::lookup_verify::<Config>(&vrf, [9; 32], h1.epoch, right, proof()).is_err());
    // No device list yet: not found.
    assert_eq!(
        kt_lookup(&other.client, p.account, "device_list").await.0,
        404
    );
    // p links a device and signs a list; the next epoch carries it.
    let (_, l) = link_flow(&s, &p, |_| {}).await;
    let l = l.unwrap();
    let list = signed_list(&p, 1, &[&l], &p.account_key);
    assert_eq!(put_list(&p, &list).await.0, 204);
    publisher.publish_pending(reg, 100).await.unwrap();
    let (st, v) = kt_lookup(&other.client, p.account, "device_list").await;
    assert_eq!(st, 200);
    let (h2, _, value) = verify(v.as_ref().unwrap(), p.account, Kind::DeviceList);
    assert_eq!(
        value,
        songbird_akd::value(&salt, Kind::DeviceList, &sha(&list.encode())).0
    );
    // A server handing out another salt cannot make the published value match another list.
    assert_ne!(
        value,
        songbird_akd::value(&[0; 32], Kind::DeviceList, &sha(b"forged")).0
    );
    assert_eq!(h2.epoch, h1.epoch + 1);
    // The identity key's history: one key, never replaced.
    let body = format!(
        r#"{{"account":"{}","kind":"identity"}}"#,
        p.account.to_hex_unredacted()
    );
    let (st, b) = other
        .client
        .send("POST", "/v1/kt/history", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 200);
    let v = json(&b);
    let h = head(&hex::decode(v["head"].as_str().unwrap()).unwrap());
    let hist = proofs::decode_history(&hex::decode(v["proof"].as_str().unwrap()).unwrap()).unwrap();
    let res = akd::client::key_history_verify::<Config>(
        &vrf,
        h.root,
        h.epoch,
        label(Kind::Identity, p.account.as_bytes()),
        hist,
        HistoryVerificationParams::Default {
            history_params: HistoryParams::MostRecent(songbird_api::kt::HISTORY),
        },
    )
    .unwrap();
    assert_eq!(res.len(), 1);
    // The directory only grew between the two heads; a forked root fails.
    let body = format!(r#"{{"from":{},"to":{}}}"#, h1.epoch, h2.epoch);
    let (st, b) = other
        .client
        .send("POST", "/v1/kt/audit", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 200);
    let audit = || {
        proofs::decode_audit(&hex::decode(json(&b)["proof"].as_str().unwrap()).unwrap()).unwrap()
    };
    akd::auditor::audit_verify::<Config>(vec![h1.root, h2.root], audit())
        .await
        .unwrap();
    assert!(
        akd::auditor::audit_verify::<Config>(vec![[3; 32], h2.root], audit())
            .await
            .is_err()
    );
    // Epochs out of order are refused; an unknown account is 404; a malformed body 400.
    let bad = format!(r#"{{"from":{},"to":{}}}"#, h2.epoch, h1.epoch);
    assert_eq!(
        other
            .client
            .send("POST", "/v1/kt/audit", Some(bad.as_bytes()))
            .await
            .unwrap()
            .0,
        400
    );
    assert_eq!(
        kt_lookup(&other.client, AccountId::random().unwrap(), "identity")
            .await
            .0,
        404
    );
    let (st, _) = other
        .client
        .send(
            "POST",
            "/v1/kt/lookup",
            Some(br#"{"account":"00","kind":"x"}"#),
        )
        .await
        .unwrap();
    assert_eq!(st, 400);
    // The current head, signed.
    let (st, b) = other.client.send("GET", "/v1/kt/head", None).await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(head(&b).epoch, h2.epoch);
}

async fn kt_lookup(
    c: &ApiClient,
    account: AccountId,
    kind: &str,
) -> (u16, Option<serde_json::Value>) {
    let body = format!(
        r#"{{"account":"{}","kind":"{kind}"}}"#,
        account.to_hex_unredacted()
    );
    let (st, b) = c
        .send("POST", "/v1/kt/lookup", Some(body.as_bytes()))
        .await
        .unwrap();
    (st, (st == 200).then(|| json(&b)))
}

fn sha(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref());
    out
}
