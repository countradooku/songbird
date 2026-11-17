//! Prompt 7, milestone 2 (D-0087), live: calls through `api` against a real LiveKit, the real
//! registry (SurrealDB: accounts, groups) and `valkey-hot` (call records, budgets, nonces).
//! OpenMLS clients (`songbird-groups-harness`) play the apps for group membership; a
//! signalling-only WebSocket plays a participant in LiveKit (media and E2EE are the harness's,
//! `tools/calls-harness`, M4).
//!
//! Runs when `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`), `SONGBIRD_TEST_VALKEY` and
//! `SONGBIRD_TEST_LIVEKIT` (`http://host:port`, with `SONGBIRD_TEST_LIVEKIT_KEY` and `_SECRET`)
//! are set; with `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::large_futures,
    clippy::many_single_char_names,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::Ed25519KeyPair;
use bytes::Bytes;
use livekit_api::access_token::TokenVerifier;
use prost::Message as _;
use songbird_accounts::{Db, Registry};
use songbird_api::calls::CallsApi;
use songbird_api::client::ApiClient;
use songbird_api::groups::Groups;
use songbird_api::messages::{Messages, SendStack};
use songbird_api::{ApiMetrics, App};
use songbird_calls::{CallLimits, Calls, RoomId};
use songbird_client::DeviceKey;
use songbird_delivery::{DeliveryMetrics, Directory, Shared};
use songbird_e2e::{settings, test_mailbox};
use songbird_groups::Limits;
use songbird_groups::roles::Role;
use songbird_groups_harness::{Device, GID};
use songbird_mailbox::{AnyMailbox, Mailbox as _};
use songbird_router::LocalRouter;
use songbird_send::directory::Access;
use songbird_types::{AccountId, DeviceId, Secret};
use tokio::sync::watch;

const API: &str = "api.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

fn random32() -> [u8; 32] {
    let mut k = [0u8; 32];
    aws_lc_rs::rand::fill(&mut k).unwrap();
    k
}

struct Person {
    api: ApiClient,
    mls: Device,
}

struct LiveKit {
    http: String,
    key: String,
    secret: String,
}

struct Stack {
    registry: Arc<Registry>,
    shared: Arc<Shared<Arc<AnyMailbox>, Arc<LocalRouter>>>,
    app: Arc<App>,
    people: Vec<Person>,
    livekit: LiveKit,
    _stop: watch::Sender<bool>,
}

/// Bob's access key in these tests: Bob (person 1) is closed with this key, Carol (person 2) is
/// closed with none, Dave (person 3) is open; Alice (person 0) and the rest are closed.
const BOB_KEY: [u8; 16] = [0xB0; 16];

impl Stack {
    fn calls(&self) -> &CallsApi {
        self.app.calls.as_ref().unwrap()
    }

    async fn pending(&self, i: usize) -> Vec<Bytes> {
        self.shared
            .mailbox
            .fetch_after(&self.people[i].mls.id, 0, 1_000)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.envelope)
            .collect()
    }

    async fn post(
        &self,
        who: usize,
        path: &str,
        body: &serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let (st, reply) = self.people[who]
            .api
            .send("POST", path, Some(&serde_json::to_vec(body).unwrap()))
            .await
            .unwrap();
        let v = if reply.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&reply).unwrap()
        };
        (st, v)
    }
}

async fn stack(people: usize) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let livekit = LiveKit {
        http: env("SONGBIRD_TEST_LIVEKIT")?,
        key: env("SONGBIRD_TEST_LIVEKIT_KEY")?,
        secret: env("SONGBIRD_TEST_LIVEKIT_SECRET")?,
    };
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("calls_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    let mut keys = Vec::new();
    for _ in 0..people {
        let id = DeviceId::random().unwrap();
        let (_, seed) = DeviceKey::generate(id).unwrap();
        let account = AccountId::random().unwrap();
        let public = DeviceKey::from_seed(id, &seed).unwrap().public_key();
        registry
            .create_account(&account, &[(id, public)])
            .await
            .unwrap();
        keys.push((id, seed, account));
    }
    let access: Vec<(AccountId, Access)> = keys
        .iter()
        .enumerate()
        .map(|(i, (_, _, a))| {
            (
                *a,
                Access {
                    key: (i == 1).then_some(BOB_KEY),
                    open: i == 3,
                    requests_off: false,
                },
            )
        })
        .collect();
    let rows = registry.load_directory().await.unwrap();
    let mailbox = Arc::new(test_mailbox().await);
    let router = Arc::new(LocalRouter::new());
    let rosters = || -> Option<Arc<dyn songbird_send::Rosters>> {
        Some(Arc::new(songbird_send::RegistryRosters::new(
            Arc::clone(&registry),
            songbird_send::groups::ROSTER_TTL,
        )))
    };
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let shared = Arc::new(
        Shared::new(
            cfg,
            Directory::from_accounts(rows.into_iter().map(|(d, a, k)| (d, k, a)))
                .with_access(access),
            Arc::clone(&mailbox),
            Arc::clone(&router),
            DeliveryMetrics::default(),
        )
        .with_policy(songbird_delivery::Policy {
            rosters: rosters(),
            ..Default::default()
        }),
    );
    let (stop, stop_rx) = watch::channel(false);
    let metrics = ApiMetrics::default();
    let (push, _pushes) = songbird_send::Pusher::new(metrics.push.clone());
    let hot_client = redis::Client::open(hot.as_str()).unwrap();
    let messages = Messages {
        path: Box::new(SendStack {
            directory: Arc::clone(&shared.directory),
            mailbox: Arc::clone(&mailbox),
            router: Arc::clone(&router),
            push,
            metrics: metrics.send.clone(),
            policy: songbird_send::Policy {
                rosters: rosters(),
                ..Default::default()
            },
        }),
        limits: songbird_proto::Limits::DEFAULT,
        sends_per_sec: 1_000,
        send_burst: 1_000,
        group_sends_per_sec: 1_000,
        group_send_burst: 1_000,
        rate_key: songbird_api::messages::rate_key(&random32()).unwrap(),
        metrics: metrics.send.clone(),
        groups: Some({
            let mut g = Groups::new(&random32(), Limits::default()).unwrap();
            g.commits_per_sec = 1_000;
            g.commit_burst = 1_000;
            g.reads_per_sec = 1_000;
            g.read_burst = 1_000;
            g
        }),
    };
    let ws = livekit.http.replacen("http", "ws", 1);
    let calls = Calls::new(
        &random32(),
        &livekit.key,
        zeroize::Zeroizing::new(livekit.secret.clone()),
        &ws,
        &livekit.http,
        None,
        CallLimits::default(),
    )
    .unwrap();
    let app = Arc::new(App {
        requests: None,
        reports: None,
        calls: Some(CallsApi {
            calls: Arc::new(calls),
            metrics: metrics.calls.clone(),
        }),
        server_name: API.into(),
        registry: Arc::clone(&registry),
        s3: songbird_s3::Client::new(songbird_s3::Config::new(
            "127.0.0.1:9".into(),
            "unused".into(),
            Secret::new("unused".into()),
            Secret::new("unused-secret".into()),
        ))
        .unwrap(),
        queue: Arc::new(
            songbird_jobs::Queue::connect(
                hot_client.clone(),
                &[3; 32],
                songbird_jobs::QueueConfig::new(format!(
                    "calls-test-{}",
                    DeviceId::random().unwrap().to_hex_unredacted()
                )),
            )
            .await
            .unwrap(),
        ),
        hot: songbird_valkey::ValkeyConn::connect(hot_client)
            .await
            .unwrap(),
        push_public: [0; 32],
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics,
        messages: Some(messages),
        registration: None,
        usernames: None,
        keys: None,
        devices: None,
        profiles: None,
        kt: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    tokio::spawn(songbird_api::server::serve(
        listener,
        None,
        Arc::clone(&app),
        64,
        stop_rx,
    ));
    let ds_key = app
        .messages
        .as_ref()
        .unwrap()
        .groups
        .as_ref()
        .unwrap()
        .external_sender();
    let people = keys
        .into_iter()
        .map(|(id, seed, account)| Person {
            api: ApiClient::new(
                api_addr,
                API,
                id,
                Ed25519KeyPair::from_seed_unchecked(&seed).unwrap(),
            ),
            mls: {
                let mut d = Device::unregistered(id, account);
                d.ds_key = Some(ds_key);
                d
            },
        })
        .collect();
    Some(Stack {
        registry,
        shared,
        app,
        people,
        livekit,
        _stop: stop,
    })
}

// --- LiveKit, from the outside ------------------------------------------------------------

/// LiveKit's own check of a token (`GET /rtc/validate`), as SDKs use it after a failed join.
async fn validate(lk: &LiveKit, token: &str) -> u16 {
    let addr = lk.http.trim_start_matches("http://").to_owned();
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = hyper::Request::get(format!("/rtc/validate?access_token={token}"))
        .header("host", &addr)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    send.send_request(req).await.unwrap().status().as_u16()
}

/// A signalling-only participant: joins over LiveKit's WebSocket with `token` and returns the
/// socket and LiveKit's `JoinResponse` (no media: enough to be a participant until ICE gives up).
async fn join(
    lk: &LiveKit,
    token: &str,
) -> (
    sockudo_ws::WebSocketStream<tokio::net::TcpStream>,
    livekit_protocol::JoinResponse,
) {
    use futures_core::Stream as _;
    let addr = lk.http.trim_start_matches("http://").to_owned();
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let client = sockudo_ws::client::WebSocketClient::<sockudo_ws::Http1>::new(
        sockudo_ws::Config::builder().build(),
    );
    let path =
        format!("/rtc?access_token={token}&auto_subscribe=1&protocol=16&sdk=rust&version=0.0.0");
    let (mut ws, _) = client.connect_raw(tcp, &addr, &path, None).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let msg = tokio::time::timeout_at(
            deadline,
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut ws).poll_next(cx)),
        )
        .await
        .expect("a JoinResponse within 10 s")
        .expect("open")
        .expect("a frame");
        if let sockudo_ws::Message::Binary(b) = msg {
            let r = livekit_protocol::SignalResponse::decode(b).unwrap();
            if let Some(livekit_protocol::signal_response::Message::Join(j)) = r.message {
                return (ws, j);
            }
        }
    }
}

/// Waits until LiveKit tells the socket to leave or closes it.
async fn told_to_leave(ws: &mut sockudo_ws::WebSocketStream<tokio::net::TcpStream>) -> bool {
    use futures_core::Stream as _;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let next = tokio::time::timeout_at(
            deadline,
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut *ws).poll_next(cx)),
        )
        .await;
        match next {
            Err(_) => return false,
            Ok(None | Some(Err(_) | Ok(sockudo_ws::Message::Close(_)))) => return true,
            Ok(Some(Ok(sockudo_ws::Message::Binary(b)))) => {
                if let Ok(r) = livekit_protocol::SignalResponse::decode(b)
                    && matches!(
                        r.message,
                        Some(livekit_protocol::signal_response::Message::Leave(_))
                    )
                {
                    return true;
                }
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}

/// A token for `room` expiring `exp_offset` seconds from now (negative: already expired), signed with
/// `secret`, made by hand (HS256) so its times can be anything.
fn token_at(lk: &LiveKit, secret: &str, room: &str, identity: &str, exp_offset: i64) -> String {
    use aws_lc_rs::hmac;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let b64 = base64url;
    let header = b64(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iss": lk.key, "sub": identity, "nbf": now - 600, "exp": now + exp_offset,
        "video": {"roomJoin": true, "room": room},
    });
    let payload = b64(&serde_json::to_vec(&claims).unwrap());
    let input = format!("{header}.{payload}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = b64(hmac::sign(&key, input.as_bytes()).as_ref());
    format!("{input}.{sig}")
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        let take = c.len() + 1;
        for i in 0..take {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap();
            out.push(char::from(A[idx]));
        }
    }
    out
}

fn ticket(v: &serde_json::Value) -> (RoomId, String, String) {
    let room = RoomId::parse(v["call"].as_str().unwrap()).unwrap();
    (
        room,
        v["token"].as_str().unwrap().to_owned(),
        v["identity"].as_str().unwrap().to_owned(),
    )
}

// --- Groups (as gate_p05) -------------------------------------------------------------------

fn group_body(rest: &[u8]) -> Vec<u8> {
    let mut b = vec![1];
    b.extend_from_slice(&GID);
    b.extend_from_slice(rest);
    b
}

fn parts(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in [a, b] {
        out.extend_from_slice(&u32::try_from(p.len()).unwrap().to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

async fn commit(s: &Stack, who: usize, bundle: &[u8]) -> u16 {
    s.people[who]
        .api
        .send("POST", "/v1/groups/commit", Some(&group_body(bundle)))
        .await
        .unwrap()
        .0
}

fn tree_of(b: &[u8]) -> Vec<u8> {
    let info_len = usize::try_from(u32::from_be_bytes(b[8..12].try_into().unwrap())).unwrap();
    let at = 12 + info_len;
    let tree_len = usize::try_from(u32::from_be_bytes(b[at..at + 4].try_into().unwrap())).unwrap();
    b[at + 4..at + 4 + tree_len].to_vec()
}

async fn published(s: &Stack, who: usize, by: usize) -> songbird_groups_harness::KeyPackage {
    let (kp, bytes) = s.people[who].mls.key_package_with_bytes();
    let device = s.people[who].mls.id;
    let stored = songbird_accounts::StoredKeyPackage {
        reference: songbird_keys::mls::reference(&bytes),
        package: bytes,
        not_after: 4_000_000_000,
    };
    s.registry
        .put_key_packages(&device, &[stored], None, 100)
        .await
        .unwrap();
    let claimed = s
        .registry
        .claim_key_packages(
            &s.people[who].mls.account,
            Some(&device),
            &s.people[by].mls.id,
            true,
        )
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    kp
}

/// Alice (person 0) creates the group and adds `who`.
async fn group_of(s: &mut Stack, who: &[usize]) {
    let (info, tree) = s.people[0].mls.create();
    let (st, _) = s.people[0]
        .api
        .send(
            "POST",
            "/v1/groups",
            Some(&group_body(&parts(&info, &tree))),
        )
        .await
        .unwrap();
    assert_eq!(st, 204);
    let mut kps = Vec::new();
    for &i in who {
        kps.push(published(s, i, 0).await);
    }
    let b = s.people[0].mls.add(&kps);
    assert_eq!(commit(s, 0, &b).await, 200);
    s.people[0].mls.merge();
    for &i in who {
        let welcome = s.pending(i).await.pop().expect("the Welcome");
        let (st, answer) = s.people[i]
            .api
            .send("POST", "/v1/groups/state", Some(&group_body(&[])))
            .await
            .unwrap();
        assert_eq!(st, 200);
        s.people[i].mls.join(&welcome, &tree_of(&answer));
    }
}

// --- The gate ------------------------------------------------------------------------------

#[tokio::test]
async fn one_to_one_calls_admit_only_the_two_accounts() {
    let Some(s) = stack(5).await else { return };
    let account = |i: usize| hex::encode(s.people[i].mls.account.as_bytes());
    let bob_key = hex::encode(BOB_KEY);

    // Not a contact: no key, a wrong key, or an account with no key at all. The same answer as
    // for an account that does not exist.
    for body in [
        serde_json::json!({"callee": account(1), "media": "video"}),
        serde_json::json!({"callee": account(1), "media": "video", "access_key": hex::encode([0xB1; 16])}),
        serde_json::json!({"callee": account(2), "media": "audio", "access_key": bob_key}),
        serde_json::json!({"callee": hex::encode([7; 16]), "media": "audio"}),
    ] {
        assert_eq!(s.post(0, "/v1/calls", &body).await.0, 404, "{body}");
    }
    // Malformed: oneself, a bad ID, an unknown field.
    assert_eq!(
        s.post(
            0,
            "/v1/calls",
            &serde_json::json!({"callee": account(0), "media": "video"})
        )
        .await
        .0,
        400
    );
    assert_eq!(
        s.post(
            0,
            "/v1/calls",
            &serde_json::json!({"callee": "AB", "media": "video"})
        )
        .await
        .0,
        400
    );
    assert_eq!(
        s.post(
            0,
            "/v1/calls",
            &serde_json::json!({"callee": account(1), "media": "video", "x": 1})
        )
        .await
        .0,
        400
    );
    // An open account needs no key.
    assert_eq!(
        s.post(
            0,
            "/v1/calls",
            &serde_json::json!({"callee": account(3), "media": "audio"})
        )
        .await
        .0,
        200
    );

    // A contact: Alice calls Bob with his key and rings him.
    let wakes = s.calls().metrics.wakes.get();
    let (st, v) = s
        .post(
            0,
            "/v1/calls",
            &serde_json::json!({"callee": account(1), "media": "video", "access_key": bob_key, "ring": true}),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        s.calls().metrics.wakes.get(),
        wakes + 1,
        "Bob's one device is woken"
    );
    let (room, alice_token, alice_id) = ticket(&v);
    assert_eq!(
        v["url"].as_str().unwrap(),
        s.livekit.http.replacen("http", "ws", 1)
    );

    // The token: one room, the pseudonym, the least grants, two minutes; LiveKit accepts it.
    let claims = TokenVerifier::with_api_key(&s.livekit.key, &s.livekit.secret)
        .verify(&alice_token)
        .unwrap();
    assert_eq!(claims.sub, alice_id);
    assert_eq!(claims.video.room, room.name());
    assert!(!claims.video.room_admin && !claims.video.room_create && !claims.video.room_record);
    assert_eq!(claims.exp - claims.nbf, 120);
    assert!(
        !alice_id.contains(&account(0))
            && !alice_id.contains(&hex::encode(s.people[0].mls.id.as_bytes()))
    );
    assert_eq!(validate(&s.livekit, &alice_token).await, 200);

    // Bob joins; Carol, Dave and Eve cannot, nor can anyone join a call that does not exist.
    let (st, v) = s
        .post(
            1,
            "/v1/calls/join",
            &serde_json::json!({"call": room.name()}),
        )
        .await;
    assert_eq!(st, 200);
    let (_, bob_token, bob_id) = ticket(&v);
    assert_ne!(bob_id, alice_id);
    for i in [2, 3, 4] {
        assert_eq!(
            s.post(
                i,
                "/v1/calls/join",
                &serde_json::json!({"call": room.name()})
            )
            .await
            .0,
            404
        );
    }
    assert_eq!(
        s.post(
            1,
            "/v1/calls/join",
            &serde_json::json!({"call": hex::encode([5; 16])})
        )
        .await
        .0,
        404
    );

    // In LiveKit, the room has the video cap, and Bob is only his pseudonym: no name, no
    // metadata, no attributes.
    let (mut ws, joined) = join(&s.livekit, &bob_token).await;
    let room_info = joined.room.unwrap();
    assert_eq!(room_info.name, room.name());
    assert_eq!(room_info.max_participants, 32);
    let me = joined.participant.unwrap();
    assert_eq!(me.identity, bob_id);
    assert!(me.name.is_empty() && me.metadata.is_empty() && me.attributes.is_empty());
    assert_eq!(
        s.calls().calls.rooms.participants(&room).await.unwrap(),
        vec![bob_id.clone()]
    );
    drop(ws.close(1000, "").await);
}

#[tokio::test]
async fn expired_and_forged_tokens_are_refused_by_livekit() {
    let Some(s) = stack(2).await else { return };
    let lk = &s.livekit;
    // LiveKit creates no room on join (`auto_create: false`): the room must exist.
    let id = RoomId::random().unwrap();
    s.calls()
        .calls
        .open_room(&id, songbird_calls::Media::Video)
        .await
        .unwrap();
    let room = id.name();
    // Made by hand so the times can be anything: LiveKit allows a minute of clock skew.
    assert_eq!(
        validate(lk, &token_at(lk, &lk.secret, &room, "p", 300)).await,
        200
    );
    assert_eq!(
        validate(lk, &token_at(lk, &lk.secret, &room, "p", -300)).await,
        401
    );
    assert_eq!(
        validate(
            lk,
            &token_at(lk, "not-the-secret-0123456789abcdef0123", &room, "p", 300)
        )
        .await,
        401
    );
    // A token for another LiveKit API key is refused too.
    let other = LiveKit {
        http: lk.http.clone(),
        key: "another-key".into(),
        secret: lk.secret.clone(),
    };
    assert_eq!(
        validate(lk, &token_at(&other, &lk.secret, &room, "p", 300)).await,
        401
    );
}

#[tokio::test]
async fn group_calls_admit_the_roster_and_drop_removed_members_mid_call() {
    let Some(mut s) = stack(4).await else { return };
    // Alice, Bob and Carol are in the group; Dave is not.
    group_of(&mut s, &[1, 2]).await;
    let group = hex::encode(GID);

    // Only the admins may start calls in this group.
    let mut roles = s.people[0].mls.roles();
    roles.policy.call = Role::Admin;
    let b = s.people[0].mls.set_roles(&roles);
    assert_eq!(commit(&s, 0, &b).await, 200);
    s.people[0].mls.merge();
    for i in [1, 2] {
        s.people[i].mls.receive(&b);
    }
    let start = |media: &str| serde_json::json!({"group": group, "media": media, "ring": true});
    assert_eq!(s.post(1, "/v1/calls/group", &start("video")).await.0, 403);
    assert_eq!(s.post(3, "/v1/calls/group", &start("video")).await.0, 404);

    // Alice (the owner) starts; Bob's "start" joins the same call; Dave cannot join it, with or
    // without the group's ID.
    let wakes = s.calls().metrics.wakes.get();
    let (st, v) = s.post(0, "/v1/calls/group", &start("video")).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        s.calls().metrics.wakes.get(),
        wakes + 2,
        "Bob and Carol are woken"
    );
    let (room, _, _) = ticket(&v);
    let (st, v) = s.post(1, "/v1/calls/group", &start("audio")).await;
    assert_eq!(st, 200);
    let (bob_room, bob_token, bob_id) = ticket(&v);
    assert_eq!(bob_room, room);
    let (st, v) = s
        .post(
            2,
            "/v1/calls/join",
            &serde_json::json!({"call": room.name(), "group": group}),
        )
        .await;
    assert_eq!(st, 200);
    let (_, carol_token, carol_id) = ticket(&v);
    for body in [
        serde_json::json!({"call": room.name(), "group": group}),
        serde_json::json!({"call": room.name()}),
        serde_json::json!({"call": room.name(), "group": hex::encode([9; 16])}),
    ] {
        assert_eq!(s.post(3, "/v1/calls/join", &body).await.0, 404, "{body}");
    }

    // Bob and Carol are in the call.
    let (mut bob_ws, _) = join(&s.livekit, &bob_token).await;
    let (mut carol_ws, _) = join(&s.livekit, &carol_token).await;
    let mut present = s.calls().calls.rooms.participants(&room).await.unwrap();
    present.sort();
    let mut want = vec![bob_id.clone(), carol_id.clone()];
    want.sort();
    assert_eq!(present, want);

    // Alice removes Bob from the group: the commit disconnects him from the call at once, and he
    // can no longer join. Carol stays.
    let bob_leaf = s.people[1].mls.leaf();
    let b = s.people[0].mls.remove(&[bob_leaf]);
    assert_eq!(commit(&s, 0, &b).await, 200);
    s.people[0].mls.merge();
    s.people[2].mls.receive(&b);
    assert!(
        told_to_leave(&mut bob_ws).await,
        "Bob is disconnected mid-call"
    );
    assert_eq!(
        s.calls().calls.rooms.participants(&room).await.unwrap(),
        vec![carol_id.clone()]
    );
    assert_eq!(s.calls().metrics.removed.get(), 1);
    assert_eq!(
        s.post(
            1,
            "/v1/calls/join",
            &serde_json::json!({"call": room.name(), "group": group})
        )
        .await
        .0,
        404
    );
    assert_eq!(s.post(1, "/v1/calls/group", &start("video")).await.0, 404);
    drop(carol_ws.close(1000, "").await);
}

// --- Call links (M3) ---------------------------------------------------------------------------

#[tokio::test]
async fn call_links_admit_holders_through_the_lobby_and_end_on_revoke() {
    use songbird_content::call::{LinkSecrets, open_card, seal_card};
    use songbird_content::schema::CallLinkCard;
    let Some(s) = stack(5).await else { return };
    let root = random32();
    let secrets = LinkSecrets::from_root(&root).unwrap();
    let link = hex::encode(*secrets.id);
    let admin = hex::encode(random32());
    let create = serde_json::json!({"link": link, "admin": admin, "media": "video", "lobby": true});
    assert_eq!(s.post(0, "/v1/calls/links", &create).await.0, 204);
    assert_eq!(s.post(0, "/v1/calls/links", &create).await.0, 409);
    let too_long = serde_json::json!({"link": hex::encode(random32()), "admin": admin, "media": "audio", "ttl_secs": 31 * 86_400});
    assert_eq!(s.post(0, "/v1/calls/links", &too_long).await.0, 400);

    // Bob holds the link: he leaves a sealed card and waits.
    let card = |i: usize, name: &str| {
        let c = CallLinkCard {
            account: s.people[i].mls.account.as_bytes().to_vec(),
            device: s.people[i].mls.id.as_bytes().to_vec(),
            identity: "p".into(),
            name: name.into(),
        };
        hex::encode(seal_card(&secrets.key, &c).unwrap())
    };
    let (st, v) = s
        .post(
            1,
            "/v1/calls/links/join",
            &serde_json::json!({"link": link, "card": card(1, "Bob")}),
        )
        .await;
    assert_eq!(st, 202, "{v}");
    let bob_handle = v["lobby"].as_str().unwrap().to_owned();
    let poll = |h: &str| serde_json::json!({"link": link, "lobby": h});
    assert_eq!(
        s.post(1, "/v1/calls/links/join", &poll(&bob_handle))
            .await
            .0,
        202
    );
    // Only Bob's device may redeem Bob's place.
    assert_eq!(
        s.post(2, "/v1/calls/links/join", &poll(&bob_handle))
            .await
            .0,
        404
    );
    // No card, no place.
    assert_eq!(
        s.post(
            3,
            "/v1/calls/links/join",
            &serde_json::json!({"link": link})
        )
        .await
        .0,
        400
    );

    // The admin sees who waits, as sealed cards only the link's holders can open.
    let admin_body = serde_json::json!({"link": link, "admin": admin});
    let (st, v) = s.post(0, "/v1/calls/links/lobby", &admin_body).await;
    assert_eq!(st, 200);
    let waiting = v["waiting"].as_array().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0]["handle"], bob_handle.as_str());
    let opened = open_card(
        &secrets.key,
        &hex::decode(waiting[0]["card"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(opened.name, "Bob");
    assert!(
        open_card(
            &secrets.id,
            &hex::decode(waiting[0]["card"].as_str().unwrap()).unwrap()
        )
        .is_err()
    );
    // A wrong admin token is no admin at all, and an unknown link looks the same.
    for body in [
        serde_json::json!({"link": link, "admin": hex::encode(random32())}),
        serde_json::json!({"link": hex::encode(random32()), "admin": admin}),
    ] {
        assert_eq!(s.post(0, "/v1/calls/links/lobby", &body).await.0, 404);
    }

    // Admitted, Bob gets a ticket once; declined, Dave gets nothing.
    let decide = |h: &str, admit: bool| serde_json::json!({"link": link, "admin": admin, "handle": h, "admit": admit});
    assert_eq!(
        s.post(0, "/v1/calls/links/admit", &decide(&bob_handle, true))
            .await
            .0,
        204
    );
    let (st, v) = s.post(1, "/v1/calls/links/join", &poll(&bob_handle)).await;
    assert_eq!(st, 200, "{v}");
    let (call_room, bob_token, bob_id) = ticket(&v);
    assert_eq!(
        s.post(1, "/v1/calls/links/join", &poll(&bob_handle))
            .await
            .0,
        404
    );
    let (st, v) = s
        .post(
            3,
            "/v1/calls/links/join",
            &serde_json::json!({"link": link, "card": card(3, "")}),
        )
        .await;
    assert_eq!(st, 202);
    let dave_handle = v["lobby"].as_str().unwrap().to_owned();
    assert_eq!(
        s.post(0, "/v1/calls/links/admit", &decide(&dave_handle, false))
            .await
            .0,
        204
    );
    assert_eq!(
        s.post(3, "/v1/calls/links/join", &poll(&dave_handle))
            .await
            .0,
        404
    );

    // The admin joins past the lobby, into the same room; a link call is not joinable through
    // /v1/calls/join.
    let (st, v) = s
        .post(
            0,
            "/v1/calls/links/join",
            &serde_json::json!({"link": link, "admin": admin}),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(ticket(&v).0, call_room);
    assert_eq!(
        s.post(
            4,
            "/v1/calls/join",
            &serde_json::json!({"call": call_room.name()})
        )
        .await
        .0,
        404
    );

    // Bob is in the call; revoking the link ends it for everyone, and the link is gone.
    let (mut bob_ws, joined) = join(&s.livekit, &bob_token).await;
    assert_eq!(joined.participant.unwrap().identity, bob_id);
    assert_eq!(
        s.post(0, "/v1/calls/links/revoke", &admin_body).await.0,
        204
    );
    assert!(told_to_leave(&mut bob_ws).await, "revoking ends the call");
    assert_eq!(
        s.post(
            1,
            "/v1/calls/links/join",
            &serde_json::json!({"link": link, "card": card(1, "Bob")})
        )
        .await
        .0,
        404
    );

    // A link without a lobby admits every holder at once.
    let open_link = hex::encode(*LinkSecrets::from_root(&random32()).unwrap().id);
    let create =
        serde_json::json!({"link": open_link, "admin": admin, "media": "audio", "ttl_secs": 600});
    assert_eq!(s.post(0, "/v1/calls/links", &create).await.0, 204);
    let (st, v) = s
        .post(
            4,
            "/v1/calls/links/join",
            &serde_json::json!({"link": open_link}),
        )
        .await;
    assert_eq!(st, 200);
    let claims = TokenVerifier::with_api_key(&s.livekit.key, &s.livekit.secret)
        .verify(v["token"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        claims.video.can_publish_sources,
        vec!["microphone".to_owned()]
    );
}

// --- Webhooks (M3) -----------------------------------------------------------------------------

fn base64std(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(
                    A[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap()],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A webhook as LiveKit sends it: the event's protobuf JSON, and a token signed with the API
/// secret whose `sha256` claim is the body's hash.
fn webhook(
    lk: &LiveKit,
    secret: &str,
    event: &str,
    room: &RoomId,
    id: &str,
    at: i64,
) -> (String, String) {
    let ev = livekit_protocol::WebhookEvent {
        event: event.into(),
        room: Some(livekit_protocol::Room {
            name: room.name(),
            ..Default::default()
        }),
        id: id.into(),
        created_at: at,
        ..Default::default()
    };
    let body = serde_json::to_string(&ev).unwrap();
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body.as_bytes());
    let token = livekit_api::access_token::AccessToken::with_api_key(&lk.key, secret)
        .with_sha256(&base64std(hash.as_ref()))
        .to_jwt()
        .unwrap();
    (token, body)
}

fn unix_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[tokio::test]
async fn webhooks_are_verified_fresh_and_once_and_clean_up_finished_rooms() {
    use songbird_calls::webhook::{Answer, WebhookMetrics, Webhooks};
    let Some(mut s) = stack(3).await else { return };
    let calls = Arc::clone(&s.calls().calls);
    let hot = songbird_valkey::ValkeyConn::connect(
        redis::Client::open(std::env::var("SONGBIRD_TEST_VALKEY").unwrap().as_str()).unwrap(),
    )
    .await
    .unwrap();
    let hooks = Webhooks::new(Arc::clone(&calls), hot, WebhookMetrics::default());
    // A live group call: Alice and Bob.
    group_of(&mut s, &[1]).await;
    let lk = &s.livekit;
    let start = serde_json::json!({"group": hex::encode(GID), "media": "video"});
    let (st, v) = s.post(0, "/v1/calls/group", &start).await;
    assert_eq!(st, 200);
    let (room, _, _) = ticket(&v);
    let records = calls.records(&s.app.hot);
    assert!(records.get(&room).await.unwrap().is_some());

    // Refused: another secret, a tampered body, a stale event, garbage.
    let id = format!("EV_{}", hex::encode(random32()));
    let (t, b) = webhook(
        lk,
        "not-the-secret-0123456789abcdef0123",
        "room_finished",
        &room,
        &id,
        unix_now(),
    );
    assert_eq!(hooks.handle(&t, b.as_bytes()).await, Answer::Refused);
    let (t, b) = webhook(lk, &lk.secret, "room_finished", &room, &id, unix_now());
    let tampered = b.replace("room_finished", "room_started_");
    assert_eq!(hooks.handle(&t, tampered.as_bytes()).await, Answer::Refused);
    let (ts, bs) = webhook(
        lk,
        &lk.secret,
        "room_finished",
        &room,
        &id,
        unix_now() - 3_600,
    );
    assert_eq!(hooks.handle(&ts, bs.as_bytes()).await, Answer::Refused);
    assert_eq!(hooks.handle("x", b"\xff\xfe").await, Answer::Malformed);
    assert_eq!(hooks.metrics.refused.get(), 4);
    assert!(
        records.get(&room).await.unwrap().is_some(),
        "nothing refused had an effect"
    );

    // The real one: the call's record and the group's pointer go; a replay does nothing.
    assert_eq!(hooks.handle(&t, b.as_bytes()).await, Answer::Ok);
    assert!(records.get(&room).await.unwrap().is_none());
    assert!(records.group(&GID).await.unwrap().is_none());
    assert_eq!(hooks.handle(&t, b.as_bytes()).await, Answer::Ok);
    assert_eq!(hooks.metrics.repeated.get(), 1);
    assert_eq!(hooks.metrics.rooms_finished.get(), 1);

    // The next start is a new call.
    let (st, v) = s.post(0, "/v1/calls/group", &start).await;
    assert_eq!(st, 200);
    let (second, _, _) = ticket(&v);
    assert_ne!(second, room);

    // A lost webhook: the room ends in LiveKit, nobody tells us. The next start notices.
    calls.rooms.delete_room(&second).await.unwrap();
    let (st, v) = s.post(1, "/v1/calls/group", &start).await;
    assert_eq!(st, 200);
    let (third, _, _) = ticket(&v);
    assert_ne!(third, second);
    assert!(records.get(&second).await.unwrap().is_none());
}

/// A webhook LiveKit itself sent, captured raw (`SONGBIRD_TEST_LIVEKIT_WEBHOOK_CAPTURE`: a file
/// holding one HTTP request as LiveKit wrote it), verifies with our receiver. Its token lives five
/// minutes, so it runs only on a fresh capture (P07-M3 says how).
#[tokio::test]
async fn a_webhook_livekit_sent_verifies() {
    use songbird_calls::webhook::{Answer, WebhookMetrics, Webhooks};
    let Ok(path) = std::env::var("SONGBIRD_TEST_LIVEKIT_WEBHOOK_CAPTURE") else {
        return;
    };
    let Some(s) = stack(1).await else { return };
    let raw = std::fs::read_to_string(path).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let auth = head
        .lines()
        .find_map(|l| l.strip_prefix("Authorization: "))
        .unwrap()
        .trim();
    let length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let body = &body.as_bytes()[..length];
    let hot = songbird_valkey::ValkeyConn::connect(
        redis::Client::open(std::env::var("SONGBIRD_TEST_VALKEY").unwrap().as_str()).unwrap(),
    )
    .await
    .unwrap();
    let hooks = Webhooks::new(Arc::clone(&s.calls().calls), hot, WebhookMetrics::default());
    assert_eq!(hooks.handle(auth, body).await, Answer::Ok);
    assert_eq!(hooks.metrics.rooms_started.get(), 1);
    let mut tampered = body.to_vec();
    tampered[length - 3] ^= 1;
    assert_eq!(hooks.handle(auth, &tampered).await, Answer::Refused);
}
