//! Prompt 4's gate, server side, against the real stores (SurrealDB for the registry and block
//! rows, `valkey-hot` for the request budgets): the contact gate, message requests, blocking, the
//! request policy, broadcast lists and request floods, over the WebSocket and `PUT /v1/messages`
//! alike (D-0062); reporting with message franking (D-0063). Runs when the compose stack is
//! configured, like `gate_p03`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::large_futures,
    reason = "tests"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::Ed25519KeyPair;
use bytes::Bytes;
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::messages::{Messages, SendStack};
use songbird_api::{ApiMetrics, App};
use songbird_client::{ClientConfig, DeviceKey, Event, ResumeState, State};
use songbird_delivery::{DeliveryMetrics, Directory, Shared, server};
use songbird_e2e::{SERVER_NAME, key, settings, test_mailbox, to};
use songbird_mailbox::{AnyMailbox, Mailbox as _};
use songbird_proto::envelope::Stamp;
use songbird_proto::frame::{RejectReason, SendFrame, SendHints, SendStatus};
use songbird_router::LocalRouter;
use songbird_send::{Franker, Gate, GateKeys, Policy, RegistryGate, RequestLimits};
use songbird_types::{AccountId, DeviceId, Secret};
use tokio::sync::mpsc;

const API: &str = "api.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b
}

struct Dev {
    id: DeviceId,
    seed: [u8; 32],
}

impl Dev {
    fn new() -> Self {
        let id = DeviceId::random().unwrap();
        let (_, seed) = DeviceKey::generate(id).unwrap();
        Self { id, seed }
    }
    fn key(&self) -> DeviceKey {
        DeviceKey::from_seed(self.id, &self.seed).unwrap()
    }
    fn api(&self, s: &Stack) -> ApiClient {
        ApiClient::new(
            s.api,
            API,
            self.id,
            Ed25519KeyPair::from_seed_unchecked(&self.seed).unwrap(),
        )
    }
}

/// An account: its primary first, then linked (listed) devices, and its access key.
struct Person {
    account: AccountId,
    devices: Vec<Dev>,
    access: [u8; 16],
}

impl Person {
    fn hex(&self) -> String {
        self.account.to_hex_unredacted()
    }
    fn ids(&self) -> Vec<DeviceId> {
        self.devices.iter().map(|d| d.id).collect()
    }
}

struct Stack {
    registry: Arc<Registry>,
    shared: Arc<Shared<Arc<AnyMailbox>, Arc<LocalRouter>>>,
    ws: SocketAddr,
    api: SocketAddr,
    franker: Franker,
    keys: GateKeys,
    /// The moderators' offline key.
    moderation: songbird_keys::provisioning::ProvisioningKey,
    worker: songbird_worker::Worker,
    _stop: tokio::sync::watch::Sender<bool>,
}

async fn stack(limits: RequestLimits) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let jobs = env("SONGBIRD_TEST_VALKEY_JOBS")?;
    let s3_addr = env("SONGBIRD_TEST_RUSTFS")?;
    let registry = Arc::new(
        Registry::connect(
            Db::connect(songbird_surreal::Config {
                addr: surreal,
                host: "localhost".into(),
                tls: None,
                user: std::env::var("SONGBIRD_TEST_SURREALDB_USER")
                    .unwrap_or_else(|_| "root".into()),
                pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
                namespace: "test".into(),
                database: format!(
                    "gatep04_{}",
                    DeviceId::random().unwrap().to_hex_unredacted()
                ),
                timeout: Duration::from_secs(30),
                max_message_bytes: 16 << 20,
            })
            .await
            .unwrap(),
        )
        .await
        .unwrap(),
    );
    // One franking key and one gate (fresh keys per run, so budgets never carry over) for the
    // delivery node and `api`, as a deployment configures them.
    let secret = rand32();
    let franker = Franker::from_secret(&secret).unwrap();
    let keys = GateKeys::from_cluster_secret(&rand32()).unwrap();
    let gate: Arc<dyn Gate> = Arc::new(RegistryGate::new(
        Arc::clone(&registry),
        songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
            .await
            .unwrap(),
        keys.clone(),
        limits,
    ));
    let policy = || Policy {
        franking: Some(Franker::from_secret(&secret).unwrap()),
        gate: Some(Arc::clone(&gate)),
        max_broadcast_accounts: limits.max_broadcast_accounts,
        rosters: None,
        channels: Arc::default(),
    };
    let mailbox = Arc::new(test_mailbox().await);
    let router = Arc::new(LocalRouter::new());
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let ws = listener.local_addr().unwrap();
    let shared = Arc::new(
        Shared::new(
            cfg,
            Directory::from_registry(&registry).await.unwrap(),
            Arc::clone(&mailbox),
            Arc::clone(&router),
            DeliveryMetrics::default(),
        )
        .with_policy(policy()),
    );
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
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
        Duration::from_millis(50),
        stop_rx.clone(),
    ));
    let metrics = ApiMetrics::default();
    let (push, _pushes) = songbird_send::Pusher::new(metrics.push.clone());
    let s3 = songbird_s3::Client::new(songbird_s3::Config::new(
        s3_addr,
        format!("songbird-gatep04-{}", &hex::encode(rand32())[..12]),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_ACCESS_KEY")?),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_SECRET_KEY")?),
    ))
    .unwrap();
    let queue = Arc::new(
        songbird_jobs::Queue::connect(
            redis::Client::open(jobs.as_str()).unwrap(),
            &[0x32; 32],
            songbird_jobs::QueueConfig::new(format!("gate-p04-{}", &hex::encode(rand32())[..8])),
        )
        .await
        .unwrap(),
    );
    let moderation = songbird_keys::provisioning::ProvisioningKey::generate().unwrap();
    let report_settings = songbird_api::config::ReportSettings {
        moderation_key: hex::encode(moderation.public()),
        retention_days: 30,
        window_days: 30,
        per_hour: 1,
        burst: 5,
    };
    let app = Arc::new(App {
        calls: None,
        reports: Some(songbird_api::reports::Reports::new(
            songbird_send::Frankers {
                current: Franker::from_secret(&secret).unwrap(),
                previous: Vec::new(),
            },
            keys.clone(),
            moderation.public(),
            report_settings,
            songbird_api::reports::ReportMetrics::default(),
        )),
        requests: Some(songbird_api::requests::Requests::new(
            keys.clone(),
            songbird_api::requests::RequestsMetrics::default(),
        )),
        server_name: API.into(),
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: Arc::clone(&queue),
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public: [0; 32],
        push_index_secret: [0x31; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        messages: Some(Messages {
            path: Box::new(SendStack {
                directory: Arc::clone(&shared.directory),
                mailbox: Arc::clone(&mailbox),
                router: Arc::clone(&router),
                push,
                metrics: metrics.send.clone(),
                policy: policy(),
            }),
            limits: songbird_proto::Limits::DEFAULT,
            sends_per_sec: 1_000,
            send_burst: 1_000,
            group_sends_per_sec: 1_000,
            group_send_burst: 1_000,
            rate_key: songbird_api::messages::rate_key(&rand32()).unwrap(),
            metrics: metrics.send.clone(),
            groups: None,
        }),
        metrics,
        registration: None,
        usernames: None,
        keys: None,
        devices: Some(
            songbird_api::devices::Devices::new(
                songbird_api::config::DeviceSettings::default(),
                &songbird_api::config::KeyThrottle::default(),
                &rand32(),
                None,
                songbird_api::devices::DeviceMetrics::default(),
            )
            .unwrap(),
        ),
        profiles: None,
        kt: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = listener.local_addr().unwrap();
    tokio::spawn(songbird_api::server::serve(
        listener,
        None,
        Arc::clone(&app),
        64,
        stop_rx,
    ));
    s3.create_bucket().await.unwrap();
    let worker = songbird_worker::Worker {
        block_keys: Some(keys.clone()),
        registry: Arc::clone(&registry),
        s3,
        queue,
        delivery: songbird_worker::DeliveryLink::Direct(songbird_delivery::internal::handler(
            Arc::clone(&shared),
        )),
        push_index_secret: [0x31; 32],
        journal: None,
        propagation: Duration::from_millis(200),
        kt: None,
        metrics: songbird_worker::WorkerMetrics::default(),
    };
    Some(Stack {
        registry,
        shared,
        ws,
        api,
        franker,
        keys,
        moderation,
        worker,
        _stop: stop,
    })
}

/// An account with `devices` devices (the first the primary) and a profile with its access key.
async fn person(s: &Stack, devices: usize) -> Person {
    let account = AccountId::random().unwrap();
    let devs: Vec<Dev> = (0..devices).map(|_| Dev::new()).collect();
    let keys: Vec<_> = devs.iter().map(|d| (d.id, d.key().public_key())).collect();
    s.registry.create_account(&account, &keys).await.unwrap();
    let mut access = [0u8; 16];
    aws_lc_rs::rand::fill(&mut access).unwrap();
    s.registry
        .put_profile(&account, 1, b"profile", &access, false)
        .await
        .unwrap();
    Person {
        account,
        devices: devs,
        access,
    }
}

/// Waits until the delivery node's directory has every account's profile.
async fn followed(s: &Stack, people: &[&Person]) {
    for _ in 0..200 {
        let dir = s.shared.directory.load();
        if people
            .iter()
            .all(|p| dir.access(&p.account).key == Some(p.access))
        {
            return;
        }
        drop(dir);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the directory never followed the profiles");
}

async fn connect(s: &Stack, d: &Dev) -> (songbird_client::Client, mpsc::Receiver<Event>) {
    let mut c = ClientConfig::new(s.ws.to_string(), SERVER_NAME);
    c.backoff.initial = Duration::from_millis(20);
    let (mut client, events) = songbird_client::Client::start(c, d.key(), ResumeState::default());
    tokio::time::timeout(Duration::from_secs(10), client.wait_for(State::Connected))
        .await
        .expect("connects");
    (client, events)
}

fn to_all(p: &Person, envelope: &'static [u8]) -> Vec<songbird_proto::frame::Recipient> {
    p.ids().into_iter().map(|d| to(d, envelope)).collect()
}

fn contact(access: [u8; 16]) -> SendHints {
    SendHints {
        access: Some(access),
        ..SendHints::default()
    }
}

fn request(commitment: [u8; 32]) -> SendHints {
    SendHints {
        request: true,
        commitment: Some(commitment),
        ..SendHints::default()
    }
}

fn refused(reason: RejectReason) -> SendStatus {
    SendStatus::Rejected {
        reason,
        retry_after_ms: 0,
    }
}

fn limited(st: &SendStatus) -> bool {
    matches!(
        st,
        SendStatus::Rejected {
            reason: RejectReason::RateLimited,
            retry_after_ms
        } if *retry_after_ms > 0
    )
}

/// Envelopes `d` can fetch (a dropped send is stored already expired: never fetchable).
async fn pending(s: &Stack, d: &Dev) -> u64 {
    u64::try_from(
        s.shared
            .mailbox
            .fetch_after(&d.id, 0, 1_000)
            .await
            .unwrap()
            .len(),
    )
    .unwrap()
}

/// Whether a delivery arrives within `ms`.
async fn delivery_within(ev: &mut mpsc::Receiver<Event>, ms: u64) -> Option<Bytes> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ev.recv()).await {
            Ok(Some(Event::Deliver { envelope, .. })) => return Some(envelope),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

fn json(body: &str) -> Vec<u8> {
    body.as_bytes().to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contacts_requests_blocks_and_the_request_policy_end_to_end() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let alice = person(&s, 2).await;
    let bob = person(&s, 2).await;
    let carol = person(&s, 1).await;
    let dave = person(&s, 1).await;
    followed(&s, &[&alice, &bob, &carol, &dave]).await;
    let (a1, _a1_ev) = connect(&s, &alice.devices[0]).await;
    let (_b1, mut b1_ev) = connect(&s, &bob.devices[0]).await;
    let (c1, _c1_ev) = connect(&s, &carol.devices[0]).await;
    let (d1, _d1_ev) = connect(&s, &dave.devices[0]).await;

    // A stranger without Bob's access key, and without the request flag: refused, nothing stored.
    let st = a1.send(key(), to_all(&bob, b"no key")).await.unwrap();
    assert_eq!(st, refused(RejectReason::AccessRequired));
    let st = a1
        .send_hinted(key(), contact(carol.access), to_all(&bob, b"wrong key"))
        .await
        .unwrap();
    assert_eq!(st, refused(RejectReason::AccessRequired));
    assert_eq!(pending(&s, &bob.devices[0]).await, 0);

    // A contact (Bob's access key): delivered.
    let st = a1
        .send_hinted(key(), contact(bob.access), to_all(&bob, b"from a contact"))
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    assert_eq!(
        &delivery_within(&mut b1_ev, 5_000).await.unwrap()[..],
        b"from a contact"
    );

    // A message request from Carol: it must be franked; Bob gets it behind a stamp that binds
    // Carol, Bob and the commitment.
    let st = c1
        .send_hinted(
            key(),
            SendHints {
                request: true,
                ..SendHints::default()
            },
            to_all(&bob, b"unfranked"),
        )
        .await
        .unwrap();
    assert_eq!(st, refused(RejectReason::InvalidRequest));
    let st = c1
        .send_hinted(
            key(),
            request([0xC0; 32]),
            to_all(&bob, b"hello, a request"),
        )
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    let got = delivery_within(&mut b1_ev, 5_000).await.unwrap();
    let (stamp, inner) = Stamp::split(&got).unwrap();
    assert_eq!(inner, b"hello, a request");
    assert_eq!(stamp.commitment, [0xC0; 32]);
    assert!(
        s.franker
            .verify(&stamp, carol.account.as_bytes(), bob.account.as_bytes())
    );

    // Bob's linked device blocks Carol (tightening: any listed device may). Her requests are
    // then accepted as before and stored nowhere.
    let b2 = bob.devices[1].api(&s);
    let body = json(&format!(r#"{{"account":"{}"}}"#, carol.hex()));
    assert_eq!(
        b2.send("PUT", "/v1/blocks", Some(&body)).await.unwrap().0,
        204
    );
    let before = pending(&s, &bob.devices[0]).await;
    let st = c1
        .send_hinted(key(), request([0xC1; 32]), to_all(&bob, b"blocked"))
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    assert!(delivery_within(&mut b1_ev, 300).await.is_none());
    assert_eq!(pending(&s, &bob.devices[0]).await, before);
    // Blocking oneself or garbage is refused.
    let me = json(&format!(r#"{{"account":"{}"}}"#, bob.hex()));
    assert_eq!(
        b2.send("PUT", "/v1/blocks", Some(&me)).await.unwrap().0,
        400
    );
    assert_eq!(
        b2.send("PUT", "/v1/blocks", Some(b"{}")).await.unwrap().0,
        400
    );

    // Unblocking loosens: the linked device may not, the primary may.
    assert_eq!(
        b2.send("DELETE", "/v1/blocks", Some(&body))
            .await
            .unwrap()
            .0,
        403
    );
    let b1_api = bob.devices[0].api(&s);
    assert_eq!(
        b1_api
            .send("DELETE", "/v1/blocks", Some(&body))
            .await
            .unwrap()
            .0,
        204
    );
    let st = c1
        .send_hinted(key(), request([0xC2; 32]), to_all(&bob, b"unblocked"))
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    let got = delivery_within(&mut b1_ev, 5_000).await.unwrap();
    assert_eq!(Stamp::split(&got).unwrap().1, b"unblocked");

    // The request policy: refusing requests from a linked device, accepting them again from
    // the primary only. Contacts are not affected.
    let nobody = json(r#"{"from":"nobody"}"#);
    let everyone = json(r#"{"from":"everyone"}"#);
    assert_eq!(
        b2.send("PUT", "/v1/account/requests", Some(&nobody))
            .await
            .unwrap()
            .0,
        204
    );
    for _ in 0..200 {
        if s.shared.directory.load().access(&bob.account).requests_off {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let st = d1
        .send_hinted(key(), request([0xD0; 32]), to_all(&bob, b"refused"))
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    assert!(delivery_within(&mut b1_ev, 300).await.is_none());
    let st = d1
        .send_hinted(
            key(),
            contact(bob.access),
            to_all(&bob, b"dave as a contact"),
        )
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    assert_eq!(
        &delivery_within(&mut b1_ev, 5_000).await.unwrap()[..],
        b"dave as a contact"
    );
    assert_eq!(
        b2.send("PUT", "/v1/account/requests", Some(&everyone))
            .await
            .unwrap()
            .0,
        403
    );
    assert_eq!(
        b1_api
            .send("PUT", "/v1/account/requests", Some(&everyone))
            .await
            .unwrap()
            .0,
        204
    );
    let (st, policy) = b2.send("GET", "/v1/account/requests", None).await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&policy).unwrap()["from"],
        "everyone"
    );

    // Over HTTP, the same rules, the same gate.
    for _ in 0..200 {
        if !s.shared.directory.load().access(&bob.account).requests_off {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let d1_api = dave.devices[0].api(&s);
    let mut f = SendFrame::per_device(42, key(), to_all(&bob, b"over http"));
    assert_eq!(
        d1_api.put_message(&f).await.unwrap(),
        (200, Some((42, refused(RejectReason::AccessRequired))))
    );
    f.hints = request([0xD1; 32]);
    assert_eq!(
        d1_api.put_message(&f).await.unwrap(),
        (200, Some((42, SendStatus::Accepted)))
    );
    let got = delivery_within(&mut b1_ev, 5_000).await.unwrap();
    assert_eq!(Stamp::split(&got).unwrap().1, b"over http");

    // A broadcast list: Alice to Bob, Carol and Dave, contacts of all three (one combined key).
    let xor = |keys: &[[u8; 16]]| {
        let mut k = [0u8; 16];
        for key in keys {
            for (a, b) in k.iter_mut().zip(key) {
                *a ^= b;
            }
        }
        k
    };
    let mut recipients = to_all(&bob, b"broadcast");
    recipients.extend(to_all(&carol, b"broadcast"));
    recipients.extend(to_all(&dave, b"broadcast"));
    let st = a1
        .send_hinted(
            key(),
            contact(xor(&[bob.access, carol.access])),
            recipients.clone(),
        )
        .await
        .unwrap();
    assert_eq!(st, refused(RejectReason::AccessRequired));
    let st = a1
        .send_hinted(
            key(),
            contact(xor(&[bob.access, carol.access, dave.access])),
            recipients,
        )
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    assert_eq!(
        &delivery_within(&mut b1_ev, 5_000).await.unwrap()[..],
        b"broadcast"
    );
    // A shared body (a group's) is no way around the contact gate: without every closed
    // member's key it is refused.
    let mut group = SendFrame {
        hints: SendHints::default(),
        req_id: 7,
        idempotency_key: key(),
        payload: songbird_proto::frame::SendPayload::Shared {
            devices: bob.ids().into_iter().chain(carol.ids()).collect(),
            body: Bytes::from_static(b"group"),
        },
    };
    let a1_api = alice.devices[0].api(&s);
    assert_eq!(
        a1_api.put_message(&group).await.unwrap(),
        (200, Some((7, refused(RejectReason::AccessRequired))))
    );
    group.hints.access = Some(xor(&[bob.access, carol.access]));
    assert_eq!(
        a1_api.put_message(&group).await.unwrap(),
        (200, Some((7, SendStatus::Accepted)))
    );
    assert_eq!(
        &delivery_within(&mut b1_ev, 5_000).await.unwrap()[..],
        b"group"
    );
    // A request is never a broadcast.
    let mut two = to_all(&bob, b"x");
    two.extend(to_all(&carol, b"x"));
    let st = a1.send_hinted(key(), request([1; 32]), two).await.unwrap();
    assert_eq!(st, refused(RejectReason::InvalidRequest));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_floods_are_held_across_the_cluster_and_a_block_does_not_show() {
    let limits = RequestLimits {
        per_sender_hour: 1,
        per_sender_burst: 3,
        per_pair_hour: 1,
        per_pair_burst: 2,
        per_recipient_hour: 1,
        per_recipient_burst: 4,
        ..RequestLimits::default()
    };
    let Some(s) = stack(limits).await else {
        return;
    };
    let mut people = Vec::new();
    for _ in 0..10 {
        people.push(person(&s, 1).await);
    }
    followed(&s, &people.iter().collect::<Vec<_>>()).await;
    let (eve, rest) = people.split_first().unwrap();
    let (e1, _ev) = connect(&s, &eve.devices[0]).await;

    // One sender to many recipients: 3 a burst, then limited, over the WebSocket and HTTP alike.
    for (i, p) in rest.iter().take(3).enumerate() {
        let st = e1
            .send_hinted(
                key(),
                request([u8::try_from(i).unwrap(); 32]),
                to_all(p, b"spam"),
            )
            .await
            .unwrap();
        assert_eq!(st, SendStatus::Accepted, "{i}");
    }
    let st = e1
        .send_hinted(key(), request([9; 32]), to_all(&rest[3], b"spam"))
        .await
        .unwrap();
    assert!(limited(&st), "{st:?}");
    let mut f = SendFrame::per_device(1, key(), to_all(&rest[4], b"spam"));
    f.hints = request([10; 32]);
    let (code, result) = eve.devices[0].api(&s).put_message(&f).await.unwrap();
    assert_eq!(code, 200);
    assert!(
        limited(&result.unwrap().1),
        "the budget is shared by every node"
    );

    // Many senders to one recipient: the recipient's budget (4), whoever the senders are.
    let target = &rest[6];
    let mut accepted = 0;
    for (i, sender) in rest.iter().take(6).enumerate() {
        let api = sender.devices[0].api(&s);
        let mut f = SendFrame::per_device(1, key(), to_all(target, b"pile-on"));
        f.hints = request([u8::try_from(i).unwrap() + 20; 32]);
        match api.put_message(&f).await.unwrap() {
            (200, Some((_, SendStatus::Accepted))) => accepted += 1,
            (200, Some((_, st))) => assert!(limited(&st), "{st:?}"),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(accepted, 4);

    // One pair: 2, then limited, and a blocked sender meets exactly the same answers.
    let (x, y) = (&rest[7], &rest[8]);
    let y_api = y.devices[0].api(&s);
    let body = json(&format!(r#"{{"account":"{}"}}"#, x.hex()));
    assert_eq!(
        y_api
            .send("PUT", "/v1/blocks", Some(&body))
            .await
            .unwrap()
            .0,
        204
    );
    let x_api = x.devices[0].api(&s);
    let mut answers = Vec::new();
    for i in 0..3u8 {
        let mut f = SendFrame::per_device(1, key(), to_all(y, b"blocked"));
        f.hints = request([i + 40; 32]);
        answers.push(x_api.put_message(&f).await.unwrap().1.unwrap().1);
    }
    assert_eq!(answers[0], SendStatus::Accepted);
    assert_eq!(answers[1], SendStatus::Accepted);
    assert!(limited(&answers[2]), "{:?}", answers[2]);
    assert_eq!(
        pending(&s, &y.devices[0]).await,
        0,
        "a block stores nothing"
    );
}

/// Carol's message to Bob as a franked request: what Bob's app keeps for a report.
async fn franked_request(
    s: &Stack,
    from: &songbird_client::Client,
    to_person: &Person,
    ev: &mut mpsc::Receiver<Event>,
    content: &[u8],
) -> (Stamp, [u8; 32]) {
    let mut fk = [0u8; 32];
    aws_lc_rs::rand::fill(&mut fk).unwrap();
    // The server's commitment code and the apps' (songbird-content) agree.
    let commitment = songbird_api::reports::commitment(&fk, content);
    assert_eq!(commitment, songbird_content::commitment(&fk, content));
    let st = from
        .send_hinted(key(), request(commitment), to_all(to_person, b"ciphertext"))
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    let got = delivery_within(ev, 5_000).await.unwrap();
    let (stamp, _) = Stamp::split(&got).unwrap();
    let _ = s;
    (stamp, fk)
}

fn report_of(stamp: Stamp, sender: &Person, fk: [u8; 32], content: &[u8]) -> Vec<u8> {
    songbird_proto::report::Report {
        reason: songbird_proto::report::Reason::Harassment,
        stamp,
        sender: *sender.account.as_bytes(),
        franking_key: fk,
        content: content.to_vec(),
    }
    .encode()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recipient_reports_a_message_and_only_moderators_can_read_it() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let bob = person(&s, 2).await;
    let carol = person(&s, 1).await;
    let dave = person(&s, 1).await;
    followed(&s, &[&bob, &carol, &dave]).await;
    let (_b1, mut b1_ev) = connect(&s, &bob.devices[0]).await;
    let (c1, _c1_ev) = connect(&s, &carol.devices[0]).await;
    let content = b"the harassing words, as encoded content".to_vec();
    let (stamp, fk) = franked_request(&s, &c1, &bob, &mut b1_ev, &content).await;

    let b1 = bob.devices[0].api(&s);
    let body = report_of(stamp, &carol, fk, &content);
    assert_eq!(
        b1.send("POST", "/v1/reports", Some(&body)).await.unwrap().0,
        204
    );
    assert_eq!(s.registry.report_count().await.unwrap(), 1);
    // The same message once only (from any of Bob's devices).
    let b2 = bob.devices[1].api(&s);
    let (st, why) = b2.send("POST", "/v1/reports", Some(&body)).await.unwrap();
    assert_eq!((st, &why[..]), (409, &br#"{"error":"duplicate"}"#[..]));
    // Someone who did not receive it (a forwarded opening) cannot report it.
    let d1 = dave.devices[0].api(&s);
    let (st, why) = d1.send("POST", "/v1/reports", Some(&body)).await.unwrap();
    assert_eq!((st, &why[..]), (403, &br#"{"error":"stamp"}"#[..]));
    // Other words than the ones Carol committed to.
    let mut other = content.clone();
    other[0] ^= 1;
    let (st, why) = b1
        .send(
            "POST",
            "/v1/reports",
            Some(&report_of(stamp, &carol, fk, &other)),
        )
        .await
        .unwrap();
    assert_eq!((st, &why[..]), (403, &br#"{"error":"commitment"}"#[..]));
    // Blaming someone else.
    let (st, why) = b1
        .send(
            "POST",
            "/v1/reports",
            Some(&report_of(stamp, &dave, fk, &content)),
        )
        .await
        .unwrap();
    assert_eq!((st, &why[..]), (403, &br#"{"error":"stamp"}"#[..]));
    // Garbage.
    assert_eq!(
        b1.send("POST", "/v1/reports", Some(b"junk"))
            .await
            .unwrap()
            .0,
        400
    );
    assert_eq!(s.registry.report_count().await.unwrap(), 1);

    // What is queued: ciphertext only the moderation key opens, holding the minimal report.
    let queued = s.registry.queued_reports(10).await.unwrap();
    assert_eq!(queued.len(), 1);
    let sealed = &queued[0].sealed;
    assert!(
        !sealed
            .windows(content.len())
            .any(|w| w == content.as_slice()),
        "the content is not in the clear"
    );
    let other_key = songbird_keys::provisioning::ProvisioningKey::generate().unwrap();
    assert!(
        songbird_keys::provisioning::open_with(
            songbird_api::reports::SEAL_DOMAIN,
            &other_key,
            sealed
        )
        .is_err()
    );
    let plain = songbird_keys::provisioning::open_with(
        songbird_api::reports::SEAL_DOMAIN,
        &s.moderation,
        sealed,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(v["reason"], "harassment");
    assert_eq!(v["sender"], carol.hex());
    assert_eq!(v["sender_attested"], true);
    assert_eq!(v["conversation"], "direct");
    assert_eq!(v["stamped_at_ms"], stamp.stamped_at_ms);
    assert_eq!(v["content"], hex::encode(&content));
    // Nothing names the reporter, and nothing else about the conversation is there.
    let text = String::from_utf8(plain).unwrap();
    assert!(!text.contains(&bob.hex()));
    assert_eq!(v.as_object().unwrap().len(), 8, "{text}");
    // A moderator deletes it once dealt with.
    s.registry.delete_report(&queued[0].id).await.unwrap();
    assert_eq!(s.registry.report_count().await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_floods_are_throttled_per_reporter() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let eve = person(&s, 1).await;
    let mallory = person(&s, 1).await;
    followed(&s, &[&eve, &mallory]).await;
    let (_e1, mut e1_ev) = connect(&s, &eve.devices[0]).await;
    let (m1, _m1_ev) = connect(&s, &mallory.devices[0]).await;
    let content = b"one message".to_vec();
    let (stamp, fk) = franked_request(&s, &m1, &eve, &mut e1_ev, &content).await;
    let api = eve.devices[0].api(&s);
    let body = report_of(stamp, &mallory, fk, &content);
    // Every attempt spends the budget (5), valid, duplicate or not: then 429.
    let mut codes = Vec::new();
    for _ in 0..7 {
        codes.push(
            api.send("POST", "/v1/reports", Some(&body))
                .await
                .unwrap()
                .0,
        );
    }
    assert_eq!(codes, vec![204, 409, 409, 409, 409, 429, 429]);
    assert_eq!(s.registry.report_count().await.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_4_stores_are_exported_and_deleted_with_the_account() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let bob = person(&s, 1).await;
    let carol = person(&s, 1).await;
    followed(&s, &[&bob, &carol]).await;
    let b1 = bob.devices[0].api(&s);
    let body = json(&format!(r#"{{"account":"{}"}}"#, carol.hex()));
    assert_eq!(
        b1.send("PUT", "/v1/blocks", Some(&body)).await.unwrap().0,
        204
    );
    assert_eq!(
        b1.send(
            "PUT",
            "/v1/account/requests",
            Some(&json(r#"{"from":"nobody"}"#))
        )
        .await
        .unwrap()
        .0,
        204
    );
    let (st, export) = b1.send("GET", "/v1/account/export", None).await.unwrap();
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_slice(&export).unwrap();
    assert_eq!(v["message_requests"]["from"], "nobody");
    assert_eq!(v["message_requests"]["blocks"], 1);
    // The export names nobody Bob blocked: only a count.
    assert!(!String::from_utf8_lossy(&export).contains(&carol.hex()));

    // Deletion: Bob's block rows go (found by his keyed tag) and are verified gone.
    let owner = s.keys.owner(&bob.account);
    assert_eq!(s.registry.block_count(&owner).await.unwrap(), 1);
    s.worker.delete_account(&bob.account).await.unwrap();
    assert_eq!(s.registry.block_count(&owner).await.unwrap(), 0);
    assert!(
        s.registry
            .device(&bob.devices[0].id)
            .await
            .unwrap()
            .is_none()
    );
    // Carol is untouched.
    assert!(
        s.registry
            .device(&carol.devices[0].id)
            .await
            .unwrap()
            .is_some()
    );
}
