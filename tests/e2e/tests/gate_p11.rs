//! Prompt 11's abuse simulations (M5, D-0131), on Prompt 4's in-process stack (a delivery node,
//! `api`, the registry gate, franking, reports): registration floods are in
//! `services/api/tests/registration_live.rs`; here, request spam from new accounts, a report
//! brigade, and a suspension, each showing the controls hold without touching normal users.
//! Runs when the stack variables are set.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::large_futures,
    dead_code,
    reason = "tests (Prompt 4's stack, shared shape)"
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
    live: Arc<songbird_entitlements::Live>,
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
                    "gatep11_{}",
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
    let live = Arc::new(songbird_entitlements::Live::from(
        songbird_entitlements::load(&registry).await.unwrap(),
    ));
    let gate: Arc<dyn Gate> = Arc::new(
        RegistryGate::new(
            Arc::clone(&registry),
            songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
                .await
                .unwrap(),
            keys.clone(),
            limits,
        )
        .with_standings(Arc::clone(&live)),
    );
    let policy = || Policy {
        franking: Some(Franker::from_secret(&secret).unwrap()),
        gate: Some(Arc::clone(&gate)),
        max_broadcast_accounts: limits.max_broadcast_accounts,
        rosters: None,
        channels: Arc::default(),
        standings: Some(Arc::clone(&live)),
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
        format!("songbird-gatep11-{}", &hex::encode(rand32())[..12]),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_ACCESS_KEY")?),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_SECRET_KEY")?),
    ))
    .unwrap();
    let queue = Arc::new(
        songbird_jobs::Queue::connect(
            redis::Client::open(jobs.as_str()).unwrap(),
            &[0x32; 32],
            songbird_jobs::QueueConfig::new(format!("gate-p11-{}", &hex::encode(rand32())[..8])),
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
        plans: songbird_api::plans::Plans {
            live: Arc::clone(&live),
            ..songbird_api::plans::Plans::default()
        },
        calls: None,
        support: None,
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
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
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
        profiles: Some(
            songbird_api::profiles::Profiles::new(
                songbird_api::config::ProfileSettings {
                    secret: songbird_types::SecretRef::Env("UNUSED".into()),
                    certificate_key: None,
                    sealed_sender: false,
                    certificate_hours: 24,
                    fetches_per_hour: 600,
                    fetch_burst: 120,
                    sealed_per_hour: 3_600,
                    sealed_per_account_hour: 3_600,
                    sealed_burst: 200,
                    presence_per_hour: 1_000_000,
                    presence_burst: 20_000,
                    policy_updates_per_hour: 120,
                    policy_update_burst: 20,
                    ipv4_prefix: 24,
                    ipv6_prefix: 48,
                },
                &rand32(),
                Some(&rand32()),
                songbird_api::profiles::ProfileMetrics::default(),
            )
            .unwrap(),
        ),
        storage: None,
        vault: None,
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
        vault_s3: None,
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
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
        live,
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

impl Stack {
    /// The snapshot again, as every service's follower does within a second.
    async fn reload(&self) {
        self.live
            .store(songbird_entitlements::load(&self.registry).await.unwrap());
    }

    /// Makes `p` an established account (created 40 days ago).
    async fn age(&self, p: &Person) {
        self.registry
            .db()
            .exec(
                "UPDATE account:[$a] SET at = time::now() - 40d RETURN NONE;",
                vec![(
                    "a".into(),
                    songbird_surreal::Value::Bytes(Bytes::copy_from_slice(p.account.as_bytes())),
                )],
            )
            .await
            .unwrap();
    }
}

async fn requests_to(c: &songbird_client::Client, people: &[Person], from: u8) -> Vec<SendStatus> {
    let mut out = Vec::new();
    for (i, p) in people.iter().enumerate() {
        out.push(
            c.send_hinted(
                key(),
                request([from.wrapping_add(u8::try_from(i).unwrap()); 32]),
                to_all(p, b"hello"),
            )
            .await
            .unwrap(),
        );
    }
    out
}

async fn block(s: &Stack, who: &Person, whom: &Person) -> u16 {
    who.devices[0]
        .api(s)
        .send(
            "PUT",
            "/v1/blocks",
            Some(&json(&format!(r#"{{"account":"{}"}}"#, whom.hex()))),
        )
        .await
        .unwrap()
        .0
}

/// Request spam from a new account: its first ten conversations go through (a real new user's
/// do too), then it waits longer than an established account would; strangers it messaged
/// block it and it is limited to a couple of requests an hour, automatically, for a week. A
/// brigade of strangers it never messaged changes nothing for an established user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_spam_is_slowed_then_limited_and_normal_users_are_not() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let spammer = person(&s, 1).await;
    let normal = person(&s, 1).await;
    s.age(&normal).await;
    let mut strangers = Vec::new();
    for _ in 0..24 {
        strangers.push(person(&s, 1).await);
    }
    let mut all: Vec<&Person> = strangers.iter().collect();
    all.push(&spammer);
    all.push(&normal);
    followed(&s, &all).await;
    let (sc, _sev) = connect(&s, &spammer.devices[0]).await;
    let (nc, _nev) = connect(&s, &normal.devices[0]).await;
    // Ten first conversations each: accepted for the new account and the established one.
    let first = requests_to(&sc, &strangers[..10], 0).await;
    assert!(
        first.iter().all(|st| *st == SendStatus::Accepted),
        "{first:?}"
    );
    let first = requests_to(&nc, &strangers[..10], 100).await;
    assert!(
        first.iter().all(|st| *st == SendStatus::Accepted),
        "{first:?}"
    );
    // The eleventh: both wait, the new account four times longer.
    let wait = |st: &SendStatus| match st {
        SendStatus::Rejected {
            reason: RejectReason::RateLimited,
            retry_after_ms,
        } => *retry_after_ms,
        other => panic!("{other:?}"),
    };
    let young = wait(&requests_to(&sc, &strangers[10..11], 50).await[0]);
    let old = wait(&requests_to(&nc, &strangers[10..11], 150).await[0]);
    assert!(young > 3 * old, "new {young} ms, established {old} ms");
    // Four strangers it messaged block it: not yet. The fifth: limited, by itself.
    for p in &strangers[..4] {
        assert_eq!(block(&s, p, &spammer).await, 204);
    }
    assert!(
        s.registry
            .standing_of(&spammer.account)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(block(&s, &strangers[4], &spammer).await, 204);
    let st = s
        .registry
        .standing_of(&spammer.account)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (st.kind.as_str(), st.reason.as_str(), st.source.as_str()),
        ("limited", "blocks", "auto")
    );
    assert_eq!(
        st.until,
        Some(songbird_entitlements::today() + songbird_api::abuse::LIMIT_DAYS)
    );
    // Blocking again changes nothing (a block is counted once).
    assert_eq!(block(&s, &strangers[4], &spammer).await, 204);
    s.reload().await;
    // Limited: two requests, then an hour's wait; it still talks to people who answered.
    let limited_sends = requests_to(&sc, &strangers[12..15], 200).await;
    assert_eq!(
        &limited_sends[..2],
        &[SendStatus::Accepted, SendStatus::Accepted]
    );
    assert!(
        wait(&limited_sends[2]) > 30 * 60 * 1_000,
        "{limited_sends:?}"
    );
    let st = sc
        .send_hinted(
            key(),
            contact(strangers[0].access),
            to_all(&strangers[0], b"hi"),
        )
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted, "contacts are not limited");
    // A brigade: ten strangers the established user never messaged block it. Nothing happens.
    for p in &strangers[14..24] {
        assert_eq!(block(&s, p, &normal).await, 204);
    }
    assert!(
        s.registry
            .standing_of(&normal.account)
            .await
            .unwrap()
            .is_none()
    );
}

/// A report brigade: two hundred accounts that received nothing from their target cannot
/// report it at all; one message reported by its recipient counts once; only direct messages
/// its recipients report count, and five distinct ones limit the sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_report_brigade_changes_nothing_without_messages() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let target = person(&s, 1).await;
    let mut brigade = Vec::new();
    for _ in 0..200 {
        brigade.push(person(&s, 1).await);
    }
    let mut all: Vec<&Person> = brigade.iter().take(6).collect();
    all.push(&target);
    followed(&s, &all).await;
    // One genuine message from the target to brigade[0].
    let (tc, _tev) = connect(&s, &target.devices[0]).await;
    let (_b0, mut b0ev) = connect(&s, &brigade[0].devices[0]).await;
    let content = b"one ordinary message".to_vec();
    let (stamp, fk) = franked_request(&s, &tc, &brigade[0], &mut b0ev, &content).await;
    let body = report_of(stamp, &target, fk, &content);
    // The other 199 hold no stamp of their own: every report is refused before it counts.
    for p in &brigade[1..] {
        let (st, _) = p.devices[0]
            .api(&s)
            .send("POST", "/v1/reports", Some(&body))
            .await
            .unwrap();
        assert_eq!(st, 403);
    }
    // Its recipient reports it: once; again: a duplicate.
    let api0 = brigade[0].devices[0].api(&s);
    assert_eq!(
        api0.send("POST", "/v1/reports", Some(&body))
            .await
            .unwrap()
            .0,
        204
    );
    assert_eq!(
        api0.send("POST", "/v1/reports", Some(&body))
            .await
            .unwrap()
            .0,
        409
    );
    assert!(
        s.registry
            .standing_of(&target.account)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(s.registry.report_count().await.unwrap(), 1);
    // Four more recipients of real messages report them: five distinct messages, limited.
    for (i, p) in brigade[1..5].iter().enumerate() {
        let (_c, mut ev) = connect(&s, &p.devices[0]).await;
        let words = format!("message {i}").into_bytes();
        let (stamp, fk) = franked_request(&s, &tc, p, &mut ev, &words).await;
        let r = report_of(stamp, &target, fk, &words);
        assert_eq!(
            p.devices[0]
                .api(&s)
                .send("POST", "/v1/reports", Some(&r))
                .await
                .unwrap()
                .0,
            204
        );
        let held = s.registry.standing_of(&target.account).await.unwrap();
        if i < 3 {
            assert!(held.is_none(), "{i}");
        } else {
            let h = held.unwrap();
            assert_eq!((h.kind.as_str(), h.reason.as_str()), ("limited", "reports"));
        }
    }
}

/// A suspension (a moderator's): the account cannot send or get a sender certificate; it still
/// receives, exports its data and deletes itself. Lifting it restores everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suspended_account_receives_exports_deletes_but_cannot_send() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let mallory = person(&s, 1).await;
    let friend = person(&s, 1).await;
    followed(&s, &[&mallory, &friend]).await;
    s.registry
        .set_standing(&mallory.account, "suspended", None, "abuse", "moderator")
        .await
        .unwrap();
    // An automatic limit never overrides a moderator's suspension.
    s.registry
        .set_standing(&mallory.account, "limited", Some(1), "blocks", "auto")
        .await
        .unwrap();
    s.reload().await;
    let (mc, mut mev) = connect(&s, &mallory.devices[0]).await;
    let (fc, _fev) = connect(&s, &friend.devices[0]).await;
    let st = mc
        .send_hinted(key(), contact(friend.access), to_all(&friend, b"hi"))
        .await
        .unwrap();
    assert_eq!(st, refused(RejectReason::Suspended));
    let mut f = SendFrame::per_device(1, key(), to_all(&friend, b"hi"));
    f.hints = contact(friend.access);
    let (_, result) = mallory.devices[0].api(&s).put_message(&f).await.unwrap();
    assert!(format!("{result:?}").contains("Suspended"), "{result:?}");
    // It still receives.
    let st = fc
        .send_hinted(
            key(),
            contact(mallory.access),
            to_all(&mallory, b"are you there"),
        )
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    assert!(delivery_within(&mut mev, 5_000).await.is_some());
    // No sender certificate.
    let (st, why) = mallory.devices[0]
        .api(&s)
        .send("GET", "/v1/certificate", None)
        .await
        .unwrap();
    assert_eq!(
        (st, why.as_ref()),
        (403, br#"{"error":"suspended"}"#.as_slice())
    );
    // Its data: exported; lifted: it sends again.
    let (st, _) = mallory.devices[0]
        .api(&s)
        .send("GET", "/v1/account/export", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    s.registry.lift_standing(&mallory.account).await.unwrap();
    s.reload().await;
    let st = mc
        .send_hinted(key(), contact(friend.access), to_all(&friend, b"sorry"))
        .await
        .unwrap();
    assert_eq!(st, SendStatus::Accepted);
    // Suspended again: it may still delete itself.
    s.registry
        .set_standing(&mallory.account, "suspended", None, "abuse", "moderator")
        .await
        .unwrap();
    s.reload().await;
    let (st, _) = mallory.devices[0]
        .api(&s)
        .send("DELETE", "/v1/account", None)
        .await
        .unwrap();
    assert_eq!(st, 202);
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
    let commitment = songbird_api::reports::commitment(&fk, content);
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
