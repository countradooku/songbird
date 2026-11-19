//! Prompt 9's gate items for presence and nudges (M3, D-0104), end to end over a delivery node,
//! `api`, the registry and `valkey-hot`:
//!
//! - presence reaches only the contacts whose access keys the sender holds, never a stranger;
//! - invisible mode sends nothing at all (counted at the server);
//! - the sender learns nothing about who is online;
//! - nudges are held to their budgets per pair of accounts and per sender, cluster-wide in
//!   `valkey-hot`, and a block drops them silently.
//!
//! Runs when the `SONGBIRD_TEST_*` variables are set; with `SONGBIRD_REQUIRE_STACK=1` a missing
//! one fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::large_futures,
    clippy::assert_is_empty,
    reason = "tests"
)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use prost::Message as _;
use songbird_accounts::{Db, Registry};
use songbird_api::client::unsigned_body;
use songbird_api::messages::{Messages, SendStack};
use songbird_api::{ApiMetrics, App};
use songbird_client::{ClientConfig, DeviceKey, Event, ResumeState, State};
use songbird_content::presence::{Attention, AttentionKind, Audience, Choice, Presencer};
use songbird_delivery::{DeliveryMetrics, Directory, Shared, server};
use songbird_e2e::{SERVER_NAME, settings, test_mailbox};
use songbird_proto::ephemeral::SealedBatch;
use songbird_router::LocalRouter;
use songbird_send::{Gate, GateKeys, Policy, RegistryGate, RequestLimits};
use songbird_types::{AccountId, DeviceId, Secret, SecretRef};
use tokio::sync::mpsc;

const API: &str = "api.gatep09.test";

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
}

struct Person {
    account: AccountId,
    devices: Vec<Dev>,
    access: [u8; 16],
}

struct Stack {
    registry: Arc<Registry>,
    shared: Arc<Shared<Arc<songbird_mailbox::AnyMailbox>, Arc<LocalRouter>>>,
    app: Arc<App>,
    ws: SocketAddr,
    api: SocketAddr,
    keys: GateKeys,
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
                    "gatep09_{}",
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
    let hot_conn = || async {
        songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
            .await
            .unwrap()
    };
    // Fresh keys per run, so budgets never carry over between runs.
    let keys = GateKeys::from_cluster_secret(&rand32()).unwrap();
    let gate: Arc<dyn Gate> = Arc::new(RegistryGate::new(
        Arc::clone(&registry),
        hot_conn().await,
        keys.clone(),
        limits,
    ));
    let policy = || Policy {
        franking: None,
        gate: Some(Arc::clone(&gate)),
        max_broadcast_accounts: limits.max_broadcast_accounts,
        rosters: None,
        channels: Arc::default(),
        standings: None,
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
        "songbird-gatep09".into(),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_ACCESS_KEY")?),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_SECRET_KEY")?),
    ))
    .unwrap();
    let queue = Arc::new(
        songbird_jobs::Queue::connect(
            redis::Client::open(jobs.as_str()).unwrap(),
            &[0x39; 32],
            songbird_jobs::QueueConfig::new(format!("gate-p09-{}", &hex::encode(rand32())[..8])),
        )
        .await
        .unwrap(),
    );
    let profiles = songbird_api::profiles::Profiles::new(
        songbird_api::config::ProfileSettings {
            secret: SecretRef::Env("SONGBIRD_UNUSED".into()),
            certificate_key: None,
            sealed_sender: true,
            certificate_hours: 24,
            fetches_per_hour: 1_000,
            fetch_burst: 1_000,
            sealed_per_hour: 1_000,
            sealed_per_account_hour: 1_000,
            sealed_burst: 200,
            presence_per_hour: 1_000_000,
            presence_burst: 20_000,
            policy_updates_per_hour: 120,
            policy_update_burst: 20,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
        },
        &rand32(),
        None,
        metrics.profiles.clone(),
    )
    .unwrap();
    let app = Arc::new(App {
        plans: songbird_api::plans::Plans::default(),
        calls: None,
        reports: None,
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
        s3,
        queue,
        hot: hot_conn().await,
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
        devices: None,
        profiles: Some(profiles),
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
    Some(Stack {
        registry,
        shared,
        app,
        ws,
        api,
        keys,
        _stop: stop,
    })
}

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

/// Ephemeral payloads that arrive within `ms`.
async fn ephemerals_within(ev: &mut mpsc::Receiver<Event>, ms: u64) -> Vec<Bytes> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, ev.recv()).await {
            Ok(Some(Event::Ephemeral { payload })) => out.push(payload),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return out,
        }
    }
}

/// Attention payloads (nudges, frame `0x84`) that arrive within `ms`; ordinary ephemeral
/// events are not among them (D-0108).
async fn attentions_within(ev: &mut mpsc::Receiver<Event>, ms: u64) -> Vec<Bytes> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, ev.recv()).await {
            Ok(Some(Event::Attention { payload })) => out.push(payload),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return out,
        }
    }
}

/// `PUT /v1/ephemeral/sealed`: no signature, the recipients' combined key in the header.
async fn sealed(s: &Stack, key: [u8; 16], events: Vec<(DeviceId, Vec<u8>)>) -> (u16, Bytes) {
    let body = SealedBatch { events }.encode().unwrap();
    unsigned_body(
        s.api,
        API,
        "PUT",
        "/v1/ephemeral/sealed",
        &[("unidentified-access-key", hex::encode(key))],
        Bytes::from(body),
    )
    .await
    .unwrap()
}

fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut o = a;
    o.iter_mut().zip(b).for_each(|(x, y)| *x ^= y);
    o
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presence_reaches_only_contacts_and_invisible_sends_nothing() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let alice = person(&s, 1).await;
    let bob = person(&s, 2).await;
    let carol = person(&s, 1).await;
    followed(&s, &[&alice, &bob, &carol]).await;
    let (_b0, mut b0) = connect(&s, &bob.devices[0]).await;
    let (bob1, mut b1) = connect(&s, &bob.devices[1]).await;
    let (_c0, mut c0) = connect(&s, &carol.devices[0]).await;
    let accepted = || s.app.metrics.profiles.presence.get();

    // Alice's presence rules decide what to send: Bob is her contact, Carol is not.
    let mut rules = Presencer::new(
        Choice::Online,
        Audience::Contacts,
        Audience::Contacts,
        BTreeSet::from([*bob.account.as_bytes()]),
    );
    rules.foreground(1_000);
    let out = rules.poll(1_000).unwrap();
    assert_eq!(out.to, BTreeSet::from([*bob.account.as_bytes()]));
    // (A real app encrypts this per device in a sealed envelope; the server sees bytes only.)
    let payload = out.presence.encode_to_vec();
    let events: Vec<(DeviceId, Vec<u8>)> = bob
        .devices
        .iter()
        .map(|d| (d.id, payload.clone()))
        .collect();
    assert_eq!(sealed(&s, bob.access, events.clone()).await.0, 204);
    assert_eq!(
        ephemerals_within(&mut b0, 1_000).await,
        vec![Bytes::from(payload.clone())]
    );
    assert_eq!(ephemerals_within(&mut b1, 500).await.len(), 1);
    assert_eq!(accepted(), 1);

    // A batch reaching Carol without her key is refused whole: nobody gets anything, and the
    // answer is the same 204 (it says nothing about which devices or accounts exist, D-0108).
    let mut with_carol = events.clone();
    with_carol.push((carol.devices[0].id, payload.clone()));
    assert_eq!(sealed(&s, bob.access, with_carol.clone()).await.0, 204);
    assert_eq!(sealed(&s, [0; 16], events.clone()).await.0, 204);
    assert_eq!(
        sealed(
            &s,
            [0; 16],
            vec![(DeviceId::from_bytes([0xEE; 16]), payload.clone())]
        )
        .await
        .0,
        204
    );
    assert!(ephemerals_within(&mut b0, 300).await.is_empty());
    assert!(ephemerals_within(&mut c0, 300).await.is_empty());
    // The two refused batches are not counted; the one for an unknown device is (it was
    // allowed, and reached nobody).
    assert_eq!(accepted(), 2);
    // With both keys (Carol became a contact) both are reached.
    assert_eq!(
        sealed(&s, xor(bob.access, carol.access), with_carol)
            .await
            .0,
        204
    );
    assert_eq!(ephemerals_within(&mut c0, 1_000).await.len(), 1);
    assert_eq!(ephemerals_within(&mut b0, 1_000).await.len(), 1);

    // The answer says nothing about who is online: Bob's second device goes offline, the
    // answer is the same.
    drop(bob1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (st, body) = sealed(&s, bob.access, events).await;
    assert_eq!((st, body.len()), (204, 0));
    assert_eq!(ephemerals_within(&mut b0, 1_000).await.len(), 1);

    // Invisible: whatever the app does, its rules never produce a batch, so the server sees no
    // request (its count does not move) and Bob receives nothing.
    let before = accepted();
    let mut ghost = Presencer::new(
        Choice::Invisible,
        Audience::Contacts,
        Audience::Contacts,
        BTreeSet::from([*bob.account.as_bytes()]),
    );
    for t in 0..20u64 {
        let now = 10_000 + t * 7_000;
        if t % 2 == 0 {
            ghost.foreground(now);
        } else {
            ghost.background(now);
        }
        if let Some(o) = ghost.poll(now) {
            let p = o.presence.encode_to_vec();
            let ev: Vec<_> = bob.devices.iter().map(|d| (d.id, p.clone())).collect();
            sealed(&s, bob.access, ev).await;
        }
    }
    assert_eq!(accepted(), before);
    assert!(ephemerals_within(&mut b0, 500).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nudges_are_held_to_their_budgets_and_blocks_drop_them() {
    let limits = RequestLimits {
        attention_pair_burst: 3,
        attention_sender_burst: 5,
        ..RequestLimits::default()
    };
    let Some(s) = stack(limits).await else { return };
    let alice = person(&s, 1).await;
    let bob = person(&s, 1).await;
    let erin = person(&s, 1).await;
    let dave = person(&s, 1).await;
    let frank = person(&s, 1).await;
    followed(&s, &[&alice, &bob, &erin, &dave, &frank]).await;
    let (a, _ae) = connect(&s, &alice.devices[0]).await;
    let (d, _de) = connect(&s, &dave.devices[0]).await;
    let (f, _fe) = connect(&s, &frank.devices[0]).await;
    let (_b, mut be) = connect(&s, &bob.devices[0]).await;
    let (_e, mut ee) = connect(&s, &erin.devices[0]).await;
    let nudge = Bytes::from(
        Attention {
            kind: i32::from(AttentionKind::Nudge),
        }
        .encode_to_vec(),
    );
    let m = &s.shared.metrics;

    // Alice nudges Bob six times: the pair's burst of three passes.
    for _ in 0..6 {
        a.attention(bob.devices[0].id, nudge.clone()).await.unwrap();
    }
    assert_eq!(attentions_within(&mut be, 1_000).await.len(), 3);
    // Another sender has its own pair budget.
    for _ in 0..3 {
        d.attention(bob.devices[0].id, nudge.clone()).await.unwrap();
    }
    assert_eq!(attentions_within(&mut be, 1_000).await.len(), 3);
    // Alice's own budget across recipients is five: two are left for Erin.
    for _ in 0..3 {
        a.attention(erin.devices[0].id, nudge.clone())
            .await
            .unwrap();
    }
    assert_eq!(attentions_within(&mut ee, 1_000).await.len(), 2);

    // Bob blocks Frank: Frank's nudges are dropped, and Frank is told nothing.
    s.registry
        .add_block(
            &s.keys.owner(&bob.account),
            &s.keys.pair(&bob.account, &frank.account),
        )
        .await
        .unwrap();
    f.attention(bob.devices[0].id, nudge.clone()).await.unwrap();
    assert!(attentions_within(&mut be, 800).await.is_empty());
    // Frank sends the same nudge as an ordinary ephemeral event: Bob gets it, if at all, only
    // as an ephemeral, never as attention, so the app doesn't treat it as a nudge.
    f.ephemeral(bob.devices[0].id, nudge.clone()).await.unwrap();
    assert!(attentions_within(&mut be, 800).await.is_empty());
    assert_eq!(m.attention_routed.get(), 3 + 3 + 2);
    assert_eq!(m.attention_dropped.get(), 3 + 1 + 1);
}

/// The cost of a full batch (M3's numbers; `--nocapture` prints them): 1,024 devices of 64
/// contacts, a 200-byte payload each, 16 of them connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::as_conversions,
    reason = "tests"
)]
async fn presence_batch_latency() {
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let mut people = Vec::new();
    for _ in 0..64 {
        people.push(person(&s, 16).await);
    }
    let refs: Vec<&Person> = people.iter().collect();
    followed(&s, &refs).await;
    let mut live = Vec::new();
    for p in &people[..16] {
        live.push(connect(&s, &p.devices[0]).await);
    }
    let key = people.iter().fold([0u8; 16], |k, p| xor(k, p.access));
    let events: Vec<(DeviceId, Vec<u8>)> = people
        .iter()
        .flat_map(|p| p.devices.iter().map(|d| (d.id, vec![7u8; 200])))
        .collect();
    assert_eq!(events.len(), 1_024);
    let mut times = Vec::new();
    // The range's burst is 20,000 devices: 19 full batches fit, then the budget refuses.
    for _ in 0..19 {
        let t = std::time::Instant::now();
        assert_eq!(sealed(&s, key, events.clone()).await.0, 204);
        times.push(t.elapsed());
    }
    let mut refused = false;
    for _ in 0..3 {
        refused |= sealed(&s, key, events.clone()).await.0 == 429;
    }
    assert!(refused, "the per-range budget holds");
    times.sort();
    let pct = |p: f64| times[((times.len() as f64 * p) as usize).min(times.len() - 1)];
    println!(
        "presence: 1,024-device sealed batch (205 KiB), 16 devices online, 19 runs: p50 {:?} max {:?}",
        pct(0.5),
        pct(1.0)
    );
    drop(live);
}

impl Dev {
    fn api(&self, s: &Stack) -> songbird_api::client::ApiClient {
        songbird_api::client::ApiClient::new(
            s.api,
            API,
            self.id,
            aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&self.seed).unwrap(),
        )
    }
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap_or_default()
}

/// Prompt 9, M4 (D-0105): a parent's signed policy locks the rules the server enforces; the
/// child's devices cannot loosen them; only the parent's signature changes or ends them, or the
/// date; the server holds no parent account and no birth date.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parents_policy_locks_rules_and_only_the_parent_or_the_date_ends_it() {
    use songbird_content::supervision::{ClientRules, PolicyKey, seal_rules, unlink_at};
    use songbird_proto::supervision::{GROUP_APPROVAL, HIDDEN, NO_REQUESTS, Policy, UNLINK};
    let Some(s) = stack(RequestLimits::default()).await else {
        return;
    };
    let child = person(&s, 2).await;
    let parent = person(&s, 1).await;
    let (child_primary, child_linked) = (child.devices[0].api(&s), child.devices[1].api(&s));
    let parent_api = parent.devices[0].api(&s);
    // In person: the parent's device makes the key and the secret; the child's enters an age.
    let key = PolicyKey::generate().unwrap();
    let secret = rand32();
    let rules = ClientRules {
        approved_contacts_only: true,
        block_unknown_calls: true,
        nudges_off: false,
        quiet_from_min: 21 * 60,
        quiet_to_min: 7 * 60,
    };
    let policy = |version: u64, flags: u8, until: u64| {
        let mut p = Policy {
            child: child.account,
            policy_key: [0; 32],
            policy_version: version,
            flags,
            unlink_at_s: until,
            client_rules: seal_rules(&secret, child.account.as_bytes(), version, &rules).unwrap(),
            signature: [0; 64],
        };
        key.sign(&mut p);
        p
    };
    let until = unlink_at(2014, 3, 16).unwrap();
    // A parent's later policies go unsigned (D-0108): the signature is the only authority.
    let update = |p: &Policy| {
        unsigned_body(
            s.api,
            API,
            "PUT",
            "/v1/supervision/update",
            &[],
            Bytes::from(p.encode()),
        )
    };
    let first = policy(1, NO_REQUESTS | HIDDEN | GROUP_APPROVAL, until);
    // Only the child's primary installs the first policy.
    let st = |r: (u16, Bytes)| r.0;
    assert_eq!(
        st(parent_api
            .send("PUT", "/v1/supervision", Some(&first.encode()))
            .await
            .unwrap()),
        403
    );
    assert_eq!(
        st(child_linked
            .send("PUT", "/v1/supervision", Some(&first.encode()))
            .await
            .unwrap()),
        403
    );
    // A policy whose signature is not the key's is refused.
    let mut forged = first.clone();
    forged.flags = 0;
    assert_eq!(
        st(child_primary
            .send("PUT", "/v1/supervision", Some(&forged.encode()))
            .await
            .unwrap()),
        403
    );
    assert_eq!(
        st(child_primary
            .send("PUT", "/v1/supervision", Some(&first.encode()))
            .await
            .unwrap()),
        204
    );
    let (_, b) = child_linked
        .send("GET", "/v1/account/settings", None)
        .await
        .unwrap();
    let v = json(&b);
    assert_eq!(
        (
            &v["supervised"],
            &v["discoverable"],
            &v["requests"],
            &v["groups"]
        ),
        (
            &serde_json::json!(true),
            &serde_json::json!(false),
            &serde_json::json!("nobody"),
            &serde_json::json!("contacts")
        )
    );
    // The child's app reads the policy as signed and checks it itself.
    let (code, raw) = child_linked
        .send("GET", "/v1/supervision", None)
        .await
        .unwrap();
    assert_eq!((code, Policy::decode(&raw).unwrap()), (200, first.clone()));
    // Not even the primary may loosen a locked rule.
    for (path, body) in [
        ("/v1/account/discoverable", &br#"{"on":true}"#[..]),
        ("/v1/account/requests", &br#"{"from":"everyone"}"#[..]),
        ("/v1/account/groups", &br#"{"from":"everyone"}"#[..]),
    ] {
        let (code, b) = child_primary.send("PUT", path, Some(body)).await.unwrap();
        assert_eq!(
            (code, json(&b)["error"].as_str()),
            (403, Some("supervised")),
            "{path}"
        );
    }
    // "No message requests" also closes the account to "anyone may send" (D-0108): no lane
    // lets a stranger in without a request.
    assert!(matches!(
        s.registry
            .put_profile_as(&child.account, 50, b"profile", &[7; 16], true, true)
            .await,
        Err(songbird_accounts::RegistryError::Supervised)
    ));
    // A signed policy for another account is refused with one answer, supervised or not
    // (D-0108): the endpoint tells nobody who is a child.
    let stranger = person(&s, 1).await;
    let mut probe = first.clone();
    probe.child = stranger.account;
    let probe_key = PolicyKey::generate().unwrap();
    probe_key.sign(&mut probe);
    let mut probe_child = first.clone();
    probe_key.sign(&mut probe_child);
    for p in [&first, &probe, &probe_child] {
        let (code, b) = parent_api
            .send("PUT", "/v1/supervision", Some(&p.encode()))
            .await
            .unwrap();
        assert_eq!((code, json(&b)["error"].as_str()), (403, Some("account")));
    }
    // Unsigned updates: a bad signature and an account with no policy get the same answer.
    for p in [&probe, &probe_child] {
        let (code, b) = update(p).await.unwrap();
        assert_eq!((code, json(&b)["error"].as_str()), (403, Some("signature")));
    }
    // A replayed or older policy is refused, and so is one that moves the date later; the
    // parent's newer one applies.
    let (code, b) = update(&first).await.unwrap();
    assert_eq!((code, json(&b)["error"].as_str()), (409, Some("version")));
    let (code, b) = update(&policy(2, NO_REQUESTS, until + 86_400))
        .await
        .unwrap();
    assert_eq!((code, json(&b)["error"].as_str()), (409, Some("date")));
    let second = policy(2, NO_REQUESTS, until);
    assert_eq!(st(update(&second).await.unwrap()), 204);
    assert_eq!(
        st(child_primary
            .send("PUT", "/v1/account/discoverable", Some(br#"{"on":true}"#))
            .await
            .unwrap()),
        204,
        "no longer locked"
    );
    // The server holds the policy key, rules, version and date: no parent account or birth date.
    let row = s
        .registry
        .db()
        .query1(
            "SELECT * FROM ONLY superv:[$a];",
            vec![(
                "a".into(),
                songbird_surreal::Value::Bytes(Bytes::copy_from_slice(child.account.as_bytes())),
            )],
        )
        .await
        .unwrap();
    let text = format!("{row:?}");
    assert!(!text.contains(&format!("{:?}", parent.account.as_bytes())));
    let fields: BTreeSet<String> = match &row {
        songbird_surreal::Value::Map(m) => m.iter().map(|(k, _)| k.clone()).collect(),
        _ => BTreeSet::new(),
    };
    assert_eq!(
        fields,
        ["flags", "id", "pkey", "policy", "pv", "unlink_at"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    // The parent unlinks: the locks lift.
    let end = policy(3, UNLINK, until);
    assert_eq!(st(update(&end).await.unwrap()), 204);
    assert_eq!(
        st(child_primary
            .send(
                "PUT",
                "/v1/account/requests",
                Some(br#"{"from":"everyone"}"#)
            )
            .await
            .unwrap()),
        204
    );
    assert_eq!(
        st(child_linked
            .send("GET", "/v1/supervision", None)
            .await
            .unwrap()),
        404
    );

    // A policy whose date has passed ends without the parent (the worker's sweep).
    let other = person(&s, 1).await;
    let other_api = other.devices[0].api(&s);
    let k2 = PolicyKey::generate().unwrap();
    let mut p = Policy {
        child: other.account,
        policy_key: [0; 32],
        policy_version: 1,
        flags: HIDDEN,
        unlink_at_s: 1,
        client_rules: Vec::new(),
        signature: [0; 64],
    };
    k2.sign(&mut p);
    assert_eq!(
        st(other_api
            .send("PUT", "/v1/supervision", Some(&p.encode()))
            .await
            .unwrap()),
        204
    );
    let due = s.registry.supervisions_due(100).await.unwrap();
    assert!(due.contains(&other.account));
    for c in due {
        s.registry.end_supervision(&c).await.unwrap();
    }
    assert_eq!(
        st(other_api
            .send("PUT", "/v1/account/discoverable", Some(br#"{"on":true}"#))
            .await
            .unwrap()),
        204
    );
}
