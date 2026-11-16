//! Prompt 5, milestone 1 (D-0066, D-0067), live: MLS groups through `api` and the send path,
//! against the real registry (SurrealDB: groups, epochs, fan-outs) and `valkey-hot` (nonces,
//! budgets). OpenMLS clients (`songbird-groups-harness`) play the apps. The mailbox is Iggy when
//! `SONGBIRD_TEST_IGGY` is set, else in memory. Runs when `SONGBIRD_TEST_SURREALDB` (+ `_USER`,
//! `_PASS`) and `SONGBIRD_TEST_VALKEY` are set; with `SONGBIRD_REQUIRE_STACK=1` a missing one fails
//! instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::large_futures,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::Ed25519KeyPair;
use bytes::Bytes;
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::groups::Groups;
use songbird_api::messages::{Messages, SendStack};
use songbird_api::{ApiMetrics, App};
use songbird_client::DeviceKey;
use songbird_delivery::{DeliveryMetrics, Directory, Shared};
use songbird_e2e::{settings, test_mailbox};
use songbird_groups::Limits;
use songbird_groups_harness::{Device, GID};
use songbird_mailbox::{AnyMailbox, Mailbox as _};
use songbird_proto::frame::{RejectReason, SendFrame, SendHints, SendPayload, SendStatus};
use songbird_router::LocalRouter;
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

/// A person: an account with one device, an HTTP client for it and an MLS client.
struct Person {
    api: ApiClient,
    mls: Device,
}

struct Stack {
    registry: Arc<Registry>,
    shared: Arc<Shared<Arc<AnyMailbox>, Arc<LocalRouter>>>,
    app: Arc<App>,
    people: Vec<Person>,
    _stop: watch::Sender<bool>,
}

impl Stack {
    fn messages(&self) -> &Messages {
        self.app.messages.as_ref().unwrap()
    }

    fn groups(&self) -> &Groups {
        self.messages().groups.as_ref().unwrap()
    }

    /// Envelopes waiting for person `i`'s device.
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
}

async fn stack(people: usize) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("groups_{}", DeviceId::random().unwrap().to_hex_unredacted()),
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
            Directory::from_accounts(rows.into_iter().map(|(d, a, k)| (d, k, a))),
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
            // Races send many commits at once; the budget itself is tested below.
            g.commits_per_sec = 1_000;
            g.commit_burst = 1_000;
            g
        }),
    };
    let app = Arc::new(App {
        requests: None,
        reports: None,
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
                songbird_jobs::QueueConfig::new("groups-test".into()),
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
    let people = keys
        .into_iter()
        .map(|(id, seed, account)| Person {
            api: ApiClient::new(
                api_addr,
                API,
                id,
                Ed25519KeyPair::from_seed_unchecked(&seed).unwrap(),
            ),
            mls: Device::unregistered(id, account),
        })
        .collect();
    Some(Stack {
        registry,
        shared,
        app,
        people,
        _stop: stop,
    })
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

/// `version | group | rest`.
fn body(rest: &[u8]) -> Vec<u8> {
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

async fn create(s: &mut Stack, creator: usize) {
    let (info, tree) = s.people[creator].mls.create();
    let (st, reply) = s.people[creator]
        .api
        .send("POST", "/v1/groups", Some(&body(&parts(&info, &tree))))
        .await
        .unwrap();
    assert_eq!(st, 204, "{}", String::from_utf8_lossy(&reply));
}

async fn commit(s: &Stack, who: usize, bundle: &[u8]) -> (u16, serde_json::Value) {
    let (st, reply) = s.people[who]
        .api
        .send("POST", "/v1/groups/commit", Some(&body(bundle)))
        .await
        .unwrap();
    (
        st,
        if reply.is_empty() {
            serde_json::Value::Null
        } else {
            json(&reply)
        },
    )
}

async fn state(s: &Stack, who: usize) -> (u16, Bytes) {
    s.people[who]
        .api
        .send("POST", "/v1/groups/state", Some(&body(&[])))
        .await
        .unwrap()
}

/// The ratchet tree from a `/v1/groups/state` answer.
fn tree_of(b: &[u8]) -> Vec<u8> {
    let info_len = usize::try_from(u32::from_be_bytes(b[8..12].try_into().unwrap())).unwrap();
    let at = 12 + info_len;
    let tree_len = usize::try_from(u32::from_be_bytes(b[at..at + 4].try_into().unwrap())).unwrap();
    b[at + 4..at + 4 + tree_len].to_vec()
}

fn group_frame(key: u8, msg: Vec<u8>) -> SendFrame {
    SendFrame {
        req_id: u32::from(key),
        idempotency_key: [key; 16],
        mls: None,
        hints: SendHints {
            group: Some(GID),
            ..SendHints::default()
        },
        payload: SendPayload::Shared {
            devices: Vec::new(),
            body: Bytes::from(msg),
        },
    }
}

/// Adds people `who` (by Alice, person 0) and has them join from their Welcome and the tree.
async fn add(s: &mut Stack, who: &[usize]) {
    let kps: Vec<_> = who.iter().map(|i| s.people[*i].mls.key_package()).collect();
    let b = s.people[0].mls.add(&kps);
    let (st, reply) = commit(s, 0, &b).await;
    assert_eq!(st, 200, "{reply}");
    s.people[0].mls.merge();
    for &i in who {
        let welcome = s.pending(i).await.pop().expect("the Welcome");
        let (st, answer) = state(s, i).await;
        assert_eq!(st, 200);
        s.people[i].mls.join(&welcome, &tree_of(&answer));
    }
}

#[tokio::test]
async fn groups_are_created_committed_fanned_out_and_messaged() {
    let Some(mut s) = stack(4).await else { return };
    create(&mut s, 0).await;
    // The same ID again.
    let (info, tree) = (s.people[0].mls.group_info(), s.people[0].mls.tree());
    let (st, _) = s.people[0]
        .api
        .send("POST", "/v1/groups", Some(&body(&parts(&info, &tree))))
        .await
        .unwrap();
    assert_eq!(st, 409);

    // Alice adds Bob and Carol; each finds exactly the Welcome in its mailbox.
    add(&mut s, &[1, 2]).await;
    assert_eq!(s.pending(1).await.len(), 1);
    assert_eq!(s.registry.group(&GID).await.unwrap().unwrap().epoch, 1);
    // Dave (person 3) is outside: no state for him, the same answer as no group.
    assert_eq!(state(&s, 3).await.0, 404);

    // A group message over `PUT /v1/messages`: to Bob and Carol, from the roster.
    let msg = s.people[0].mls.message(b"hello group");
    let (st, result) = s.people[0]
        .api
        .put_message(&group_frame(1, msg))
        .await
        .unwrap();
    assert_eq!((st, result.map(|r| r.1)), (200, Some(SendStatus::Accepted)));
    let got = s.pending(1).await.pop().unwrap();
    assert_eq!(s.people[1].mls.read(&got), b"hello group");
    assert_eq!(s.pending(3).await.len(), 0, "Dave never receives");
    // Dave cannot post into it.
    let fake = s.people[1].mls.message(b"x");
    let (_, result) = s.people[3]
        .api
        .put_message(&group_frame(2, fake))
        .await
        .unwrap();
    assert_eq!(
        result.map(|r| r.1),
        Some(SendStatus::Rejected {
            reason: RejectReason::NotMember,
            retry_after_ms: 0
        })
    );

    // Bob removes Carol: Alice and Carol receive the commit; Carol is out once rosters refresh.
    let carol_leaf = s.people[2].mls.leaf();
    let b = s.people[1].mls.remove(&[carol_leaf]);
    let (st, reply) = commit(&s, 1, &b).await;
    assert_eq!((st, reply["epoch"].as_u64()), (200, Some(2)));
    s.people[1].mls.merge();
    let to_alice = s.pending(0).await.pop().unwrap();
    s.people[0].mls.receive(
        &songbird_groups::wire::Bundle {
            commit: &to_alice,
            welcome: None,
            group_info: b"-",
        }
        .encode(),
    );
    assert!(
        s.pending(2).await.len() >= 2,
        "Carol is told she was removed"
    );
    tokio::time::sleep(songbird_send::groups::ROSTER_TTL + Duration::from_millis(200)).await;
    let late = s.people[2].mls.message(b"still here?");
    let (_, result) = s.people[2]
        .api
        .put_message(&group_frame(3, late))
        .await
        .unwrap();
    assert_eq!(
        result.map(|r| r.1),
        Some(SendStatus::Rejected {
            reason: RejectReason::NotMember,
            retry_after_ms: 0
        })
    );
    assert_eq!(s.people[0].mls.roster(), s.people[1].mls.roster());
}

#[tokio::test]
async fn concurrent_commits_over_http_have_one_winner_per_epoch() {
    let Some(mut s) = stack(5).await else { return };
    create(&mut s, 0).await;
    add(&mut s, &[1, 2, 3, 4]).await;
    let mut pending: Vec<usize> = (0..5).collect();
    while !pending.is_empty() {
        let epoch = s.registry.group(&GID).await.unwrap().unwrap().epoch;
        let bundles: Vec<Vec<u8>> = pending.iter().map(|&i| s.people[i].mls.update()).collect();
        // All at once, over separate connections.
        let answers = futures_util::future::join_all(
            pending.iter().zip(&bundles).map(|(&i, b)| commit(&s, i, b)),
        )
        .await;
        let winners: Vec<usize> = answers
            .iter()
            .enumerate()
            .filter(|(_, (st, _))| *st == 200)
            .map(|(k, _)| k)
            .collect();
        assert_eq!(winners.len(), 1, "epoch {epoch}: {answers:?}");
        for (k, (st, reply)) in answers.iter().enumerate() {
            if *st != 200 {
                assert_eq!((*st, reply["error"].as_str()), (409, Some("stale")));
                assert_eq!(reply["epoch"].as_u64(), Some(epoch + 1));
                s.people[pending[k]].mls.discard();
            }
        }
        let w = pending[winners[0]];
        s.people[w].mls.merge();
        for i in 0..5 {
            if i != w {
                s.people[i].mls.receive(&bundles[winners[0]]);
            }
        }
        pending.remove(winners[0]);
    }
    let epoch = s.registry.group(&GID).await.unwrap().unwrap().epoch;
    assert_eq!(epoch, 1 + 5);
    for p in &s.people {
        assert_eq!(p.mls.epoch(), epoch, "nobody forked");
    }
}

#[tokio::test]
async fn a_lost_answer_is_recognised_and_an_interrupted_fan_out_is_redriven() {
    let Some(mut s) = stack(3).await else { return };
    create(&mut s, 0).await;
    add(&mut s, &[1]).await;

    // The same commit twice (the first answer was lost): one store, the same epoch.
    let b = s.people[0].mls.update();
    let first = commit(&s, 0, &b).await;
    let again = commit(&s, 0, &b).await;
    assert_eq!(first.0, 200);
    assert_eq!(again, first, "a retried commit is answered as accepted");
    s.people[0].mls.merge();
    assert_eq!(
        s.pending(1).await.len(),
        1 + 1,
        "the Welcome, and the commit once"
    );
    let once = s.pending(1).await.pop().unwrap();
    s.people[1].mls.receive(
        &songbird_groups::wire::Bundle {
            commit: &once,
            welcome: None,
            group_info: b"-",
        }
        .encode(),
    );

    // A crash after the registry recorded a commit, before the mailboxes stored it: the
    // fan-out row stays, and a re-drive pass delivers it.
    let b = s.people[0].mls.update();
    let row = s.registry.group(&GID).await.unwrap().unwrap();
    let rec = songbird_groups::Record::decode(&row.state).unwrap();
    let dir = {
        let mut d = songbird_groups_harness::Dir::default();
        for p in &s.people {
            d.0.insert(p.mls.id, p.mls.account);
        }
        d
    };
    let (g, applied) = songbird_groups::Group::load(rec)
        .unwrap()
        .apply_commit(&s.people[0].mls.id, &b, &dir, &Limits::default())
        .unwrap();
    let parts = songbird_groups::wire::Bundle::parse(&b, usize::MAX).unwrap();
    let plan = postcard::to_stdvec(&(
        parts.commit.to_vec(),
        vec![*s.people[1].mls.id.as_bytes()],
        None::<Vec<u8>>,
        Vec::<[u8; 16]>::new(),
    ))
    .unwrap();
    let roster: Vec<DeviceId> = g.roster().devices().collect();
    s.registry
        .commit_group(
            &GID,
            applied.from_epoch,
            &g.record().encode().unwrap(),
            &songbird_send::Roster::to_bytes(&roster),
            &applied.commit_hash,
            &plan,
        )
        .await
        .unwrap();
    s.people[0].mls.merge();
    let before = s.pending(1).await.len();
    assert_eq!(
        s.groups().redrive_once(&s.registry, s.messages(), 0).await,
        1
    );
    assert_eq!(s.pending(1).await.len(), before + 1);
    assert_eq!(
        s.groups().redrive_once(&s.registry, s.messages(), 0).await,
        0,
        "done once"
    );
    let delivered = s.pending(1).await.pop().unwrap();
    s.people[1].mls.receive(
        &songbird_groups::wire::Bundle {
            commit: &delivered,
            welcome: None,
            group_info: b"-",
        }
        .encode(),
    );
    assert_eq!(s.people[1].mls.epoch(), s.people[0].mls.epoch());
    let _ = &s.people[2];
}
