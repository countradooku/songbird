//! Prompt 3's final gate, GDPR part (M7, D-0056), against the real stores (SurrealDB, `RustFS`,
//! `valkey-hot`, `valkey-jobs`): an account with data in every Prompt 3 store is exported, then
//! deleted through `api` and the worker's job, and every store is inspected; inactivity warns
//! twice and then deletes. Runs when the compose stack is configured, like `gate_m5`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::assert_is_empty,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::devices::{ListEntry, StoredPasskey};
use songbird_accounts::{Db, KeysUpdate, NewAccount, Registry, push_index};
use songbird_api::client::ApiClient;
use songbird_api::{ApiMetrics, App};
use songbird_delivery::{DeliveryMetrics, Directory, Shared};
use songbird_e2e::{settings, test_mailbox};
use songbird_jobs::{Job, Outcome, Queue, QueueConfig, Stream, Work};
use songbird_router::LocalRouter;
use songbird_surreal::Value;
use songbird_types::{AccountId, DeviceId, Secret};
use songbird_worker::{DeliveryLink, Worker, WorkerMetrics};

const API: &str = "api.test";
const PUSH_INDEX: [u8; 32] = [0x31; 32];

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

struct Stack {
    registry: Arc<Registry>,
    app: Arc<App>,
    addr: std::net::SocketAddr,
    worker: Worker,
    s3: songbird_s3::Client,
    _stop: tokio::sync::watch::Sender<bool>,
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b
}

async fn stack() -> Option<Stack> {
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
                    "gatep03_{}",
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
    let s3 = songbird_s3::Client::new(songbird_s3::Config::new(
        s3_addr,
        format!("songbird-gatep03-{}", &hex::encode(rand32())[..12]),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_ACCESS_KEY")?),
        Secret::new(env("SONGBIRD_TEST_RUSTFS_SECRET_KEY")?),
    ))
    .unwrap();
    s3.create_bucket().await.unwrap();
    let queue_name = format!("gate-p03-{}", &hex::encode(rand32())[..8]);
    let queue = Arc::new(
        Queue::connect(
            redis::Client::open(jobs.as_str()).unwrap(),
            &[0x32; 32],
            QueueConfig::new(queue_name),
        )
        .await
        .unwrap(),
    );
    queue
        .ensure_groups(&[Stream::Deletion, Stream::Push])
        .await
        .unwrap();
    let shared = Arc::new(Shared::new(
        settings(),
        Directory::from_registry(&registry).await.unwrap(),
        test_mailbox().await,
        LocalRouter::new(),
        DeliveryMetrics::default(),
    ));
    let (_, push_public) = songbird_accounts::push_token::key_pair(&[0x33; 32]).unwrap();
    let app = Arc::new(App {
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
        s3: s3.clone(),
        queue: Arc::clone(&queue),
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public,
        push_index_secret: PUSH_INDEX,
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
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
                    ipv4_prefix: 24,
                    ipv6_prefix: 48,
                },
                &rand32(),
                None,
                songbird_api::profiles::ProfileMetrics::default(),
            )
            .unwrap(),
        ),
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
    let worker = Worker {
        block_keys: None,
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue,
        delivery: DeliveryLink::Direct(songbird_delivery::internal::handler(shared)),
        push_index_secret: PUSH_INDEX,
        journal: None,
        propagation: Duration::from_millis(200),
        kt: None,
        metrics: WorkerMetrics::default(),
    };
    Some(Stack {
        registry,
        app,
        addr,
        worker,
        s3,
        _stop: stop,
    })
}

/// A registered account (primary with an uploaded identity key) and its API client.
async fn person(s: &Stack) -> (NewAccount, ApiClient) {
    let account_key = Ed25519KeyPair::generate().unwrap();
    let auth = Ed25519KeyPair::generate().unwrap();
    let n = NewAccount {
        account: AccountId::random().unwrap(),
        identity: account_key.public_key().as_ref().try_into().unwrap(),
        device: DeviceId::random().unwrap(),
        auth_key: auth.public_key().as_ref().try_into().unwrap(),
        allowance: 3,
    };
    s.registry.register(&n, None).await.unwrap();
    let c = ApiClient::new(s.addr, API, n.device, auth);
    (n, c)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_is_exported_then_deleted_from_every_prompt_3_store() {
    let Some(s) = Box::pin(stack()).await else {
        return;
    };
    let (n, c) = person(&s).await;
    let r = &s.registry;
    let a = n.account;
    // Something in every store: keys and one-time prekeys, a username and its link, a device
    // list, a PIN, a passkey, a profile and an avatar, a link token, a push registration, the
    // transparency log.
    let mut ik = [4u8; 33];
    ik[0] = 5;
    r.put_keys(
        &n.device,
        &KeysUpdate {
            identity: Some(ik),
            signed: Some(vec![1]),
            last_resort: Some(vec![2]),
            one_time_ec: vec![(1, vec![3]), (2, vec![4])],
            ..KeysUpdate::default()
        },
        10,
    )
    .await
    .unwrap();
    r.set_username(&a, &[0x55; 32]).await.unwrap();
    r.put_username_link(&a, &[0x66; 16], b"link").await.unwrap();
    let job = Job::new(Work::DeleteDevices { account: a }).unwrap();
    let entry = ListEntry {
        device: n.device,
        auth_key: n.auth_key,
        identity: ik,
        primary: true,
    };
    r.put_device_list(&a, 1, &[entry], b"list", &job)
        .await
        .unwrap();
    r.set_pin(&a, Some(&[7; 48])).await.unwrap();
    r.add_passkey(
        &a,
        &StoredPasskey {
            id: vec![8; 32],
            key: vec![2; 33],
            count: 0,
        },
        10,
    )
    .await
    .unwrap();
    let profile = songbird_proto::profile::ProfileUpload {
        profile_version: 1,
        access_key: [9; 16],
        open: false,
        blob: vec![0xAB; 64],
    };
    assert_eq!(
        c.send("PUT", "/v1/profile", Some(&profile.encode()))
            .await
            .unwrap()
            .0,
        204
    );
    let (st, b) = c
        .send("PUT", "/v1/profile/avatar", Some(&[0xCD; 1000]))
        .await
        .unwrap();
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let avatar: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let avatar_id: [u8; 32] = hex::decode(avatar["avatar"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        s.s3.head_object(&songbird_api::profiles::avatar_name(&avatar_id))
            .await
            .unwrap()
            .is_some()
    );
    r.create_link_token(
        &n.device,
        &rand32(),
        &DeviceId::random().unwrap(),
        Duration::from_secs(600),
        6,
    )
    .await
    .unwrap();
    assert_eq!(
        c.send(
            "PUT",
            "/v1/push",
            Some(br#"{"fcm":{"token":"gate-token"}}"#)
        )
        .await
        .unwrap()
        .0,
        204
    );
    // The worker's publish pass (the akd epoch itself is `songbird-akd`'s test).
    for p in r.kt_pending(100).await.unwrap() {
        r.kt_logged(&p).await.unwrap();
    }
    assert!(r.kt_salt(&a).await.unwrap().is_some());

    // The export: everything above, from the primary only.
    let (st, b) = c.send("GET", "/v1/account/export", None).await.unwrap();
    assert_eq!(st, 200);
    let x: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let acc = &x["account"];
    assert_eq!(acc["id"], a.to_hex_unredacted());
    assert_eq!(acc["identity_key"], hex::encode(n.identity));
    assert_eq!(acc["username_hash"], hex::encode([0x55; 32]));
    assert_eq!(acc["device_list"], hex::encode(b"list"));
    assert_eq!(acc["profile"], hex::encode([0xAB; 64]));
    assert_eq!(acc["pin_set"], true);
    assert_eq!(acc["inactivity_months"], 12);
    assert!(acc["transparency_salt"].is_string());
    assert_eq!(
        x["username_links"],
        serde_json::json!([hex::encode([0x66; 16])])
    );
    assert_eq!(x["passkeys"].as_array().unwrap().len(), 1);
    assert_eq!(x["avatars"], serde_json::json!([hex::encode(avatar_id)]));
    let dev = &x["devices"][0];
    assert_eq!(dev["id"], n.device.to_hex_unredacted());
    assert_eq!(dev["identity_key"], hex::encode(ik));
    assert_eq!(dev["one_time_prekeys"]["x25519"], 2);
    assert_eq!(dev["primary"], true);
    assert!(dev["push_registration"].is_string());
    // It never hands out the PIN verifier.
    assert!(!String::from_utf8_lossy(&b).contains(&hex::encode([7u8; 48])));

    // Deletion through api, then the worker's job.
    assert_eq!(c.send("DELETE", "/v1/account", None).await.unwrap().0, 202);
    let mut done = false;
    for _ in 0..100 {
        for d in s.worker.queue.read(Stream::Deletion, 16).await.unwrap() {
            let mine = d.job.work == (Work::DeleteAccount { account: a });
            let outcome = if mine {
                s.worker.handle(d.job.clone()).await
            } else {
                Outcome::Done
            };
            s.worker.queue.finish(&d, outcome).await.unwrap();
            if mine {
                assert_eq!(outcome, Outcome::Done, "deletion verified");
                done = true;
            }
        }
        if done {
            break;
        }
    }
    assert!(done, "deletion job ran");
    // Every store, inspected directly.
    let index = [push_index(&PUSH_INDEX, &n.device)];
    let rem = r.remnants(&a, &[n.device]).await.unwrap();
    assert!(rem.is_empty(), "{rem:?}");
    assert_eq!(
        songbird_accounts::PushStore::beside(r)
            .await
            .unwrap()
            .count(&index)
            .await
            .unwrap(),
        0
    );
    assert!(r.profile(&a).await.unwrap().is_none());
    assert!(r.passkey(&a, &[8; 32]).await.unwrap().is_none());
    assert!(r.avatars_of(&a).await.unwrap().is_empty());
    assert!(
        s.s3.head_object(&songbird_api::profiles::avatar_name(&avatar_id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(r.kt_salt(&a).await.unwrap().is_none());
    let left: Value = r
        .db()
        .query1(
            "RETURN count(SELECT id FROM username WHERE account != NONE);",
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(left, Value::Int(0));
    let _ = &s.app;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inactivity_warns_a_month_and_a_week_before_then_deletes() {
    let Some(s) = Box::pin(stack()).await else {
        return;
    };
    let r = &s.registry;
    let (n, c) = person(&s).await;
    let (busy, busy_c) = person(&s).await;
    // Six months; refused values first.
    let (st, _) = c
        .send("PUT", "/v1/account/inactivity", Some(br#"{"months":7}"#))
        .await
        .unwrap();
    assert_eq!(st, 400);
    assert_eq!(
        c.send("PUT", "/v1/account/inactivity", Some(br#"{"months":6}"#))
            .await
            .unwrap()
            .0,
        204
    );
    let set_seen = |days: i64, a: AccountId| async move {
        r.db()
            .query(
                "UPDATE account:[$a] SET last_seen = time::now() - duration::from_days($d) RETURN NONE;",
                vec![
                    ("a".to_owned(), Value::Bytes(Bytes::copy_from_slice(a.as_bytes()))),
                    ("d".to_owned(), Value::Int(days)),
                ],
            )
            .await
            .unwrap();
    };
    // Which warning an account has been sent (the worker marks it once the wake-up jobs are
    // queued; counting the shared push stream would race the other gate tests).
    let warned = |a: AccountId| async move {
        r.db()
            .query1(
                "RETURN account:[$a].inact_warned ?? 0;",
                vec![(
                    "a".to_owned(),
                    Value::Bytes(Bytes::copy_from_slice(a.as_bytes())),
                )],
            )
            .await
            .unwrap()
    };
    let recent = |a: AccountId| async move {
        r.db()
            .query1(
                "RETURN account:[$a].last_seen > time::now() - 1h;",
                vec![(
                    "a".to_owned(),
                    Value::Bytes(Bytes::copy_from_slice(a.as_bytes())),
                )],
            )
            .await
            .unwrap()
            == Value::Bool(true)
    };
    // A signed request records use (the first of the day).
    set_seen(100, busy.account).await;
    assert!(!recent(busy.account).await);
    assert_eq!(
        busy_c
            .send("PUT", "/v1/account/inactivity", Some(br#"{"months":6}"#))
            .await
            .unwrap()
            .0,
        204
    );
    assert!(recent(busy.account).await, "the request counted as use");
    // 160 and 170 days unused (six months is 180): the month's warning, a wake-up per device.
    set_seen(160, n.account).await;
    set_seen(170, busy.account).await;
    s.worker.inactivity().await;
    assert_eq!(
        (warned(n.account).await, warned(busy.account).await),
        (Value::Int(1), Value::Int(1))
    );
    // The busy account is used again (any signed request, at most once a day counts): its clock
    // and warnings reset. Its daily mark was set by the request above, so clear it first.
    r.touch(&busy.account).await.unwrap();
    assert_eq!(
        busy_c
            .send("GET", "/v1/account/factors", None)
            .await
            .unwrap()
            .0,
        200
    );
    // Not twice for the same stage, and nothing for the busy one.
    s.worker.inactivity().await;
    assert_eq!(
        (warned(n.account).await, warned(busy.account).await),
        (Value::Int(1), Value::Int(0))
    );
    // 175 days: the week's warning, for the idle account only.
    set_seen(175, n.account).await;
    s.worker.inactivity().await;
    assert_eq!(
        (warned(n.account).await, warned(busy.account).await),
        (Value::Int(2), Value::Int(0))
    );
    // 181 days: deletion starts (as if it had asked), the busy one is untouched.
    set_seen(181, n.account).await;
    s.worker.inactivity().await;
    assert!(r.device(&n.device).await.unwrap().unwrap().disabled);
    assert_eq!(s.worker.metrics.inactive_deleted.get(), 1);
    assert!(!r.device(&busy.device).await.unwrap().unwrap().disabled);
    let found = r.inactive(100).await.unwrap();
    assert!(found.expired.is_empty() && found.warn_month.is_empty() && found.warn_week.is_empty());
}
