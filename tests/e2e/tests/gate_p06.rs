//! The Prompt 6 lifecycle gate, live (SurrealDB, `valkey-hot`, `valkey-jobs`, `RustFS`):
//!
//! - a real file encrypted in the attachment format goes up in parallel parts and comes back by
//!   capability, whole and by range, and decrypts chunk by chunk;
//! - each recipient device confirms its fetch, and the last confirmation deletes the object;
//! - an attachment nobody fetched is deleted at 30 days;
//! - multipart uploads whose grant is gone are aborted, and an expired grant's partial object
//!   is removed.
//!
//! Runs when the stack variables are set (as `gate_m5`); `SONGBIRD_REQUIRE_STACK=1` makes a
//! missing one fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::as_conversions,
    clippy::many_single_char_names,
    clippy::manual_assert_eq,
    clippy::large_futures,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::{Db, Registry, push_token};
use songbird_api::client::{ApiClient, unsigned_full};
use songbird_api::config::{AttachmentLimits, MediaBudgets, MediaDownloads};
use songbird_api::media::Media;
use songbird_api::{ApiMetrics, App, object_name};
use songbird_content::attachment::{self, Decryptor, Suite};
use songbird_jobs::{ObjectKey, Outcome, Queue, QueueConfig, Stream};
use songbird_types::{AccountId, DeviceId, Secret};
use songbird_worker::{DeliveryLink, Worker, WorkerMetrics};

const SERVER: &str = "api.test";
const PART: u64 = 5 << 20;

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
    worker: Worker,
    addr: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

async fn stack() -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let jobs = env("SONGBIRD_TEST_VALKEY_JOBS")?;
    let s3 = env("SONGBIRD_TEST_RUSTFS")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("p06_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    // A bucket of its own: the abort sweep lists every upload in progress.
    let mut cfg = songbird_s3::Config::new(
        s3,
        format!(
            "p06-{}",
            &DeviceId::random().unwrap().to_hex_unredacted()[..12]
        ),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap()),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").unwrap()),
    );
    cfg.max_connections = 32;
    let s3 = songbird_s3::Client::new(cfg).unwrap();
    s3.create_bucket().await.unwrap();
    let queue = |name: &'static str| {
        let jobs = jobs.clone();
        async move {
            let q = Queue::connect(
                redis::Client::open(jobs.as_str()).unwrap(),
                &[4; 32],
                QueueConfig::new(name.into()),
            )
            .await
            .unwrap();
            q.ensure_groups(&Stream::ALL).await.unwrap();
            Arc::new(q)
        }
    };
    let hot = songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
        .await
        .unwrap();
    let (_, push_public) = push_token::key_pair(&[0x77; 32]).unwrap();
    let mut secret = [0u8; 32];
    aws_lc_rs::rand::fill(&mut secret).unwrap();
    let app = Arc::new(App {
        requests: None,
        reports: None,
        server_name: SERVER.into(),
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: queue("p06-api").await,
        hot,
        push_public,
        push_index_secret: [9; 32],
        limits: AttachmentLimits {
            part_size: PART,
            ..AttachmentLimits::default()
        },
        // Budgets out of the way: the throttles have tests of their own (`media_live`).
        media: Some(Media::new(
            MediaBudgets {
                grants_per_hour: 100_000,
                grant_burst: 100_000,
                bytes_per_day: 1 << 40,
            },
            MediaDownloads {
                per_hour: 1_000_000,
                burst: 100_000,
                ..MediaDownloads::default()
            },
            &secret,
        )),
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
        profiles: None,
        devices: None,
    });
    let worker = Worker {
        block_keys: None,
        registry,
        s3,
        queue: queue("p06-worker").await,
        // The media lifecycle never reaches delivery.
        delivery: DeliveryLink::Direct(Arc::new(|_| Box::pin(async { Bytes::new() }))),
        push_index_secret: [9; 32],
        journal: None,
        propagation: Duration::from_millis(10),
        kt: None,
        metrics: WorkerMetrics::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(songbird_api::server::serve(
        listener,
        None,
        Arc::clone(&app),
        256,
        rx,
    ));
    Some(Stack {
        app,
        worker,
        addr,
        stop,
    })
}

async fn device(s: &Stack) -> ApiClient {
    let mut seed = [0u8; 32];
    aws_lc_rs::rand::fill(&mut seed).unwrap();
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    let (a, d) = (AccountId::random().unwrap(), DeviceId::random().unwrap());
    s.app.registry.create_account(&a, &[(d, pk)]).await.unwrap();
    ApiClient::new(s.addr, SERVER, d, kp)
}

async fn grant(c: &ApiClient, size: u64, fetches: u32) -> String {
    let body = format!(r#"{{"size":{size},"fetches":{fetches}}}"#);
    let (st, b) = c
        .send("POST", "/v1/attachments", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 201);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["id"].as_str().unwrap().to_owned()
}

async fn get(s: &Stack, path: &str, range: Option<String>) -> (u16, hyper::HeaderMap, Bytes) {
    let h: Vec<(&str, String)> = range.map(|r| ("range", r)).into_iter().collect();
    unsigned_full(s.addr, SERVER, "GET", path, &h)
        .await
        .unwrap()
}

async fn located(s: &Stack, id: &str) -> Option<String> {
    let (st, h, _) = get(s, &format!("/v1/attachments/{id}"), None).await;
    (st == 303).then(|| h["location"].to_str().unwrap().to_owned())
}

async fn confirm(s: &Stack, id: &str) -> u16 {
    unsigned_full(
        s.addr,
        SERVER,
        "POST",
        &format!("/v1/attachments/{id}/fetched"),
        &[],
    )
    .await
    .unwrap()
    .0
}

/// Runs the worker over every queued cleanup job.
async fn drain(s: &Stack) {
    for _ in 0..50 {
        let jobs = s.worker.queue.read(Stream::Cleanup, 64).await.unwrap();
        if jobs.is_empty() {
            return;
        }
        for d in jobs {
            let out = s.worker.handle(d.job.clone()).await;
            assert!(matches!(out, Outcome::Done), "{out:?}");
            s.worker.queue.finish(&d, out).await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_encrypted_file_goes_up_in_parts_comes_back_by_range_and_goes_after_the_last_fetch() {
    let Some(s) = stack().await else { return };
    let up = Arc::new(device(&s).await);
    // 11 MiB of "video", encrypted on the device.
    let plain: Vec<u8> = (0..(11u64 << 20))
        .map(|i| u8::try_from(i * 7 % 253).unwrap())
        .collect();
    let (key, salt) = attachment::fresh().unwrap();
    let mut ct = Vec::new();
    let digest = attachment::encrypt(
        Suite::DEFAULT,
        &key,
        &salt,
        plain.len() as u64,
        &mut &plain[..],
        &mut ct,
    )
    .unwrap();
    let ct = Bytes::from(ct);
    let size = ct.len() as u64;
    // Two recipient devices.
    let id = grant(&up, size, 2).await;
    let parts = size.div_ceil(PART);
    let mut tasks = Vec::new();
    for n in 1..=parts {
        let (path, body) = (
            format!("/v1/attachments/{id}/parts/{n}"),
            ct.slice(
                usize::try_from((n - 1) * PART).unwrap()
                    ..usize::try_from((n * PART).min(size)).unwrap(),
            ),
        );
        let up = Arc::clone(&up);
        tasks.push(tokio::spawn(async move {
            let len = body.len().to_string();
            up.upload_with("PUT", &path, &[("content-length", len)], body)
                .await
                .unwrap()
                .0
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 204);
    }
    assert_eq!(
        up.send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        201
    );
    // A player seeks to 6 MiB: it fetches the header once and the chunk holding that byte.
    let url = located(&s, &id).await.unwrap();
    let (st, _, header) = get(&s, &url, Some("bytes=0-32".into())).await;
    assert_eq!(st, 206);
    let dec = Decryptor::new(&key[..], &digest, plain.len() as u64, &header).unwrap();
    let at = 6u64 << 20;
    let (first, last) = dec.chunks_for(at, at + 1).unwrap();
    assert_eq!(first, last);
    let (a, b) = dec.chunk_range(first).unwrap();
    let (st, _, chunk) = get(&s, &url, Some(format!("bytes={a}-{}", b - 1))).await;
    assert_eq!(st, 206);
    let mut chunk = chunk.to_vec();
    let opened = dec.open_chunk(first, &mut chunk).unwrap();
    let off = usize::try_from(first * songbird_proto::media::CHUNK).unwrap();
    assert_eq!(opened, &plain[off..off + opened.len()]);
    // Each device downloads the whole file and decrypts it.
    for left in [1u32, 0] {
        let url = located(&s, &id).await.unwrap();
        let (st, _, got) = get(&s, &url, None).await;
        assert_eq!(st, 200);
        let mut out = Vec::new();
        attachment::decrypt(
            &key[..],
            &digest,
            plain.len() as u64,
            &mut &got[..],
            &mut out,
        )
        .unwrap();
        assert!(out == plain);
        assert_eq!(confirm(&s, &id).await, 204);
        let rec = s
            .app
            .registry
            .attachment(&ObjectKey::parse_hex(&id).unwrap())
            .await
            .unwrap();
        assert_eq!(rec.map_or(0, |r| r.left), left);
    }
    // The last confirmation queued the deletion; the worker runs it; the object is gone.
    drain(&s).await;
    let object = ObjectKey::parse_hex(&id).unwrap();
    assert!(
        s.app
            .s3
            .head_object(&object_name(&object))
            .await
            .unwrap()
            .is_none()
    );
    assert!(located(&s, &id).await.is_none());
    let (st, _, _) = get(&s, &url, None).await;
    assert_eq!(st, 404, "a signed URL outliving its object serves nothing");
    let _ = s.stop.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachments_nobody_fetches_go_at_30_days_and_abandoned_uploads_are_aborted() {
    let Some(s) = stack().await else { return };
    let up = device(&s).await;
    let body = Bytes::from(vec![
        9u8;
        usize::try_from(
            songbird_proto::media::ciphertext_len(5_000).unwrap()
        )
        .unwrap()
    ]);
    let id = grant(&up, body.len() as u64, 3).await;
    assert_eq!(
        up.upload(&format!("/v1/attachments/{id}"), body.clone())
            .await
            .unwrap()
            .0,
        201
    );
    let object = ObjectKey::parse_hex(&id).unwrap();
    // One fetch of three confirmed; then 30 days pass (the record is aged in place).
    assert_eq!(confirm(&s, &id).await, 204);
    s.worker.sweep().await;
    assert!(
        s.app
            .s3
            .head_object(&object_name(&object))
            .await
            .unwrap()
            .is_some()
    );
    s.app
        .registry
        .db()
        .exec(
            "UPDATE attachment:[$o] SET expires = time::now() - 1s RETURN NONE;",
            vec![(
                "o".into(),
                songbird_surreal::cbor::Value::Bytes(Bytes::copy_from_slice(&object.0)),
            )],
        )
        .await
        .unwrap();
    assert!(located(&s, &id).await.is_none(), "expired: no URL");
    s.worker.sweep().await;
    assert!(
        s.app
            .s3
            .head_object(&object_name(&object))
            .await
            .unwrap()
            .is_none()
    );
    assert!(s.app.registry.attachment(&object).await.unwrap().is_none());

    // A resumable upload abandoned after one part: its grant expires; the sweep aborts the
    // upload and removes the grant.
    let size = songbird_proto::media::ciphertext_len(12 << 20).unwrap();
    let gone = grant(&up, size, 1).await;
    let part = Bytes::from(vec![1u8; usize::try_from(PART).unwrap()]);
    let (st, _, _) = up
        .upload_with(
            "PUT",
            &format!("/v1/attachments/{gone}/parts/1"),
            &[("content-length", PART.to_string())],
            part,
        )
        .await
        .unwrap();
    assert_eq!(st, 204);
    let gone_key = ObjectKey::parse_hex(&gone).unwrap();
    let in_progress = |name: String| {
        let s3 = s.app.s3.clone();
        async move {
            s3.list_multipart_uploads("a/")
                .await
                .unwrap()
                .iter()
                .any(|u| u.key == name)
        }
    };
    assert!(in_progress(object_name(&gone_key)).await);
    // A live grant's upload is kept.
    s.worker.abort_abandoned_uploads().await;
    assert!(in_progress(object_name(&gone_key)).await);
    s.app
        .registry
        .db()
        .exec(
            "UPDATE upload_grant:[$o] SET expires = time::now() - 1s RETURN NONE;",
            vec![(
                "o".into(),
                songbird_surreal::cbor::Value::Bytes(Bytes::copy_from_slice(&gone_key.0)),
            )],
        )
        .await
        .unwrap();
    s.worker.sweep().await;
    assert!(!in_progress(object_name(&gone_key)).await, "aborted");
    assert!(s.app.registry.grant(&gone_key).await.unwrap().is_none());
    let (st, _, _) = up
        .upload_with(
            "PUT",
            &format!("/v1/attachments/{gone}/parts/2"),
            &[("content-length", "0".into())],
            Bytes::new(),
        )
        .await
        .unwrap();
    assert_eq!(st, 404);
    let _ = s.stop.send(true);
}

fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i.min(v.len() - 1)]
}

/// The M3 measurement (D-0082): latency, throughput and concurrency of uploads, downloads and
/// range requests through `api`, and the same downloads straight from `RustFS` (what a caching
/// proxy could at best save). Release build, live stack:
/// `cargo test --release -p songbird-e2e --test gate_p06 media_load -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "a benchmark: run in release by hand"]
#[allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a benchmark"
)]
async fn media_load() {
    let Some(s) = stack().await else { return };
    let s = Arc::new(s);
    let size = songbird_proto::media::ciphertext_len(1 << 20).unwrap();
    let body = Bytes::from(vec![0x5au8; usize::try_from(size).unwrap()]);
    // Where an upload's time goes, one at a time.
    {
        let c = device(&s).await;
        let (mut g, mut p, mut d) = (Vec::new(), Vec::new(), Vec::new());
        for i in 0..32u32 {
            let t = std::time::Instant::now();
            let id = grant(&c, size, 1).await;
            g.push(t.elapsed());
            let t = std::time::Instant::now();
            let (st, _) = c
                .upload(&format!("/v1/attachments/{id}"), body.clone())
                .await
                .unwrap();
            assert_eq!(st, 201);
            p.push(t.elapsed());
            let t = std::time::Instant::now();
            s.app
                .s3
                .put_object_bytes(&format!("bench/{i}"), body.clone())
                .await
                .unwrap();
            d.push(t.elapsed());
        }
        println!(
            "1 MiB upload, one at a time: grant {:?}; PUT through api {:?}; PUT straight to RustFS {:?} (p50)",
            pct(&mut g, 0.5),
            pct(&mut p, 0.5),
            pct(&mut d, 0.5)
        );
    }
    println!("1 MiB attachments; latency p50 / p99; throughput is the aggregate");
    for conc in [1usize, 16, 64] {
        let per = (512 / conc).max(8);
        let started = std::time::Instant::now();
        let mut clients = Vec::new();
        for _ in 0..conc {
            clients.push(device(&s).await);
        }
        let mut tasks = Vec::new();
        for c in clients {
            let (s, body) = (Arc::clone(&s), body.clone());
            tasks.push(tokio::spawn(async move {
                let (mut up, mut down, mut ids) = (Vec::new(), Vec::new(), Vec::new());
                for _ in 0..per {
                    let t = std::time::Instant::now();
                    let id = grant(&c, size, 1).await;
                    let (st, _) = c
                        .upload(&format!("/v1/attachments/{id}"), body.clone())
                        .await
                        .unwrap();
                    assert_eq!(st, 201);
                    up.push(t.elapsed());
                    ids.push(id);
                }
                for id in &ids {
                    let t = std::time::Instant::now();
                    let url = located(&s, id).await.unwrap();
                    let (st, _, got) = get(&s, &url, None).await;
                    assert_eq!((st, got.len() as u64), (200, size));
                    down.push(t.elapsed());
                }
                (up, down)
            }));
        }
        let (mut up, mut down) = (Vec::new(), Vec::new());
        for t in tasks {
            let (u, d) = t.await.unwrap();
            up.extend(u);
            down.extend(d);
        }
        let total = started.elapsed().as_secs_f64();
        let mb = (up.len() as f64) * size as f64 / 1e6;
        println!(
            "  concurrency {conc:>2}: upload (grant + PUT) {:?} / {:?}; download (redirect + GET) {:?} / {:?}; {:.0} MB/s each way over {} files",
            pct(&mut up, 0.5),
            pct(&mut up, 0.99),
            pct(&mut down, 0.5),
            pct(&mut down, 0.99),
            2.0 * mb / total,
            up.len()
        );
    }
    // Straight from the store, 16 at a time: the floor any proxy in front of RustFS could reach.
    let object = {
        let c = device(&s).await;
        let id = grant(&c, size, 1).await;
        c.upload(&format!("/v1/attachments/{id}"), body.clone())
            .await
            .unwrap();
        ObjectKey::parse_hex(&id).unwrap()
    };
    let mut direct = Vec::new();
    let mut via = Vec::new();
    let url = located(&s, &object.to_hex_unredacted()).await.unwrap();
    for _ in 0..8 {
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let s3 = s.app.s3.clone();
            tasks.push(tokio::spawn(async move {
                let t = std::time::Instant::now();
                let g = s3.get_object(&object_name(&object), None).await.unwrap();
                let mut b = g.body;
                while let Some(x) = futures_util::StreamExt::next(&mut b).await {
                    x.unwrap();
                }
                t.elapsed()
            }));
            let (s2, url) = (Arc::clone(&s), url.clone());
            tasks.push(tokio::spawn(async move {
                let t = std::time::Instant::now();
                let (st, _, _) = get(&s2, &url, None).await;
                assert_eq!(st, 200);
                t.elapsed()
            }));
        }
        for (i, t) in tasks.into_iter().enumerate() {
            let d = t.await.unwrap();
            if i % 2 == 0 {
                direct.push(d);
            } else {
                via.push(d);
            }
        }
    }
    println!(
        "  1 MiB GET at 32 in flight: RustFS directly {:?} / {:?}; through api (signed URL) {:?} / {:?}",
        pct(&mut direct, 0.5),
        pct(&mut direct, 0.99),
        pct(&mut via, 0.5),
        pct(&mut via, 0.99)
    );
    // Seeking in a 64 MiB video: 128 KiB ranges at random offsets, 8 at a time.
    let big = songbird_proto::media::ciphertext_len(64 << 20).unwrap();
    let c = device(&s).await;
    let id = grant(&c, big, 1).await;
    let bytes = Bytes::from(vec![1u8; usize::try_from(big).unwrap()]);
    let t = std::time::Instant::now();
    let parts = big.div_ceil(PART);
    let c = Arc::new(c);
    let mut tasks = Vec::new();
    for n in 1..=parts {
        let (c, path, b) = (
            Arc::clone(&c),
            format!("/v1/attachments/{id}/parts/{n}"),
            bytes.slice(
                usize::try_from((n - 1) * PART).unwrap()
                    ..usize::try_from((n * PART).min(big)).unwrap(),
            ),
        );
        tasks.push(tokio::spawn(async move {
            let len = b.len().to_string();
            c.upload_with("PUT", &path, &[("content-length", len)], b)
                .await
                .unwrap()
                .0
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 204);
    }
    assert_eq!(
        c.send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        201
    );
    let up_rate = big as f64 / t.elapsed().as_secs_f64() / 1e6;
    let url = located(&s, &id).await.unwrap();
    let t = std::time::Instant::now();
    let (st, _, got) = get(&s, &url, None).await;
    assert_eq!((st, got.len() as u64), (200, big));
    let down_rate = big as f64 / t.elapsed().as_secs_f64() / 1e6;
    let mut seeks = Vec::new();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..16 {
        let mut tasks = Vec::new();
        for _ in 0..8 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let a = rng % (big - (128 << 10));
            let (s, url) = (Arc::clone(&s), url.clone());
            tasks.push(tokio::spawn(async move {
                let t = std::time::Instant::now();
                let (st, _, b) =
                    get(&s, &url, Some(format!("bytes={a}-{}", a + (128 << 10) - 1))).await;
                assert_eq!((st, b.len()), (206, 128 << 10));
                t.elapsed()
            }));
        }
        for t in tasks {
            seeks.push(t.await.unwrap());
        }
    }
    println!(
        "64 MiB: upload in parallel parts {up_rate:.0} MB/s; download {down_rate:.0} MB/s; 128 KiB range at 8 in flight {:?} / {:?}",
        pct(&mut seeks, 0.5),
        pct(&mut seeks, 0.99)
    );
    let _ = s.stop.send(true);
}
