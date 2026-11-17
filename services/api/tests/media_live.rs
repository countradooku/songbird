//! Prompt 6 uploads against the real stores (SurrealDB, `valkey-hot`, `valkey-jobs`, `RustFS`):
//! grants held to the attachment format and the budgets, resumable uploads in parts,
//! resumed after interruptions, and never reusable or enlargeable. Runs when the `api_live`
//! variables are set.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::single_match_else,
    clippy::as_conversions,
    clippy::many_single_char_names,
    clippy::manual_assert_eq,
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
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{Queue, QueueConfig, Stream};
use songbird_proto::media::ciphertext_len;
use songbird_types::{AccountId, DeviceId, Secret};

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
    addr: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

async fn stack(budgets: MediaBudgets) -> Option<Stack> {
    stack_with(budgets, MediaDownloads::default(), PART).await
}

async fn stack_with(
    budgets: MediaBudgets,
    downloads: MediaDownloads,
    part_size: u64,
) -> Option<Stack> {
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
        database: format!("media_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    let mut cfg = songbird_s3::Config::new(
        s3,
        "songbird-media-test".into(),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap()),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").unwrap()),
    );
    cfg.max_connections = 32;
    let s3 = songbird_s3::Client::new(cfg).unwrap();
    s3.create_bucket().await.unwrap();
    let queue = Queue::connect(
        redis::Client::open(jobs).unwrap(),
        &[3; 32],
        QueueConfig::new("media-test".into()),
    )
    .await
    .unwrap();
    queue.ensure_groups(&Stream::ALL).await.unwrap();
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
        registry,
        s3,
        queue: Arc::new(queue),
        hot,
        push_public,
        push_index_secret: [9; 32],
        limits: AttachmentLimits {
            part_size,
            ..AttachmentLimits::default()
        },
        media: Some(Media::new(budgets, downloads, &secret)),
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
        profiles: None,
        devices: None,
    });
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
    Some(Stack { app, addr, stop })
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

fn data(len: u64) -> Bytes {
    (0..len)
        .map(|i| u8::try_from(i * 131 % 251).unwrap())
        .collect::<Vec<u8>>()
        .into()
}

async fn grant(c: &ApiClient, size: u64, fetches: u32) -> (u16, Option<String>) {
    let body = format!(r#"{{"size":{size},"fetches":{fetches}}}"#);
    let (st, b) = c
        .send("POST", "/v1/attachments", Some(body.as_bytes()))
        .await
        .unwrap();
    let id = (st == 201).then(|| {
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["part_size"].as_u64().is_some_and(|p| p >= PART));
        v["id"].as_str().unwrap().to_owned()
    });
    (st, id)
}

async fn parts_of(c: &ApiClient, id: &str) -> Vec<u64> {
    let (st, b) = c
        .send("GET", &format!("/v1/attachments/{id}/parts"), None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["parts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap())
        .collect()
}

/// Status 0: the server dropped the connection mid-body (a refused part it stopped reading,
/// as when two copies of a part race).
async fn put_part(c: &ApiClient, id: &str, n: u64, body: Bytes) -> u16 {
    let path = format!("/v1/attachments/{id}/parts/{n}");
    let len = body.len().to_string();
    c.upload_with("PUT", &path, &[("content-length", len)], body)
        .await
        .map_or(0, |r| r.0)
}

/// The signed media URL for an attachment, by capability (no signature).
async fn locate(s: &Stack, id: &str) -> (u16, Option<String>) {
    let (st, h, _) = unsigned_full(s.addr, SERVER, "GET", &format!("/v1/attachments/{id}"), &[])
        .await
        .unwrap();
    (
        st,
        h.get("location").map(|v| v.to_str().unwrap().to_owned()),
    )
}

async fn fetch(s: &Stack, url: &str, range: Option<&str>) -> (u16, hyper::HeaderMap, Bytes) {
    let headers: Vec<(&str, String)> = range.map(|r| ("range", r.to_owned())).into_iter().collect();
    unsigned_full(s.addr, SERVER, "GET", url, &headers)
        .await
        .unwrap()
}

async fn download(s: &Stack, id: &str) -> Bytes {
    let (st, url) = locate(s, id).await;
    assert_eq!(st, 303);
    let (st, _, b) = fetch(s, &url.unwrap(), None).await;
    assert_eq!(st, 200);
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grants_hold_the_format_and_the_budgets() {
    let Some(s) = stack(MediaBudgets {
        grants_per_hour: 3_600,
        grant_burst: 3,
        bytes_per_day: 64 << 20,
    })
    .await
    else {
        return;
    };
    let c = device(&s).await;
    // Only lengths the attachment format produces: an uploader cannot pick an exact size.
    let legal = ciphertext_len(10_000).unwrap();
    for bad in [legal + 1, legal - 1, 4_096, 0] {
        assert_eq!(grant(&c, bad, 1).await.0, 400, "{bad}");
    }
    // The grant budget: a burst of three, then a wait.
    for _ in 0..3 {
        assert_eq!(grant(&c, legal, 1).await.0, 201);
    }
    let body = format!(r#"{{"size":{legal},"fetches":1}}"#);
    let (st, _) = c
        .send("POST", "/v1/attachments", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 429);
    // The byte budget is the account's, apart from the grant count: another account has its own,
    // and a grant bigger than what is left of the day waits.
    let d = device(&s).await;
    let big = ciphertext_len(40 << 20).unwrap();
    assert_eq!(grant(&d, big, 1).await.0, 201);
    assert_eq!(grant(&d, big, 1).await.0, 429);
    let _ = s.stop.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumable_parts_survive_interruptions_and_complete_exactly() {
    let Some(s) = stack(MediaBudgets::default()).await else {
        return;
    };
    let up = device(&s).await;
    let other = device(&s).await;
    let size = ciphertext_len(12 << 20).unwrap(); // three parts of 5 MiB, the last shorter
    let all = data(size);
    let (_, id) = grant(&up, size, 1).await;
    let id = id.unwrap();
    let part = |n: u64| {
        let start = usize::try_from((n - 1) * PART).unwrap();
        let end = usize::try_from((n * PART).min(size)).unwrap();
        all.slice(start..end)
    };
    assert!(parts_of(&up, &id).await.is_empty());
    // Only the granted device; only the exact length of each part; no part past the last.
    assert_eq!(put_part(&other, &id, 1, Bytes::new()).await, 404);
    assert_eq!(put_part(&up, &id, 1, Bytes::new()).await, 400);
    assert_eq!(put_part(&up, &id, 4, Bytes::new()).await, 404);
    // Part 3 first, part 1 in parallel with a second copy of itself (both first parts race to
    // open the upload: one is kept, the other aborted).
    assert_eq!(put_part(&up, &id, 3, part(3)).await, 204);
    let (a, b) = tokio::join!(
        put_part(&up, &id, 1, part(1)),
        put_part(&up, &id, 1, part(1))
    );
    assert!(a == 204 || b == 204, "{a} {b}");
    // Completing too early: 409, nothing assembled.
    assert_eq!(
        up.send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        409
    );
    // The resuming client asks what is there, and sends only what is missing.
    let got = parts_of(&up, &id).await;
    assert!(
        got.contains(&1) && got.contains(&3) && !got.contains(&2),
        "{got:?}"
    );
    assert_eq!(put_part(&up, &id, 2, part(2)).await, 204);
    assert_eq!(parts_of(&up, &id).await, vec![1, 2, 3]);
    assert_eq!(
        other
            .send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        404
    );
    assert_eq!(
        up.send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        201
    );
    // Used: nothing more can be sent, listed or completed.
    assert_eq!(put_part(&up, &id, 1, Bytes::new()).await, 404);
    assert_eq!(
        up.send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        404
    );
    assert!(download(&s, &id).await == all, "assembled bytes differ");
    let _ = s.stop.send(true);
}

fn bench_part() -> u64 {
    std::env::var("SONGBIRD_BENCH_PART_MIB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(PART, |m| m << 20)
}

/// The resumable-upload measurement behind D-0081: one 256 MiB attachment uploaded as a single
/// `PUT`, as parts one at a time and as parts four at a time. Release build, live stack (tus 1.0
/// was measured too and removed, D-0081; `SONGBIRD_BENCH_PART_MIB` sets the part size):
/// `cargo test --release -p songbird-api --test media_live upload_protocols -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a benchmark: run in release by hand"]
#[allow(
    clippy::print_stderr,
    clippy::cast_precision_loss,
    reason = "a benchmark"
)]
async fn upload_protocols() {
    let Some(s) = stack_with(
        MediaBudgets {
            grants_per_hour: 100_000,
            grant_burst: 10_000,
            bytes_per_day: 1 << 40,
        },
        MediaDownloads::default(),
        bench_part(),
    )
    .await
    else {
        return;
    };
    let part = bench_part();
    let c = Arc::new(device(&s).await);
    let size = ciphertext_len(256 << 20).unwrap();
    let all = data(size);
    let n_parts = size.div_ceil(part);
    eprintln!(
        "protocol                     MB/s (median of 5, 256 MiB, part {} MiB)",
        part >> 20
    );
    for mode in ["single PUT", "parts x1", "parts x4"] {
        let mut rates = Vec::new();
        for _ in 0..5 {
            let (_, id) = grant(&c, size, 1).await;
            let id = id.unwrap();
            let t = std::time::Instant::now();
            match mode {
                "single PUT" => {
                    let (st, _) = c
                        .upload(&format!("/v1/attachments/{id}"), all.clone())
                        .await
                        .unwrap();
                    assert_eq!(st, 201);
                }
                _ => {
                    let width = if mode == "parts x1" { 1 } else { 4 };
                    let next = Arc::new(std::sync::atomic::AtomicU64::new(1));
                    let mut tasks = Vec::new();
                    for _ in 0..width {
                        let (c, id, next, all) =
                            (Arc::clone(&c), id.clone(), Arc::clone(&next), all.clone());
                        tasks.push(tokio::spawn(async move {
                            loop {
                                let n = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if n > n_parts {
                                    break;
                                }
                                let body = all.slice(
                                    usize::try_from((n - 1) * part).unwrap()
                                        ..usize::try_from((n * part).min(size)).unwrap(),
                                );
                                assert_eq!(put_part(&c, &id, n, body).await, 204);
                            }
                        }));
                    }
                    for t in tasks {
                        t.await.unwrap();
                    }
                    let (st, _) = c
                        .send("POST", &format!("/v1/attachments/{id}/complete"), None)
                        .await
                        .unwrap();
                    assert_eq!(st, 201);
                }
            }
            rates.push(size as f64 / t.elapsed().as_secs_f64() / 1e6);
        }
        rates.sort_by(f64::total_cmp);
        eprintln!(
            "{mode:<28} {:>6.0}   (min {:.0}, max {:.0})",
            rates[2], rates[0], rates[4]
        );
    }
    let _ = s.stop.send(true);
}

async fn upload_whole(c: &ApiClient, body: &Bytes, fetches: u32) -> String {
    let (st, id) = grant(c, body.len() as u64, fetches).await;
    assert_eq!(st, 201);
    let id = id.unwrap();
    assert_eq!(
        c.upload(&format!("/v1/attachments/{id}"), body.clone())
            .await
            .unwrap()
            .0,
        201
    );
    id
}

/// Downloads (Prompt 6, M3, D-0082): by capability with no account, through a short-lived signed
/// URL that serves byte ranges; a tampered, expired or misdirected URL serves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_need_no_account_and_serve_ranges() {
    let Some(s) = stack(MediaBudgets::default()).await else {
        return;
    };
    let up = device(&s).await;
    let size = ciphertext_len(300_000).unwrap();
    let all = data(size);
    let id = upload_whole(&up, &all, 3).await;
    let (st, url) = locate(&s, &id).await;
    assert_eq!(st, 303);
    let url = url.unwrap();
    assert!(url.starts_with(&format!("/v1/media/{id}?e=")));
    let (st, h, b) = fetch(&s, &url, None).await;
    assert_eq!(st, 200);
    assert_eq!(h["accept-ranges"], "bytes");
    assert!(
        h["cache-control"]
            .to_str()
            .unwrap()
            .starts_with("private, max-age=")
    );
    assert!(b == all);
    let z = |a: u64, b: u64| all.slice(usize::try_from(a).unwrap()..=usize::try_from(b).unwrap());
    // Ranges: first bytes, a chunk in the middle, a suffix, an open end, past the end.
    let chunk = songbird_proto::media::chunk_offset(2);
    for (ask, a, b) in [
        ("bytes=0-32".to_owned(), 0, 32),
        (
            format!("bytes={chunk}-{}", chunk + 65_551),
            chunk,
            chunk + 65_551,
        ),
        ("bytes=-50".to_owned(), size - 50, size - 1),
        (format!("bytes={}-", size - 7), size - 7, size - 1),
        (format!("bytes=10-{}", size + 1_000), 10, size - 1),
    ] {
        let (st, h, body) = fetch(&s, &url, Some(&ask)).await;
        assert_eq!(st, 206, "{ask}");
        assert_eq!(
            h["content-range"].to_str().unwrap(),
            format!("bytes {a}-{b}/{size}")
        );
        assert!(body == z(a, b), "{ask}");
    }
    let (st, h, _) = fetch(&s, &url, Some(&format!("bytes={size}-"))).await;
    assert_eq!(
        (st, h["content-range"].to_str().unwrap()),
        (416, format!("bytes */{size}").as_str())
    );
    // Several ranges, or nonsense: the whole object.
    for ask in ["bytes=0-1,5-6", "bytes=9-3", "items=0-1"] {
        assert_eq!(fetch(&s, &url, Some(ask)).await.0, 200, "{ask}");
    }
    // Tampered: another expiry, another size, another MAC, another object; expired.
    let (path, query) = url.split_once('?').unwrap();
    let mut parts: Vec<String> = query.split('&').map(str::to_owned).collect();
    let e: u64 = parts[0][2..].parse().unwrap();
    for (i, v) in [(0, format!("e={}", e + 1)), (1, format!("z={}", size + 1))] {
        let mut p = parts.clone();
        p[i] = v;
        assert_eq!(
            fetch(&s, &format!("{path}?{}", p.join("&")), None).await.0,
            403
        );
    }
    let mac = parts[2].clone();
    parts[2] = format!(
        "s={}{}",
        if mac.as_bytes()[2] == b'0' { '1' } else { '0' },
        &mac[3..]
    );
    assert_eq!(
        fetch(&s, &format!("{path}?{}", parts.join("&")), None)
            .await
            .0,
        403
    );
    let other = upload_whole(&up, &all, 1).await;
    assert_eq!(fetch(&s, &url.replace(&id, &other), None).await.0, 403);
    let m = s.app.media.as_ref().unwrap();
    let object = songbird_jobs::ObjectKey::parse_hex(&id).unwrap();
    let expired = m.media_url(&object, size, e - 10_000);
    assert_eq!(fetch(&s, &expired, None).await.0, 403);
    // Too far in the future is refused too (a URL cannot be made to last).
    let forever = m.media_url(&object, size, e + 86_400);
    assert_eq!(fetch(&s, &forever, None).await.0, 403);
    for bad in ["?e=1&z=2", "?s=00&e=1&z=1", "", "?e=1&z=1&s=zz"] {
        assert_eq!(
            fetch(&s, &format!("{path}{bad}"), None).await.0,
            404,
            "{bad}"
        );
    }
    // Unknown IDs and malformed ones look the same.
    assert_eq!(locate(&s, &"ab".repeat(32)).await.0, 404);
    assert_eq!(locate(&s, "zz").await.0, 404);
    let _ = s.stop.send(true);
}

/// The lifecycle's server side (Prompt 6, M3, D-0082): each device confirms its fetch; the last
/// confirmation removes the record and queues the object's deletion. Redirects and confirmations
/// are throttled per IP range.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetches_are_confirmed_and_the_last_one_deletes() {
    let Some(s) = stack_with(
        MediaBudgets::default(),
        MediaDownloads {
            burst: 6,
            per_hour: 60,
            ..MediaDownloads::default()
        },
        PART,
    )
    .await
    else {
        return;
    };
    let up = device(&s).await;
    let all = data(ciphertext_len(2_000).unwrap());
    let id = upload_whole(&up, &all, 2).await;
    let depth = s.app.queue.depth(Stream::Cleanup).await.unwrap();
    let confirm = || async {
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
    };
    // Downloading does not count; confirming does.
    let _ = download(&s, &id).await;
    let _ = download(&s, &id).await;
    assert_eq!(confirm().await, 204);
    assert_eq!(locate(&s, &id).await.0, 303);
    assert_eq!(confirm().await, 204);
    // Gone: no URL, no more confirmations, and the object's deletion is queued.
    assert_eq!(locate(&s, &id).await.0, 404);
    assert_eq!(confirm().await, 404);
    assert!(s.app.queue.depth(Stream::Cleanup).await.unwrap() > depth);
    // The IP range's redirect budget (a burst of six; four spent above) runs out, with a wait.
    let mut throttled = None;
    for i in 0..10 {
        let (st, h, _) =
            unsigned_full(s.addr, SERVER, "GET", &format!("/v1/attachments/{id}"), &[])
                .await
                .unwrap();
        if st == 429 {
            assert!(h.contains_key("retry-after"));
            throttled = Some(i);
            break;
        }
    }
    assert!(throttled.is_some_and(|i| i <= 3), "{throttled:?}");
    let _ = s.stop.send(true);
}
