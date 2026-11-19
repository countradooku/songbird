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
    clippy::needless_range_loop,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::{Db, Registry, push_token};
use songbird_api::client::{ApiClient, unsigned_from, unsigned_full};
use songbird_api::config::{AttachmentLimits, GifSettings, MediaBudgets, MediaDownloads};
use songbird_api::gifs::{Gifs, Giphy};
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
    stack_full(budgets, downloads, part_size, None).await
}

async fn stack_full(
    budgets: MediaBudgets,
    downloads: MediaDownloads,
    part_size: u64,
    gifs: Option<GifSettings>,
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
        plans: songbird_api::plans::Plans::default(),
        requests: None,
        reports: None,
        support: None,
        calls: None,
        server_name: SERVER.into(),
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
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
        media: Some({
            let m = Media::new(budgets, downloads, &secret);
            match gifs {
                Some(g) => m.with_gifs(
                    Gifs::new(
                        g,
                        Box::new(Giphy::new("test-key".into(), "pg-13".into())),
                        &secret,
                    )
                    .unwrap(),
                ),
                None => m,
            }
        }),
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        storage: None,
        vault: None,
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
    // Each recipient device confirms from its own address (127.0.0.1, 127.0.0.2, ...).
    let confirm = |source: u8| {
        let path = format!("/v1/attachments/{id}/fetched");
        let s = &s;
        async move {
            unsigned_from(s.addr, [127, 0, 0, source].into(), SERVER, "POST", &path)
                .await
                .unwrap()
                .0
        }
    };
    // Downloading does not count; confirming does, once per source (D-0084).
    let _ = download(&s, &id).await;
    let _ = download(&s, &id).await;
    assert_eq!(confirm(1).await, 204);
    assert_eq!(confirm(1).await, 204, "accepted, but counted once");
    assert_eq!(confirm(1).await, 204);
    assert_eq!(
        locate(&s, &id).await.0,
        303,
        "one recipient alone cannot delete it"
    );
    assert_eq!(confirm(2).await, 204);
    // Gone: no URL, no more confirmations, and the object's deletion is queued.
    assert_eq!(locate(&s, &id).await.0, 404);
    assert_eq!(confirm(3).await, 404);
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

/// Packs (Prompt 6, M4, D-0083): created by a device and charged to its account; uploaded object
/// by object at exact sizes; complete only when every object is stored, after which they are
/// fetched with no account and the pack forgets its creator; deleted only with the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packs_are_created_fetched_anonymously_and_deleted_by_token() {
    let Some(s) = stack(MediaBudgets::default()).await else {
        return;
    };
    let creator = device(&s).await;
    let other = device(&s).await;
    let token = [0x2au8; 32];
    let token_hash = hex::encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        &token,
    ));
    let sizes: Vec<u64> = [500u64, 20_000, 70_000]
        .iter()
        .map(|n| ciphertext_len(*n).unwrap())
        .collect();
    let body = format!(
        r#"{{"sizes":[{}],"token":"{token_hash}"}}"#,
        sizes
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    let (st, b) = creator
        .send("POST", "/v1/packs", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 201);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let pack = v["pack"].as_str().unwrap().to_owned();
    assert_eq!(v["objects"].as_u64(), Some(3));
    let objects: Vec<Bytes> = sizes.iter().map(|z| data(*z)).collect();
    // Only the creating device; only exact sizes; not before it exists anywhere.
    assert_eq!(pack_put(&other, &pack, 0, Bytes::new()).await, 404);
    assert_eq!(pack_put(&creator, &pack, 0, Bytes::new()).await, 400);
    assert_eq!(pack_put(&creator, &pack, 3, Bytes::new()).await, 404);
    assert_eq!(pack_put(&creator, &pack, 0, objects[0].clone()).await, 201);
    assert_eq!(pack_put(&creator, &pack, 1, objects[1].clone()).await, 201);
    // Not fetchable, and not completable, while an object is missing.
    let fetch_pack = |n: usize| {
        let path = format!("/v1/packs/{pack}/{n}");
        let s = &s;
        async move {
            unsigned_full(s.addr, SERVER, "GET", &path, &[])
                .await
                .unwrap()
        }
    };
    assert_eq!(fetch_pack(0).await.0, 404);
    assert_eq!(pack_complete(&creator, &pack).await, 409);
    assert_eq!(pack_put(&creator, &pack, 2, objects[2].clone()).await, 201);
    // Rewrites are counted: three objects allow 2 × 3 + 8 = 14 writes, three spent so far.
    let mut codes = Vec::new();
    for _ in 0..12 {
        codes.push(pack_put(&creator, &pack, 0, objects[0].clone()).await);
    }
    assert_eq!(&codes[..11], &[201; 11]);
    assert_eq!(codes[11], 409);
    assert_eq!(pack_complete(&other, &pack).await, 404);
    assert_eq!(pack_complete(&creator, &pack).await, 201);
    // Complete: the creator is forgotten and can no longer write.
    let id: [u8; 16] = hex::decode(&pack).unwrap().try_into().unwrap();
    let row = s.app.registry.pack(&id).await.unwrap().unwrap();
    assert!(row.done && row.device.is_none());
    assert_eq!(pack_put(&creator, &pack, 1, Bytes::new()).await, 404);
    // Anyone with the link fetches, by redirect to signed media URLs.
    for n in 0..3 {
        let (st, h, _) = fetch_pack(n).await;
        assert_eq!(st, 303);
        let (st, _, got) = fetch(&s, h["location"].to_str().unwrap(), None).await;
        assert_eq!(st, 200);
        assert!(got == objects[n]);
    }
    assert_eq!(fetch_pack(3).await.0, 404);
    // Deletion: the wrong token and no token look like no pack; the right one deletes.
    let del = |t: Option<String>| {
        let path = format!("/v1/packs/{pack}");
        let s = &s;
        async move {
            let h: Vec<(&str, String)> = t
                .map(|t| ("x-songbird-pack-token", t))
                .into_iter()
                .collect();
            unsigned_full(s.addr, SERVER, "DELETE", &path, &h)
                .await
                .unwrap()
                .0
        }
    };
    assert_eq!(del(None).await, 404);
    assert_eq!(del(Some(hex::encode([0x2bu8; 32]))).await, 404);
    assert_eq!(
        del(Some(token_hash.clone())).await,
        404,
        "the hash is not the token"
    );
    assert_eq!(del(Some(hex::encode(token))).await, 204);
    assert_eq!(fetch_pack(0).await.0, 404);
    assert!(s.app.registry.pack(&id).await.unwrap().is_none());
    // Bounds: one object only; an illegal size; a bad token.
    for bad in [
        format!(r#"{{"sizes":[{}],"token":"{token_hash}"}}"#, sizes[0]),
        format!(r#"{{"sizes":[{},4096],"token":"{token_hash}"}}"#, sizes[0]),
        format!(r#"{{"sizes":[{},{}],"token":"ab"}}"#, sizes[0], sizes[1]),
    ] {
        assert_eq!(
            creator
                .send("POST", "/v1/packs", Some(bad.as_bytes()))
                .await
                .unwrap()
                .0,
            400
        );
    }
    let _ = s.stop.send(true);
}

async fn pack_put(c: &ApiClient, pack: &str, n: usize, body: Bytes) -> u16 {
    let path = format!("/v1/packs/{pack}/{n}");
    let len = body.len().to_string();
    c.upload_with("PUT", &path, &[("content-length", len)], body)
        .await
        .map_or(0, |r| r.0)
}

async fn pack_complete(c: &ApiClient, pack: &str) -> u16 {
    c.send("POST", &format!("/v1/packs/{pack}/complete"), None)
        .await
        .unwrap()
        .0
}

/// A request the mock provider received: its URI and headers.
type Seen = (String, Vec<(String, String)>);

/// A stand-in for GIPHY that records every request it receives.
struct MockGiphy {
    addr: std::net::SocketAddr,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

async fn mock_giphy() -> MockGiphy {
    use hyper::service::service_fn;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (s2, f2) = (Arc::clone(&seen), Arc::clone(&fail));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (seen, fail) = (Arc::clone(&s2), Arc::clone(&f2));
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (seen, fail) = (Arc::clone(&seen), Arc::clone(&fail));
                    async move {
                        let uri = req.uri().to_string();
                        let headers = req
                            .headers()
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned())
                            })
                            .collect();
                        seen.lock().unwrap().push((uri.clone(), headers));
                        let path = req.uri().path().to_owned();
                        let mut r = hyper::Response::new(http_body_util::Full::new(Bytes::new()));
                        if fail.load(std::sync::atomic::Ordering::Relaxed) {
                            *r.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                        } else if path.starts_with("/v1/gifs/") {
                            let a = format!("http://{addr}/media/a.gif");
                            let body = format!(
                                r#"{{"data":[
                                  {{"id":"a","images":{{"fixed_width":{{"url":"{a}","width":"200","height":"150","mp4":"http://{addr}/media/a.mp4"}},"fixed_width_still":{{"url":"http://{addr}/media/a_s.gif"}}}}}},
                                  {{"id":"evil","images":{{"fixed_width":{{"url":"https://evil.example/x.gif","width":"1","height":"1"}}}}}},
                                  {{"id":"page","images":{{"fixed_width":{{"url":"http://{addr}/media/page.html","width":"1","height":"1"}}}}}},
                                  {{"id":"gone","images":{{"fixed_width":{{"url":"http://{addr}/media/gone.gif","width":"1","height":"1"}}}}}}
                                ],"pagination":{{"count":3}}}}"#
                            );
                            *r.body_mut() = http_body_util::Full::new(Bytes::from(body));
                        } else if path == "/media/gone.gif" {
                            *r.status_mut() = hyper::StatusCode::NOT_FOUND;
                        } else if path == "/media/page.html" {
                            r.headers_mut()
                                .insert("content-type", "text/html".parse().unwrap());
                            *r.body_mut() =
                                http_body_util::Full::new(Bytes::from_static(b"<html>"));
                        } else {
                            r.headers_mut()
                                .insert("content-type", "image/gif".parse().unwrap());
                            *r.body_mut() = http_body_util::Full::new(Bytes::from_static(
                                b"GIF89a fake frames",
                            ));
                        }
                        Ok::<_, std::convert::Infallible>(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    MockGiphy { addr, seen, fail }
}

/// The GIF proxy (Prompt 6, M4, D-0083): the provider gets the query and nothing of the app;
/// files come through `api` from the provider's hosts only; answers and files are cached;
/// searches are budgeted per account; an outage opens the circuit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gif_proxy_hides_who_searches_and_survives_the_provider() {
    let giphy = mock_giphy().await;
    let Some(s) = stack_full(
        MediaBudgets::default(),
        MediaDownloads::default(),
        PART,
        Some(GifSettings {
            base_url: format!("http://{}", giphy.addr),
            cdn_hosts: vec![giphy.addr.to_string()],
            search_burst: 6,
            searches_per_hour: 60,
            ..GifSettings::default()
        }),
    )
    .await
    else {
        return;
    };
    let c = device(&s).await;
    let search = |q: &str| {
        let body = format!(r#"{{"q":"{q}","offset":0,"lang":"en"}}"#);
        let c = &c;
        async move {
            c.send("POST", "/v1/gifs/search", Some(body.as_bytes()))
                .await
                .unwrap()
        }
    };
    let (st, b) = search("happy birthday").await;
    assert_eq!(st, 200);
    let text = String::from_utf8(b.to_vec()).unwrap();
    assert!(
        !text.contains("127.0.0.1") && !text.contains("evil"),
        "{text}"
    );
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let gifs = v["gifs"].as_array().unwrap();
    assert_eq!(gifs.len(), 3, "the file from another host is dropped");
    let file = gifs[0]["gif"].as_str().unwrap().to_owned();
    assert!(file.starts_with("/v1/gifs/media/"));
    // What the provider received: its key, the query, paging, rating and language; no header
    // but host, user agent and accept; nothing of the app.
    {
        let seen = giphy.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].0,
            "/v1/gifs/search?api_key=test-key&q=happy%20birthday&limit=24&offset=0&rating=pg-13&lang=en"
        );
        let mut names: Vec<&str> = seen[0].1.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["accept", "host", "user-agent"]);
    }
    // The same search again: from the cache.
    assert_eq!(search("happy birthday").await.0, 200);
    assert_eq!(giphy.seen.lock().unwrap().len(), 1);
    // The file, with no account: through api, then from the cache.
    for _ in 0..2 {
        let (st, h, body) = unsigned_full(s.addr, SERVER, "GET", &file, &[])
            .await
            .unwrap();
        assert_eq!(
            (st, h["content-type"].to_str().unwrap()),
            (200, "image/gif")
        );
        assert_eq!(&body[..], b"GIF89a fake frames");
    }
    assert_eq!(giphy.seen.lock().unwrap().len(), 2);
    let mut bad = file.clone();
    bad.pop();
    bad.push('0');
    assert_eq!(
        unsigned_full(s.addr, SERVER, "GET", &bad, &[])
            .await
            .unwrap()
            .0,
        404
    );
    // A provider answer that is not an image is never passed on.
    let page = gifs[1]["gif"].as_str().unwrap().to_owned();
    assert_eq!(
        unsigned_full(s.addr, SERVER, "GET", &page, &[])
            .await
            .unwrap()
            .0,
        503
    );
    // A GIF the provider removed (404), fetched again and again with no account: it fails, and
    // it does not open the circuit for everyone's searches (D-0084).
    let gone = gifs[2]["gif"].as_str().unwrap().to_owned();
    for _ in 0..8 {
        assert_eq!(
            unsigned_full(s.addr, SERVER, "GET", &gone, &[])
                .await
                .unwrap()
                .0,
            503
        );
    }
    assert_eq!(search("still searching").await.0, 200);
    // No account, no search.
    let (st, _, _) = unsigned_full(s.addr, SERVER, "POST", "/v1/gifs/search", &[])
        .await
        .unwrap();
    assert_eq!(st, 401);
    // The provider fails: 503 with a wait; after five failures the circuit opens and the
    // provider is left alone.
    giphy.fail.store(true, std::sync::atomic::Ordering::Relaxed);
    let before = giphy.seen.lock().unwrap().len();
    let mut throttled = false;
    for i in 0..8 {
        let (st, _) = search(&format!("outage {i}")).await;
        if st == 429 {
            throttled = true;
            break;
        }
        assert_eq!(st, 503);
    }
    let after = giphy.seen.lock().unwrap().len();
    assert!(
        after - before <= 5,
        "the circuit opened ({} requests)",
        after - before
    );
    // The account's search budget (a burst of six) ran out along the way.
    assert!(throttled);
    let _ = s.stop.send(true);
}

/// A part may be sent again (a retry), but not endlessly: at most twice the part count and a few
/// more writes per grant (D-0084).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parts_can_be_retried_but_not_rewritten_forever() {
    let Some(s) = stack(MediaBudgets::default()).await else {
        return;
    };
    let up = device(&s).await;
    let size = ciphertext_len(10).unwrap();
    let (_, id) = grant(&up, size, 1).await;
    let id = id.unwrap();
    let body = data(size);
    let mut codes = Vec::new();
    for _ in 0..12 {
        codes.push(put_part(&up, &id, 1, body.clone()).await);
    }
    // One part: 2 × 1 + 8 = 10 writes.
    assert_eq!(&codes[..10], &[204; 10]);
    assert_eq!(&codes[10..], &[409, 409]);
    // Completing still works: the stored part is intact.
    assert_eq!(
        up.send("POST", &format!("/v1/attachments/{id}/complete"), None)
            .await
            .unwrap()
            .0,
        201
    );
    assert!(download(&s, &id).await == body);
    let _ = s.stop.send(true);
}

/// The plan sets the largest file, the daily upload bytes and new packs per 30 days (Prompt
/// 11, D-0127): Free 2 GiB, 10 GiB a day and 5 packs; Plus 4 GiB, 50 GiB and 50, each level on a
/// budget of its own so an upgrade applies at once; an expired entitlement reads as Free.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_plan_sets_file_size_daily_bytes_and_packs() {
    use songbird_accounts::entitlements::{EntRow, Source};
    use songbird_entitlements::{Snapshot, today};
    let Some(s) = stack(MediaBudgets {
        grants_per_hour: 10_000,
        grant_burst: 1_000,
        ..MediaBudgets::default()
    })
    .await
    else {
        return;
    };
    let c = device(&s).await;
    let account = s
        .app
        .registry
        .device(&c.device())
        .await
        .unwrap()
        .unwrap()
        .account;
    let set = |last_day: Option<u32>| {
        s.app.plans.live.store(Snapshot::from_rows(
            i64::from(last_day.unwrap_or(0)),
            &last_day
                .map(|d| EntRow {
                    account,
                    level: 1,
                    last_day: d,
                    source: Source::Token,
                })
                .into_iter()
                .collect::<Vec<_>>(),
        ));
    };
    // Largest file: 3 GiB is over Free's 2 and under Plus's 4.
    let three = ciphertext_len(3 << 30).unwrap();
    let (st, b) = c
        .send(
            "POST",
            "/v1/attachments",
            Some(format!(r#"{{"size":{three},"fetches":1}}"#).as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(st, 413);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        (v["error"].as_str(), v["file_bytes"].as_u64()),
        (Some("plan"), Some(2 << 30))
    );
    set(Some(today() - 1));
    assert_eq!(grant(&c, three, 1).await.0, 413, "expired yesterday: Free");
    set(Some(today()));
    assert_eq!(grant(&c, three, 1).await.0, 201);
    // Past 4 GiB nobody may (the ceiling).
    assert_eq!(grant(&c, ciphertext_len(5 << 30).unwrap(), 1).await.0, 400);

    // Daily bytes: Free's 10 GiB run out in 1 GiB grants...
    set(None);
    let one = ciphertext_len(1 << 30).unwrap();
    let mut ok = 0;
    while grant(&c, one, 1).await.0 == 201 {
        ok += 1;
        assert!(ok <= 10, "Free's 10 GiB a day must run out");
    }
    assert_eq!(ok, 9, "nine grants of a little over 1 GiB fit in 10 GiB");
    // ... and Plus has a budget of its own at once.
    set(Some(today()));
    assert_eq!(grant(&c, one, 1).await.0, 201);
    set(None);
    assert_eq!(
        grant(&c, one, 1).await.0,
        429,
        "back on Free, Free's budget is still spent"
    );

    // New packs: five on Free, then the plan's answer with a wait.
    let small = ciphertext_len(1_000).unwrap();
    let pack = || {
        let mut t = [0u8; 32];
        aws_lc_rs::rand::fill(&mut t).unwrap();
        format!(
            r#"{{"sizes":[{small},{small}],"token":"{}"}}"#,
            hex::encode(t)
        )
    };
    let p = device(&s).await;
    for _ in 0..5 {
        let (st, _) = p
            .send("POST", "/v1/packs", Some(pack().as_bytes()))
            .await
            .unwrap();
        assert_eq!(st, 201);
    }
    let (st, b) = p
        .send("POST", "/v1/packs", Some(pack().as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 429);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        (v["error"].as_str(), v["packs_per_month"].as_u64()),
        (Some("plan"), Some(5))
    );
    let pa = s
        .app
        .registry
        .device(&p.device())
        .await
        .unwrap()
        .unwrap()
        .account;
    s.app.plans.live.store(Snapshot::from_rows(
        9,
        &[EntRow {
            account: pa,
            level: 1,
            last_day: today(),
            source: Source::Grant,
        }],
    ));
    let (st, _) = p
        .send("POST", "/v1/packs", Some(pack().as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 201, "Plus: a budget of its own");
}
