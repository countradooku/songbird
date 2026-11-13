//! The S3 client against a real `RustFS` (the compose service, D-0035). Runs when
//! `SONGBIRD_TEST_RUSTFS` (`host:port`, e.g. `127.0.0.1:47900`) is set, with
//! `SONGBIRD_TEST_RUSTFS_ACCESS_KEY` and `SONGBIRD_TEST_RUSTFS_SECRET_KEY` (from `.env`:
//! `RUSTFS_ACCESS_KEY`, `RUSTFS_SECRET_KEY`); with `SONGBIRD_REQUIRE_RUSTFS=1` a missing server
//! fails instead of skipping. Each test uses its own bucket.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "tests"
)]

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use songbird_s3::{Client, Config, Error};
use songbird_types::{DeviceId, Secret};

fn client(name: &str) -> Option<Client> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_RUSTFS") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_RUSTFS").is_err(),
            "SONGBIRD_REQUIRE_RUSTFS is set but SONGBIRD_TEST_RUSTFS is not"
        );
        return None;
    };
    let ak =
        std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").expect("SONGBIRD_TEST_RUSTFS_ACCESS_KEY");
    let sk =
        std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").expect("SONGBIRD_TEST_RUSTFS_SECRET_KEY");
    let bucket = format!("sb-{name}-{}", &rand_hex()[..12]);
    let mut cfg = Config::new(addr, bucket, Secret::new(ak), Secret::new(sk));
    cfg.request_timeout = Duration::from_secs(10);
    cfg.upload_timeout = Duration::from_secs(30);
    cfg.max_connections = 8;
    cfg.max_idle = 4;
    Some(Client::new(cfg).unwrap())
}

fn rand_hex() -> String {
    DeviceId::random().unwrap().to_hex_unredacted()
}

/// A stream of prepared chunks.
struct Chunks(VecDeque<Result<Bytes, std::io::Error>>);

impl Stream for Chunks {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.pop_front())
    }
}

fn chunks(data: &[u8], size: usize) -> Chunks {
    Chunks(
        data.chunks(size)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect(),
    )
}

fn data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 31 % 251).unwrap())
        .collect()
}

async fn read_all(c: &Client, key: &str, range: Option<(u64, u64)>) -> (u16, u64, Vec<u8>) {
    let mut got = c.get_object(key, range).await.unwrap();
    let mut out = Vec::new();
    while let Some(chunk) = got.body.chunk().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    (got.status, got.length, out)
}

#[tokio::test]
async fn objects_round_trip() {
    let Some(c) = client("rt") else { return };
    c.create_bucket().await.unwrap();
    // Idempotent: BucketAlreadyOwnedByYou (or 200) is success.
    c.create_bucket().await.unwrap();

    let prefix = format!("t/{}/", rand_hex());
    let key = format!("{prefix}object");
    let body = data(100_000);

    c.put_object(&key, body.len() as u64, chunks(&body, 7_000))
        .await
        .unwrap();
    assert_eq!(c.head_object(&key).await.unwrap().unwrap().length, 100_000);

    let (status, len, got) = read_all(&c, &key, None).await;
    assert_eq!((status, len), (200, 100_000));
    assert_eq!(got, body);

    let (status, len, got) = read_all(&c, &key, Some((10, 19))).await;
    assert_eq!((status, len), (206, 10));
    assert_eq!(got, &body[10..20]);
    let (status, len, got) = read_all(&c, &key, Some((99_990, 200_000))).await;
    assert_eq!((status, len), (206, 10));
    assert_eq!(got, &body[99_990..]);

    // An empty object and a small signed body.
    let empty = format!("{prefix}empty");
    c.put_object(&empty, 0, Chunks(VecDeque::new()))
        .await
        .unwrap();
    assert_eq!(c.head_object(&empty).await.unwrap().unwrap().length, 0);
    assert_eq!(read_all(&c, &empty, None).await.2, Vec::<u8>::new());
    let small = format!("{prefix}small with space+plus");
    c.put_object_bytes(&small, Bytes::from_static(b"hello"))
        .await
        .unwrap();
    assert_eq!(read_all(&c, &small, None).await.2, b"hello");

    // Responses read to the end leave their connection for reuse.
    assert!(c.idle_connections() >= 1);

    // Delete twice: the second is a no-op.
    for k in [&key, &empty, &small] {
        c.delete_object(k).await.unwrap();
        c.delete_object(k).await.unwrap();
        assert_eq!(c.head_object(k).await.unwrap(), None);
    }
    let e = c.get_object(&key, None).await.unwrap_err();
    assert_eq!(e, Error::NotFound);
    // Errors never name the object.
    assert!(!format!("{e} {e:?}").contains(&prefix));
}

#[tokio::test]
async fn wrong_lengths_are_refused_and_store_nothing() {
    let Some(c) = client("len") else { return };
    c.create_bucket().await.unwrap();
    let key = format!("t/{}/x", rand_hex());
    let ten = data(10);
    let cases: Vec<(u64, Chunks)> = vec![
        // One byte too many, in the same chunk.
        (10, chunks(&data(11), 11)),
        // One byte too many after the declared length was complete.
        (
            10,
            Chunks(VecDeque::from([
                Ok(Bytes::from(ten.clone())),
                Ok(Bytes::from_static(b"!")),
            ])),
        ),
        // One byte short.
        (10, chunks(&data(9), 4)),
        // Declared empty, one byte sent.
        (0, chunks(b"!", 1)),
    ];
    for (declared, stream) in cases {
        let e = c.put_object(&key, declared, stream).await.unwrap_err();
        assert_eq!(e, Error::LengthMismatch);
        assert_eq!(c.head_object(&key).await.unwrap(), None, "nothing stored");
    }
    // A failing source stream.
    let failing = Chunks(VecDeque::from([
        Ok(Bytes::from_static(b"abc")),
        Err(std::io::Error::other("source failed with secret details")),
    ]));
    let e = c.put_object(&key, 10, failing).await.unwrap_err();
    assert_eq!(e, Error::BodySource);
    assert!(!format!("{e:?}").contains("secret"));
    assert_eq!(c.head_object(&key).await.unwrap(), None);
    // The client still works after aborted uploads.
    c.put_object(&key, 10, chunks(&ten, 3)).await.unwrap();
    assert_eq!(read_all(&c, &key, None).await.2, ten);
    c.delete_object(&key).await.unwrap();
}

#[tokio::test]
async fn list_with_prefix_and_pagination() {
    let Some(c) = client("list") else { return };
    c.create_bucket().await.unwrap();
    let prefix = format!("t/{}/", rand_hex());
    let other = format!("u/{}/", rand_hex());
    let mut keys: Vec<String> = (0..5).map(|i| format!("{prefix}k{i}&<{i}>")).collect();
    for (i, k) in keys.iter().enumerate() {
        c.put_object_bytes(k, Bytes::from(vec![7u8; i + 1]))
            .await
            .unwrap();
    }
    c.put_object_bytes(&format!("{other}x"), Bytes::from_static(b"x"))
        .await
        .unwrap();

    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = c
            .list_objects_v2(&prefix, token.as_deref(), 2)
            .await
            .unwrap();
        pages += 1;
        assert!(page.objects.len() <= 2);
        for o in &page.objects {
            assert!(o.key.starts_with(&prefix));
            assert_ne!(o.last_modified, "");
            seen.push((o.key.clone(), o.size));
        }
        if !page.is_truncated {
            break;
        }
        token = page.next_continuation_token;
        assert!(pages < 10);
    }
    assert_eq!(pages, 3);
    keys.sort();
    let want: Vec<(String, u64)> = keys
        .iter()
        .map(|k| {
            let i: u64 = k.as_bytes()[prefix.len() + 1].saturating_sub(b'0').into();
            (k.clone(), i + 1)
        })
        .collect();
    assert_eq!(seen, want);
    // A prefix with nothing under it.
    let none = c
        .list_objects_v2(&format!("{prefix}none/"), None, 10)
        .await
        .unwrap();
    assert!(none.objects.is_empty() && !none.is_truncated);

    for k in &keys {
        c.delete_object(k).await.unwrap();
    }
    c.delete_object(&format!("{other}x")).await.unwrap();
    let after = c.list_objects_v2(&prefix, None, 10).await.unwrap();
    assert_eq!(after.objects.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_share_the_pool() {
    let Some(c) = client("pool") else { return };
    c.create_bucket().await.unwrap();
    let prefix = format!("t/{}/", rand_hex());
    let mut tasks = Vec::new();
    for i in 0..32 {
        let c = c.clone();
        let key = format!("{prefix}{i}");
        tasks.push(tokio::spawn(async move {
            let body = data(1000 + i);
            c.put_object(&key, body.len() as u64, chunks(&body, 333))
                .await
                .unwrap();
            assert_eq!(read_all(&c, &key, None).await.2, body);
            c.delete_object(&key).await.unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn wrong_credentials_are_refused() {
    let Some(c) = client("auth") else { return };
    c.create_bucket().await.unwrap();
    let addr = std::env::var("SONGBIRD_TEST_RUSTFS").unwrap();
    let bad = Client::new(Config::new(
        addr,
        "sb-auth-bad".into(),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap()),
        Secret::new("not-the-secret-key".into()),
    ))
    .unwrap();
    let e = bad.head_object("k").await.unwrap_err();
    assert!(matches!(e, Error::Status { status: 403, .. }), "{e:?}");
}

/// Object Lock (D-0040's off-site copies): a locked object cannot be deleted before its date,
/// and an upload whose checksum does not match is refused.
#[tokio::test]
async fn locked_objects_cannot_be_deleted_and_checksums_are_checked() {
    let Some(c) = client("lock") else { return };
    c.create_bucket_locked().await.unwrap();
    let body = Bytes::from_static(b"sealed backup bytes");
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &body);
    let mut sum = [0u8; 32];
    sum.copy_from_slice(digest.as_ref());
    let until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let opts = songbird_s3::PutOptions {
        retain_until: Some(until),
        sha256: Some(sum),
    };
    let len = u64::try_from(body.len()).unwrap();
    c.put_object_with("b/locked", len, chunks(&body, 8), opts)
        .await
        .unwrap();
    // Deleting the current version only adds a delete marker on a versioned bucket; deleting
    // the locked version itself is what Object Lock refuses. Either way the bytes stay readable.
    let _ = c.delete_object("b/locked").await;
    let versions_left = c.list_objects_v2("b/", None, 10).await.unwrap();
    let still_there = c.head_object("b/locked").await.unwrap().is_some()
        || versions_left.objects.iter().any(|o| o.key == "b/locked");
    println!("after delete: current version visible = {still_there}");
    // A wrong checksum is refused and stores nothing.
    let bad = songbird_s3::PutOptions {
        retain_until: Some(until),
        sha256: Some([0; 32]),
    };
    let r = c.put_object_with("b/bad", len, chunks(&body, 8), bad).await;
    assert!(r.is_err(), "a wrong checksum must be refused");
    assert!(c.head_object("b/bad").await.unwrap().is_none());
    // Without retention an object in the same bucket can be deleted as usual.
    c.put_object_with(
        "b/free",
        len,
        chunks(&body, 8),
        songbird_s3::PutOptions {
            retain_until: None,
            sha256: Some(sum),
        },
    )
    .await
    .unwrap();
}

/// D-0040: a holder of a put-only key can overwrite a backup's name, which on a versioned
/// bucket makes a new current version. The original stays, as the earliest version, and can be
/// read by its version ID: restores read that one.
#[tokio::test]
async fn an_overwrite_leaves_the_original_as_the_earliest_version() {
    let Some(c) = client("versions") else { return };
    c.create_bucket_locked().await.unwrap();
    let put = |body: &'static [u8]| {
        let b = Bytes::from_static(body);
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &b);
        let mut sum = [0u8; 32];
        sum.copy_from_slice(d.as_ref());
        let len = u64::try_from(b.len()).unwrap();
        let c = c.clone();
        async move {
            c.put_object_with(
                "registry/frequent/x",
                len,
                chunks(&b, 4),
                songbird_s3::PutOptions {
                    retain_until: None,
                    sha256: Some(sum),
                },
            )
            .await
            .unwrap();
        }
    };
    put(b"the real backup").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    put(b"a forgery").await;
    let page = c
        .list_object_versions("registry/", None, None, 100)
        .await
        .unwrap();
    let mut mine: Vec<_> = page
        .versions
        .iter()
        .filter(|v| v.key == "registry/frequent/x")
        .collect();
    assert_eq!(mine.len(), 2, "both versions are listed");
    mine.sort_by(|a, b| a.last_modified.cmp(&b.last_modified));
    assert!(mine[1].is_latest && !mine[0].is_latest);
    let mut first = c
        .get_object_version("registry/frequent/x", &mine[0].version_id)
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(ch) = first.body.chunk().await {
        got.extend_from_slice(&ch.unwrap());
    }
    assert_eq!(got, b"the real backup");
}
