//! Prompt 10, M3 (D-0122): the conformance suite on the adapters that need a server: S3 on the
//! compose `RustFS`, `WebDAV` on the compose Apache `mod_dav`. Runs when `SONGBIRD_TEST_RUSTFS`
//! (and `SONGBIRD_TEST_WEBDAV`) are set; with `SONGBIRD_REQUIRE_STACK=1` a missing one fails.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "tests"
)]

use std::sync::Arc;

use songbird_backup_format::{OsRng, RecoveryKey};
use songbird_backup_storage::conformance::{self, Plan};
use songbird_backup_storage::http::HyperHttp;
use songbird_backup_storage::s3::{S3Config, S3Store};
use zeroize::Zeroizing;

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

fn keys() -> Arc<songbird_backup_format::BackupKeys> {
    Arc::new(RecoveryKey::generate(&mut OsRng).unwrap().derive().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s3_on_rustfs_conforms() {
    let Some(addr) = env("SONGBIRD_TEST_RUSTFS") else {
        return;
    };
    let access = std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap();
    let secret = std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").unwrap();
    let bucket = "songbird-backup-s3-test".to_owned();
    songbird_s3::Client::new(songbird_s3::Config::new(
        addr.clone(),
        bucket.clone(),
        songbird_types::Secret::new(access.clone()),
        songbird_types::Secret::new(secret.clone()),
    ))
    .unwrap()
    .create_bucket()
    .await
    .unwrap();
    let k = keys();
    let store = S3Store::new(
        Arc::new(HyperHttp::new(&[]).unwrap()),
        S3Config {
            endpoint: format!("http://{addr}"),
            bucket,
            region: "us-east-1".into(),
            access_key: Zeroizing::new(access),
            secret_key: Zeroizing::new(secret),
            prefix: format!("songbird/{}/", hex::encode(k.vault_id)),
        },
    )
    .unwrap();
    let r = conformance::run(Arc::new(store), k, Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn webdav_on_apache_conforms() {
    let Some(url) = env("SONGBIRD_TEST_WEBDAV") else {
        return;
    };
    let k = keys();
    let store = songbird_backup_storage::webdav::WebDavStore::new(
        Arc::new(HyperHttp::new(&[]).unwrap()),
        &songbird_backup_storage::webdav::WebDavConfig {
            url: format!(
                "{}/songbird-{}/",
                url.trim_end_matches('/'),
                &hex::encode(k.vault_id)[..16]
            ),
            user: "songbird".into(),
            password: Zeroizing::new(std::env::var("SONGBIRD_TEST_WEBDAV_PASSWORD").unwrap()),
        },
    )
    .unwrap();
    let r = conformance::run(Arc::new(store), k, Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}
