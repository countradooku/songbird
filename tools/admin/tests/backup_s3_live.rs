//! D-0040: a backup overwritten by someone holding the put-only key is never restored, and the
//! daily verification reports it. Against real `SurrealDB`, `RustFS` and the age tool; runs when
//! `SONGBIRD_TEST_SURREALDB` (+ `_PASS`), `SONGBIRD_TEST_RUSTFS` (+ `_ACCESS_KEY`, `_SECRET_KEY`)
//! and `SONGBIRD_TEST_AGE` (a directory with `age` and `age-keygen`) are set.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests; one scenario read top to bottom"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bytes::Bytes;

struct Env {
    surreal: String,
    surreal_pass: String,
    rustfs: String,
    access: String,
    secret: String,
    age: PathBuf,
}

fn env() -> Option<Env> {
    let v = |k: &str| std::env::var(k).ok();
    Some(Env {
        surreal: v("SONGBIRD_TEST_SURREALDB")?,
        surreal_pass: v("SONGBIRD_TEST_SURREALDB_PASS")?,
        rustfs: v("SONGBIRD_TEST_RUSTFS")?,
        access: v("SONGBIRD_TEST_RUSTFS_ACCESS_KEY")?,
        secret: v("SONGBIRD_TEST_RUSTFS_SECRET_KEY")?,
        age: PathBuf::from(v("SONGBIRD_TEST_AGE")?),
    })
}

fn admin(e: &Env, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_songbird-admin"))
        .args(args)
        .env("SURREAL_PASS", &e.surreal_pass)
        .env("BACKUP_S3_ACCESS_KEY", &e.access)
        .env("BACKUP_S3_SECRET_KEY", &e.secret)
        .env("DELETION_JOURNAL_KEY", hex::encode(JOURNAL_KEY))
        .output()
        .unwrap();
    println!(
        "songbird-admin {}: {}{}",
        args.first().copied().unwrap_or_default(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

const JOURNAL_KEY: [u8; 32] = [0x4b; 32];

fn surreal_cfg(e: &Env, db: &str) -> songbird_surreal::Config {
    songbird_surreal::Config {
        addr: e.surreal.clone(),
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: e.surreal_pass.clone(),
        namespace: "test".into(),
        database: db.into(),
        timeout: std::time::Duration::from_secs(10),
        max_message_bytes: 16 << 20,
    }
}

async fn seed(
    e: &Env,
    db: &str,
    accounts: usize,
) -> Vec<(songbird_types::AccountId, songbird_types::DeviceId)> {
    let d = songbird_accounts::Db::connect(surreal_cfg(e, db))
        .await
        .unwrap();
    d.exec(
        &format!("REMOVE DATABASE IF EXISTS {db}; DEFINE DATABASE {db};"),
        Vec::new(),
    )
    .await
    .unwrap();
    let registry = songbird_accounts::Registry::connect(d).await.unwrap();
    let mut out = Vec::new();
    for _ in 0..accounts {
        let device = songbird_types::DeviceId::random().unwrap();
        let account = songbird_types::AccountId::random().unwrap();
        registry
            .create_account(&account, &[(device, [7u8; 32])])
            .await
            .unwrap();
        out.push((account, device));
    }
    out
}

fn recipient(key: &Path) -> String {
    let text = std::fs::read_to_string(key).unwrap();
    text.lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn an_overwritten_backup_is_never_restored_and_verify_reports_it() {
    let Some(e) = env() else {
        println!("skipped: SurrealDB, RustFS or age not configured");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("owner.key");
    assert!(
        Command::new(e.age.join("age-keygen"))
            .arg("-o")
            .arg(&key)
            .output()
            .unwrap()
            .status
            .success()
    );
    let r = recipient(&key);
    let suffix = hex::encode(getrandom_bytes());
    let (src, forge) = (format!("bksrc{suffix}"), format!("bkforge{suffix}"));
    seed(&e, &src, 2).await;
    seed(&e, &forge, 5).await;

    // A versioned bucket (created with Object Lock, as in production).
    let bucket = format!("bk-live-{suffix}");
    let s3 = songbird_s3::Client::new(songbird_s3::Config::new(
        e.rustfs.clone(),
        bucket.clone(),
        songbird_types::Secret::new(e.access.clone()),
        songbird_types::Secret::new(e.secret.clone()),
    ))
    .unwrap();
    s3.create_bucket_locked().await.unwrap();

    let age = e.age.join("age");
    let age = age.to_str().unwrap();
    let state = tmp.path().join("state");
    let common = |db: &str| -> Vec<String> {
        [
            "--addr",
            &e.surreal,
            "--namespace",
            "test",
            "--database",
            db,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    };
    // The real backup, to S3.
    let mut run: Vec<String> = vec!["backup".into(), "run".into()];
    run.extend(common(&src));
    run.extend(
        [
            "--s3-addr",
            &e.rustfs,
            "--s3-bucket",
            &bucket,
            "--recipient",
            &r,
            "--age",
            age,
            "--state",
            state.to_str().unwrap(),
        ]
        .iter()
        .map(|s| (*s).to_owned()),
    );
    let out = admin(&e, &run.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(out.status.success());
    let name = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .strip_prefix("stored ")
        .unwrap()
        .to_owned();

    // A forgery (another registry, encrypted to the same public recipient, which anyone can do)
    // written over the real backup's name, as the put-only key allows.
    let forged_dir = tmp.path().join("forged");
    let mut run2: Vec<String> = vec!["backup".into(), "run".into()];
    run2.extend(common(&forge));
    run2.extend(
        [
            "--dir",
            forged_dir.to_str().unwrap(),
            "--recipient",
            &r,
            "--age",
            age,
            "--state",
            tmp.path().join("state2").to_str().unwrap(),
        ]
        .iter()
        .map(|s| (*s).to_owned()),
    );
    let out = admin(&e, &run2.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(out.status.success());
    let forged_name = String::from_utf8(out.stdout).unwrap();
    let forged =
        std::fs::read(forged_dir.join(forged_name.trim().strip_prefix("stored ").unwrap()))
            .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    s3.put_object_bytes(&name, Bytes::from(forged))
        .await
        .unwrap();

    let load = |verb: &str, db: &str| -> Vec<String> {
        let mut v: Vec<String> = vec!["backup".into(), verb.into()];
        v.extend(common(db));
        v.extend(
            [
                "--s3-addr",
                &e.rustfs,
                "--s3-bucket",
                &bucket,
                "--identity",
                key.to_str().unwrap(),
                "--age",
                age,
            ]
            .iter()
            .map(|s| (*s).to_owned()),
        );
        v
    };
    // The daily verification fails, naming tampering.
    let out = admin(
        &e,
        &load("verify", &format!("bkv{suffix}"))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("tampering"));

    // A restore reads the original: 2 accounts, not the forgery's 5.
    let rdb = format!("bkr{suffix}");
    let target = format!("test/{rdb}");
    let audit = tmp.path().join("audit.jsonl");
    let mut restore = load("restore", &rdb);
    restore.extend(
        ["--confirm", &target, "--audit-log", audit.to_str().unwrap()]
            .iter()
            .map(|s| (*s).to_owned()),
    );
    let out = admin(&e, &restore.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("WARNING: the bucket shows tampering: 1 names written twice"));
    assert!(text.contains(": 2 accounts, 2 devices"), "{text}");
}

fn getrandom_bytes() -> [u8; 4] {
    let id = songbird_types::DeviceId::random().unwrap();
    let mut b = [0u8; 4];
    b.copy_from_slice(&id.as_bytes()[..4]);
    b
}

/// D-0041: an account deleted after the backup was taken is deleted again by the restore (its
/// tombstone in the bucket), and no other account is touched.
#[tokio::test]
async fn a_deletion_after_the_backup_survives_the_restore() {
    let Some(e) = env() else {
        println!("skipped: SurrealDB, RustFS or age not configured");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("owner.key");
    assert!(
        Command::new(e.age.join("age-keygen"))
            .arg("-o")
            .arg(&key)
            .output()
            .unwrap()
            .status
            .success()
    );
    let r = recipient(&key);
    let suffix = hex::encode(getrandom_bytes());
    let src = format!("jsrc{suffix}");
    let people = seed(&e, &src, 3).await;
    let bucket = format!("bk-journal-{suffix}");
    let s3 = songbird_s3::Client::new(songbird_s3::Config::new(
        e.rustfs.clone(),
        bucket.clone(),
        songbird_types::Secret::new(e.access.clone()),
        songbird_types::Secret::new(e.secret.clone()),
    ))
    .unwrap();
    s3.create_bucket_locked().await.unwrap();
    let age = e.age.join("age");
    let age = age.to_str().unwrap();
    let state = tmp.path().join("state");
    let out = admin(
        &e,
        &[
            "backup",
            "run",
            "--addr",
            &e.surreal,
            "--namespace",
            "test",
            "--database",
            &src,
            "--s3-addr",
            &e.rustfs,
            "--s3-bucket",
            &bucket,
            "--recipient",
            &r,
            "--age",
            age,
            "--state",
            state.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());

    // After the backup, the first account is deleted: the worker's first step is its tombstone.
    let (gone, gone_dev) = people[0];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = songbird_accounts::journal::tombstone_name(
        &songbird_s3::sigv4::amz_date(now),
        &songbird_accounts::journal::tag(&JOURNAL_KEY, &gone),
    );
    s3.put_object_bytes(&name, Bytes::new()).await.unwrap();

    // The registry is lost; the restore brings the deleted account back and deletes it again.
    let rdb = format!("jr{suffix}");
    let target = format!("test/{rdb}");
    let audit = tmp.path().join("audit.jsonl");
    let out = admin(
        &e,
        &[
            "backup",
            "restore",
            "--addr",
            &e.surreal,
            "--namespace",
            "test",
            "--database",
            &rdb,
            "--s3-addr",
            &e.rustfs,
            "--s3-bucket",
            &bucket,
            "--identity",
            key.to_str().unwrap(),
            "--age",
            age,
            "--confirm",
            &target,
            "--audit-log",
            audit.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("deletion journal: 1 restored accounts"));
    let registry = songbird_accounts::Registry::connect(
        songbird_accounts::Db::connect(surreal_cfg(&e, &rdb))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    // Its devices are disabled at once (delivery drops them) and its deletion job is queued.
    assert!(registry.device(&gone_dev).await.unwrap().unwrap().disabled);
    for (_, d) in &people[1..] {
        assert!(!registry.device(d).await.unwrap().unwrap().disabled);
    }
    let audit = std::fs::read_to_string(&audit).unwrap();
    assert!(audit.contains("re-deleted 1"), "{audit}");

    // Without the journal key the restore refuses (an erased account must not come back
    // silently); --no-journal is explicit and audit-logged.
    let rdb2 = format!("jr2{suffix}");
    let target2 = format!("test/{rdb2}");
    let out = Command::new(env!("CARGO_BIN_EXE_songbird-admin"))
        .args([
            "backup",
            "restore",
            "--addr",
            &e.surreal,
            "--namespace",
            "test",
            "--database",
            &rdb2,
            "--s3-addr",
            &e.rustfs,
            "--s3-bucket",
            &bucket,
            "--identity",
            key.to_str().unwrap(),
            "--age",
            age,
            "--confirm",
            &target2,
            "--audit-log",
            tmp.path().join("audit2.jsonl").to_str().unwrap(),
        ])
        .env("SURREAL_PASS", &e.surreal_pass)
        .env("BACKUP_S3_ACCESS_KEY", &e.access)
        .env("BACKUP_S3_SECRET_KEY", &e.secret)
        .env_remove("DELETION_JOURNAL_KEY")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("DELETION_JOURNAL_KEY is not set"));
    // Refused before anything was restored or logged.
    assert!(!tmp.path().join("audit2.jsonl").exists());
}
