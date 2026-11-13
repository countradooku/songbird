//! Registry backups (D-0040): export, encrypt, store write-once; verify; restore.
//!
//! - **run**: `GET /export` from SurrealDB, streamed straight into the reference `age` tool (the
//!   plaintext dump never touches a disk), encrypted to the given recipients (the owner's offline
//!   identity and the verification identity), then stored: in a directory (development, drills)
//!   or in S3 with Object Lock in compliance mode and a SHA-256 checksum. Each export goes to one
//!   retention tier, the highest it qualifies for: the first export of a month (`monthly`, kept
//!   93 days), of a week (`weekly`, 29 days), of a day (`daily`, 8 days), else `frequent` (25
//!   hours). The tier marks live in a small state file on the backup host, because the production
//!   credential cannot list the bucket.
//! - **verify**: the newest backup, decrypted with the verification identity and streamed into
//!   `POST /import` of a scratch database (never production), then checked; fails when it is
//!   older than the allowed age.
//! - **restore**: the same into the real registry, then the store generation is bumped, so every
//!   client resends what has no delivery receipt.
//!
//! Object names carry a timestamp and a random suffix, nothing about users.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use clap::Args;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::Frame;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::store::StoreArgs;

/// The retention tiers: (name, retain for).
const TIERS: [(&str, Duration); 4] = [
    ("monthly", Duration::from_hours(93 * 24)),
    ("weekly", Duration::from_hours(29 * 24)),
    ("daily", Duration::from_hours(8 * 24)),
    ("frequent", Duration::from_hours(25)),
];

/// Where backups go or come from.
#[derive(Debug, Clone, Args)]
pub(crate) struct DestArgs {
    /// A directory (development and drills) instead of S3.
    #[arg(long, conflicts_with = "s3_addr")]
    pub(crate) dir: Option<PathBuf>,
    /// S3 `host:port`.
    #[arg(long)]
    pub(crate) s3_addr: Option<String>,
    /// S3 bucket.
    #[arg(long, default_value = "songbird-backups")]
    pub(crate) s3_bucket: String,
    /// Environment variable holding the access key ID.
    #[arg(long, default_value = "BACKUP_S3_ACCESS_KEY")]
    pub(crate) s3_access_key_env: String,
    /// Environment variable holding the secret key.
    #[arg(long, default_value = "BACKUP_S3_SECRET_KEY")]
    pub(crate) s3_secret_key_env: String,
    /// S3 signing region.
    #[arg(long, default_value = "fr-par")]
    pub(crate) s3_region: String,
    /// Use TLS with the system's roots (the off-site provider).
    #[arg(long)]
    pub(crate) s3_tls: bool,
}

enum Dest {
    Dir(PathBuf),
    S3(songbird_s3::Client),
}

impl DestArgs {
    fn open(&self) -> Result<Dest> {
        if let Some(d) = &self.dir {
            return Ok(Dest::Dir(d.clone()));
        }
        let Some(addr) = &self.s3_addr else {
            bail!("give --dir or --s3-addr");
        };
        let ak = std::env::var(&self.s3_access_key_env)
            .with_context(|| format!("{} is not set", self.s3_access_key_env))?;
        let sk = std::env::var(&self.s3_secret_key_env)
            .with_context(|| format!("{} is not set", self.s3_secret_key_env))?;
        let mut cfg = songbird_s3::Config::new(
            addr.clone(),
            self.s3_bucket.clone(),
            songbird_types::Secret::new(ak),
            songbird_types::Secret::new(sk),
        );
        cfg.region.clone_from(&self.s3_region);
        cfg.upload_timeout = Duration::from_mins(30);
        if self.s3_tls {
            let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
            host.clone_into(&mut cfg.host);
            cfg.tls = Some(songbird_s3::Tls {
                config: std::sync::Arc::new(tls),
                server_name: host.to_owned(),
            });
        }
        Ok(Dest::S3(songbird_s3::Client::new(cfg)?))
    }
}

/// `backup run`.
#[derive(Debug, Clone, Args)]
pub(crate) struct RunArgs {
    #[command(flatten)]
    pub(crate) store: StoreArgs,
    #[command(flatten)]
    pub(crate) dest: DestArgs,
    /// age recipients (`age1…`): the owner's offline identity and the verification identity.
    #[arg(long = "recipient", required = true)]
    pub(crate) recipients: Vec<String>,
    /// The `age` binary.
    #[arg(long, default_value = "age")]
    pub(crate) age: PathBuf,
    /// State file remembering the last daily, weekly and monthly export.
    #[arg(long, default_value = "/var/lib/songbird/backup/state")]
    pub(crate) state: PathBuf,
    /// Store with S3 Object Lock (compliance mode) for the tier's retention.
    #[arg(long)]
    pub(crate) lock: bool,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Calendar keys of a Unix time: (day, ISO-ish week, month), as numbers.
fn calendar(secs: u64) -> (u64, u64, u64) {
    let day = secs / 86_400;
    // 1970-01-01 was a Thursday: weeks start on Monday.
    let week = (day + 3) / 7;
    let ts = songbird_s3::sigv4::iso8601(secs);
    let month = ts
        .get(..4)
        .and_then(|y| y.parse::<u64>().ok())
        .zip(ts.get(5..7).and_then(|m| m.parse::<u64>().ok()))
        .map_or(0, |(y, m)| y * 12 + m);
    (day, week, month)
}

/// Picks the tier for an export at `secs` given the last marks `(day, week, month)`, and returns
/// the new marks.
fn tier_for(secs: u64, last: (u64, u64, u64)) -> (&'static str, Duration, (u64, u64, u64)) {
    let (day, week, month) = calendar(secs);
    let (tier, keep) = if month != last.2 {
        TIERS[0]
    } else if week != last.1 {
        TIERS[1]
    } else if day != last.0 {
        TIERS[2]
    } else {
        TIERS[3]
    };
    let marks = match tier {
        "frequent" => last,
        _ => (day, week, month),
    };
    (tier, keep, marks)
}

fn read_state(p: &Path) -> (u64, u64, u64) {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| {
            let mut it = s.split_whitespace().map(|x| x.parse::<u64>().ok());
            Some((it.next()??, it.next()??, it.next()??))
        })
        .unwrap_or((0, 0, 0))
}

fn write_state(p: &Path, m: (u64, u64, u64)) -> Result<()> {
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, format!("{} {} {}\n", m.0, m.1, m.2))?;
    std::fs::rename(tmp, p)?;
    Ok(())
}

/// A private scratch directory (mode 0700) for the encrypted file before upload.
fn private_dir() -> Result<tempfile::TempDir> {
    let d = tempfile::Builder::new()
        .prefix("songbird-backup")
        .tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(d)
}

/// An HTTP/1.1 request to SurrealDB's HTTP endpoint (same host and port as RPC).
async fn surreal_http(
    store: &StoreArgs,
    method: hyper::Method,
    path: &str,
    body: http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>,
) -> Result<hyper::Response<hyper::body::Incoming>> {
    let cfg = store.config()?;
    let tcp = tokio::net::TcpStream::connect(&cfg.addr)
        .await
        .context("connecting to SurrealDB")?;
    let auth = songbird_s3::sigv4::base64(format!("{}:{}", cfg.user, cfg.pass).as_bytes());
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", &cfg.host)
        .header("authorization", format!("Basic {auth}"))
        .header("surreal-ns", &cfg.namespace)
        .header("surreal-db", &cfg.database)
        .header("accept", "application/json")
        .body(body)?;
    let resp = if let Some(tls) = cfg.tls {
        let name = rustls_pki_types::ServerName::try_from(cfg.host.clone())?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(name, tcp)
            .await?;
        let (mut s, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        s.send_request(req).await?
    } else {
        let (mut s, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await?;
        tokio::spawn(conn);
        s.send_request(req).await?
    };
    Ok(resp)
}

fn empty_body() -> http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error> {
    http_body_util::Empty::new()
        .map_err(|e| match e {})
        .boxed_unsync()
}

/// `backup run`: returns the stored object's name.
pub(crate) async fn run(a: &RunArgs) -> Result<String> {
    let dest = a.dest.open()?;
    let when = now_secs();
    let (tier, keep, marks) = tier_for(when, read_state(&a.state));
    let mut suffix = [0u8; 4];
    aws_lc_rs::rand::fill(&mut suffix).map_err(|_| anyhow::anyhow!("no randomness"))?;
    let stamp = songbird_s3::sigv4::amz_date(when);
    let name = format!("registry/{tier}/{stamp}-{}.surql.age", hex::encode(suffix));

    // Export -> age (stdin) -> encrypted file in a private directory.
    let dir = private_dir()?;
    let out = dir.path().join("backup.age");
    let mut age = tokio::process::Command::new(&a.age);
    age.arg("--encrypt").arg("--output").arg(&out);
    for r in &a.recipients {
        age.arg("--recipient").arg(r);
    }
    let mut child = age
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", a.age.display()))?;
    let mut stdin = child.stdin.take().context("age stdin")?;
    let resp = surreal_http(&a.store, hyper::Method::GET, "/export", empty_body()).await?;
    if !resp.status().is_success() {
        bail!("SurrealDB export answered {}", resp.status());
    }
    let mut body = resp.into_body();
    let mut plain_bytes = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.context("reading the export")?;
        if let Ok(data) = frame.into_data() {
            plain_bytes += u64::try_from(data.len()).unwrap_or(0);
            stdin.write_all(&data).await.context("feeding age")?;
        }
    }
    drop(stdin);
    let status = child.wait().await?;
    if !status.success() || plain_bytes == 0 {
        bail!("encryption failed (age {status}, {plain_bytes} bytes exported)");
    }
    let sealed = tokio::fs::read(&out).await?;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &sealed);
    let mut sum = [0u8; 32];
    sum.copy_from_slice(digest.as_ref());

    match dest {
        Dest::Dir(root) => {
            let path = root.join(&name);
            if let Some(p) = path.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::write(&path, &sealed)?;
        }
        Dest::S3(c) => {
            let len = u64::try_from(sealed.len()).unwrap_or(u64::MAX);
            let retain_until = a.lock.then(|| when + keep.as_secs());
            let chunks: Vec<std::result::Result<Bytes, std::io::Error>> = Bytes::from(sealed)
                .chunks(1 << 20)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect();
            c.put_object_with(
                &name,
                len,
                futures_util::stream::iter(chunks),
                songbird_s3::PutOptions {
                    retain_until,
                    sha256: Some(sum),
                },
            )
            .await
            .context("uploading the backup")?;
        }
    }
    write_state(&a.state, marks)?;
    Ok(name)
}

/// The newest backup's name and its timestamp (Unix seconds).
async fn newest(dest: &Dest) -> Result<(String, u64)> {
    let mut names = Vec::new();
    match dest {
        Dest::Dir(root) => {
            for tier in TIERS.map(|(t, _)| t) {
                let dir = root.join("registry").join(tier);
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for e in rd.flatten() {
                    if let Some(n) = e.file_name().to_str() {
                        names.push(format!("registry/{tier}/{n}"));
                    }
                }
            }
        }
        Dest::S3(c) => {
            let mut token: Option<String> = None;
            loop {
                let page = c
                    .list_objects_v2("registry/", token.as_deref(), 1000)
                    .await?;
                names.extend(page.objects.into_iter().map(|o| o.key));
                if !page.is_truncated {
                    break;
                }
                token = page.next_continuation_token;
            }
        }
    }
    let stamped = names.into_iter().filter_map(|n| {
        let file = n.rsplit('/').next()?;
        let secs = parse_amz_date(file.get(..16)?)?;
        Some((n, secs))
    });
    stamped.max_by_key(|(_, s)| *s).context("no backup found")
}

/// Parses `YYYYMMDDTHHMMSSZ`.
fn parse_amz_date(s: &str) -> Option<u64> {
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<u64>().ok();
    if s.get(8..9)? != "T" || s.get(15..16)? != "Z" {
        return None;
    }
    let (y, m, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hh, mm, ss) = (num(9..11)?, num(11..13)?, num(13..15)?);
    // days_from_civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

async fn fetch(dest: &Dest, name: &str) -> Result<Vec<u8>> {
    match dest {
        Dest::Dir(root) => Ok(tokio::fs::read(root.join(name)).await?),
        Dest::S3(c) => {
            let mut obj = c.get_object(name, None).await?;
            let mut out = Vec::with_capacity(usize::try_from(obj.length).unwrap_or(0));
            while let Some(chunk) = obj.body.chunk().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
    }
}

/// `backup verify` / `backup restore` settings.
#[derive(Debug, Clone, Args)]
pub(crate) struct LoadArgs {
    /// The database to restore into (a scratch one for `verify`).
    #[command(flatten)]
    pub(crate) store: StoreArgs,
    #[command(flatten)]
    pub(crate) dest: DestArgs,
    /// age identity file that can decrypt the backups.
    #[arg(long)]
    pub(crate) identity: PathBuf,
    /// The `age` binary.
    #[arg(long, default_value = "age")]
    pub(crate) age: PathBuf,
    /// A specific backup; the newest when absent.
    #[arg(long)]
    pub(crate) object: Option<String>,
    /// Fail when the backup is older than this many hours.
    #[arg(long, default_value_t = 24)]
    pub(crate) max_age_hours: u64,
}

/// What a restored database holds (consistency checks).
#[derive(Debug)]
pub(crate) struct Report {
    pub(crate) object: String,
    pub(crate) age_secs: u64,
    pub(crate) accounts: u64,
    pub(crate) devices: u64,
    pub(crate) orphan_devices: u64,
    pub(crate) generation: u64,
}

/// Decrypts a backup and streams it into `POST /import` of `a.store`'s database (created
/// first); returns the consistency report.
pub(crate) async fn load(a: &LoadArgs) -> Result<Report> {
    let dest = a.dest.open()?;
    let (object, stamp) = match &a.object {
        Some(o) => {
            let file = o.rsplit('/').next().unwrap_or(o);
            let secs = file
                .get(..16)
                .and_then(parse_amz_date)
                .context("backup name has no timestamp")?;
            (o.clone(), secs)
        }
        None => newest(&dest).await?,
    };
    let age_secs = now_secs().saturating_sub(stamp);
    if age_secs > a.max_age_hours * 3600 {
        bail!("the newest backup is {} hours old", age_secs / 3600);
    }
    let sealed = fetch(&dest, &object).await?;
    import(a, sealed).await?;
    check(&a.store, object, age_secs).await
}

/// Creates the target database, then streams age's output into `POST /import`.
async fn import(a: &LoadArgs, sealed: Vec<u8>) -> Result<()> {
    let db = songbird_accounts::Db::connect(a.store.config()?).await?;
    db.exec(
        &format!(
            "DEFINE DATABASE IF NOT EXISTS {};",
            sanitize_ident(&a.store.database)?
        ),
        Vec::new(),
    )
    .await?;
    let mut child = tokio::process::Command::new(&a.age)
        .arg("--decrypt")
        .arg("--identity")
        .arg(&a.identity)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", a.age.display()))?;
    let mut stdin = child.stdin.take().context("age stdin")?;
    let mut stdout = child.stdout.take().context("age stdout")?;
    let feeder = tokio::spawn(async move {
        let r = stdin.write_all(&sealed).await;
        drop(stdin);
        r
    });
    let (tx, rx) =
        tokio::sync::mpsc::channel::<std::result::Result<Frame<Bytes>, std::io::Error>>(8);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(buf.get(..n).unwrap_or_default());
                    if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });
    let body = StreamBody::new(tokio_stream_from(rx)).boxed_unsync();
    let resp = surreal_http(&a.store, hyper::Method::POST, "/import", body).await?;
    let status = resp.status();
    let answer = resp.into_body().collect().await?.to_bytes();
    feeder.await??;
    reader.await?;
    let age_status = child.wait().await?;
    if !age_status.success() {
        bail!("decryption failed (age {age_status})");
    }
    if !status.is_success() {
        bail!("SurrealDB import answered {status}");
    }
    let results: serde_json::Value =
        serde_json::from_slice(&answer).context("import answer is not JSON")?;
    let failed = results
        .as_array()
        .map_or(0, |r| r.iter().filter(|x| x["status"] != "OK").count());
    if failed > 0 {
        bail!("{failed} statements of the import failed");
    }
    Ok(())
}

/// Consistency checks on what was restored.
async fn check(store: &StoreArgs, object: String, age_secs: u64) -> Result<Report> {
    let registry = store.registry().await?;
    let counts = registry
        .db()
        .query(
            "RETURN count(SELECT id FROM account);
             RETURN count(SELECT id FROM device);
             RETURN count(SELECT id FROM device WHERE !record::exists(type::record('account', [account])));",
            Vec::new(),
        )
        .await?;
    let n = |i: usize| -> u64 {
        counts
            .get(i)
            .and_then(songbird_surreal::Value::as_i64)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(u64::MAX)
    };
    Ok(Report {
        object,
        age_secs,
        accounts: n(0),
        devices: n(1),
        orphan_devices: n(2),
        generation: registry.store_generation().await?,
    })
}

/// A mpsc receiver as a `Stream` (no extra crate).
fn tokio_stream_from<T: Send + 'static>(
    mut rx: tokio::sync::mpsc::Receiver<T>,
) -> impl futures_core::Stream<Item = T> + Send + 'static {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

/// A database name safe to place in a statement.
fn sanitize_ident(s: &str) -> Result<&str> {
    if !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        Ok(s)
    } else {
        bail!("database name must be [A-Za-z0-9_], at most 64 characters")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_follow_the_calendar() {
        let day = 86_400;
        // 2026-11-02 is a Monday.
        let mon = parse_amz_date("20261102T000500Z").unwrap();
        let first = tier_for(mon, (0, 0, 0));
        assert_eq!(first.0, "monthly");
        let again = tier_for(mon + 300, first.2);
        assert_eq!(again.0, "frequent");
        let tue = tier_for(mon + day, again.2);
        assert_eq!(tue.0, "daily");
        let next_mon = tier_for(mon + 7 * day, tue.2);
        assert_eq!(next_mon.0, "weekly");
        let dec = tier_for(parse_amz_date("20261201T000000Z").unwrap(), next_mon.2);
        assert_eq!(dec.0, "monthly");
    }

    #[test]
    fn names_parse_back_to_their_time() {
        for t in [0, 1_700_000_000, 1_763_000_123] {
            let s = songbird_s3::sigv4::amz_date(t);
            assert_eq!(parse_amz_date(&s), Some(t), "{s}");
        }
        assert_eq!(parse_amz_date("2026110XT000000Z"), None);
        assert!(sanitize_ident("songbird").is_ok());
        assert!(sanitize_ident("a; REMOVE DATABASE x").is_err());
    }
}
