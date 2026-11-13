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
    /// S3 signing region (the Hetzner location, D-0042).
    #[arg(long, default_value = "hel1")]
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

/// A private scratch directory for the encrypted file before upload, inside `base` (the state
/// file's directory, which belongs to the backup job alone: never a shared temporary directory).
/// Created exclusively with a random name and mode 0700 from the start, removed when dropped.
/// (Standard library only: no extra crate in a binary that runs on production hosts.)
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_dir(base: &Path) -> Result<PrivateDir> {
    let id = songbird_types::DeviceId::random()?;
    let path = base.join(format!(".scratch-{}", hex::encode(id.as_bytes())));
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    // `create`, not `create_all`: fails if the name exists (never reuses another's directory).
    b.create(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(PrivateDir(path))
}

#[cfg(all(test, unix))]
mod private_dir_tests {
    #[test]
    fn private_and_removed() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = tempfile::tempdir().unwrap();
        let d = super::private_dir(base.path()).unwrap();
        let p = d.path().to_path_buf();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::write(p.join("x"), b"y").unwrap();
        drop(d);
        assert!(!p.exists());
    }
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
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", &cfg.host)
        .header("authorization", format!("Basic {auth}"))
        .header("surreal-ns", &cfg.namespace)
        .header("surreal-db", &cfg.database)
        .header("accept", "application/json");
    if store.database_user {
        // Where the user is defined (the selected namespace and database are separate).
        req = req
            .header("surreal-auth-ns", &cfg.namespace)
            .header("surreal-auth-db", &cfg.database);
    }
    let req = req.body(body)?;
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
    let base = match a.state.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let dir = private_dir(&base)?;
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
/// Every stored backup: (name, stored version, when the server stored it). On S3 every version
/// of every name is listed, with the server's own time (the uploader cannot choose it); in a
/// directory the name's time stands in for it.
async fn listing(dest: &Dest, prefix: &str) -> Result<Vec<(String, Option<String>, u64)>> {
    let mut out = Vec::new();
    match dest {
        Dest::Dir(root) => {
            for tier in TIERS.map(|(t, _)| t) {
                let dir = root.join("registry").join(tier);
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for e in rd.flatten() {
                    let Some(n) = e
                        .file_name()
                        .to_str()
                        .map(|n| format!("registry/{tier}/{n}"))
                    else {
                        continue;
                    };
                    if let Some(t) = name_secs(&n).filter(|_| n.starts_with(prefix)) {
                        out.push((n, None, t));
                    }
                }
            }
        }
        Dest::S3(c) => {
            let (mut key, mut version): (Option<String>, Option<String>) = (None, None);
            loop {
                let page = c
                    .list_object_versions(prefix, key.as_deref(), version.as_deref(), 1000)
                    .await?;
                for v in page.versions {
                    let t = parse_iso8601(&v.last_modified)
                        .context("a stored version has no usable LastModified")?;
                    out.push((v.key, Some(v.version_id), t));
                }
                if !page.is_truncated {
                    break;
                }
                key = page.next_key_marker;
                version = page.next_version_id_marker;
            }
        }
    }
    Ok(out)
}

/// Greatest distance between the time in a backup's name and the time the server stored it.
const MAX_SKEW_SECS: u64 = 600;

/// The backup a restore reads.
#[derive(Debug, PartialEq, Eq)]
struct Chosen {
    name: String,
    version: Option<String>,
    stamp: u64,
}

/// Signs of tampering in the listing (D-0040): the writer key can put but not delete, so a name
/// written twice, or a backup whose name claims another time than the server's, was not written
/// by the backup timer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Integrity {
    /// Names with more than one stored version: only the earliest is ever read.
    pub(crate) overwritten: usize,
    /// Backups whose name and stored time differ by more than `MAX_SKEW_SECS`: never read.
    pub(crate) misdated: usize,
}

/// Picks the newest trustworthy backup stored before `before`: for each name its earliest
/// version, then the latest of those by the server's time.
fn select(
    entries: Vec<(String, Option<String>, u64)>,
    before: Option<u64>,
) -> Result<(Chosen, Integrity)> {
    let mut by_name: std::collections::BTreeMap<String, Vec<(Option<String>, u64)>> =
        std::collections::BTreeMap::new();
    for (name, version, t) in entries {
        by_name.entry(name).or_default().push((version, t));
    }
    let mut integrity = Integrity::default();
    let mut best: Option<Chosen> = None;
    for (name, mut versions) in by_name {
        versions.sort_by_key(|(_, t)| *t);
        if versions.len() > 1 {
            integrity.overwritten += 1;
        }
        let Some((version, stored)) = versions.into_iter().next() else {
            continue;
        };
        match name_secs(&name) {
            Some(n) if n.abs_diff(stored) <= MAX_SKEW_SECS => {}
            _ => {
                integrity.misdated += 1;
                continue;
            }
        }
        if before.is_some_and(|b| stored >= b) {
            continue;
        }
        if best.as_ref().is_none_or(|c| stored > c.stamp) {
            best = Some(Chosen {
                name,
                version,
                stamp: stored,
            });
        }
    }
    Ok((best.context("no backup found")?, integrity))
}

/// The time in a backup's name (`registry/<tier>/<YYYYMMDDTHHMMSSZ>-<id>.surql.age`).
fn name_secs(name: &str) -> Option<u64> {
    name.rsplit('/').next()?.get(..16).and_then(parse_amz_date)
}

/// Parses S3's `LastModified` (`2026-11-13T10:05:00.000Z`) to Unix seconds.
fn parse_iso8601(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let ok = b.len() >= 20
        && b.get(4) == Some(&b'-')
        && b.get(7) == Some(&b'-')
        && b.get(10) == Some(&b'T')
        && b.get(13) == Some(&b':')
        && b.get(16) == Some(&b':')
        && s.ends_with('Z');
    if !ok {
        return None;
    }
    let compact = format!(
        "{}{}{}T{}{}{}Z",
        s.get(0..4)?,
        s.get(5..7)?,
        s.get(8..10)?,
        s.get(11..13)?,
        s.get(14..16)?,
        s.get(17..19)?
    );
    parse_amz_date(&compact)
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

async fn fetch(dest: &Dest, chosen: &Chosen) -> Result<Vec<u8>> {
    match dest {
        Dest::Dir(root) => Ok(tokio::fs::read(root.join(&chosen.name)).await?),
        Dest::S3(c) => {
            let version = chosen
                .version
                .as_deref()
                .context("a stored backup without a version")?;
            let mut obj = c.get_object_version(&chosen.name, version).await?;
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
    /// Only backups stored before this time (`YYYYMMDDTHHMMSSZ`): restore from before a mistake
    /// or a compromise.
    #[arg(long)]
    pub(crate) before: Option<String>,
}

/// What a restored database holds (consistency checks).
#[derive(Debug)]
pub(crate) struct Report {
    pub(crate) object: String,
    pub(crate) age_secs: u64,
    /// How many account rows were restored (a count, never an identifier).
    pub(crate) registered: u64,
    /// How many device rows were restored.
    pub(crate) device_rows: u64,
    /// Device rows whose account row is missing (must be 0).
    pub(crate) orphans: u64,
    pub(crate) generation: u64,
    pub(crate) integrity: Integrity,
}

/// Decrypts a backup and streams it into `POST /import` of `a.store`'s database (created
/// first); returns the consistency report.
pub(crate) async fn load(a: &LoadArgs) -> Result<Report> {
    let dest = a.dest.open()?;
    let before = a
        .before
        .as_deref()
        .map(|b| parse_amz_date(b).context("--before is YYYYMMDDTHHMMSSZ"))
        .transpose()?;
    let prefix = a.object.as_deref().unwrap_or("registry/");
    let (chosen, integrity) = select(listing(&dest, prefix).await?, before)?;
    if a.object.as_deref().is_some_and(|o| o != chosen.name) {
        bail!("no such backup");
    }
    let age_secs = now_secs().saturating_sub(chosen.stamp);
    if age_secs > a.max_age_hours * 3600 {
        bail!("the newest backup is {} hours old", age_secs / 3600);
    }
    let sealed = fetch(&dest, &chosen).await?;
    import(a, sealed).await?;
    let mut report = check(&a.store, chosen.name, age_secs).await?;
    report.integrity = integrity;
    Ok(report)
}

/// `backup restore`: the deletion journal (D-0041).
#[derive(Debug, Clone, Args)]
pub(crate) struct JournalArgs {
    /// Environment variable holding the journal key (64 hex characters).
    #[arg(long, default_value = "DELETION_JOURNAL_KEY")]
    pub(crate) journal_key_env: String,
    /// Restore without re-deleting journaled accounts (audit-logged; only when the journal is
    /// lost or untrusted).
    #[arg(long)]
    pub(crate) no_journal: bool,
}

/// The tags of every tombstone (stored before `before`, by the server's time on S3). Their age
/// does not matter: account IDs are random and never reused, so a restored account with a
/// tombstone is one whose deletion the restore undid, or one still being deleted at the backup.
async fn tombstones(
    dest: &Dest,
    before: Option<u64>,
) -> Result<std::collections::HashSet<[u8; 32]>> {
    use songbird_accounts::journal;
    let mut stamped: Vec<(String, u64)> = Vec::new();
    match dest {
        Dest::Dir(root) => {
            if let Ok(rd) = std::fs::read_dir(root.join("deletions")) {
                for e in rd.flatten() {
                    if let Some(n) = e.file_name().to_str() {
                        let name = format!("{}{n}", journal::PREFIX);
                        if let Some(t) = n.get(..16).and_then(parse_amz_date) {
                            stamped.push((name, t));
                        }
                    }
                }
            }
        }
        Dest::S3(_) => {
            for (name, _, t) in listing(dest, journal::PREFIX).await? {
                stamped.push((name, t));
            }
        }
    }
    Ok(stamped
        .into_iter()
        .filter(|(_, t)| before.is_none_or(|b| *t < b))
        .filter_map(|(n, _)| journal::parse_tombstone(&n))
        .collect())
}

/// Starts the deletion again (through the outbox, so the worker clears every store) of every
/// restored account with a tombstone. Returns how many.
impl JournalArgs {
    /// The journal key, read before anything is restored (a restore that cannot re-delete must
    /// not start).
    pub(crate) fn key(&self) -> Result<[u8; 32]> {
        let hex_key = std::env::var(&self.journal_key_env).with_context(|| {
            format!(
                "{} is not set: the journal key is needed so deleted accounts stay deleted \
                 (or --no-journal)",
                self.journal_key_env
            )
        })?;
        let mut key = [0u8; 32];
        hex::decode_to_slice(hex_key.trim(), &mut key).context("journal key: 64 hex characters")?;
        Ok(key)
    }
}

pub(crate) async fn reapply_deletions(a: &LoadArgs, key: &[u8; 32]) -> Result<usize> {
    let before = a
        .before
        .as_deref()
        .map(|b| parse_amz_date(b).context("--before is YYYYMMDDTHHMMSSZ"))
        .transpose()?;
    let tags = tombstones(&a.dest.open()?, before).await?;
    if tags.is_empty() {
        return Ok(0);
    }
    let registry = a.store.registry().await?;
    let mut matched = Vec::new();
    let mut start = 0;
    loop {
        let page = registry.accounts_page(start, 10_000).await?;
        if page.is_empty() {
            break;
        }
        start += page.len();
        matched.extend(
            page.into_iter()
                .filter(|acc| tags.contains(&songbird_accounts::journal::tag(key, acc))),
        );
    }
    for account in &matched {
        let job =
            songbird_jobs::Job::new(songbird_jobs::Work::DeleteAccount { account: *account })?;
        registry.begin_account_deletion(account, &job).await?;
    }
    Ok(matched.len())
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
    // Only into an empty database: an import over existing records has no defined result.
    let tables = db
        .query("RETURN object::len((INFO FOR DB).tables);", Vec::new())
        .await?
        .first()
        .and_then(songbird_surreal::Value::as_i64);
    if tables != Some(0) {
        bail!(
            "the database {} is not empty: restore into a removed or new database (runbook \
             docs/RUNBOOKS/backup-and-restore.md)",
            a.store.database
        );
    }
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
        registered: n(0),
        device_rows: n(1),
        orphans: n(2),
        generation: registry.store_generation().await?,
        integrity: Integrity::default(),
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
    fn restores_read_the_earliest_version_and_skip_forgeries() {
        let t = parse_amz_date("20261113T100000Z").unwrap();
        let name = |secs: u64| {
            format!(
                "registry/frequent/{}-00000000.surql.age",
                songbird_s3::sigv4::amz_date(secs)
            )
        };
        let v = |s: &str| Some(s.to_owned());
        let entries = vec![
            (name(t), v("a1"), t + 2),
            // Overwritten later by someone holding the put-only key: the original is read.
            (name(t + 300), v("b1"), t + 301),
            (name(t + 300), v("b2-forged"), t + 4000),
            // Named for a time it was not stored at: never read.
            (name(t + 9000), v("c1"), t + 600),
        ];
        let (c, i) = select(entries.clone(), None).unwrap();
        assert_eq!(
            (c.name, c.version, c.stamp),
            (name(t + 300), v("b1"), t + 301)
        );
        assert_eq!(
            i,
            Integrity {
                overwritten: 1,
                misdated: 1
            }
        );
        // Before a compromise at t + 100: the earlier one.
        let (c, _) = select(entries, Some(t + 100)).unwrap();
        assert_eq!(c.version, v("a1"));
        assert!(select(Vec::new(), None).is_err());
        assert_eq!(parse_iso8601("2026-11-13T10:00:00.000Z"), Some(t));
        assert_eq!(parse_iso8601("2026-11-13 10:00:00"), None);
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
