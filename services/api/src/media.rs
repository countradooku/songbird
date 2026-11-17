//! Attachments (Prompt 2, D-0036; Prompt 6, D-0079 to D-0081): upload grants, single and
//! resumable uploads to `RustFS`, and downloads.
//!
//! | Request | What it does |
//! | --- | --- |
//! | `POST /v1/attachments` | A grant: `{"size", "fetches"}` → `{"id", "part_size", "parts"}`. `size` must be a length the attachment format produces (PROTOCOL §7.1), within the plan's limit and the account's budgets |
//! | `PUT /v1/attachments/<id>` | The whole ciphertext in one request |
//! | `PUT /v1/attachments/<id>/parts/<n>` | Part `n` (1-based) of a resumable upload, exactly its length |
//! | `GET /v1/attachments/<id>/parts` | The parts received: `{"part_size", "parts": [n, …]}` |
//! | `POST /v1/attachments/<id>/complete` | Assembles the parts; the grant becomes the attachment |
//! | `GET /v1/attachments/<id>` | A download |
//!
//! Every upload request is signed by the granted device (the body is the client's own
//! ciphertext and is not signed, only held to its exact length). A part streams straight into an
//! S3 `UploadPart`; nothing is buffered. Each part keeps the grant alive for its idle time, never
//! past [`songbird_accounts::GRANT_MAX_AGE`]. Object IDs never reach a log line.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::hmac;
use bytes::Bytes;
use futures_core::Stream;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::header::CONTENT_LENGTH;
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use songbird_accounts::{Grant, PendingUpload};
use songbird_jobs::ObjectKey;
use songbird_types::{AccountId, DeviceId};
use songbird_valkey::ValkeyConn;

use crate::config::MediaBudgets;
use crate::{App, Body, Refusal, empty, json, object_name};

/// Budget units: the daily volume is counted in MiB.
const UNIT: u64 = 1 << 20;

fn status(s: StatusCode) -> Refusal {
    Refusal::Status(s)
}

/// The grant request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    /// The ciphertext length.
    pub size: u64,
    /// Recipient fetches due.
    pub fetches: u32,
}

impl GrantRequest {
    /// Decodes and checks a grant request against the format and `max_bytes` / `max_fetches`.
    /// `None` for anything else: unknown fields, a length the format never produces, zero or
    /// too many fetches.
    #[must_use]
    pub fn decode(body: &[u8], max_bytes: u64, max_fetches: u32) -> Option<Self> {
        let g: GrantRequest = serde_json::from_slice(body).ok()?;
        (songbird_proto::media::padded_from_ciphertext(g.size).is_some()
            && g.size <= max_bytes
            && (1..=max_fetches).contains(&g.fetches))
        .then_some(g)
    }
}

/// How many parts an upload of `size` bytes has, in parts of `part_size`.
#[must_use]
pub fn part_count(size: u64, part_size: u64) -> u64 {
    size.div_ceil(part_size.max(1)).max(1)
}

/// The exact length of part `n` (1-based), or `None` past the last.
#[must_use]
pub fn part_len(size: u64, part_size: u64, n: u64) -> Option<u64> {
    (n >= 1 && n <= part_count(size, part_size))
        .then(|| size.saturating_sub((n - 1) * part_size).min(part_size))
}

/// `[api.media]`: the keyed budget records, and (later milestones) download URLs, packs and
/// GIFs.
pub struct Media {
    settings: MediaBudgets,
    record_key: hmac::Key,
}

impl std::fmt::Debug for Media {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Media")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// A key for one purpose, derived from the media secret.
fn derive(secret: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(hmac::sign(&k, purpose).as_ref());
    out
}

impl Media {
    /// From the settings and the media secret.
    #[must_use]
    pub fn new(settings: MediaBudgets, secret: &[u8; 32]) -> Self {
        Self {
            settings,
            record_key: hmac::Key::new(
                hmac::HMAC_SHA256,
                &derive(secret, b"songbird.v1/media-records"),
            ),
        }
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &MediaBudgets {
        &self.settings
    }

    /// A budget record: keyed, so `valkey-hot` holds no account ID (`m:<kind>:<16 bytes hex>`).
    fn record(&self, kind: &str, account: &AccountId) -> String {
        let mut ctx = hmac::Context::with_key(&self.record_key);
        ctx.update(kind.as_bytes());
        ctx.update(&[0]);
        ctx.update(account.as_bytes());
        format!(
            "m:{kind}:{}",
            hex::encode(ctx.sign().as_ref().get(..16).unwrap_or_default())
        )
    }

    async fn spend(
        hot: &ValkeyConn,
        record: &str,
        interval_us: u64,
        burst: u64,
        cost: u64,
    ) -> Result<u64, ()> {
        hot.query::<i64>(
            redis::cmd("EVAL")
                .arg(songbird_send::gate::GCRA_COST)
                .arg(1)
                .arg(record)
                .arg(interval_us)
                .arg(interval_us.saturating_mul(burst.max(1)))
                .arg(cost.max(1)),
        )
        .await
        .map(|w| u64::try_from(w).unwrap_or(0))
        .map_err(|_| ())
    }

    /// Spends one grant and `size` bytes of the account's budgets. `Ok(0)` when allowed, else
    /// the wait in microseconds.
    ///
    /// # Errors
    /// `valkey-hot` is unreachable.
    pub(crate) async fn admit_grant(
        &self,
        hot: &ValkeyConn,
        account: &AccountId,
        size: u64,
    ) -> Result<u64, ()> {
        let s = &self.settings;
        let per_hour = u64::from(s.grants_per_hour.max(1));
        let wait = Self::spend(
            hot,
            &self.record("g", account),
            3_600_000_000 / per_hour,
            u64::from(s.grant_burst),
            1,
        )
        .await?;
        if wait > 0 {
            return Ok(wait);
        }
        let units = (s.bytes_per_day / UNIT).max(1);
        Self::spend(
            hot,
            &self.record("b", account),
            86_400_000_000 / units,
            units,
            size.div_ceil(UNIT),
        )
        .await
    }
}

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct MediaMetrics {
    /// Parts of resumable uploads stored.
    pub parts: songbird_service::telemetry::sharded::ShardedCounter,
    /// Grants refused by a budget.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
}

impl MediaMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            (
                "api_upload_parts",
                "Parts of resumable uploads stored",
                &self.parts,
            ),
            (
                "api_grants_throttled",
                "Upload grants refused by a budget",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// `/v1/attachments…`.
pub(crate) async fn route(
    app: &Arc<App>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Refusal> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let rest = path.strip_prefix("/v1/attachments").unwrap_or_default();
    if rest.is_empty() {
        return if method == Method::POST {
            grant(app, req).await
        } else {
            Err(status(StatusCode::NOT_FOUND))
        };
    }
    let rest = rest
        .strip_prefix('/')
        .ok_or(status(StatusCode::NOT_FOUND))?;
    let (id, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let object = ObjectKey::parse_hex(id).ok_or(status(StatusCode::NOT_FOUND))?;
    match (&method, tail) {
        (&Method::PUT, "") => upload(app, req, object).await,
        (&Method::GET, "") => {
            let (_, _) = app.authenticate_json(req).await?;
            app.download(object).await
        }
        (&Method::GET, "parts") => list(app, req, object).await,
        (&Method::POST, "complete") => complete(app, req, object).await,
        (&Method::PUT, t) => {
            let n = t
                .strip_prefix("parts/")
                .and_then(|n| n.parse::<u16>().ok())
                .ok_or(status(StatusCode::NOT_FOUND))?;
            put_part(app, req, object, n).await
        }
        _ => Err(status(StatusCode::NOT_FOUND)),
    }
}

async fn grant(app: &Arc<App>, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
    let (device, body) = app.authenticate_json(req).await?;
    let l = &app.limits;
    let g = GrantRequest::decode(&body, l.max_bytes, l.max_fetches)
        .ok_or(status(StatusCode::BAD_REQUEST))?;
    if let Some(m) = &app.media {
        let account = account_of(app, &device).await?;
        match m.admit_grant(&app.hot, &account, g.size).await {
            Ok(0) => {}
            Ok(wait) => {
                app.metrics.media.throttled.inc();
                return Ok(crate::retry_after(wait));
            }
            Err(()) => return Err(status(StatusCode::SERVICE_UNAVAILABLE)),
        }
    }
    let object = ObjectKey::random().map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    app.registry
        .create_grant(
            &object,
            &Grant {
                device,
                size: g.size,
                fetches: g.fetches,
            },
            Duration::from_secs(l.grant_ttl_secs),
        )
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok(json(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": object.to_hex_unredacted(),
            "part_size": l.part_size,
            "parts": part_count(g.size, l.part_size),
        }),
    ))
}

async fn account_of(app: &App, device: &DeviceId) -> Result<AccountId, Refusal> {
    app.registry
        .device(device)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
        .map(|r| r.account)
        .ok_or(status(StatusCode::UNAUTHORIZED))
}

/// The granted device's pending upload, or 404 for anyone else (an unknown ID and someone
/// else's grant look the same).
async fn pending(
    app: &App,
    parts: &hyper::http::request::Parts,
    object: &ObjectKey,
) -> Result<PendingUpload, Refusal> {
    // The body is the client's own ciphertext: unsigned, held to its exact length.
    let device = app
        .verify(&parts.method, parts.uri.path(), &parts.headers, &[0; 32])
        .await?;
    app.registry
        .pending_upload(object)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
        .filter(|p| p.grant.device == device)
        .ok_or(status(StatusCode::NOT_FOUND))
}

fn content_length(parts: &hyper::http::request::Parts) -> Option<u64> {
    parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}

async fn upload(
    app: &Arc<App>,
    req: Request<Incoming>,
    object: ObjectKey,
) -> Result<Response<Body>, Refusal> {
    let (parts, body) = req.into_parts();
    let p = pending(app, &parts, &object).await?;
    let size = p.grant.size;
    if content_length(&parts) != Some(size) {
        return Err(status(StatusCode::BAD_REQUEST));
    }
    match app
        .s3
        .put_object(&object_name(&object), size, body.into_data_stream())
        .await
    {
        Ok(()) => {}
        Err(songbird_s3::Error::LengthMismatch | songbird_s3::Error::BodySource) => {
            return Err(status(StatusCode::BAD_REQUEST));
        }
        Err(_) => return Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
    finish(app, &object).await
}

/// The grant becomes the attachment record; an object whose grant expired meanwhile goes.
async fn finish(app: &App, object: &ObjectKey) -> Result<Response<Body>, Refusal> {
    let done = app
        .registry
        .complete_upload(object)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    if !done {
        let _ = app.s3.delete_object(&object_name(object)).await;
        return Err(status(StatusCode::NOT_FOUND));
    }
    app.metrics.uploads.inc();
    Ok(empty(StatusCode::CREATED))
}

/// The grant's multipart upload, opened on first use. Two first parts racing open two; the
/// registry keeps one and the loser is aborted.
async fn open(app: &App, object: &ObjectKey, p: &PendingUpload) -> Result<String, Refusal> {
    if let Some(u) = &p.upload {
        return Ok(u.clone());
    }
    let name = object_name(object);
    let mine = app
        .s3
        .create_multipart_upload(&name)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    let kept = app
        .registry
        .set_grant_upload(object, &mine)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    if kept.as_deref() != Some(mine.as_str()) {
        let _ = app.s3.abort_multipart_upload(&name, &mine).await;
    }
    kept.ok_or(status(StatusCode::NOT_FOUND))
}

/// Parts the store holds with exactly their expected length, in order.
async fn received(
    app: &App,
    object: &ObjectKey,
    p: &PendingUpload,
) -> Result<Vec<songbird_s3::multipart::Part>, Refusal> {
    let Some(upload) = &p.upload else {
        return Ok(Vec::new());
    };
    let part_size = app.limits.part_size;
    match app.s3.list_parts(&object_name(object), upload).await {
        Ok(parts) => Ok(parts
            .into_iter()
            .filter(|x| part_len(p.grant.size, part_size, u64::from(x.number)) == Some(x.size))
            .collect()),
        Err(songbird_s3::Error::NotFound) => Err(status(StatusCode::NOT_FOUND)),
        Err(_) => Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
}

async fn put_part(
    app: &Arc<App>,
    req: Request<Incoming>,
    object: ObjectKey,
    n: u16,
) -> Result<Response<Body>, Refusal> {
    let (parts, body) = req.into_parts();
    let p = pending(app, &parts, &object).await?;
    let len = part_len(p.grant.size, app.limits.part_size, u64::from(n))
        .ok_or(status(StatusCode::NOT_FOUND))?;
    if content_length(&parts) != Some(len) {
        return Err(status(StatusCode::BAD_REQUEST));
    }
    let upload = open(app, &object, &p).await?;
    send_part(app, &object, &upload, n, len, body.into_data_stream()).await?;
    Ok(empty(StatusCode::NO_CONTENT))
}

async fn send_part<S, E>(
    app: &App,
    object: &ObjectKey,
    upload: &str,
    n: u16,
    len: u64,
    body: S,
) -> Result<(), Refusal>
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: 'static,
{
    match app
        .s3
        .upload_part(&object_name(object), upload, n, len, body)
        .await
    {
        Ok(_) => {}
        Err(songbird_s3::Error::LengthMismatch | songbird_s3::Error::BodySource) => {
            return Err(status(StatusCode::BAD_REQUEST));
        }
        Err(songbird_s3::Error::NotFound) => return Err(status(StatusCode::NOT_FOUND)),
        Err(_) => return Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
    app.metrics.media.parts.inc();
    app.registry
        .touch_grant(object, Duration::from_secs(app.limits.grant_ttl_secs))
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))
}

async fn list(
    app: &Arc<App>,
    req: Request<Incoming>,
    object: ObjectKey,
) -> Result<Response<Body>, Refusal> {
    let (parts, _) = req.into_parts();
    let p = pending(app, &parts, &object).await?;
    let got: Vec<u16> = received(app, &object, &p)
        .await?
        .iter()
        .map(|x| x.number)
        .collect();
    Ok(json(
        StatusCode::OK,
        &serde_json::json!({ "part_size": app.limits.part_size, "parts": got }),
    ))
}

async fn complete(
    app: &Arc<App>,
    req: Request<Incoming>,
    object: ObjectKey,
) -> Result<Response<Body>, Refusal> {
    let (parts, _) = req.into_parts();
    let p = pending(app, &parts, &object).await?;
    assemble(app, &object, &p).await
}

/// Completes the multipart upload if every part is there with its exact length; 409 otherwise.
async fn assemble(
    app: &App,
    object: &ObjectKey,
    p: &PendingUpload,
) -> Result<Response<Body>, Refusal> {
    let upload = p.upload.as_deref().ok_or(status(StatusCode::CONFLICT))?;
    let got = received(app, object, p).await?;
    let want = part_count(p.grant.size, app.limits.part_size);
    let complete = u64::try_from(got.len()).is_ok_and(|n| n == want)
        && got.iter().zip(1u16..).all(|(x, n)| x.number == n);
    if !complete {
        return Err(status(StatusCode::CONFLICT));
    }
    match app
        .s3
        .complete_multipart_upload(&object_name(object), upload, &got)
        .await
    {
        Ok(()) => {}
        Err(songbird_s3::Error::NotFound) => return Err(status(StatusCode::NOT_FOUND)),
        Err(_) => return Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
    finish(app, object).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn parts_cover_the_upload_exactly() {
        let p = 8 << 20;
        assert_eq!(part_count(1_073, p), 1);
        assert_eq!(part_len(1_073, p, 1), Some(1_073));
        assert_eq!(part_len(1_073, p, 2), None);
        assert_eq!(part_len(1_073, p, 0), None);
        let size = 3 * p + 17;
        assert_eq!(part_count(size, p), 4);
        let total: u64 = (1..=4).map(|n| part_len(size, p, n).unwrap()).sum();
        assert_eq!(total, size);
        assert_eq!(part_len(size, p, 4), Some(17));
        assert_eq!(part_count(2 * p, p), 2);
        assert_eq!(part_len(2 * p, p, 2), Some(p));
    }

    #[test]
    fn grant_requests_hold_the_format_and_the_limits() {
        let legal = songbird_proto::media::ciphertext_len(5_000).unwrap();
        let ok = format!(r#"{{"size":{legal},"fetches":3}}"#);
        assert_eq!(
            GrantRequest::decode(ok.as_bytes(), 1 << 30, 1024),
            Some(GrantRequest {
                size: legal,
                fetches: 3
            })
        );
        for bad in [
            format!(r#"{{"size":{},"fetches":3}}"#, legal + 1),
            format!(r#"{{"size":{legal},"fetches":0}}"#),
            format!(r#"{{"size":{legal},"fetches":1025}}"#),
            format!(r#"{{"size":{legal},"fetches":1,"x":1}}"#),
            r#"{"size":4096,"fetches":1}"#.to_owned(),
            "[]".to_owned(),
        ] {
            assert_eq!(
                GrantRequest::decode(bad.as_bytes(), 1 << 30, 1024),
                None,
                "{bad}"
            );
        }
        assert_eq!(GrantRequest::decode(ok.as_bytes(), legal - 1, 1024), None);
    }

    #[test]
    fn budget_records_are_keyed_and_reveal_no_account() {
        let m = Media::new(MediaBudgets::default(), &[7; 32]);
        let a = AccountId::random().unwrap();
        let r = m.record("b", &a);
        assert!(r.starts_with("m:b:") && r.len() == 4 + 32);
        assert!(!r.contains(&a.to_hex_unredacted()));
        assert_ne!(r, m.record("g", &a));
        assert_ne!(
            r,
            Media::new(MediaBudgets::default(), &[8; 32]).record("b", &a)
        );
    }
}
