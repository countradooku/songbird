//! Packs (Prompt 6, M4; D-0079 §3, D-0083): one service for sticker packs, chat scenes, sound
//! stickers and emoticon packs. The server stores an encrypted manifest and encrypted assets, and
//! never holds the key (it travels in the share link's fragment).
//!
//! | Request | What it does |
//! | --- | --- |
//! | `POST /v1/packs` | `{"sizes": [manifest, asset 1, …], "token": <64 hex: SHA-256 of the management token>}` → `{"pack": <32 hex>, "objects": n}`. Signed by the creating device; charged to its account's budgets |
//! | `PUT /v1/packs/<pack>/<n>` | Object `n` (0 the manifest), exactly its size; the creating device only |
//! | `POST /v1/packs/<pack>/complete` | Every object checked in the store; the pack becomes fetchable and forgets its creator |
//! | `GET /v1/packs/<pack>/<n>` | No account: a 303 to the object's signed media URL |
//! | `DELETE /v1/packs/<pack>` | No account: `x-songbird-pack-token: <64 hex>`, the management token itself |

use std::sync::Arc;

use aws_lc_rs::digest;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use songbird_accounts::packs::{MAX_PACK_OBJECTS, PackRow};
use songbird_jobs::{Job, ObjectKey, Work};

use crate::media::{Media, account_of, now_secs, peer, throttle};
use crate::{App, Body, Refusal, empty, json, object_name};

/// Largest object in a pack (the manifest or one asset): one part.
pub const MAX_OBJECT_BYTES: u64 = 16 << 20;
/// Largest pack, all objects together (D-0079 §3).
pub const MAX_PACK_BYTES: u64 = 300 << 20;
/// The header carrying the management token on deletion.
pub const TOKEN_HEADER: &str = "x-songbird-pack-token";

fn status(s: StatusCode) -> Refusal {
    Refusal::Status(s)
}

/// A pack creation request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRequest {
    /// Each object's exact ciphertext size, the manifest first.
    pub sizes: Vec<u64>,
    /// SHA-256 of the management token (64 hex).
    pub token: String,
}

impl PackRequest {
    /// Decodes and checks a creation request: 2 to 201 objects, each a length the attachment
    /// format produces and at most [`MAX_OBJECT_BYTES`], [`MAX_PACK_BYTES`] in all, and a
    /// 32-byte token hash. Returns the sizes, their total and the hash.
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<(Vec<u64>, u64, [u8; 32])> {
        let r: PackRequest = serde_json::from_slice(body).ok()?;
        if !(2..=MAX_PACK_OBJECTS).contains(&r.sizes.len()) {
            return None;
        }
        let mut total = 0u64;
        for s in &r.sizes {
            songbird_proto::media::padded_from_ciphertext(*s)?;
            if *s > MAX_OBJECT_BYTES {
                return None;
            }
            total = total.checked_add(*s)?;
        }
        if total > MAX_PACK_BYTES || r.token.len() != 64 {
            return None;
        }
        let mut token = [0u8; 32];
        hex::decode_to_slice(&r.token, &mut token).ok()?;
        Some((r.sizes, total, token))
    }
}

fn pack_id(hex_id: &str) -> Option<[u8; 16]> {
    let mut p = [0u8; 16];
    (hex_id.len() == 32 && hex::decode_to_slice(hex_id, &mut p).is_ok()).then_some(p)
}

/// `/v1/packs…`.
pub(crate) async fn route(
    app: &Arc<App>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Refusal> {
    let m = app
        .media
        .as_ref()
        .ok_or(status(StatusCode::SERVICE_UNAVAILABLE))?;
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let rest = path.strip_prefix("/v1/packs").unwrap_or_default();
    if rest.is_empty() {
        return if method == Method::POST {
            create(app, m, req).await
        } else {
            Err(status(StatusCode::NOT_FOUND))
        };
    }
    let rest = rest
        .strip_prefix('/')
        .ok_or(status(StatusCode::NOT_FOUND))?;
    let (id, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let pack = pack_id(id).ok_or(status(StatusCode::NOT_FOUND))?;
    match (&method, tail) {
        (&Method::DELETE, "") => delete(app, m, &req, &pack).await,
        (&Method::POST, "complete") => complete(app, req, &pack).await,
        (&Method::PUT | &Method::GET, n) => {
            let n = n
                .parse::<usize>()
                .ok()
                .filter(|n| *n < MAX_PACK_OBJECTS)
                .ok_or(status(StatusCode::NOT_FOUND))?;
            if method == Method::PUT {
                upload(app, req, &pack, n).await
            } else {
                fetch(app, m, &req, &pack, n).await
            }
        }
        _ => Err(status(StatusCode::NOT_FOUND)),
    }
}

async fn create(
    app: &Arc<App>,
    m: &Media,
    req: Request<Incoming>,
) -> Result<Response<Body>, Refusal> {
    let (device, body) = app.authenticate_json(req).await?;
    let (sizes, total, token) =
        PackRequest::decode(&body).ok_or(status(StatusCode::BAD_REQUEST))?;
    let account = account_of(app, &device).await?;
    let level = app.plans.level(&account);
    let plan = *app.plans.catalog.limits(level);
    // New packs per 30 days are the plan's (D-0127); the pack forgets its creator once complete,
    // so the budget is all the server can count.
    match m
        .admit_pack(&app.hot, &account, level, plan.packs_per_month)
        .await
    {
        Ok(0) => {}
        Ok(wait) => {
            app.metrics.media.throttled.inc();
            let mut r = json(
                StatusCode::TOO_MANY_REQUESTS,
                &serde_json::json!({ "error": "plan", "packs_per_month": plan.packs_per_month }),
            );
            if let Ok(v) = HeaderValue::from_str(&wait.div_ceil(1_000_000).max(1).to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            return Ok(r);
        }
        Err(()) => return Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
    match m
        .admit_grant(
            &app.hot,
            &account,
            total,
            (level, plan.upload_bytes_per_day),
        )
        .await
    {
        Ok(0) => {}
        Ok(wait) => {
            app.metrics.media.throttled.inc();
            return Ok(crate::retry_after(wait));
        }
        Err(()) => return Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
    let mut pack = [0u8; 16];
    aws_lc_rs::rand::fill(&mut pack).map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    let objects = sizes
        .iter()
        .map(|_| ObjectKey::random())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    app.registry
        .create_pack(&pack, &objects, &sizes, &device, &token)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok(json(
        StatusCode::CREATED,
        &serde_json::json!({ "pack": hex::encode(pack), "objects": objects.len() }),
    ))
}

/// The unfinished pack the signing device is uploading, or 404.
async fn pending(
    app: &App,
    parts: &hyper::http::request::Parts,
    pack: &[u8; 16],
) -> Result<PackRow, Refusal> {
    let device = app
        .verify(&parts.method, parts.uri.path(), &parts.headers, &[0; 32])
        .await?;
    app.registry
        .pack(pack)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
        .filter(|p| !p.done && p.device == Some(device))
        .ok_or(status(StatusCode::NOT_FOUND))
}

async fn upload(
    app: &Arc<App>,
    req: Request<Incoming>,
    pack: &[u8; 16],
    n: usize,
) -> Result<Response<Body>, Refusal> {
    let (parts, body) = req.into_parts();
    let p = pending(app, &parts, pack).await?;
    let (object, size) = p
        .objects
        .get(n)
        .zip(p.sizes.get(n))
        .ok_or(status(StatusCode::NOT_FOUND))?;
    let declared = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared != Some(*size) {
        return Err(status(StatusCode::BAD_REQUEST));
    }
    // Retries yes, endless rewrites no (D-0084).
    let most = 2 * u64::try_from(p.objects.len()).unwrap_or(u64::MAX) + 8;
    if !app
        .registry
        .spend_pack_put(pack, most)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
    {
        return Err(status(StatusCode::CONFLICT));
    }
    match app
        .s3
        .put_object(&object_name(object), *size, body.into_data_stream())
        .await
    {
        Ok(()) => {
            // The pack may have been deleted or expired while this streamed: then nothing refers to
            // the object any more (D-0084). A pack completed meanwhile keeps it: that race is the
            // creator's own, and deleting would break a finished pack.
            let still = app
                .registry
                .pack(pack)
                .await
                .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
                .is_some();
            if still {
                Ok(empty(StatusCode::CREATED))
            } else {
                let _ = app.s3.delete_object(&object_name(object)).await;
                Err(status(StatusCode::NOT_FOUND))
            }
        }
        Err(songbird_s3::Error::LengthMismatch | songbird_s3::Error::BodySource) => {
            Err(status(StatusCode::BAD_REQUEST))
        }
        Err(_) => Err(status(StatusCode::SERVICE_UNAVAILABLE)),
    }
}

async fn complete(
    app: &Arc<App>,
    req: Request<Incoming>,
    pack: &[u8; 16],
) -> Result<Response<Body>, Refusal> {
    let (parts, _) = req.into_parts();
    let p = pending(app, &parts, pack).await?;
    for (object, size) in p.objects.iter().zip(&p.sizes) {
        let meta = app
            .s3
            .head_object(&object_name(object))
            .await
            .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
        if meta.map(|m| m.length) != Some(*size) {
            return Err(status(StatusCode::CONFLICT));
        }
    }
    if !app
        .registry
        .complete_pack(pack)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
    {
        return Err(status(StatusCode::NOT_FOUND));
    }
    app.metrics.media.packs.inc();
    Ok(empty(StatusCode::CREATED))
}

async fn fetch(
    app: &App,
    m: &Media,
    req: &Request<Incoming>,
    pack: &[u8; 16],
    n: usize,
) -> Result<Response<Body>, Refusal> {
    if let Some(r) = throttle(app, m, "d", peer(req)?).await {
        return Ok(r);
    }
    let p = app
        .registry
        .pack(pack)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
        .filter(|p| p.done)
        .ok_or(status(StatusCode::NOT_FOUND))?;
    let (object, size) = p
        .objects
        .get(n)
        .zip(p.sizes.get(n))
        .ok_or(status(StatusCode::NOT_FOUND))?;
    // Any fetch keeps the pack alive; the record moves at most once a day (its lifetime).
    app.registry
        .touch_pack(pack)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?;
    let url = m.media_url(object, *size, now_secs() + m.url_ttl());
    let mut r = empty(StatusCode::SEE_OTHER);
    r.headers_mut().insert(
        hyper::header::LOCATION,
        HeaderValue::from_str(&url).map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?,
    );
    r.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(r)
}

async fn delete(
    app: &App,
    m: &Media,
    req: &Request<Incoming>,
    pack: &[u8; 16],
) -> Result<Response<Body>, Refusal> {
    if let Some(r) = throttle(app, m, "f", peer(req)?).await {
        return Ok(r);
    }
    let mut token = [0u8; 32];
    req.headers()
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|t| t.len() == 64)
        .and_then(|t| hex::decode_to_slice(t, &mut token).ok())
        .ok_or(status(StatusCode::NOT_FOUND))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest::digest(&digest::SHA256, &token).as_ref());
    let objects = app
        .registry
        .delete_pack(pack, &hash)
        .await
        .map_err(|_| status(StatusCode::SERVICE_UNAVAILABLE))?
        .ok_or(status(StatusCode::NOT_FOUND))?;
    // The objects go through the cleanup stream (the sweep catches a lost job: their pack row is
    // gone, so nothing references them; they are also deleted here when the store answers).
    let jobs: Vec<Job> = objects
        .iter()
        .filter_map(|o| Job::new(Work::DeleteObject { object: *o }).ok())
        .collect();
    if app.queue.enqueue(&jobs).await.is_err() {
        for o in &objects {
            let _ = app.s3.delete_object(&object_name(o)).await;
        }
    }
    Ok(empty(StatusCode::NO_CONTENT))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn pack_requests_hold_their_bounds() {
        let ok = songbird_proto::media::ciphertext_len(10_000).unwrap();
        let t = "ab".repeat(32);
        let good = format!(r#"{{"sizes":[{ok},{ok}],"token":"{t}"}}"#);
        let (sizes, total, token) = PackRequest::decode(good.as_bytes()).unwrap();
        assert_eq!((sizes.len(), total, token), (2, 2 * ok, [0xab; 32]));
        let big = songbird_proto::media::ciphertext_len(17 << 20).unwrap();
        let many = vec![ok.to_string(); MAX_PACK_OBJECTS + 1].join(",");
        for bad in [
            format!(r#"{{"sizes":[{ok}],"token":"{t}"}}"#),
            format!(r#"{{"sizes":[{ok},{}],"token":"{t}"}}"#, ok + 1),
            format!(r#"{{"sizes":[{ok},{big}],"token":"{t}"}}"#),
            format!(r#"{{"sizes":[{many}],"token":"{t}"}}"#),
            format!(r#"{{"sizes":[{ok},{ok}],"token":"abcd"}}"#),
            format!(r#"{{"sizes":[{ok},{ok}],"token":"{}"}}"#, "zz".repeat(32)),
            format!(r#"{{"sizes":[{ok},{ok}],"token":"{t}","x":1}}"#),
        ] {
            assert!(PackRequest::decode(bad.as_bytes()).is_none(), "{bad}");
        }
        // 300 MiB in all.
        let near = songbird_proto::media::ciphertext_len(15 << 20).unwrap();
        let twenty = vec![near.to_string(); 21].join(",");
        assert!(
            PackRequest::decode(format!(r#"{{"sizes":[{twenty}],"token":"{t}"}}"#).as_bytes())
                .is_none()
        );
        assert!(pack_id(&"0f".repeat(16)).is_some());
        assert!(pack_id("0f").is_none());
    }
}
