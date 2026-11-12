//! Songbird `api`: HTTP for everything that is not on the hot path (D-0036).
//!
//! | Method and path | What |
//! | --- | --- |
//! | `PUT /v1/push` | Registers the device's push channel, sealed to the push service's key |
//! | `DELETE /v1/push` | Removes it |
//! | `POST /v1/attachments` | An upload grant: exact (padded) size and recipient fetches due |
//! | `PUT /v1/attachments/<id>` | The upload, streamed to `RustFS`; exactly the granted size |
//! | `GET /v1/attachments/<id>` | A download; each completed one counts a fetch, the last deletes |
//! | `DELETE /v1/account` | Deletes the device's account from every store (outbox job) |
//!
//! Every request is signed by the device ([`auth`]); there are no tokens or cookies. Bodies are
//! bounded before they are read. Responses carry status codes and small JSON; errors say nothing
//! about whether a device, account or object exists beyond what the caller already proved.
//! Nothing here logs identifiers or object names (invariant 6).
#![forbid(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod client;
pub mod config;
pub mod server;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use songbird_accounts::push_token::{self, Registration};
use songbird_accounts::{Grant, Registry, push_index};
use songbird_jobs::{Job, ObjectKey, Queue, Work};
use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_types::DeviceId;
use songbird_valkey::ValkeyConn;

pub use config::{ApiConfig, ApiSettings};

/// Largest JSON body accepted.
pub const MAX_JSON: usize = 16 * 1024;

/// Response body type.
pub type Body = UnsyncBoxBody<Bytes, std::io::Error>;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct ApiMetrics {
    /// Requests answered.
    pub requests: Counter,
    /// Requests refused for authentication (bad, stale, replayed or unknown).
    pub auth_failures: Counter,
    /// Push registrations stored.
    pub push_registrations: Counter,
    /// Uploads completed.
    pub uploads: Counter,
    /// Downloads completed.
    pub downloads: Counter,
    /// Account deletions started.
    pub deletions: Counter,
    /// Requests that failed on a dependency (database, Valkey, object store).
    pub errors: Counter,
}

impl ApiMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            ("api_requests", "Requests answered", &self.requests),
            (
                "api_auth_failures",
                "Requests refused for authentication",
                &self.auth_failures,
            ),
            (
                "api_push_registrations",
                "Push registrations stored",
                &self.push_registrations,
            ),
            ("api_uploads", "Attachment uploads completed", &self.uploads),
            (
                "api_downloads",
                "Attachment downloads completed",
                &self.downloads,
            ),
            (
                "api_deletions",
                "Account deletions started",
                &self.deletions,
            ),
            (
                "api_errors",
                "Requests failed on a dependency",
                &self.errors,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// Everything a request needs.
pub struct App {
    /// Host name devices sign.
    pub server_name: String,
    /// Account registry.
    pub registry: Arc<Registry>,
    /// Attachment store.
    pub s3: songbird_s3::Client,
    /// Job queue.
    pub queue: Arc<Queue>,
    /// `valkey-hot` (nonces).
    pub hot: ValkeyConn,
    /// Push service public key.
    pub push_public: [u8; 32],
    /// Push-token row key.
    pub push_index_secret: [u8; 32],
    /// Attachment limits.
    pub limits: config::AttachmentLimits,
    /// Metrics.
    pub metrics: ApiMetrics,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App").finish_non_exhaustive()
    }
}

fn empty(status: StatusCode) -> Response<Body> {
    let mut r = Response::new(Empty::new().map_err(|e| match e {}).boxed_unsync());
    *r.status_mut() = status;
    r
}

fn json(status: StatusCode, v: &serde_json::Value) -> Response<Body> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let mut r = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|e| match e {})
            .boxed_unsync(),
    );
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

/// The push registration a device sends (binary fields in hex).
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
enum PushBody {
    Apns {
        token: String,
        #[serde(default)]
        voip: Option<String>,
    },
    Fcm {
        token: String,
    },
    Webpush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
}

impl PushBody {
    fn registration(self) -> Option<Registration> {
        let bin = |s: &str, max: usize| (s.len() <= 2 * max).then(|| hex::decode(s).ok()).flatten();
        let r = match self {
            Self::Apns { token, voip } => Registration::Apns {
                token: bin(&token, push_token::MAX_APNS_TOKEN)?,
                voip: match voip {
                    Some(v) => Some(bin(&v, push_token::MAX_APNS_TOKEN)?),
                    None => None,
                },
            },
            Self::Fcm { token } => Registration::Fcm { token },
            Self::Webpush {
                endpoint,
                p256dh,
                auth,
            } => {
                let mut p = [0u8; 65];
                hex::decode_to_slice(p256dh, &mut p).ok()?;
                let mut a = [0u8; 16];
                hex::decode_to_slice(auth, &mut a).ok()?;
                Registration::WebPush {
                    endpoint,
                    p256dh: p,
                    auth: a,
                }
            }
        };
        r.validate().ok()?;
        Some(r)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    size: u64,
    fetches: u32,
}

/// A download that counts its fetch once the whole object went out. hyper stops polling a body
/// once it has sent `Content-Length` bytes, so the end is the last byte, not the end of stream.
struct Counted {
    inner: songbird_s3::ObjectBody,
    left: u64,
    on_done: Option<Box<dyn FnOnce() + Send>>,
}

impl Stream for Counted {
    type Item = Result<Frame<Bytes>, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(b))) => {
                self.left = self
                    .left
                    .saturating_sub(u64::try_from(b.len()).unwrap_or(u64::MAX));
                if self.left == 0
                    && let Some(f) = self.on_done.take()
                {
                    f();
                }
                Poll::Ready(Some(Ok(Frame::data(b))))
            }
            Poll::Ready(Some(Err(_))) => {
                // An interrupted download is not a fetch.
                self.on_done = None;
                Poll::Ready(Some(Err(std::io::Error::other("object store"))))
            }
            Poll::Ready(None) => {
                if let Some(f) = self.on_done.take() {
                    f();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Why a request was refused before its handler ran.
enum Refusal {
    Status(StatusCode),
}

impl App {
    /// Handles one request.
    pub async fn handle(self: &Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        self.metrics.requests.inc();
        match self.route(req).await {
            Ok(r) => r,
            Err(Refusal::Status(s)) => {
                if s == StatusCode::UNAUTHORIZED {
                    self.metrics.auth_failures.inc();
                } else if s == StatusCode::SERVICE_UNAVAILABLE {
                    self.metrics.errors.inc();
                }
                empty(s)
            }
        }
    }

    async fn route(self: &Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let path = req.uri().path().to_owned();
        let method = req.method().clone();
        let object = path
            .strip_prefix("/v1/attachments/")
            .map(|id| ObjectKey::parse_hex(id).ok_or(Refusal::Status(StatusCode::NOT_FOUND)))
            .transpose()?;
        match (&method, path.as_str(), object) {
            (&Method::PUT, "/v1/push", None) => {
                let (device, body) = self.authenticate_json(req).await?;
                self.put_push(device, &body).await
            }
            (&Method::DELETE, "/v1/push", None) => {
                let (device, _) = self.authenticate_json(req).await?;
                self.registry
                    .delete_push_tokens(&[push_index(&self.push_index_secret, &device)])
                    .await
                    .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
                Ok(empty(StatusCode::NO_CONTENT))
            }
            (&Method::POST, "/v1/attachments", None) => {
                let (device, body) = self.authenticate_json(req).await?;
                self.grant(device, &body).await
            }
            (&Method::PUT, _, Some(o)) => self.upload(req, o).await,
            (&Method::GET, _, Some(o)) => {
                let (_, _) = self.authenticate_json(req).await?;
                self.download(o).await
            }
            (&Method::DELETE, "/v1/account", None) => {
                let (device, _) = self.authenticate_json(req).await?;
                self.delete_account(device).await
            }
            _ => Err(Refusal::Status(StatusCode::NOT_FOUND)),
        }
    }

    /// Checks the signature over the request and its body (read here, bounded); returns the
    /// device and the body.
    async fn authenticate_json(
        &self,
        req: Request<Incoming>,
    ) -> Result<(DeviceId, Bytes), Refusal> {
        let (parts, body) = req.into_parts();
        let declared = parts
            .headers
            .get(auth::CONTENT_SHA256)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                let mut h = [0u8; 32];
                hex::decode_to_slice(v, &mut h).map(|()| h)
            })
            .transpose()
            .map_err(|_| Refusal::Status(StatusCode::UNAUTHORIZED))?;
        let body = Limited::new(body, MAX_JSON)
            .collect()
            .await
            .map_err(|_| Refusal::Status(StatusCode::PAYLOAD_TOO_LARGE))?
            .to_bytes();
        // A body must be signed; no body signs as zeros.
        let hash = match declared {
            Some(h) if h == auth::body_sha256(&body) => h,
            None if body.is_empty() => [0; 32],
            _ => return Err(Refusal::Status(StatusCode::UNAUTHORIZED)),
        };
        let device = self
            .verify(&parts.method, parts.uri.path(), &parts.headers, &hash)
            .await?;
        Ok((device, body))
    }

    async fn verify(
        &self,
        method: &Method,
        path: &str,
        headers: &hyper::HeaderMap,
        hash: &[u8; 32],
    ) -> Result<DeviceId, Refusal> {
        let unauthorized = || Refusal::Status(StatusCode::UNAUTHORIZED);
        let s = headers
            .get(auth::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(auth::Signed::parse)
            .ok_or_else(unauthorized)?;
        if !auth::fresh(s.ts_ms) {
            return Err(unauthorized());
        }
        let row = self
            .registry
            .device(&s.device)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        let key = row.filter(|r| !r.disabled).map(|r| r.key);
        let t = auth::transcript(
            &self.server_name,
            method.as_str(),
            path,
            s.ts_ms,
            &s.nonce,
            &s.device,
            hash,
        );
        if !auth::verify(key.as_ref(), &t, &s.sig) {
            return Err(unauthorized());
        }
        // Single use: a replay within the window finds the record.
        let fresh: redis::Value = self
            .hot
            .query(
                redis::cmd("SET")
                    .arg(auth::nonce_key(&s.device, &s.nonce))
                    .arg(1)
                    .arg("NX")
                    .arg("PX")
                    .arg(u64::try_from(2 * auth::MAX_SKEW.as_millis()).unwrap_or(u64::MAX)),
            )
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        if matches!(fresh, redis::Value::Nil) {
            return Err(unauthorized());
        }
        Ok(s.device)
    }

    async fn put_push(&self, device: DeviceId, body: &[u8]) -> Result<Response<Body>, Refusal> {
        let reg = serde_json::from_slice::<PushBody>(body)
            .ok()
            .and_then(PushBody::registration)
            .ok_or(Refusal::Status(StatusCode::BAD_REQUEST))?;
        let index = push_index(&self.push_index_secret, &device);
        let sealed = push_token::seal(&self.push_public, &index, &reg)
            .map_err(|_| Refusal::Status(StatusCode::BAD_REQUEST))?;
        self.registry
            .put_push_token(&index, &sealed)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        self.metrics.push_registrations.inc();
        Ok(empty(StatusCode::NO_CONTENT))
    }

    async fn grant(&self, device: DeviceId, body: &[u8]) -> Result<Response<Body>, Refusal> {
        let g: GrantBody =
            serde_json::from_slice(body).map_err(|_| Refusal::Status(StatusCode::BAD_REQUEST))?;
        if g.size == 0
            || g.size > self.limits.max_bytes
            || g.fetches == 0
            || g.fetches > self.limits.max_fetches
        {
            return Err(Refusal::Status(StatusCode::BAD_REQUEST));
        }
        let object =
            ObjectKey::random().map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        self.registry
            .create_grant(
                &object,
                &Grant {
                    device,
                    size: g.size,
                    fetches: g.fetches,
                },
                Duration::from_secs(self.limits.grant_ttl_secs),
            )
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        Ok(json(
            StatusCode::CREATED,
            &serde_json::json!({ "id": object.to_hex_unredacted() }),
        ))
    }

    async fn upload(
        &self,
        req: Request<Incoming>,
        object: ObjectKey,
    ) -> Result<Response<Body>, Refusal> {
        let (parts, body) = req.into_parts();
        // The body is the client's own ciphertext: unsigned, held to the granted length.
        let device = self
            .verify(&parts.method, parts.uri.path(), &parts.headers, &[0; 32])
            .await?;
        let grant = self
            .registry
            .grant(&object)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?
            .filter(|g| g.device == device)
            .ok_or(Refusal::Status(StatusCode::NOT_FOUND))?;
        let length = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if length != Some(grant.size) {
            return Err(Refusal::Status(StatusCode::BAD_REQUEST));
        }
        let stream = body.into_data_stream();
        match self
            .s3
            .put_object(&object_name(&object), grant.size, stream)
            .await
        {
            Ok(()) => {}
            Err(songbird_s3::Error::LengthMismatch | songbird_s3::Error::BodySource) => {
                return Err(Refusal::Status(StatusCode::BAD_REQUEST));
            }
            Err(_) => return Err(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE)),
        }
        let done = self
            .registry
            .complete_upload(&object)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        if !done {
            // The grant expired while uploading: the object has no record; remove it.
            let _ = self.s3.delete_object(&object_name(&object)).await;
            return Err(Refusal::Status(StatusCode::NOT_FOUND));
        }
        self.metrics.uploads.inc();
        Ok(empty(StatusCode::CREATED))
    }

    async fn download(self: &Arc<Self>, object: ObjectKey) -> Result<Response<Body>, Refusal> {
        // Any authenticated device that knows the 256-bit ID may fetch it (the ID travels inside
        // the end-to-end encrypted message); the record says whether fetches are still due.
        if self
            .registry
            .attachment(&object)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?
            .is_none()
        {
            return Err(Refusal::Status(StatusCode::NOT_FOUND));
        }
        let got = match self.s3.get_object(&object_name(&object), None).await {
            Ok(g) => g,
            Err(songbird_s3::Error::NotFound) => {
                return Err(Refusal::Status(StatusCode::NOT_FOUND));
            }
            Err(_) => return Err(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE)),
        };
        let app = Arc::clone(self);
        let counted = Counted {
            inner: got.body,
            left: got.length,
            on_done: Some(Box::new(move || {
                tokio::spawn(async move { app.count_fetch(object).await });
            })),
        };
        let mut r = Response::new(StreamBody::new(counted).boxed_unsync());
        r.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        r.headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(got.length));
        Ok(r)
    }

    async fn count_fetch(&self, object: ObjectKey) {
        self.metrics.downloads.inc();
        match self.registry.count_fetch(&object).await {
            // The last fetch: delete it now (the worker's sweep catches a lost job).
            Ok(Some(0)) => {
                if let Ok(job) = Job::new(Work::DeleteObject { object })
                    && self.queue.enqueue(&[job]).await.is_err()
                {
                    tracing::warn!("cleanup job not queued; the sweep will delete the object");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "fetch not counted"),
        }
    }

    async fn delete_account(&self, device: DeviceId) -> Result<Response<Body>, Refusal> {
        let row = self
            .registry
            .device(&device)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?
            .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?;
        let job = Job::new(Work::DeleteAccount {
            account: row.account,
        })
        .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        self.registry
            .begin_account_deletion(&row.account, &job)
            .await
            .map_err(|_| Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        self.metrics.deletions.inc();
        // Relay now; the periodic relay retries if this fails.
        if let Err(e) = songbird_jobs::relay(self.registry.as_ref(), &self.queue).await {
            tracing::warn!(error = %e, "outbox relay deferred");
        }
        Ok(empty(StatusCode::ACCEPTED))
    }
}

/// An attachment's object name in the store: `a/` and its 64 hex characters (no identifiers).
#[must_use]
pub fn object_name(o: &ObjectKey) -> String {
    format!("a/{}", o.to_hex_unredacted())
}
