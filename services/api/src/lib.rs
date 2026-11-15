//! Songbird `api`: HTTP for everything that is not on the hot path (D-0036).
//!
//! | Method and path | What |
//! | --- | --- |
//! | `POST /v1/registration/challenge` | A proof-of-work challenge ([`registration`]; unsigned) |
//! | `POST /v1/registration` | A new account and its first device ([`registration`]; unsigned, proof of work) |
//! | `POST`, `GET`, `DELETE /v1/invites` | Invite codes: create from the allowance, see it, revoke ([`registration`]) |
//! | `PUT`, `DELETE /v1/username`; `POST /v1/username/lookup` | Claim, release and look up usernames ([`usernames`]) |
//! | `PUT`, `DELETE /v1/username/key`; `PUT`, `DELETE`, `GET /v1/username/link[/<handle>]` | The username key; username links ([`usernames`]) |
//! | `PUT`, `GET /v1/keys`; `POST /v1/keys/fetch` | The key directory: upload, counts, fetch bundles ([`keys`]) |
//! | `PUT`, `GET /v1/keypackages`; `POST /v1/keypackages/fetch` | MLS KeyPackages: upload, counts, fetch ([`keys`]) |
//! | `POST /v1/provisioning`; `PUT`, `GET /v1/provisioning/<channel>` | The QR provisioning channel ([`devices`]; open and read unsigned) |
//! | `POST /v1/devices/link-token`; `POST /v1/devices/link` | Linking a new device ([`devices`]; the link itself unsigned, both keys proven) |
//! | `PUT /v1/profile`; `POST /v1/profile/fetch`; `PUT`, `GET /v1/profile/avatar[/<id>]` | Encrypted profiles and avatars ([`profiles`]) |
//! | `GET /v1/certificate`; `PUT /v1/messages/sealed` | Sealed sender ([`profiles`]; the sealed send unsigned, authorized by access keys) |
//! | `GET /v1/devices`; `PUT /v1/devices/list`; `POST /v1/devices/list/fetch`; `DELETE /v1/devices/self` | The signed device list and removal ([`devices`]) |
//! | `PUT /v1/push` | Registers the device's push channel, sealed to the push service's key |
//! | `DELETE /v1/push` | Removes it |
//! | `POST /v1/attachments` | An upload grant: exact (padded) size and recipient fetches due |
//! | `PUT /v1/attachments/<id>` | The upload, streamed to `RustFS`; exactly the granted size |
//! | `GET /v1/attachments/<id>` | A download; each completed one counts a fetch, the last deletes |
//! | `DELETE /v1/account` | Deletes the device's account from every store (outbox job) |
//! | `PUT /v1/messages` | A WebSocket `Send` frame, for clients with no open socket; answers its `SendResult` ([`messages`]) |
//!
//! Every request but the two registration steps, opening and reading a provisioning channel and
//! linking is signed by the device ([`auth`]); there are no
//! tokens or cookies. Registration is paid for with proof of work and throttled per IP range. Bodies are
//! bounded before they are read. Responses carry status codes and small JSON; errors say nothing
//! about whether a device, account or object exists beyond what the caller already proved.
//! Nothing here logs identifiers or object names (invariant 6).
#![forbid(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod client;
pub mod config;
pub mod devices;
pub mod keys;
pub mod messages;
pub mod profiles;
pub mod registration;
pub mod server;
pub mod usernames;

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
    /// The send path's counters (`PUT /v1/messages`), registered as `api_*`.
    pub send: songbird_send::SendMetrics,
    /// Push wake-ups from `PUT /v1/messages`.
    pub push: songbird_send::PushMetrics,
    /// Registration and invites.
    pub registration: registration::RegistrationMetrics,
    /// Usernames.
    pub usernames: usernames::UsernameMetrics,
    /// The key directory.
    pub keys: keys::KeyMetrics,
    /// Devices.
    pub devices: devices::DeviceMetrics,
    /// Profiles and sealed sender.
    pub profiles: profiles::ProfileMetrics,
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
            (
                "api_push_jobs",
                "Push jobs enqueued for offline devices",
                &self.push.jobs,
            ),
            (
                "api_push_dropped",
                "Push wake-ups dropped (the message stays in the mailbox)",
                &self.push.dropped,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        self.registration.register(m)?;
        self.usernames.register(m)?;
        self.keys.register(m)?;
        self.devices.register(m)?;
        self.profiles.register(m)?;
        self.send.register(m, "api")
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
    /// `PUT /v1/messages` (absent: the endpoint answers 503).
    pub messages: Option<messages::Messages>,
    /// Registration and invites (absent: those endpoints answer 503).
    pub registration: Option<registration::Registration>,
    /// Usernames (absent: those endpoints answer 503).
    pub usernames: Option<usernames::Usernames>,
    /// The key directory (absent: those endpoints answer 503).
    pub keys: Option<keys::KeyDirectory>,
    /// Devices: provisioning, linking, the signed list (absent: those endpoints answer 503).
    pub devices: Option<devices::Devices>,
    /// Encrypted profiles and sealed sender (absent: those endpoints answer 503).
    pub profiles: Option<profiles::Profiles>,
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
            (&Method::PUT, "/v1/messages", None) => self.put_message(req).await,
            (_, p, None)
                if p == "/v1/messages/sealed"
                    || p == "/v1/certificate"
                    || p == "/v1/profile"
                    || p.starts_with("/v1/profile/") =>
            {
                self.profiles(req).await
            }
            (&Method::POST, "/v1/registration/challenge", None) => {
                let (r, peer) = self.registration_and_peer(&req)?;
                Ok(outcome(r.challenge(&self.hot, peer).await))
            }
            (&Method::POST, "/v1/registration", None) => {
                let (r, peer) = self.registration_and_peer(&req)?;
                let body = bounded_body(req, songbird_proto::registration::MAX_LEN).await?;
                Ok(outcome(
                    r.register(&self.registry, &self.hot, &self.server_name, peer, &body)
                        .await,
                ))
            }
            (&Method::POST | &Method::GET | &Method::DELETE, "/v1/invites", None) => {
                self.invites(req).await
            }
            (_, p, None) if p == "/v1/username" || p.starts_with("/v1/username/") => {
                self.usernames(req).await
            }
            (
                _,
                "/v1/keys" | "/v1/keys/fetch" | "/v1/keypackages" | "/v1/keypackages/fetch",
                None,
            ) => self.keys(req).await,
            (_, p, None) if p.starts_with("/v1/account/") => self.factors(req).await,
            (_, p, None) if p.starts_with("/v1/provisioning") || p.starts_with("/v1/devices") => {
                self.devices(req).await
            }
            _ => Err(Refusal::Status(StatusCode::NOT_FOUND)),
        }
    }

    fn registration_and_peer(
        &self,
        req: &Request<Incoming>,
    ) -> Result<(&registration::Registration, std::net::IpAddr), Refusal> {
        let r = self
            .registration
            .as_ref()
            .ok_or(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        // The listener always sets it; without it there is nothing to throttle by.
        let peer = req
            .extensions()
            .get::<registration::Peer>()
            .ok_or(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        Ok((r, peer.0))
    }

    /// `/v1/profile…`, `/v1/certificate` and `/v1/messages/sealed` ([`profiles`]).
    async fn profiles(self: &Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let unavailable = || Refusal::Status(StatusCode::SERVICE_UNAVAILABLE);
        let p = self.profiles.as_ref().ok_or_else(unavailable)?;
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        // Who may change account-wide state: a listed (not pending) device of the account.
        let listed = |device: DeviceId| async move {
            let row = self
                .registry
                .device(&device)
                .await
                .map_err(|_| unavailable())?
                .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?;
            Ok::<_, Refusal>((row.account, !row.pending))
        };
        let out = match (&method, path.as_str()) {
            (&Method::PUT, "/v1/messages/sealed") => {
                let peer = req
                    .extensions()
                    .get::<registration::Peer>()
                    .map(|x| x.0)
                    .ok_or_else(unavailable)?;
                let key = req
                    .headers()
                    .get("unidentified-access-key")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| {
                        let mut k = [0u8; 16];
                        hex::decode_to_slice(v, &mut k).ok().map(|()| k)
                    });
                let max = self
                    .messages
                    .as_ref()
                    .map_or(0, |m| m.limits.max_send_bytes);
                let body = bounded_body(req, max.max(1)).await?;
                p.sealed_send(
                    &self.registry,
                    &self.hot,
                    self.messages.as_ref(),
                    peer,
                    key,
                    body,
                )
                .await
            }
            (&Method::GET, "/v1/certificate") => {
                let (device, _) = self.authenticate_json(req).await?;
                match listed(device).await? {
                    (a, true) => p.certificate(&self.registry, &a, &device).await,
                    (_, false) => return Ok(pending_refusal()),
                }
            }
            (&Method::PUT, "/v1/profile") => {
                let (device, body) = self
                    .authenticate_body(req, songbird_proto::profile::MAX_PROFILE + 64)
                    .await?;
                match listed(device).await? {
                    (a, true) => p.put(&self.registry, &a, &body).await,
                    (_, false) => return Ok(pending_refusal()),
                }
            }
            (&Method::POST, "/v1/profile/fetch") => {
                let (device, body) = self.authenticate_json(req).await?;
                let (a, _) = listed(device).await?;
                p.fetch(&self.registry, &self.hot, &a, &body).await
            }
            (&Method::PUT, "/v1/profile/avatar") => {
                let (device, body) = self
                    .authenticate_body(req, songbird_proto::profile::MAX_AVATAR)
                    .await?;
                match listed(device).await? {
                    (a, true) => p.put_avatar(&self.registry, &self.s3, &a, body).await,
                    (_, false) => return Ok(pending_refusal()),
                }
            }
            (&Method::GET, path) if path.starts_with("/v1/profile/avatar/") => {
                let mut id = [0u8; 32];
                hex::decode_to_slice(path.trim_start_matches("/v1/profile/avatar/"), &mut id)
                    .map_err(|_| Refusal::Status(StatusCode::NOT_FOUND))?;
                let (device, _) = self.authenticate_json(req).await?;
                let (a, _) = listed(device).await?;
                if let Err(o) = p.avatar_allowed(&self.registry, &self.hot, &a, &id).await {
                    return Ok(profile_outcome(o));
                }
                return self.serve_avatar(&id).await;
            }
            _ => return Err(Refusal::Status(StatusCode::NOT_FOUND)),
        };
        Ok(profile_outcome(out))
    }

    /// An avatar object, streamed.
    async fn serve_avatar(&self, id: &[u8; 32]) -> Result<Response<Body>, Refusal> {
        let got = match self.s3.get_object(&profiles::avatar_name(id), None).await {
            Ok(g) => g,
            Err(songbird_s3::Error::NotFound) => {
                return Err(Refusal::Status(StatusCode::NOT_FOUND));
            }
            Err(_) => return Err(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE)),
        };
        let counted = Counted {
            inner: got.body,
            left: got.length,
            on_done: None,
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

    /// `/v1/account/…` second factors ([`devices`], M4b): the primary's to change.
    async fn factors(&self, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let unavailable = || Refusal::Status(StatusCode::SERVICE_UNAVAILABLE);
        let d = self.devices.as_ref().ok_or_else(unavailable)?;
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let (device, body) = self.authenticate_json(req).await?;
        let row = self
            .registry
            .device(&device)
            .await
            .map_err(|_| unavailable())?
            .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?;
        let primary = row.primary.then_some(row.account);
        let not_primary = || devices::Outcome::Forbidden("primary");
        let out = match (&method, path.as_str()) {
            (&Method::PUT, "/v1/account/pin") => match primary {
                Some(a) => d.set_pin(&self.registry, &a, &body).await,
                None => not_primary(),
            },
            (&Method::DELETE, "/v1/account/pin") => match primary {
                Some(a) => d.clear_pin(&self.registry, &a).await,
                None => not_primary(),
            },
            (&Method::POST, "/v1/account/passkeys/challenge") => match primary {
                Some(a) => d.passkey_challenge(&self.hot, &a).await,
                None => not_primary(),
            },
            (&Method::PUT, "/v1/account/passkeys") => match primary {
                Some(a) => d.add_passkey(&self.registry, &self.hot, &a, &body).await,
                None => not_primary(),
            },
            (&Method::DELETE, "/v1/account/passkeys") => match primary {
                Some(a) => d.delete_passkey(&self.registry, &a, &body).await,
                None => not_primary(),
            },
            (&Method::GET, "/v1/account/factors") => d.factors(&self.registry, &row.account).await,
            _ => return Err(Refusal::Status(StatusCode::NOT_FOUND)),
        };
        Ok(device_outcome(out))
    }

    /// `/v1/provisioning…` and `/v1/devices…` ([`devices`]).
    async fn devices(&self, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let unavailable = || Refusal::Status(StatusCode::SERVICE_UNAVAILABLE);
        let d = self.devices.as_ref().ok_or_else(unavailable)?;
        let peer = req
            .extensions()
            .get::<registration::Peer>()
            .map(|p| p.0)
            .ok_or_else(unavailable)?;
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let channel = path.strip_prefix("/v1/provisioning/").map(str::to_owned);
        let account_of = |device: DeviceId| async move {
            self.registry
                .device(&device)
                .await
                .map_err(|_| unavailable())?
                .map(|r| r.account)
                .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))
        };
        let out = match (&method, path.as_str(), channel) {
            (&Method::POST, "/v1/provisioning", None) => d.open_channel(&self.hot, peer).await,
            (&Method::GET, _, Some(c)) => d.take_message(&self.hot, peer, &c).await,
            (&Method::PUT, _, Some(c)) => {
                let (device, body) = self
                    .authenticate_body(req, songbird_proto::devices::MAX_PROVISIONING_LEN)
                    .await?;
                let account = account_of(device).await?;
                d.put_message(&self.hot, &account, &c, &body).await
            }
            (&Method::POST, "/v1/devices/link-token", None) => {
                let (device, _) = self.authenticate_json(req).await?;
                let account = account_of(device).await?;
                d.link_token(&self.registry, &self.hot, &account, &device)
                    .await
            }
            (&Method::POST, "/v1/devices/link", None) => {
                let body = bounded_body(req, songbird_proto::devices::MAX_LINK_LEN).await?;
                d.link(
                    &self.registry,
                    &self.hot,
                    self.messages.as_ref(),
                    &self.server_name,
                    peer,
                    body,
                )
                .await
            }
            (&Method::GET, "/v1/devices", None) => {
                let (device, _) = self.authenticate_json(req).await?;
                let account = account_of(device).await?;
                d.list_own(&self.registry, &account).await
            }
            (&Method::PUT, "/v1/devices/list", None) => {
                let (device, body) = self
                    .authenticate_body(req, songbird_proto::devices::MAX_LIST_LEN)
                    .await?;
                let account = account_of(device).await?;
                d.put_list(
                    &self.registry,
                    &self.queue,
                    self.messages.as_ref(),
                    (&account, &device),
                    body,
                )
                .await
            }
            (&Method::POST, "/v1/devices/list/fetch", None) => {
                let (device, body) = self.authenticate_json(req).await?;
                let account = account_of(device).await?;
                d.fetch_list(&self.registry, &self.hot, &account, &body)
                    .await
            }
            (&Method::DELETE, "/v1/devices/self", None) => {
                let (device, _) = self.authenticate_json(req).await?;
                d.remove_self(&self.registry, &self.queue, self.messages.as_ref(), &device)
                    .await
            }
            _ => return Err(Refusal::Status(StatusCode::NOT_FOUND)),
        };
        Ok(device_outcome(out))
    }

    /// `/v1/keys…` ([`keys`]): signed like every device request.
    async fn keys(&self, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let unavailable = || Refusal::Status(StatusCode::SERVICE_UNAVAILABLE);
        let k = self.keys.as_ref().ok_or_else(unavailable)?;
        let peer = req
            .extensions()
            .get::<registration::Peer>()
            .map(|p| p.0)
            .ok_or_else(unavailable)?;
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let out = match (&method, path.as_str()) {
            (&Method::PUT, "/v1/keys") => {
                // Large and signed over its digest: authenticated from the headers before the
                // body is read.
                let (device, body) = self
                    .authenticate_body(req, songbird_proto::keys::MAX_UPLOAD_LEN)
                    .await?;
                k.upload(&self.registry, &device, body).await
            }
            (&Method::GET, "/v1/keys") => {
                let (device, _) = self.authenticate_json(req).await?;
                k.counts(&self.registry, &device).await
            }
            (&Method::PUT, "/v1/keypackages") => {
                let (device, body) = self
                    .authenticate_body(req, songbird_proto::keys::MAX_KEY_PACKAGE_UPLOAD_LEN)
                    .await?;
                k.upload_key_packages(&self.registry, &device, body).await
            }
            (&Method::GET, "/v1/keypackages") => {
                let (device, _) = self.authenticate_json(req).await?;
                k.key_package_counts(&self.registry, &device).await
            }
            (&Method::POST, "/v1/keypackages/fetch") => {
                let (device, body) = self.authenticate_json(req).await?;
                let account = self
                    .registry
                    .device(&device)
                    .await
                    .map_err(|_| unavailable())?
                    .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?
                    .account;
                k.fetch_key_packages(
                    &self.registry,
                    &self.hot,
                    self.messages.as_ref(),
                    (&account, &device),
                    peer,
                    &body,
                )
                .await
            }
            (&Method::POST, "/v1/keys/fetch") => {
                let (device, body) = self.authenticate_json(req).await?;
                let account = self
                    .registry
                    .device(&device)
                    .await
                    .map_err(|_| unavailable())?
                    .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?
                    .account;
                k.fetch(
                    &self.registry,
                    &self.hot,
                    self.messages.as_ref(),
                    (&account, &device),
                    peer,
                    &body,
                )
                .await
            }
            _ => return Err(Refusal::Status(StatusCode::NOT_FOUND)),
        };
        Ok(key_outcome(out))
    }

    /// `/v1/username…` ([`usernames`]): signed like every device request.
    async fn usernames(&self, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let unavailable = || Refusal::Status(StatusCode::SERVICE_UNAVAILABLE);
        let u = self.usernames.as_ref().ok_or_else(unavailable)?;
        let peer = req
            .extensions()
            .get::<registration::Peer>()
            .map(|p| p.0)
            .ok_or_else(unavailable)?;
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let handle = path
            .strip_prefix("/v1/username/link/")
            .map(|h| {
                let mut out = [0u8; 16];
                hex::decode_to_slice(h, &mut out)
                    .map(|()| out)
                    .map_err(|_| Refusal::Status(StatusCode::NOT_FOUND))
            })
            .transpose()?;
        let (device, body) = self.authenticate_json(req).await?;
        let row = self
            .registry
            .device(&device)
            .await
            .map_err(|_| unavailable())?
            .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?;
        // A pending device (linked, not yet vouched for by a signed list) changes nothing
        // account-wide (D-0052); it may look up and read links.
        let changes = !(method == Method::GET || path == "/v1/username/lookup");
        if row.pending && changes {
            return Ok(pending_refusal());
        }
        let account = row.account;
        let (r, hot) = (self.registry.as_ref(), &self.hot);
        let done = |res: Result<(), songbird_accounts::RegistryError>| match res {
            Ok(()) => Ok(empty(StatusCode::NO_CONTENT)),
            Err(_) => Err(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE)),
        };
        let out = match (&method, path.as_str(), handle) {
            (&Method::PUT, "/v1/username", None) => u.claim(r, hot, &account, &body).await,
            (&Method::DELETE, "/v1/username", None) => {
                return done(r.delete_username(&account).await);
            }
            (&Method::POST, "/v1/username/lookup", None) => {
                u.lookup(r, hot, &account, peer, &body).await
            }
            (&Method::PUT, "/v1/username/key", None) => u.set_key(r, &account, &body).await,
            (&Method::DELETE, "/v1/username/key", None) => {
                return done(r.set_username_key(&account, None).await);
            }
            (&Method::PUT, "/v1/username/link", None) => u.put_link(r, &account, &body).await,
            (&Method::DELETE, "/v1/username/link", None) => {
                return done(r.delete_username_link(&account).await);
            }
            (&Method::GET, _, Some(h)) => u.get_link(r, hot, &account, peer, &h).await,
            _ => return Err(Refusal::Status(StatusCode::NOT_FOUND)),
        };
        Ok(username_outcome(out))
    }

    /// `/v1/invites`: signed like every device request.
    async fn invites(&self, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let unavailable = || Refusal::Status(StatusCode::SERVICE_UNAVAILABLE);
        let r = self.registration.as_ref().ok_or_else(unavailable)?;
        let method = req.method().clone();
        let (device, body) = self.authenticate_json(req).await?;
        let parsed: registration::InviteBody = if body.is_empty() {
            registration::InviteBody::default()
        } else {
            serde_json::from_slice(&body).map_err(|_| Refusal::Status(StatusCode::BAD_REQUEST))?
        };
        let row = self
            .registry
            .device(&device)
            .await
            .map_err(|_| unavailable())?
            .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?;
        // Invites spend the account's allowance: not from a pending device (D-0052).
        if row.pending {
            return Ok(pending_refusal());
        }
        let account = row.account;
        match method {
            Method::POST => match r.create_invite(&self.registry, &account, &parsed).await {
                Ok(Some((code, ttl))) => Ok(json(
                    StatusCode::CREATED,
                    &serde_json::json!({ "code": code, "expires_in_secs": ttl }),
                )),
                Ok(None) => Ok(json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({ "error": "allowance" }),
                )),
                Err(_) => Err(unavailable()),
            },
            Method::GET => {
                let left = self
                    .registry
                    .invite_allowance(&account)
                    .await
                    .map_err(|_| unavailable())?;
                Ok(json(
                    StatusCode::OK,
                    &serde_json::json!({
                        "allowance": left,
                        "invite_only": r.settings.invite_only,
                    }),
                ))
            }
            _ => {
                let code = parsed
                    .code
                    .as_deref()
                    .and_then(songbird_proto::registration::invite::parse)
                    .ok_or(Refusal::Status(StatusCode::BAD_REQUEST))?;
                self.registry
                    .revoke_invite(&songbird_accounts::invite_hash(&code))
                    .await
                    .map_err(|_| unavailable())?;
                // The same answer whether or not the code existed.
                Ok(empty(StatusCode::NO_CONTENT))
            }
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

    /// A signed body read only after its signature verified: the signature covers the declared
    /// digest, so the headers alone authenticate the request (time, nonce, key, not disabled);
    /// then at most the declared `Content-Length` (itself at most `max`) is read and must match
    /// the digest.
    async fn authenticate_body(
        &self,
        req: Request<Incoming>,
        max: usize,
    ) -> Result<(DeviceId, Bytes), Refusal> {
        let (parts, body) = req.into_parts();
        let length = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or(Refusal::Status(StatusCode::LENGTH_REQUIRED))?;
        if length == 0 || length > max {
            return Err(Refusal::Status(StatusCode::PAYLOAD_TOO_LARGE));
        }
        let mut declared = [0u8; 32];
        parts
            .headers
            .get(auth::CONTENT_SHA256)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| hex::decode_to_slice(v, &mut declared).ok())
            .ok_or(Refusal::Status(StatusCode::UNAUTHORIZED))?;
        let device = self
            .verify(&parts.method, parts.uri.path(), &parts.headers, &declared)
            .await?;
        let body = Limited::new(body, length)
            .collect()
            .await
            .map_err(|_| Refusal::Status(StatusCode::PAYLOAD_TOO_LARGE))?
            .to_bytes();
        if body.len() != length || auth::body_sha256(&body) != declared {
            return Err(Refusal::Status(StatusCode::UNAUTHORIZED));
        }
        Ok((device, body))
    }

    /// `PUT /v1/messages` ([`messages`]).
    async fn put_message(&self, req: Request<Incoming>) -> Result<Response<Body>, Refusal> {
        let received = std::time::Instant::now();
        let m = self
            .messages
            .as_ref()
            .ok_or(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE))?;
        let (device, body) = self.authenticate_body(req, m.limits.max_send_bytes).await?;
        let frame =
            messages::decode(&body, &m.limits).ok_or(Refusal::Status(StatusCode::BAD_REQUEST))?;
        let req_id = frame.req_id;
        let status = match self.rate(m, &device).await {
            Ok(0) => m.path.submit(&device, frame, received).await,
            Ok(wait_us) => {
                m.metrics.sends_rejected.inc();
                messages::rate_limited(wait_us)
            }
            Err(()) => {
                // Fail closed: without the limiter, nothing is sent.
                self.metrics.errors.inc();
                m.metrics.sends_rejected.inc();
                songbird_proto::frame::SendStatus::Rejected {
                    reason: songbird_proto::frame::RejectReason::Unavailable,
                    retry_after_ms: songbird_send::RETRY_MS,
                }
            }
        };
        let mut r = Response::new(
            Full::new(messages::result_frame(req_id, status))
                .map_err(|e| match e {})
                .boxed_unsync(),
        );
        r.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        Ok(r)
    }

    /// The device's send rate (GCRA in `valkey-hot`): 0 if allowed, else microseconds to wait.
    async fn rate(&self, m: &messages::Messages, device: &DeviceId) -> Result<u64, ()> {
        let interval_us = 1_000_000 / u64::from(m.sends_per_sec.max(1));
        let tolerance_us = interval_us.saturating_mul(u64::from(m.send_burst.max(1)));
        self.hot
            .query::<i64>(
                redis::cmd("EVAL")
                    .arg(messages::GCRA)
                    .arg(1)
                    .arg(messages::rate_record(&m.rate_key, device))
                    .arg(interval_us)
                    .arg(tolerance_us),
            )
            .await
            .map(|w| u64::try_from(w).unwrap_or(0))
            .map_err(|_| ())
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
        // Only the primary may delete the account (D-0052): a linked device, above all a pending
        // one the primary has not vouched for, could otherwise delete it irreversibly.
        match self
            .registry
            .begin_account_deletion_by(&device, |account| {
                Job::new(Work::DeleteAccount { account: *account }).ok()
            })
            .await
        {
            Ok(_) => {}
            Err(songbird_accounts::RegistryError::NotPrimary) => {
                return Ok(json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({ "error": "primary" }),
                ));
            }
            Err(_) => return Err(Refusal::Status(StatusCode::SERVICE_UNAVAILABLE)),
        }
        self.metrics.deletions.inc();
        // Relay now; the periodic relay retries if this fails.
        if let Err(e) = songbird_jobs::relay(self.registry.as_ref(), &self.queue).await {
            tracing::warn!(error = %e, "outbox relay deferred");
        }
        Ok(empty(StatusCode::ACCEPTED))
    }
}

/// The HTTP answer for a profile outcome.
fn profile_outcome(o: profiles::Outcome) -> Response<Body> {
    use profiles::Outcome;
    let bytes = |b: Bytes| {
        let mut r = Response::new(Full::new(b).map_err(|e| match e {}).boxed_unsync());
        r.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        r
    };
    match o {
        Outcome::Done => empty(StatusCode::NO_CONTENT),
        Outcome::Json(v) => json(StatusCode::OK, &v),
        Outcome::Blob(b) | Outcome::Sent(b) => bytes(b),
        Outcome::Malformed(what) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": what }),
        ),
        Outcome::Unauthorized => empty(StatusCode::UNAUTHORIZED),
        Outcome::NotFound => empty(StatusCode::NOT_FOUND),
        Outcome::Conflict(what) => {
            json(StatusCode::CONFLICT, &serde_json::json!({ "error": what }))
        }
        Outcome::Throttled(wait_us) => {
            let mut r = empty(StatusCode::TOO_MANY_REQUESTS);
            let secs = wait_us.div_ceil(1_000_000).max(1);
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        Outcome::Unavailable => empty(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// 403 for an account-wide change from a pending device (D-0052).
fn pending_refusal() -> Response<Body> {
    json(
        StatusCode::FORBIDDEN,
        &serde_json::json!({ "error": "pending" }),
    )
}

/// A body of at most `max` bytes, read only after `Content-Length` says it fits.
async fn bounded_body(req: Request<Incoming>, max: usize) -> Result<Bytes, Refusal> {
    let length = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .ok_or(Refusal::Status(StatusCode::LENGTH_REQUIRED))?;
    if length == 0 || length > max {
        return Err(Refusal::Status(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let body = Limited::new(req.into_body(), length)
        .collect()
        .await
        .map_err(|_| Refusal::Status(StatusCode::PAYLOAD_TOO_LARGE))?
        .to_bytes();
    if body.len() != length {
        return Err(Refusal::Status(StatusCode::BAD_REQUEST));
    }
    Ok(body)
}

/// The HTTP answer for a device outcome.
fn device_outcome(o: devices::Outcome) -> Response<Body> {
    use devices::Outcome;
    match o {
        Outcome::Done => empty(StatusCode::NO_CONTENT),
        Outcome::Json(v) => json(StatusCode::OK, &v),
        Outcome::Blob(b) => {
            let mut r = Response::new(Full::new(b).map_err(|e| match e {}).boxed_unsync());
            r.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        Outcome::Malformed(what) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": what }),
        ),
        Outcome::NotFound => empty(StatusCode::NOT_FOUND),
        Outcome::Conflict(what) => {
            json(StatusCode::CONFLICT, &serde_json::json!({ "error": what }))
        }
        Outcome::Forbidden(what) => {
            json(StatusCode::FORBIDDEN, &serde_json::json!({ "error": what }))
        }
        Outcome::Locked(left) => {
            let mut r = json(
                StatusCode::FORBIDDEN,
                &serde_json::json!({ "error": "locked", "retry_after": left }),
            );
            if let Some(secs) = left
                && let Ok(v) = HeaderValue::from_str(&secs.to_string())
            {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        Outcome::Throttled(wait_us) => {
            let mut r = empty(StatusCode::TOO_MANY_REQUESTS);
            let secs = wait_us.div_ceil(1_000_000).max(1);
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        Outcome::Unavailable => empty(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// The HTTP answer for a key directory outcome.
fn key_outcome(o: keys::Outcome) -> Response<Body> {
    use keys::Outcome;
    match o {
        Outcome::Done => empty(StatusCode::NO_CONTENT),
        Outcome::Counts(ec, kem) => {
            json(StatusCode::OK, &serde_json::json!({ "ec": ec, "kem": kem }))
        }
        Outcome::KeyPackageCounts(n, lr) => json(
            StatusCode::OK,
            &serde_json::json!({ "single_use": n, "last_resort": lr }),
        ),
        Outcome::Bundles(b) => {
            let mut r = Response::new(Full::new(b).map_err(|e| match e {}).boxed_unsync());
            r.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        Outcome::Malformed(what) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": what }),
        ),
        Outcome::NotFound => empty(StatusCode::NOT_FOUND),
        Outcome::Conflict(what) => {
            json(StatusCode::CONFLICT, &serde_json::json!({ "error": what }))
        }
        Outcome::Throttled(wait_us) => {
            let mut r = empty(StatusCode::TOO_MANY_REQUESTS);
            let secs = wait_us.div_ceil(1_000_000).max(1);
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        Outcome::Unavailable => empty(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// The HTTP answer for a username outcome.
fn username_outcome(o: usernames::Outcome) -> Response<Body> {
    use usernames::Outcome;
    match o {
        Outcome::Done => empty(StatusCode::NO_CONTENT),
        Outcome::Found(a) => json(
            StatusCode::OK,
            &serde_json::json!({ "account": a.to_hex_unredacted() }),
        ),
        Outcome::Link(h) => json(
            StatusCode::OK,
            &serde_json::json!({ "handle": hex::encode(h) }),
        ),
        Outcome::Blob(b) => {
            let mut r = Response::new(Full::new(b).map_err(|e| match e {}).boxed_unsync());
            r.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        Outcome::Malformed(what) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": what }),
        ),
        Outcome::NotFound => empty(StatusCode::NOT_FOUND),
        Outcome::Taken => json(
            StatusCode::CONFLICT,
            &serde_json::json!({ "error": "taken" }),
        ),
        Outcome::NoUsername => json(
            StatusCode::CONFLICT,
            &serde_json::json!({ "error": "no username" }),
        ),
        Outcome::Throttled(wait_us) => {
            let mut r = empty(StatusCode::TOO_MANY_REQUESTS);
            let secs = wait_us.div_ceil(1_000_000).max(1);
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        Outcome::Unavailable => empty(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// The HTTP answer for a registration outcome.
fn outcome(o: registration::Outcome) -> Response<Body> {
    use registration::Outcome;
    match o {
        Outcome::Challenge(b) => {
            let mut r = Response::new(Full::new(b).map_err(|e| match e {}).boxed_unsync());
            r.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        Outcome::Registered { account, device } => json(
            StatusCode::CREATED,
            &serde_json::json!({
                "account": account.to_hex_unredacted(),
                "device": device.to_hex_unredacted(),
            }),
        ),
        Outcome::Malformed(what) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": what }),
        ),
        Outcome::Challenge403 => json(
            StatusCode::FORBIDDEN,
            &serde_json::json!({ "error": "challenge" }),
        ),
        Outcome::Invite403 => json(
            StatusCode::FORBIDDEN,
            &serde_json::json!({ "error": "invite" }),
        ),
        Outcome::Throttled(wait_us) => {
            let mut r = empty(StatusCode::TOO_MANY_REQUESTS);
            let secs = wait_us.div_ceil(1_000_000).max(1);
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        Outcome::Unavailable => empty(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// An attachment's object name in the store: `a/` and its 64 hex characters (no identifiers).
#[must_use]
pub fn object_name(o: &ObjectKey) -> String {
    let mut name = String::with_capacity(66);
    name.push_str("a/");
    name.push_str(&o.to_hex_unredacted());
    name
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    /// Every metric name passes the telemetry layer's redaction rules (invariant 6): a refused
    /// name stops the service at start-up.
    #[test]
    fn every_metric_name_is_accepted() {
        let mut m = songbird_service::telemetry::Metrics::new("api", "test");
        super::ApiMetrics::default().register(&mut m).unwrap();
    }
}
