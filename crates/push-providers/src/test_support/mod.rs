//! Mock providers for tests (feature `test-support`): APNs (HTTP/2), FCM (HTTP/2, with its OAuth
//! token endpoint at `/token`) and a Web Push endpoint (HTTP/1.1 or HTTP/2), all over TLS with a
//! certificate from a throwaway CA. Each records every request (headers and body) and answers
//! from a script of [`Behaviour`]s (default: success).
#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test support: a broken fixture should fail the test loudly"
)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aws_lc_rs::agreement::{ECDH_P256, PrivateKey};
use aws_lc_rs::encoding::{AsBigEndian as _, AsDer as _, EcPrivateKeyBin};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::{HttpConfig, Target};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A throwaway CA and a server certificate for `localhost` and `127.0.0.1`.
pub struct TestCa {
    roots: Arc<RootCertStore>,
    server: Arc<ServerConfig>,
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestCa")
    }
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCa {
    /// A new CA and server certificate.
    #[must_use]
    pub fn new() -> Self {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let ca_cert = ca.self_signed(&ca_key).expect("ca cert");
        let issuer = Issuer::new(ca, ca_key);

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("leaf params");
        leaf.is_ca = IsCa::ExplicitNoCa;
        let leaf_cert = leaf.signed_by(&key, &issuer).expect("leaf cert");

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).expect("root");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("server config");
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Self {
            roots: Arc::new(roots),
            server: Arc::new(server),
        }
    }

    /// Trust anchors containing only this CA.
    #[must_use]
    pub fn roots(&self) -> Arc<RootCertStore> {
        Arc::clone(&self.roots)
    }

    /// Client settings trusting this CA, with short timeouts.
    #[must_use]
    pub fn http_config(&self) -> HttpConfig {
        HttpConfig {
            roots: self.roots(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            connections: 1,
        }
    }
}

/// A fresh P-256 key as PKCS#8 DER (APNs `.p8` keys, VAPID keys).
#[must_use]
pub fn p256_pkcs8() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .expect("p256")
        .as_ref()
        .to_vec()
}

/// A fresh RSA-2048 key as PKCS#8 DER (service accounts).
#[must_use]
pub fn rsa_pkcs8() -> Vec<u8> {
    aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
        .expect("rsa")
        .as_der()
        .expect("rsa der")
        .as_ref()
        .to_vec()
}

/// A Web Push subscription as a user agent holds it, to build targets and open what arrives.
pub struct TestSubscription {
    /// The user agent's public key.
    pub p256dh: [u8; 65],
    /// The authentication secret.
    pub auth: [u8; 16],
    private: [u8; 32],
}

impl std::fmt::Debug for TestSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestSubscription")
    }
}

impl TestSubscription {
    /// Fresh keys.
    #[must_use]
    pub fn generate() -> Self {
        let k = PrivateKey::generate(&ECDH_P256).expect("ecdh key");
        let public = k.compute_public_key().expect("public");
        let bin: EcPrivateKeyBin<'static> = k.as_be_bytes().expect("private");
        let auth: [u8; 16] = aws_lc_rs::rand::generate(&SystemRandom::new())
            .expect("rand")
            .expose();
        Self {
            p256dh: public.as_ref().try_into().expect("65 bytes"),
            auth,
            private: bin.as_ref().try_into().expect("32 bytes"),
        }
    }

    /// The target for `endpoint`.
    #[must_use]
    pub fn target(&self, endpoint: String) -> Target {
        Target::WebPush {
            endpoint,
            p256dh: self.p256dh,
            auth: self.auth,
        }
    }

    /// Decrypts a push body sent to this subscription.
    #[must_use]
    pub fn decrypt(&self, body: &[u8]) -> Option<Vec<u8>> {
        crate::webpush::decrypt(&self.private, &self.auth, body)
    }
}

/// How the mock answers one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// Success (APNs 200, FCM 200, Web Push 201; token endpoint issues a token).
    Ok,
    /// The token is gone (APNs 410 `Unregistered`, FCM 404 `UNREGISTERED`, Web Push 410).
    Unregistered,
    /// 429, with `retry-after` in seconds if given.
    RateLimited {
        /// `retry-after` seconds.
        retry_after: Option<u64>,
    },
    /// 500.
    ServerError,
    /// 503.
    Unavailable,
    /// Authentication expired (APNs 403 `ExpiredProviderToken`, FCM 401, Web Push 403; token
    /// endpoint 400 `invalid_grant`).
    ExpiredAuth,
    /// Wait this long, then succeed.
    Slow(Duration),
    /// Accept the request and never answer (a black-holed provider): only the client's own
    /// timeout ends it (Prompt 8, D-0095).
    Hang,
    /// Reset the request mid-stream (HTTP/2 `RST_STREAM`; HTTP/1 closes the connection).
    Reset,
}

/// Why the mock reset a request (only ever [`Behaviour::Reset`]).
#[derive(Debug)]
struct MockReset;

impl std::fmt::Display for MockReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mock reset")
    }
}

impl std::error::Error for MockReset {}

/// A request the mock received.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// Method.
    pub method: String,
    /// Path and query.
    pub path: String,
    /// Whether it came over HTTP/2.
    pub http2: bool,
    /// Headers in order (lower-case names).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// When the mock had read the whole request (latency measurements).
    pub at: std::time::Instant,
}

impl RecordedRequest {
    /// The first value of header `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Apns,
    Fcm,
    WebPush,
}

struct State {
    flavor: Flavor,
    requests: Mutex<Vec<RecordedRequest>>,
    token_requests: Mutex<Vec<RecordedRequest>>,
    script: Mutex<VecDeque<Behaviour>>,
    /// What requests get once the script is empty (default: success).
    fallback: Mutex<Behaviour>,
    token_script: Mutex<VecDeque<Behaviour>>,
    issued: Mutex<Vec<String>>,
    token_lifetime: AtomicU64,
    connections: AtomicUsize,
}

/// A running mock provider. Stops accepting when dropped.
pub struct MockServer {
    addr: SocketAddr,
    state: Arc<State>,
    goaway: watch::Sender<u64>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for MockServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockServer")
            .field("flavor", &self.state.flavor)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn json(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::copy_from_slice(body.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}

fn with_retry_after(mut r: Response<Full<Bytes>>, secs: Option<u64>) -> Response<Full<Bytes>> {
    if let Some(s) = secs {
        r.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from(s),
        );
    }
    r
}

impl MockServer {
    /// A mock APNs.
    pub async fn apns(ca: &TestCa) -> Self {
        Self::start(ca, Flavor::Apns).await
    }

    /// A mock FCM with its OAuth token endpoint at `/token`.
    pub async fn fcm(ca: &TestCa) -> Self {
        Self::start(ca, Flavor::Fcm).await
    }

    /// A mock Web Push endpoint (any path).
    pub async fn web_push(ca: &TestCa) -> Self {
        Self::start(ca, Flavor::WebPush).await
    }

    async fn start(ca: &TestCa, flavor: Flavor) -> Self {
        let (v4, v6) = bind_loopback().await;
        let addr = v4.local_addr().expect("addr");
        let state = Arc::new(State {
            flavor,
            requests: Mutex::default(),
            token_requests: Mutex::default(),
            script: Mutex::default(),
            fallback: Mutex::new(Behaviour::Ok),
            token_script: Mutex::default(),
            issued: Mutex::default(),
            token_lifetime: AtomicU64::new(3600),
            connections: AtomicUsize::new(0),
        });
        let (goaway, _) = watch::channel(0u64);
        let acceptor = TlsAcceptor::from(Arc::clone(&ca.server));
        let tasks = std::iter::once(v4)
            .chain(v6)
            .map(|listener| {
                tokio::spawn(accept_loop(
                    listener,
                    acceptor.clone(),
                    Arc::clone(&state),
                    goaway.clone(),
                ))
            })
            .collect();
        Self {
            addr,
            state,
            goaway,
            tasks,
        }
    }

    /// `https://localhost:<port>`.
    #[must_use]
    pub fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }

    /// The listening address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// How many requests arrived (cheap: no copy, unlike [`MockServer::requests`]).
    #[must_use]
    pub fn request_count(&self) -> usize {
        lock(&self.state.requests).len()
    }

    /// Answers the next requests with `b` (in order); then success again.
    pub fn push(&self, b: Behaviour) {
        lock(&self.state.script).push_back(b);
    }

    /// Answers every request without a scripted behaviour with `b` from now on: an outage
    /// (`Unavailable`, `Hang`, `Reset`, `RateLimited`) until [`MockServer::recover`].
    pub fn outage(&self, b: Behaviour) {
        *lock(&self.state.fallback) = b;
    }

    /// Ends an [`outage`](Self::outage): success again.
    pub fn recover(&self) {
        *lock(&self.state.fallback) = Behaviour::Ok;
    }

    /// Answers the next token requests with `b` (FCM).
    pub fn push_token(&self, b: Behaviour) {
        lock(&self.state.token_script).push_back(b);
    }

    /// `expires_in` of issued access tokens (FCM), in seconds.
    pub fn set_token_lifetime(&self, secs: u64) {
        self.state.token_lifetime.store(secs, Ordering::Relaxed);
    }

    /// Push requests received so far.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        lock(&self.state.requests).clone()
    }

    /// Token requests received so far (FCM).
    #[must_use]
    pub fn token_requests(&self) -> Vec<RecordedRequest> {
        lock(&self.state.token_requests).clone()
    }

    /// TLS connections accepted so far.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::Relaxed)
    }

    /// Sends GOAWAY on every open connection (graceful shutdown), as a provider does before
    /// maintenance.
    pub fn goaway_all(&self) {
        self.goaway.send_modify(|g| *g += 1);
    }
}

/// Listeners on one port of both loopbacks, `127.0.0.1` first, so that `localhost` reaches the
/// mock whichever address it resolves to first. Without the `::1` listener a client that tries
/// `::1` first waits for the refusal before trying `127.0.0.1`: at once on Linux, but about two
/// seconds on Windows (it retries a refused SYN), the whole 2-second connect timeout. Where the
/// host has no IPv6 loopback (or no port is free on both), `127.0.0.1` alone.
async fn bind_loopback() -> (TcpListener, Option<TcpListener>) {
    let bind_v4 = || async {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind 127.0.0.1")
    };
    for _ in 0..16 {
        let v4 = bind_v4().await;
        let port = v4.local_addr().expect("addr").port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            Ok(v6) => return (v4, Some(v6)),
            // Someone else holds this port on `::1`: try another.
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(_) => return (v4, None),
        }
    }
    (bind_v4().await, None)
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<State>,
    goaway: watch::Sender<u64>,
) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
        let mut goaway = goaway.subscribe();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            state.connections.fetch_add(1, Ordering::Relaxed);
            let io = TokioIo::new(tls);
            let svc_state = Arc::clone(&state);
            let svc = service_fn(move |req| handle(Arc::clone(&svc_state), req, h2));
            goaway.borrow_and_update();
            if h2 {
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc);
                tokio::pin!(conn);
                tokio::select! {
                    _ = conn.as_mut() => return,
                    _ = goaway.changed() => conn.as_mut().graceful_shutdown(),
                }
                let _ = conn.await;
            } else {
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
                tokio::pin!(conn);
                tokio::select! {
                    _ = conn.as_mut() => return,
                    _ = goaway.changed() => conn.as_mut().graceful_shutdown(),
                }
                let _ = conn.await;
            }
        });
    }
}

async fn handle(
    state: Arc<State>,
    req: Request<Incoming>,
    http2: bool,
) -> Result<Response<Full<Bytes>>, MockReset> {
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, 1 << 20)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let rec = RecordedRequest {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_default(),
        http2,
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.to_vec(),
        at: std::time::Instant::now(),
    };

    if state.flavor == Flavor::Fcm && rec.path == "/token" {
        return Ok(token(&state, rec));
    }
    let auth = rec.header("authorization").map(str::to_owned);
    lock(&state.requests).push(rec);
    let scripted = lock(&state.script).pop_front();
    let mut b = scripted.unwrap_or_else(|| lock(&state.fallback).clone());
    match b {
        Behaviour::Slow(d) => {
            tokio::time::sleep(d).await;
            b = Behaviour::Ok;
        }
        Behaviour::Hang => std::future::pending::<()>().await,
        Behaviour::Reset => return Err(MockReset),
        _ => {}
    }
    // FCM: only tokens this mock issued are accepted.
    if state.flavor == Flavor::Fcm && b == Behaviour::Ok {
        let issued = lock(&state.issued);
        let ok = auth
            .as_deref()
            .and_then(|a| a.strip_prefix("Bearer "))
            .is_some_and(|t| issued.iter().any(|i| i == t));
        if !ok {
            b = Behaviour::ExpiredAuth;
        }
    }
    Ok(respond(state.flavor, &b))
}

fn respond(flavor: Flavor, b: &Behaviour) -> Response<Full<Bytes>> {
    match (flavor, b) {
        (Flavor::Apns, Behaviour::Ok | Behaviour::Slow(_)) => {
            let mut r = json(StatusCode::OK, "");
            r.headers_mut().insert(
                "apns-id",
                hyper::header::HeaderValue::from_static("00000000-0000-0000-0000-000000000000"),
            );
            r
        }
        (Flavor::Apns, Behaviour::Unregistered) => json(
            StatusCode::GONE,
            r#"{"reason":"Unregistered","timestamp":1700000000000}"#,
        ),
        (Flavor::Apns, Behaviour::RateLimited { retry_after }) => with_retry_after(
            json(
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"reason":"TooManyRequests"}"#,
            ),
            *retry_after,
        ),
        (Flavor::Apns, Behaviour::ServerError) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"reason":"InternalServerError"}"#,
        ),
        (Flavor::Apns, Behaviour::Unavailable) => json(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"reason":"ServiceUnavailable"}"#,
        ),
        (Flavor::Apns, Behaviour::ExpiredAuth) => json(
            StatusCode::FORBIDDEN,
            r#"{"reason":"ExpiredProviderToken"}"#,
        ),
        (Flavor::Fcm, Behaviour::Ok | Behaviour::Slow(_)) => {
            json(StatusCode::OK, r#"{"name":"projects/mock/messages/0:1"}"#)
        }
        (Flavor::Fcm, Behaviour::Unregistered) => json(
            StatusCode::NOT_FOUND,
            r#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#,
        ),
        (Flavor::Fcm, Behaviour::RateLimited { retry_after }) => with_retry_after(
            json(
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"errorCode":"QUOTA_EXCEEDED"}]}}"#,
            ),
            *retry_after,
        ),
        (Flavor::Fcm, Behaviour::ServerError) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":{"code":500,"status":"INTERNAL","details":[{"errorCode":"INTERNAL"}]}}"#,
        ),
        (Flavor::Fcm, Behaviour::Unavailable) => json(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":{"code":503,"status":"UNAVAILABLE","details":[{"errorCode":"UNAVAILABLE"}]}}"#,
        ),
        (Flavor::Fcm, Behaviour::ExpiredAuth) => json(
            StatusCode::UNAUTHORIZED,
            r#"{"error":{"code":401,"status":"UNAUTHENTICATED"}}"#,
        ),
        (Flavor::WebPush, Behaviour::Ok | Behaviour::Slow(_)) => json(StatusCode::CREATED, ""),
        (Flavor::WebPush, Behaviour::Unregistered) => json(StatusCode::GONE, ""),
        (Flavor::WebPush, Behaviour::RateLimited { retry_after }) => {
            with_retry_after(json(StatusCode::TOO_MANY_REQUESTS, ""), *retry_after)
        }
        (Flavor::WebPush, Behaviour::ServerError) => json(StatusCode::INTERNAL_SERVER_ERROR, ""),
        (Flavor::WebPush, Behaviour::Unavailable) => json(StatusCode::SERVICE_UNAVAILABLE, ""),
        (Flavor::WebPush, Behaviour::ExpiredAuth) => json(StatusCode::FORBIDDEN, ""),
        // Handled before answering; a 500 if one ever got here.
        (_, Behaviour::Hang | Behaviour::Reset) => json(StatusCode::INTERNAL_SERVER_ERROR, ""),
    }
}

fn token(state: &State, rec: RecordedRequest) -> Response<Full<Bytes>> {
    lock(&state.token_requests).push(rec);
    match lock(&state.token_script)
        .pop_front()
        .unwrap_or(Behaviour::Ok)
    {
        Behaviour::Ok | Behaviour::Slow(_) => {
            let mut issued = lock(&state.issued);
            let t = format!("mock-access-{}", issued.len());
            issued.push(t.clone());
            let lifetime = state.token_lifetime.load(Ordering::Relaxed);
            json(
                StatusCode::OK,
                &format!(
                    r#"{{"access_token":"{t}","expires_in":{lifetime},"token_type":"Bearer"}}"#
                ),
            )
        }
        Behaviour::RateLimited { retry_after } => {
            with_retry_after(json(StatusCode::TOO_MANY_REQUESTS, "{}"), retry_after)
        }
        Behaviour::ServerError | Behaviour::Unavailable | Behaviour::Hang | Behaviour::Reset => {
            json(StatusCode::INTERNAL_SERVER_ERROR, "{}")
        }
        Behaviour::ExpiredAuth | Behaviour::Unregistered => {
            json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#)
        }
    }
}
