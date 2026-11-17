//! Minimal S3 client for `RustFS` (D-0036): AWS Signature V4 with aws-lc-rs over `hyper`'s HTTP/1
//! client connection API, path-style URLs, one bucket per [`Client`].
//!
//! Instead of the AWS SDK and its dependency tree, this is the handful of operations Songbird
//! needs: create a bucket, put an object of an exact length, get (optionally a byte range), head,
//! delete, and list with `ListObjectsV2`.
//!
//! Security properties:
//! - Every input is bounded before use: bucket names follow the S3 rules, keys are at most
//!   [`MAX_KEY_BYTES`] without control characters or `.`/`..` segments, uploads are at most
//!   [`MAX_OBJECT_BYTES`] and must yield exactly the declared length, and response bodies the
//!   client reads (errors, lists) are capped before they are read.
//! - Object names never leave this crate in errors: [`Error`]'s `Display` and `Debug` hold only
//!   the kind of failure, the HTTP status and the S3 error code (invariant 6). Listing results
//!   redact keys in `Debug`. Credentials are [`Secret`]s.
//! - Streamed uploads are sent with `UNSIGNED-PAYLOAD` (the transport is TLS, or loopback behind
//!   the mutual-TLS tunnel); small bodies carry their real SHA-256.
#![forbid(unsafe_code)]

mod body;
pub mod multipart;
pub mod sigv4;
mod xml;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use hyper::body::{Body as _, Incoming};
use hyper::client::conn::http1;
use hyper::header::{CONTENT_LENGTH, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use songbird_types::Secret;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub use body::ObjectBody;
use body::{BODY_MISMATCH, BODY_OK, BODY_SOURCE, ExactBody, ReqBody};

/// Longest object key accepted, in bytes (the S3 limit).
pub const MAX_KEY_BYTES: usize = 1024;
/// Largest object a single PUT may carry (the S3 limit, 5 GiB).
pub const MAX_OBJECT_BYTES: u64 = 5 << 30;
/// Longest continuation token accepted, in bytes.
pub const MAX_TOKEN_BYTES: usize = 4096;
/// Largest S3 error document read.
const MAX_ERROR_BYTES: usize = 16 << 10;

/// TLS settings for the connection to the S3 endpoint.
#[derive(Clone)]
pub struct Tls {
    /// rustls client configuration (internal CA; client certificate for mutual TLS).
    pub config: Arc<rustls::ClientConfig>,
    /// Name the server certificate must carry.
    pub server_name: String,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// Client settings. `Debug` never shows the credentials.
#[derive(Clone)]
pub struct Config {
    /// `host:port` to connect to.
    pub addr: String,
    /// Value of the `Host` header (signed), usually the same as `addr`.
    pub host: String,
    /// TLS; `None` for plain TCP (loopback, development and CI).
    pub tls: Option<Tls>,
    /// Signing region.
    pub region: String,
    /// The bucket every operation works on.
    pub bucket: String,
    /// Access key ID.
    pub access_key: Secret,
    /// Secret access key.
    pub secret_key: Secret,
    /// Limit for TCP connect, TLS and the HTTP handshake.
    pub connect_timeout: Duration,
    /// Limit for each request up to its response head (and the whole response for operations
    /// that read it), and the longest pause between two chunks of an object body.
    pub request_timeout: Duration,
    /// Limit for a whole `put_object` upload.
    pub upload_timeout: Duration,
    /// Most connections open at once (in use or idle).
    pub max_connections: usize,
    /// Most idle connections kept for reuse.
    pub max_idle: usize,
    /// Largest `ListObjectsV2` response read.
    pub max_list_bytes: usize,
}

impl Config {
    /// Settings with defaults: region `us-east-1`, `host` = `addr`, plain TCP, connect 5 s,
    /// request 30 s, upload 10 min, 64 connections, 16 idle, list responses up to 4 MiB.
    #[must_use]
    pub fn new(addr: String, bucket: String, access_key: Secret, secret_key: Secret) -> Self {
        Self {
            host: addr.clone(),
            addr,
            tls: None,
            region: "us-east-1".to_owned(),
            bucket,
            access_key,
            secret_key,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(600),
            max_connections: 64,
            max_idle: 16,
            max_list_bytes: 4 << 20,
        }
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("host", &self.host)
            .field("tls", &self.tls)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key", &self.access_key)
            .field("secret_key", &self.secret_key)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("upload_timeout", &self.upload_timeout)
            .field("max_connections", &self.max_connections)
            .field("max_idle", &self.max_idle)
            .field("max_list_bytes", &self.max_list_bytes)
            .finish()
    }
}

/// An S3 error code from an error response (`NoSuchKey`, `AccessDenied`, …): ASCII letters and
/// digits only, at most 64, so it can never carry a key or a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCode(String);

impl ErrorCode {
    pub(crate) fn new(s: &str) -> Option<Self> {
        (!s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            .then(|| Self(s.to_owned()))
    }

    /// The code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Failures. Never contain object keys, bucket contents, response bodies or credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A key, bucket, range, length or setting outside the accepted bounds.
    #[error("invalid S3 request: {0}")]
    InvalidInput(&'static str),
    /// Could not connect (TCP, TLS or the HTTP handshake).
    #[error("cannot connect to object storage")]
    Connect,
    /// No answer within the configured timeout; the operation may or may not have happened.
    #[error("object storage request timed out")]
    Timeout,
    /// The connection failed during the request; the operation may or may not have happened.
    #[error("object storage connection failed")]
    Transport,
    /// The upload stream yielded more or fewer bytes than the declared length; nothing stored.
    #[error("upload body length differs from the declared length")]
    LengthMismatch,
    /// The upload stream returned an error; nothing stored.
    #[error("upload body stream failed")]
    BodySource,
    /// No such object (or bucket).
    #[error("object not found")]
    NotFound,
    /// Any other unexpected status.
    #[error("object storage returned status {status}{}", code.as_ref().map(|c| format!(" ({c})")).unwrap_or_default())]
    Status {
        /// HTTP status.
        status: u16,
        /// S3 error code, when the body carried a well-formed one.
        code: Option<ErrorCode>,
    },
    /// A response larger than the configured cap.
    #[error("object storage response too large")]
    TooLarge,
    /// A response this client cannot interpret.
    #[error("object storage protocol error: {0}")]
    Protocol(&'static str),
}

/// Result of [`Client::get_object`].
#[derive(Debug)]
pub struct GetObject {
    /// 200, or 206 for a range.
    pub status: u16,
    /// Bytes in `body` (the response's `Content-Length`).
    pub length: u64,
    /// The bytes.
    pub body: ObjectBody,
}

/// Extra settings for an upload ([`Client::put_object_with`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PutOptions {
    /// S3 Object Lock in compliance mode until this Unix time (seconds): nobody, not even the
    /// bucket owner, can delete or overwrite the object before then. The bucket must have been
    /// created with Object Lock ([`Client::create_bucket_locked`]).
    pub retain_until: Option<u64>,
    /// The body's SHA-256, sent as `x-amz-checksum-sha256` and checked by the server (Object
    /// Lock uploads require a checksum).
    pub sha256: Option<[u8; 32]>,
}

/// Result of [`Client::head_object`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Object size in bytes.
    pub length: u64,
}

/// One object of a listing. `Debug` hides the key.
#[derive(Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Object key (never log it).
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// `LastModified` as sent (ISO 8601), empty if absent.
    pub last_modified: String,
}

impl std::fmt::Debug for ListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListEntry")
            .field("size", &self.size)
            .field("last_modified", &self.last_modified)
            .finish_non_exhaustive()
    }
}

/// One stored version of an object ([`Client::list_object_versions`]). `Debug` hides the key.
#[derive(Clone, PartialEq, Eq)]
pub struct VersionEntry {
    /// Object key (never log it).
    pub key: String,
    /// The version's ID, for [`Client::get_object_version`].
    pub version_id: String,
    /// `LastModified` as sent (ISO 8601): when the server stored this version. The uploader
    /// cannot choose it.
    pub last_modified: String,
    /// Size in bytes.
    pub size: u64,
    /// The version a plain `GET` returns.
    pub is_latest: bool,
}

impl std::fmt::Debug for VersionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionEntry")
            .field("last_modified", &self.last_modified)
            .field("size", &self.size)
            .field("is_latest", &self.is_latest)
            .finish_non_exhaustive()
    }
}

/// One page of [`Client::list_object_versions`]. `Debug` hides keys and markers.
#[derive(Clone, PartialEq, Eq)]
pub struct VersionPage {
    /// Versions on this page (delete markers are left out).
    pub versions: Vec<VersionEntry>,
    /// More pages follow.
    pub is_truncated: bool,
    /// Pass to the next call when `is_truncated`.
    pub next_key_marker: Option<String>,
    /// Pass to the next call when `is_truncated`.
    pub next_version_id_marker: Option<String>,
}

impl std::fmt::Debug for VersionPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionPage")
            .field("versions", &self.versions)
            .field("is_truncated", &self.is_truncated)
            .finish_non_exhaustive()
    }
}

/// One page of [`Client::list_objects_v2`]. `Debug` hides keys and the token.
#[derive(Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Objects on this page, in key order.
    pub objects: Vec<ListEntry>,
    /// More pages follow.
    pub is_truncated: bool,
    /// Pass to the next call when `is_truncated`.
    pub next_continuation_token: Option<String>,
}

impl std::fmt::Debug for ListPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListPage")
            .field("objects", &self.objects)
            .field("is_truncated", &self.is_truncated)
            .field(
                "next_continuation_token",
                &self.next_continuation_token.is_some(),
            )
            .finish()
    }
}

/// A connection checked out of the pool, with its slot.
pub(crate) struct Pooled {
    tx: http1::SendRequest<ReqBody>,
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct Inner {
    addr: String,
    host: HeaderValue,
    tls: Option<(
        tokio_rustls::TlsConnector,
        rustls_pki_types::ServerName<'static>,
    )>,
    region: String,
    bucket: String,
    access_key: Secret,
    secret_key: Secret,
    connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
    upload_timeout: Duration,
    max_idle: usize,
    max_list_bytes: usize,
    slots: Arc<Semaphore>,
    idle: Mutex<Vec<http1::SendRequest<ReqBody>>>,
}

impl Inner {
    /// Returns a connection whose last response was read to the end.
    pub(crate) fn release(&self, conn: Pooled) {
        if conn.tx.is_closed() {
            return;
        }
        if let Ok(mut idle) = self.idle.lock()
            && idle.len() < self.max_idle
        {
            idle.push(conn.tx);
        }
    }

    fn take_idle(&self) -> Option<http1::SendRequest<ReqBody>> {
        self.idle.lock().ok()?.pop()
    }

    async fn connect(&self) -> Result<http1::SendRequest<ReqBody>, Error> {
        let fut = async {
            let tcp = TcpStream::connect(&self.addr)
                .await
                .map_err(|_| Error::Connect)?;
            tcp.set_nodelay(true).map_err(|_| Error::Connect)?;
            let mut b = http1::Builder::new();
            b.max_headers(64).max_buf_size(64 << 10);
            if let Some((connector, name)) = &self.tls {
                let tls = connector
                    .connect(name.clone(), tcp)
                    .await
                    .map_err(|_| Error::Connect)?;
                let (tx, conn) = b
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|_| Error::Connect)?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(tx)
            } else {
                let (tx, conn) = b
                    .handshake(TokioIo::new(tcp))
                    .await
                    .map_err(|_| Error::Connect)?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(tx)
            }
        };
        tokio::time::timeout(self.connect_timeout, fut)
            .await
            .map_err(|_| Error::Connect)?
    }

    /// Sends `req` on a pooled or new connection. A request that a reused connection did not
    /// send (closed by the server while idle) is sent again once on a new one.
    async fn send(&self, req: Request<ReqBody>) -> Result<(Response<Incoming>, Pooled), Error> {
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| Error::Transport)?;
        let mut req = req;
        loop {
            let (mut tx, reused) = if let Some(mut tx) = self.take_idle() {
                let ready = tokio::time::timeout(self.connect_timeout, tx.ready()).await;
                if !matches!(ready, Ok(Ok(()))) {
                    continue;
                }
                (tx, true)
            } else {
                let mut tx = self.connect().await?;
                tx.ready().await.map_err(|_| Error::Connect)?;
                (tx, false)
            };
            match tx.try_send_request(req).await {
                Ok(resp) => {
                    return Ok((
                        resp,
                        Pooled {
                            tx,
                            _permit: permit,
                        },
                    ));
                }
                Err(mut e) => match e.take_message() {
                    Some(r) if reused => req = r,
                    _ => {
                        return Err(if e.error().is_user() {
                            // Our body failed; the caller reads why from the body state.
                            Error::BodySource
                        } else {
                            Error::Transport
                        });
                    }
                },
            }
        }
    }

    fn path(&self, key: Option<&str>) -> String {
        let mut p = String::with_capacity(2 + self.bucket.len() + key.map_or(0, |k| k.len() * 3));
        p.push('/');
        p.push_str(&self.bucket);
        if let Some(k) = key {
            p.push('/');
            p.push_str(&sigv4::uri_encode(k, true));
        }
        p
    }

    /// Builds and signs a request.
    fn request(
        &self,
        method: &Method,
        key: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(&'static str, String)],
        payload_hash: &str,
        body: ReqBody,
    ) -> Result<Request<ReqBody>, Error> {
        let path = self.path(key);
        let q = sigv4::canonical_query(query);
        let uri = if q.is_empty() {
            path.clone()
        } else {
            format!("{path}?{q}")
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidInput("clock before 1970"))?
            .as_secs();
        let date = sigv4::amz_date(now);
        let host = self
            .host
            .to_str()
            .map_err(|_| Error::InvalidInput("host"))?;
        let mut signed: Vec<(&str, &str)> = vec![
            ("host", host),
            ("x-amz-content-sha256", payload_hash),
            ("x-amz-date", &date),
        ];
        for (n, v) in extra {
            signed.push((*n, v.as_str()));
        }
        let auth = sigv4::authorization(
            self.access_key.expose(),
            self.secret_key.expose(),
            sigv4::Scope {
                region: &self.region,
                service: "s3",
            },
            &date,
            &sigv4::Signable {
                method: method.as_str(),
                canonical_uri: &path,
                query,
                headers: &signed,
                payload_hash,
            },
        );
        let mut b = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(hyper::header::HOST, self.host.clone())
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", date.as_str())
            .header(hyper::header::AUTHORIZATION, auth);
        for (n, v) in extra {
            b = b.header(*n, v.as_str());
        }
        b.body(body).map_err(|_| Error::InvalidInput("request"))
    }

    /// Reads a whole response body of at most `cap` bytes; returns the connection to the pool
    /// when it was read to the end.
    async fn read_body(
        &self,
        resp: Response<Incoming>,
        conn: Pooled,
        cap: usize,
    ) -> Result<(StatusCode, Bytes), Error> {
        if let Some(len) = content_length(&resp)?
            && len > u64::try_from(cap).unwrap_or(u64::MAX)
        {
            return Err(Error::TooLarge);
        }
        self.read_to_end(resp, conn, cap).await
    }

    /// As `read_body`, without checking `Content-Length` (a HEAD response announces the
    /// object's length but has no body).
    async fn read_to_end(
        &self,
        resp: Response<Incoming>,
        conn: Pooled,
        cap: usize,
    ) -> Result<(StatusCode, Bytes), Error> {
        let status = resp.status();
        let mut body = resp.into_body();
        let mut buf = BytesMut::new();
        loop {
            let frame =
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
            match frame {
                None => break,
                Some(Err(_)) => return Err(Error::Transport),
                Some(Ok(f)) => {
                    if let Ok(data) = f.into_data() {
                        if buf.len() + data.len() > cap {
                            return Err(Error::TooLarge);
                        }
                        buf.extend_from_slice(&data);
                    }
                }
            }
        }
        self.release(conn);
        Ok((status, buf.freeze()))
    }

    async fn error_for(&self, resp: Response<Incoming>, conn: Pooled) -> Error {
        let status = resp.status();
        let code = match self.read_body(resp, conn, MAX_ERROR_BYTES).await {
            Ok((_, body)) => xml::error_code(&body),
            Err(_) => None,
        };
        if status == StatusCode::NOT_FOUND {
            return Error::NotFound;
        }
        Error::Status {
            status: status.as_u16(),
            code,
        }
    }
}

fn content_length<B>(resp: &Response<B>) -> Result<Option<u64>, Error> {
    resp.headers()
        .get(CONTENT_LENGTH)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(Error::Protocol("bad Content-Length"))
        })
        .transpose()
}

/// Bucket name rules (S3, path style): 3–63 of lowercase letters, digits, `-`, `.`, starting and
/// ending with a letter or digit, no `..`.
fn valid_bucket(b: &str) -> bool {
    let bytes = b.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.'))
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && !b.contains("..")
}

/// Keys: 1..=1024 bytes, no control characters, no leading `/`, no empty, `.` or `..` segment
/// (servers that normalize paths would otherwise address another object).
fn check_key(key: &str) -> Result<(), Error> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(Error::InvalidInput("key length"));
    }
    if key.chars().any(char::is_control) {
        return Err(Error::InvalidInput("key characters"));
    }
    if key
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(Error::InvalidInput("key segments"));
    }
    Ok(())
}

/// An S3 client bound to one bucket. Cheap to clone; clones share the connection pool.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("addr", &self.inner.addr)
            .field("bucket", &self.inner.bucket)
            .field("tls", &self.inner.tls.is_some())
            .field("idle", &self.inner.idle.lock().map_or(0, |i| i.len()))
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Validates the settings. Connects lazily.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] for a bad bucket name, host, region, TLS name or limits.
    pub fn new(cfg: Config) -> Result<Self, Error> {
        if !valid_bucket(&cfg.bucket) {
            return Err(Error::InvalidInput("bucket name"));
        }
        if cfg.region.is_empty()
            || cfg.region.len() > 32
            || !cfg
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::InvalidInput("region"));
        }
        let host = HeaderValue::from_str(&cfg.host).map_err(|_| Error::InvalidInput("host"))?;
        if cfg.host.is_empty() || !cfg.host.is_ascii() {
            return Err(Error::InvalidInput("host"));
        }
        if cfg.max_connections == 0 || cfg.max_connections > Semaphore::MAX_PERMITS {
            return Err(Error::InvalidInput("max_connections"));
        }
        if cfg.max_list_bytes == 0 {
            return Err(Error::InvalidInput("max_list_bytes"));
        }
        let ak = cfg.access_key.expose();
        if ak.is_empty()
            || ak.len() > 128
            || !ak.bytes().all(|b| b.is_ascii_graphic())
            || ak.contains('/')
        {
            return Err(Error::InvalidInput("access key"));
        }
        if cfg.secret_key.expose().is_empty() {
            return Err(Error::InvalidInput("secret key"));
        }
        let tls = match cfg.tls {
            Some(t) => {
                let name = rustls_pki_types::ServerName::try_from(t.server_name)
                    .map_err(|_| Error::InvalidInput("TLS server name"))?;
                Some((tokio_rustls::TlsConnector::from(t.config), name))
            }
            None => None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                addr: cfg.addr,
                host,
                tls,
                region: cfg.region,
                bucket: cfg.bucket,
                access_key: cfg.access_key,
                secret_key: cfg.secret_key,
                connect_timeout: cfg.connect_timeout,
                request_timeout: cfg.request_timeout,
                upload_timeout: cfg.upload_timeout,
                max_idle: cfg.max_idle,
                max_list_bytes: cfg.max_list_bytes,
                slots: Arc::new(Semaphore::new(cfg.max_connections)),
                idle: Mutex::new(Vec::new()),
            }),
        })
    }

    /// Idle connections held for reuse (for metrics and tests).
    #[must_use]
    pub fn idle_connections(&self) -> usize {
        self.inner.idle.lock().map_or(0, |i| i.len())
    }

    async fn timed<T>(
        &self,
        limit: Duration,
        fut: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        tokio::time::timeout(limit, fut)
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// Creates the bucket. Succeeds if this account already owns it.
    ///
    /// # Errors
    /// [`Error`]; `Status` with `BucketAlreadyExists` if another account owns the name.
    pub async fn create_bucket(&self) -> Result<(), Error> {
        self.create_bucket_inner(false).await
    }

    /// Creates the bucket with S3 Object Lock enabled (it cannot be turned off afterwards).
    /// Already owned: success.
    ///
    /// # Errors
    /// As [`Client::create_bucket`].
    pub async fn create_bucket_locked(&self) -> Result<(), Error> {
        self.create_bucket_inner(true).await
    }

    async fn create_bucket_inner(&self, locked: bool) -> Result<(), Error> {
        let i = &self.inner;
        let mut headers = vec![(CONTENT_LENGTH.as_str(), "0".to_owned())];
        if locked {
            headers.push(("x-amz-bucket-object-lock-enabled", "true".to_owned()));
        }
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::PUT,
                None,
                &[],
                &headers,
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status().is_success() {
                i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                return Ok(());
            }
            match i.error_for(resp, conn).await {
                Error::Status { code: Some(c), .. } if c.as_str() == "BucketAlreadyOwnedByYou" => {
                    Ok(())
                }
                e => Err(e),
            }
        })
        .await
    }

    /// Uploads `length` bytes from `body` under `key`, sent with exactly that `Content-Length`
    /// and `UNSIGNED-PAYLOAD`. If the stream yields more or fewer bytes the request is aborted
    /// before the server has a complete body, so nothing is stored.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`], [`Error::BodySource`] (the stream's own error is discarded:
    /// it could carry anything), [`Error::InvalidInput`] for a bad key or a length over
    /// [`MAX_OBJECT_BYTES`], [`Error::Timeout`] after `upload_timeout`, and the others.
    pub async fn put_object<S, E>(&self, key: &str, length: u64, body: S) -> Result<(), Error>
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: 'static,
    {
        self.put_object_with(key, length, body, PutOptions::default())
            .await
    }

    /// [`Client::put_object`] with Object Lock retention and a checksum.
    ///
    /// # Errors
    /// As [`Client::put_object`].
    pub async fn put_object_with<S, E>(
        &self,
        key: &str,
        length: u64,
        body: S,
        opts: PutOptions,
    ) -> Result<(), Error>
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: 'static,
    {
        check_key(key)?;
        if length > MAX_OBJECT_BYTES {
            return Err(Error::InvalidInput("object too large"));
        }
        let i = &self.inner;
        let state = Arc::new(AtomicU8::new(BODY_OK));
        let mut exact = ExactBody::new(body, length, Arc::clone(&state));
        let body_error = |state: &AtomicU8| match state.load(Ordering::Relaxed) {
            BODY_MISMATCH => Some(Error::LengthMismatch),
            BODY_SOURCE => Some(Error::BodySource),
            _ => None,
        };
        let result = self
            .timed(i.upload_timeout, async {
                let body = if length == 0 {
                    // hyper never polls a body announced as empty: check it here.
                    exact
                        .confirm_empty()
                        .await
                        .map_err(|_| body_error(&state).unwrap_or(Error::LengthMismatch))?;
                    ReqBody::Empty
                } else {
                    ReqBody::Exact(exact)
                };
                let mut headers = vec![(CONTENT_LENGTH.as_str(), length.to_string())];
                if let Some(until) = opts.retain_until {
                    headers.push(("x-amz-object-lock-mode", "COMPLIANCE".to_owned()));
                    headers.push(("x-amz-object-lock-retain-until-date", sigv4::iso8601(until)));
                }
                if let Some(sum) = opts.sha256 {
                    headers.push(("x-amz-checksum-sha256", sigv4::base64(&sum)));
                }
                let req = i.request(
                    &Method::PUT,
                    Some(key),
                    &[],
                    &headers,
                    sigv4::UNSIGNED_PAYLOAD,
                    body,
                )?;
                let (resp, conn) = i.send(req).await?;
                if resp.status().is_success() {
                    i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                    Ok(())
                } else {
                    Err(i.error_for(resp, conn).await)
                }
            })
            .await;
        match result {
            Err(e) => Err(body_error(&state).unwrap_or(e)),
            Ok(()) => body_error(&state).map_or(Ok(()), Err),
        }
    }

    /// Uploads a small body in one piece, signed with its SHA-256.
    ///
    /// # Errors
    /// As [`Client::put_object`].
    pub async fn put_object_bytes(&self, key: &str, body: Bytes) -> Result<(), Error> {
        check_key(key)?;
        let length = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if length > MAX_OBJECT_BYTES {
            return Err(Error::InvalidInput("object too large"));
        }
        let i = &self.inner;
        let hash = sigv4::sha256_hex(&body);
        self.timed(i.upload_timeout, async {
            let req = i.request(
                &Method::PUT,
                Some(key),
                &[],
                &[(CONTENT_LENGTH.as_str(), length.to_string())],
                &hash,
                if body.is_empty() {
                    ReqBody::Empty
                } else {
                    ReqBody::Full(Some(body))
                },
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status().is_success() {
                i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                Ok(())
            } else {
                Err(i.error_for(resp, conn).await)
            }
        })
        .await
    }

    /// Downloads `key`, or the inclusive byte range `first..=last` of it.
    ///
    /// # Errors
    /// [`Error::NotFound`]; `Status` 416 for a range past the end; the others.
    pub async fn get_object(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> Result<GetObject, Error> {
        self.get(key, range, None).await
    }

    /// Downloads one stored version of `key` (a bucket with versioning).
    ///
    /// # Errors
    /// [`Error::NotFound`]; the others.
    pub async fn get_object_version(
        &self,
        key: &str,
        version_id: &str,
    ) -> Result<GetObject, Error> {
        if version_id.is_empty()
            || version_id.len() > 1024
            || version_id.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput("version_id"));
        }
        self.get(key, None, Some(version_id)).await
    }

    async fn get(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
        version_id: Option<&str>,
    ) -> Result<GetObject, Error> {
        check_key(key)?;
        if let Some((first, last)) = range
            && first > last
        {
            return Err(Error::InvalidInput("range"));
        }
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let extra: Vec<(&'static str, String)> = range
                .map(|(a, b)| vec![("range", format!("bytes={a}-{b}"))])
                .unwrap_or_default();
            let query: Vec<(&str, &str)> = version_id
                .map(|v| vec![("versionId", v)])
                .unwrap_or_default();
            let req = i.request(
                &Method::GET,
                Some(key),
                &query,
                &extra,
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            let status = resp.status();
            let expected = if range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            if status != expected {
                return Err(if status.is_success() {
                    Error::Protocol("unexpected success status")
                } else {
                    i.error_for(resp, conn).await
                });
            }
            let length = content_length(&resp)?.ok_or(Error::Protocol("no Content-Length"))?;
            if let Some((a, b)) = range
                && length.saturating_sub(1) > b - a
            {
                return Err(Error::Protocol("range longer than requested"));
            }
            Ok(GetObject {
                status: status.as_u16(),
                length,
                body: ObjectBody::new(resp.into_body(), length, conn, Arc::clone(i)),
            })
        })
        .await
    }

    /// The object's size, or `None` if there is no such object.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn head_object(&self, key: &str) -> Result<Option<ObjectMeta>, Error> {
        check_key(key)?;
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::HEAD,
                Some(key),
                &[],
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            let status = resp.status();
            if status == StatusCode::NOT_FOUND {
                i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                return Ok(None);
            }
            if status != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let length = content_length(&resp)?.ok_or(Error::Protocol("no Content-Length"))?;
            // A HEAD response has no body; reading it only checks the connection is reusable.
            i.read_to_end(resp, conn, 0).await?;
            Ok(Some(ObjectMeta { length }))
        })
        .await
    }

    /// Deletes `key`. Deleting an object that does not exist succeeds.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn delete_object(&self, key: &str) -> Result<(), Error> {
        check_key(key)?;
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::DELETE,
                Some(key),
                &[],
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            let status = resp.status();
            if status.is_success() {
                i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                return Ok(());
            }
            match i.error_for(resp, conn).await {
                Error::NotFound => Ok(()),
                e => Err(e),
            }
        })
        .await
    }

    /// One page of up to `max_keys` (1–1000) objects whose keys start with `prefix`, after the
    /// page that returned `continuation`.
    ///
    /// # Errors
    /// [`Error::TooLarge`] past `max_list_bytes`; [`Error::Protocol`] for a malformed result;
    /// the others.
    pub async fn list_objects_v2(
        &self,
        prefix: &str,
        continuation: Option<&str>,
        max_keys: u16,
    ) -> Result<ListPage, Error> {
        if prefix.len() > MAX_KEY_BYTES || prefix.chars().any(char::is_control) {
            return Err(Error::InvalidInput("prefix"));
        }
        if !(1..=1000).contains(&max_keys) {
            return Err(Error::InvalidInput("max_keys"));
        }
        if let Some(t) = continuation
            && (t.is_empty() || t.len() > MAX_TOKEN_BYTES)
        {
            return Err(Error::InvalidInput("continuation token"));
        }
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let max = max_keys.to_string();
            let mut query: Vec<(&str, &str)> = vec![("list-type", "2"), ("max-keys", &max)];
            if !prefix.is_empty() {
                query.push(("prefix", prefix));
            }
            if let Some(t) = continuation {
                query.push(("continuation-token", t));
            }
            let req = i.request(
                &Method::GET,
                None,
                &query,
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let (_, body) = i.read_body(resp, conn, i.max_list_bytes).await?;
            xml::list_objects(&body, usize::from(max_keys))
        })
        .await
    }

    /// One page of up to `max_keys` (1–1000) object versions whose keys start with `prefix`,
    /// after the markers of the previous page (delete markers are left out).
    ///
    /// # Errors
    /// As [`Client::list_objects_v2`].
    pub async fn list_object_versions(
        &self,
        prefix: &str,
        key_marker: Option<&str>,
        version_id_marker: Option<&str>,
        max_keys: u16,
    ) -> Result<VersionPage, Error> {
        if prefix.len() > MAX_KEY_BYTES || prefix.chars().any(char::is_control) {
            return Err(Error::InvalidInput("prefix"));
        }
        if !(1..=1000).contains(&max_keys) {
            return Err(Error::InvalidInput("max_keys"));
        }
        for m in [key_marker, version_id_marker].into_iter().flatten() {
            if m.is_empty()
                || m.len() > MAX_TOKEN_BYTES.max(MAX_KEY_BYTES)
                || m.chars().any(char::is_control)
            {
                return Err(Error::InvalidInput("marker"));
            }
        }
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let max = max_keys.to_string();
            let mut query: Vec<(&str, &str)> = vec![("versions", ""), ("max-keys", &max)];
            if !prefix.is_empty() {
                query.push(("prefix", prefix));
            }
            if let Some(k) = key_marker {
                query.push(("key-marker", k));
            }
            if let Some(v) = version_id_marker {
                query.push(("version-id-marker", v));
            }
            let req = i.request(
                &Method::GET,
                None,
                &query,
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let (_, body) = i.read_body(resp, conn, i.max_list_bytes).await?;
            xml::list_versions(&body, usize::from(max_keys))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::new(
            "127.0.0.1:1".into(),
            "songbird-test".into(),
            Secret::new("AKIDEXAMPLE".into()),
            Secret::new("very-secret-value".into()),
        )
    }

    #[test]
    fn debug_hides_secrets() {
        let c = cfg();
        let s = format!("{c:?}");
        assert!(
            !s.contains("very-secret-value") && !s.contains("AKIDEXAMPLE"),
            "{s}"
        );
        let client = Client::new(c).unwrap();
        assert!(!format!("{client:?}").contains("very-secret-value"));
    }

    #[test]
    fn validates_config() {
        for bucket in ["ab", "Upper", "-a-b", "a..b", "a_b", &"a".repeat(64)] {
            let mut c = cfg();
            c.bucket = bucket.to_owned();
            assert!(Client::new(c).is_err(), "{bucket}");
        }
        let mut c = cfg();
        c.max_connections = 0;
        assert!(Client::new(c).is_err());
        let mut c = cfg();
        c.region = "US EAST".into();
        assert!(Client::new(c).is_err());
        let mut c = cfg();
        c.host = "bad\nhost".into();
        assert!(Client::new(c).is_err());
    }

    #[test]
    fn keys_are_bounded() {
        assert!(check_key("a/b/c.bin").is_ok());
        assert!(check_key(&"k".repeat(MAX_KEY_BYTES)).is_ok());
        for bad in ["", "/a", "a//b", "a/", "./a", "a/../b", "a\nb", "a\u{7f}"] {
            assert!(check_key(bad).is_err(), "{bad:?}");
        }
        assert!(check_key(&"k".repeat(MAX_KEY_BYTES + 1)).is_err());
    }

    #[test]
    fn errors_never_show_keys() {
        let e = Error::Status {
            status: 409,
            code: ErrorCode::new("BucketAlreadyExists"),
        };
        assert_eq!(
            e.to_string(),
            "object storage returned status 409 (BucketAlreadyExists)"
        );
        assert_eq!(
            Error::Status {
                status: 500,
                code: None
            }
            .to_string(),
            "object storage returned status 500"
        );
        assert!(ErrorCode::new("No/Such").is_none());
    }

    #[test]
    fn signed_request_shape() {
        let client = Client::new(cfg()).unwrap();
        let req = client
            .inner
            .request(
                &Method::GET,
                None,
                &[("list-type", "2"), ("prefix", "a b/c")],
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )
            .unwrap();
        assert_eq!(req.uri().path(), "/songbird-test");
        assert_eq!(req.uri().query(), Some("list-type=2&prefix=a%20b%2Fc"));
        let auth = req.headers()["authorization"].to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(auth.contains("/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="));
        let req = client
            .inner
            .request(
                &Method::GET,
                Some("dir/a b+c"),
                &[],
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )
            .unwrap();
        assert_eq!(req.uri().path(), "/songbird-test/dir/a%20b%2Bc");
    }

    /// A server that answers one request per connection, then closes it (and, for the oversized
    /// case, announces a body larger than the client's cap).
    async fn one_shot_server(response: &'static [u8]) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let Ok(n) = s.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let _ = s.write_all(response).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn closed_idle_connections_are_replaced() {
        let addr = one_shot_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").await;
        let mut c = cfg();
        c.addr = addr.clone();
        c.host = addr;
        let client = Client::new(c).unwrap();
        for _ in 0..3 {
            let meta = client.head_object("k").await.unwrap();
            assert_eq!(meta, Some(ObjectMeta { length: 5 }));
        }
    }

    #[tokio::test]
    async fn oversized_list_is_refused_before_reading() {
        let addr = one_shot_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n<ListBucketResult>",
        )
        .await;
        let mut c = cfg();
        c.addr = addr.clone();
        c.host = addr;
        c.max_list_bytes = 1024;
        let client = Client::new(c).unwrap();
        assert_eq!(
            client.list_objects_v2("", None, 10).await.unwrap_err(),
            Error::TooLarge
        );
    }

    #[tokio::test]
    async fn connect_failures_and_timeouts_are_bounded() {
        // Nothing listens on port 1.
        let client = Client::new(cfg()).unwrap();
        assert_eq!(client.head_object("k").await.unwrap_err(), Error::Connect);
        // A server that accepts and never answers.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        let mut c = cfg();
        c.addr = addr.clone();
        c.host = addr;
        c.request_timeout = Duration::from_millis(200);
        let client = Client::new(c).unwrap();
        assert_eq!(client.head_object("k").await.unwrap_err(), Error::Timeout);
    }
}
