//! The GIF search proxy (Prompt 6, M4; D-0079 §4, D-0083): the provider (GIPHY) sees queries,
//! never who sent them; the GIF files come through `api` too, so the provider's CDN never sees an
//! app's address either.
//!
//! | Request | What it does |
//! | --- | --- |
//! | `POST /v1/gifs/search` | `{"q": <1–64 chars>, "offset": <0–4999>, "lang": <2 letters>}`, signed (for the account's budget) → `{"gifs": [{"id", "width", "height", "still", "gif", "mp4"}], "next"}` |
//! | `POST /v1/gifs/trending` | `{"offset", "lang"}`, the same answer |
//! | `GET /v1/gifs/media/<token>` | No account: the file behind a token the search answer gave (an hour), through `api` |
//!
//! What the provider receives is built from scratch: its own API key, the query, paging, the
//! rating and the language. No address, header, cookie, account or device of the app, and no
//! per-user `random_id`. Queries live only in memory (a cache keyed by a keyed hash, minutes) and
//! are never logged. Media URLs are wrapped in MAC-protected tokens and fetched only from the
//! provider's own hosts (no open proxy, no request forgery to internal addresses).

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use songbird_valkey::ValkeyConn;

use crate::Body;
use crate::config::GifSettings;

/// Largest provider answer read (a page of results).
const MAX_ANSWER: usize = 512 * 1024;
/// Longest media URL wrapped in a token.
const MAX_URL: usize = 512;
/// How long a media token works.
const TOKEN_TTL: u64 = 3_600;
/// Results per page.
const PAGE: u32 = 24;
/// Consecutive provider failures that open the circuit, and how long it stays open.
const BREAKER_FAILURES: u32 = 5;
const BREAKER_OPEN: Duration = Duration::from_secs(30);

/// One GIF of an answer, as the provider describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gif {
    /// The provider's ID.
    pub id: String,
    /// Pixels.
    pub width: u32,
    /// Pixels.
    pub height: u32,
    /// A still frame.
    pub still: String,
    /// The animation as GIF.
    pub gif: String,
    /// The animation as MP4 (smaller), if offered.
    pub mp4: Option<String>,
}

/// A GIF provider: how to ask it and how to read its answers. The transport, the cache and the
/// privacy rules are the proxy's, the same for every provider.
pub trait Provider: Send + Sync + 'static {
    /// The search request's path and query (the API key and every parameter included).
    fn search(&self, q: &str, offset: u32, lang: &str) -> String;
    /// The trending request's path and query.
    fn trending(&self, offset: u32) -> String;
    /// Reads an answer.
    ///
    /// # Errors
    /// Malformed.
    fn parse(&self, body: &[u8]) -> Result<Vec<Gif>, GifError>;
}

/// GIPHY (`https://developers.giphy.com`), the owner's choice (D-0079 §4).
pub struct Giphy {
    key: String,
    rating: String,
}

impl std::fmt::Debug for Giphy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Giphy").finish_non_exhaustive()
    }
}

impl Giphy {
    /// With the API key and the content rating (`g`, `pg`, `pg-13`, `r`).
    #[must_use]
    pub fn new(key: String, rating: String) -> Self {
        Self { key, rating }
    }
}

/// Percent-encodes a query parameter (RFC 3986 unreserved characters kept).
#[must_use]
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[derive(Deserialize)]
struct GiphyAnswer {
    #[serde(default)]
    data: Vec<GiphyGif>,
}

#[derive(Deserialize)]
struct GiphyGif {
    #[serde(default)]
    id: String,
    #[serde(default)]
    images: GiphyImages,
}

#[derive(Deserialize, Default)]
struct GiphyImages {
    #[serde(default)]
    fixed_width: Option<GiphyImage>,
    #[serde(default)]
    fixed_width_still: Option<GiphyImage>,
}

#[derive(Deserialize, Default)]
struct GiphyImage {
    #[serde(default)]
    url: String,
    #[serde(default)]
    width: String,
    #[serde(default)]
    height: String,
    #[serde(default)]
    mp4: Option<String>,
}

impl Provider for Giphy {
    fn search(&self, q: &str, offset: u32, lang: &str) -> String {
        format!(
            "/v1/gifs/search?api_key={}&q={}&limit={PAGE}&offset={offset}&rating={}&lang={}",
            encode(&self.key),
            encode(q),
            encode(&self.rating),
            encode(lang)
        )
    }

    fn trending(&self, offset: u32) -> String {
        format!(
            "/v1/gifs/trending?api_key={}&limit={PAGE}&offset={offset}&rating={}",
            encode(&self.key),
            encode(&self.rating)
        )
    }

    fn parse(&self, body: &[u8]) -> Result<Vec<Gif>, GifError> {
        let a: GiphyAnswer = serde_json::from_slice(body).map_err(|_| GifError::Unavailable)?;
        Ok(a.data
            .into_iter()
            .take(usize::try_from(PAGE).unwrap_or(24))
            .filter_map(|g| {
                let anim = g.images.fixed_width?;
                let still = g
                    .images
                    .fixed_width_still
                    .map(|s| s.url)
                    .unwrap_or_default();
                Some(Gif {
                    id: g.id.chars().take(64).collect(),
                    width: anim.width.parse().unwrap_or(0),
                    height: anim.height.parse().unwrap_or(0),
                    still,
                    gif: anim.url,
                    mp4: anim.mp4.filter(|m| !m.is_empty()),
                })
            })
            .collect())
    }
}

/// A small least-recently-inserted cache, bounded in entries and bytes.
struct Cache {
    map: HashMap<[u8; 32], (Instant, Bytes, String)>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    ttl: Duration,
}

impl Cache {
    fn new(max_entries: usize, max_bytes: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
            ttl,
        }
    }

    fn get(&self, k: &[u8; 32]) -> Option<(Bytes, String)> {
        self.map
            .get(k)
            .filter(|(at, _, _)| at.elapsed() < self.ttl)
            .map(|(_, b, t)| (b.clone(), t.clone()))
    }

    fn put(&mut self, k: [u8; 32], b: Bytes, kind: String) {
        if b.len() > self.max_bytes / 4 {
            return;
        }
        if let Some((_, old, _)) = self.map.remove(&k) {
            self.bytes -= old.len();
            self.order.retain(|o| o != &k);
        }
        while self.map.len() >= self.max_entries || self.bytes + b.len() > self.max_bytes {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some((_, ob, _)) = self.map.remove(&old) {
                self.bytes -= ob.len();
            }
        }
        self.bytes += b.len();
        self.order.push_back(k);
        self.map.insert(k, (Instant::now(), b, kind));
    }
}

/// Why the proxy could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GifError {
    /// The request is malformed (400).
    Request,
    /// No such token, or it expired (404).
    NotFound,
    /// The provider failed or the circuit is open (503 with a wait).
    Unavailable,
}

/// `[api.media.gifs]`, ready: the provider, the HTTP client, the caches, the breaker.
pub struct Gifs {
    settings: GifSettings,
    provider: Box<dyn Provider>,
    base: Uri,
    tls: Option<tokio_rustls::TlsConnector>,
    token_key: hmac::Key,
    record_key: hmac::Key,
    answers: Mutex<Cache>,
    media: Mutex<Cache>,
    failures: AtomicU32,
    open_until: AtomicU64,
    started: Instant,
}

impl std::fmt::Debug for Gifs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gifs").finish_non_exhaustive()
    }
}

impl Gifs {
    /// The proxy for `provider` at `settings.base_url`, keyed from the media secret.
    ///
    /// # Errors
    /// A malformed base URL.
    pub fn new(
        settings: GifSettings,
        provider: Box<dyn Provider>,
        secret: &[u8; 32],
    ) -> Result<Self, &'static str> {
        let base: Uri = settings.base_url.parse().map_err(|_| "gifs.base_url")?;
        let tls = match base.scheme_str() {
            Some("https") => {
                let roots = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|_| "gifs tls")?
                .with_root_certificates(roots)
                .with_no_client_auth();
                Some(tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg)))
            }
            Some("http") => None,
            _ => return Err("gifs.base_url"),
        };
        let key = |p: &[u8]| {
            let k = hmac::Key::new(hmac::HMAC_SHA256, secret);
            hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(&k, p).as_ref())
        };
        let ttl = Duration::from_secs(settings.cache_ttl_secs);
        Ok(Self {
            answers: Mutex::new(Cache::new(settings.cache_entries, 64 << 20, ttl)),
            media: Mutex::new(Cache::new(
                settings.cache_entries,
                usize::try_from(settings.media_cache_bytes).unwrap_or(usize::MAX),
                Duration::from_hours(24),
            )),
            token_key: key(b"songbird.v1/gif-token"),
            record_key: key(b"songbird.v1/gif-records"),
            provider,
            base,
            tls,
            settings,
            failures: AtomicU32::new(0),
            open_until: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &GifSettings {
        &self.settings
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether the breaker lets a provider request through.
    fn closed(&self) -> bool {
        self.open_until.load(Ordering::Relaxed) <= self.now_ms()
    }

    fn outcome(&self, ok: bool) {
        if ok {
            self.failures.store(0, Ordering::Relaxed);
        } else if self.failures.fetch_add(1, Ordering::Relaxed) + 1 >= BREAKER_FAILURES {
            let until = self.now_ms() + u64::try_from(BREAKER_OPEN.as_millis()).unwrap_or(30_000);
            self.open_until.store(until, Ordering::Relaxed);
            self.failures.store(0, Ordering::Relaxed);
            tracing::warn!("gif provider failing: circuit open");
        }
    }

    /// A keyed name: for budget records (`kind` and the subject) and cache keys.
    fn keyed(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&self.record_key);
        for p in parts {
            ctx.update(&u64::try_from(p.len()).unwrap_or(0).to_be_bytes());
            ctx.update(p);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }

    /// The budget record of an account's searches.
    #[must_use]
    pub fn record(&self, kind: &str, subject: &[u8]) -> String {
        format!(
            "m:{kind}:{}",
            hex::encode(
                self.keyed(&[kind.as_bytes(), subject])
                    .get(..16)
                    .unwrap_or_default()
            )
        )
    }

    /// Spends one provider request of the cluster-wide budget.
    async fn provider_budget(&self, hot: &ValkeyConn) -> bool {
        let per_sec = u64::from(self.settings.provider_per_sec.max(1));
        let interval = 1_000_000 / per_sec;
        hot.query::<i64>(
            redis::cmd("EVAL")
                .arg(songbird_send::gate::GCRA_COST)
                .arg(1)
                .arg("m:gp")
                .arg(interval)
                .arg(interval.saturating_mul(per_sec))
                .arg(1),
        )
        .await
        .is_ok_and(|w| w == 0)
    }

    /// One GET to the provider's API or CDN, built from scratch: no header of the app's request
    /// is ever copied.
    async fn get(&self, uri: &Uri, max: usize) -> Result<(Bytes, String), ()> {
        let host = uri.host().ok_or(())?.to_owned();
        let https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let timeout = Duration::from_secs(self.settings.timeout_secs);
        let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
        let authority = uri.authority().ok_or(())?.as_str().to_owned();
        let fut = async {
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| ())?;
            let _ = tcp.set_nodelay(true);
            let req = Request::get(path)
                .header(hyper::header::HOST, authority)
                .header(hyper::header::USER_AGENT, "songbird")
                .header(hyper::header::ACCEPT, "*/*")
                .body(Empty::<Bytes>::new())
                .map_err(|_| ())?;
            let resp = if https {
                let tls = self.tls.as_ref().ok_or(())?;
                let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|_| ())?;
                let stream = tls.connect(name, tcp).await.map_err(|_| ())?;
                let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|_| ())?;
                tokio::spawn(conn);
                send.send_request(req).await.map_err(|_| ())?
            } else {
                let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                    .await
                    .map_err(|_| ())?;
                tokio::spawn(conn);
                send.send_request(req).await.map_err(|_| ())?
            };
            if resp.status() != StatusCode::OK {
                return Err(());
            }
            let kind = resp
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = Limited::new(resp.into_body(), max)
                .collect()
                .await
                .map_err(|_| ())?
                .to_bytes();
            Ok((body, kind))
        };
        tokio::time::timeout(timeout, fut).await.map_err(|_| ())?
    }

    /// A provider URL may be fetched only from the provider's own hosts, over the base URL's
    /// scheme.
    fn allowed(&self, url: &Uri) -> bool {
        url.scheme_str() == self.base.scheme_str()
            && url
                .authority()
                .is_some_and(|a| self.settings.cdn_hosts.iter().any(|h| h == a.as_str()))
    }

    /// Wraps a provider URL: `hex(be64(expiry) ‖ MAC16 ‖ url)`.
    fn wrap(&self, url: &str, now: u64) -> Option<String> {
        if url.is_empty()
            || url.len() > MAX_URL
            || !url.parse::<Uri>().is_ok_and(|u| self.allowed(&u))
        {
            return None;
        }
        let expires = now + TOKEN_TTL;
        let mut out = Vec::with_capacity(24 + url.len());
        out.extend_from_slice(&expires.to_be_bytes());
        out.extend_from_slice(&self.token_mac(expires, url.as_bytes()));
        out.extend_from_slice(url.as_bytes());
        Some(format!("/v1/gifs/media/{}", hex::encode(out)))
    }

    fn token_mac(&self, expires: u64, url: &[u8]) -> [u8; 16] {
        let mut ctx = hmac::Context::with_key(&self.token_key);
        ctx.update(&expires.to_be_bytes());
        ctx.update(url);
        let mut m = [0u8; 16];
        m.copy_from_slice(ctx.sign().as_ref().get(..16).unwrap_or(&[0; 16]));
        m
    }

    /// Unwraps a media token: its URL, if the MAC holds and it has not expired.
    #[must_use]
    pub fn unwrap_token(&self, token: &str, now: u64) -> Option<Uri> {
        if token.len() > 2 * (24 + MAX_URL) {
            return None;
        }
        let raw = hex::decode(token).ok()?;
        let (e, rest) = raw.split_first_chunk::<8>()?;
        let (mac, url) = rest.split_first_chunk::<16>()?;
        let expires = u64::from_be_bytes(*e);
        verify_slices_are_equal(&self.token_mac(expires, url), mac).ok()?;
        if expires <= now || expires > now + TOKEN_TTL + 60 {
            return None;
        }
        let uri: Uri = std::str::from_utf8(url).ok()?.parse().ok()?;
        self.allowed(&uri).then_some(uri)
    }

    /// A page of search results or trending GIFs, as the app's JSON answer.
    pub(crate) async fn page(
        &self,
        hot: &ValkeyConn,
        search: Option<(&str, &str)>,
        offset: u32,
        now: u64,
    ) -> Result<Bytes, GifError> {
        let off = offset.to_be_bytes();
        let key = match search {
            Some((q, lang)) => self.keyed(&[b"s", lang.as_bytes(), &off, q.as_bytes()]),
            None => self.keyed(&[b"t", &off]),
        };
        if let Ok(c) = self.answers.lock()
            && let Some((b, _)) = c.get(&key)
        {
            return Ok(b);
        }
        if !self.closed() || !self.provider_budget(hot).await {
            return Err(GifError::Unavailable);
        }
        let path = match search {
            Some((q, lang)) => self.provider.search(q, offset, lang),
            None => self.provider.trending(offset),
        };
        let uri = format!("{}{path}", self.settings.base_url.trim_end_matches('/'))
            .parse::<Uri>()
            .map_err(|_| GifError::Unavailable)?;
        let got = self.get(&uri, MAX_ANSWER).await;
        self.outcome(got.is_ok());
        let (body, _) = got.map_err(|()| GifError::Unavailable)?;
        let gifs = self.provider.parse(&body).map_err(|_| {
            self.outcome(false);
            GifError::Unavailable
        })?;
        let items: Vec<serde_json::Value> = gifs
            .iter()
            .filter_map(|g| {
                Some(serde_json::json!({
                    "id": g.id,
                    "width": g.width,
                    "height": g.height,
                    "gif": self.wrap(&g.gif, now)?,
                    "still": self.wrap(&g.still, now),
                    "mp4": g.mp4.as_deref().and_then(|m| self.wrap(m, now)),
                }))
            })
            .collect();
        let next = (gifs.len() == usize::try_from(PAGE).unwrap_or(24))
            .then(|| offset.saturating_add(PAGE));
        let answer = Bytes::from(
            serde_json::to_vec(&serde_json::json!({ "gifs": items, "next": next }))
                .map_err(|_| GifError::Unavailable)?,
        );
        if let Ok(mut c) = self.answers.lock() {
            c.put(key, answer.clone(), String::new());
        }
        Ok(answer)
    }

    /// A GIF file through the proxy (cached).
    pub(crate) async fn media(
        &self,
        hot: &ValkeyConn,
        token: &str,
        now: u64,
    ) -> Result<(Bytes, &'static str), GifError> {
        let uri = self.unwrap_token(token, now).ok_or(GifError::NotFound)?;
        let key = self.keyed(&[b"m", uri.to_string().as_bytes()]);
        if let Ok(c) = self.media.lock()
            && let Some((b, kind)) = c.get(&key)
        {
            return Ok((b, media_type(&kind).ok_or(GifError::Unavailable)?));
        }
        if !self.closed() || !self.provider_budget(hot).await {
            return Err(GifError::Unavailable);
        }
        let got = self
            .get(
                &uri,
                usize::try_from(self.settings.max_media_bytes).unwrap_or(usize::MAX),
            )
            .await;
        self.outcome(got.is_ok());
        let (body, kind) = got.map_err(|()| GifError::Unavailable)?;
        let t = media_type(&kind).ok_or(GifError::Unavailable)?;
        if let Ok(mut c) = self.media.lock() {
            c.put(key, body.clone(), t.to_owned());
        }
        Ok((body, t))
    }
}

/// Only image and video types pass through, normalised.
fn media_type(header: &str) -> Option<&'static str> {
    let t = header
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match t.as_str() {
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        "image/png" => Some("image/png"),
        "image/jpeg" => Some("image/jpeg"),
        "video/mp4" => Some("video/mp4"),
        _ => None,
    }
}

/// The app's search request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GifRequest {
    /// The query (search only).
    #[serde(default)]
    pub q: Option<String>,
    /// Paging.
    #[serde(default)]
    pub offset: u32,
    /// The language (two letters).
    #[serde(default)]
    pub lang: Option<String>,
}

impl GifRequest {
    /// Decodes and bounds a request: a query of 1 to 64 characters with no control characters
    /// (for a search), an offset below 5,000, a two-letter language.
    #[must_use]
    pub fn decode(body: &[u8], search: bool) -> Option<(Option<String>, u32, String)> {
        let r: GifRequest = serde_json::from_slice(body).ok()?;
        let lang = r.lang.unwrap_or_else(|| "en".into());
        if lang.len() != 2 || !lang.bytes().all(|b| b.is_ascii_lowercase()) || r.offset >= 5_000 {
            return None;
        }
        let q = if search {
            let q = r.q?;
            let n = q.chars().count();
            ((1..=64).contains(&n) && !q.chars().any(char::is_control)).then_some(Some(q))?
        } else {
            r.q.is_none().then_some(None)?
        };
        Some((q, r.offset, lang))
    }
}

/// A JSON or media answer.
pub(crate) fn bytes_response(
    body: Bytes,
    kind: &'static str,
    cache: &'static str,
) -> Response<Body> {
    let mut r = Response::new(
        http_body_util::Full::new(body)
            .map_err(|e| match e {})
            .boxed_unsync(),
    );
    r.headers_mut()
        .insert(hyper::header::CONTENT_TYPE, HeaderValue::from_static(kind));
    r.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static(cache),
    );
    r
}

fn status(s: StatusCode) -> crate::Refusal {
    crate::Refusal::Status(s)
}

fn unavailable() -> Response<Body> {
    let mut r = crate::empty(StatusCode::SERVICE_UNAVAILABLE);
    r.headers_mut().insert(
        hyper::header::RETRY_AFTER,
        HeaderValue::from(BREAKER_OPEN.as_secs()),
    );
    r
}

/// `/v1/gifs…`.
pub(crate) async fn route(
    app: &std::sync::Arc<crate::App>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Body>, crate::Refusal> {
    use crate::media::{Media, account_of, now_secs, peer, throttle};
    let media = app
        .media
        .as_ref()
        .ok_or(status(StatusCode::SERVICE_UNAVAILABLE))?;
    let proxy = media
        .gifs()
        .ok_or(status(StatusCode::SERVICE_UNAVAILABLE))?;
    let path = req.uri().path().to_owned();
    if let Some(token) = path.strip_prefix("/v1/gifs/media/") {
        if req.method() != hyper::Method::GET {
            return Err(status(StatusCode::NOT_FOUND));
        }
        if let Some(r) = throttle(app, media, "g", peer(&req)?).await {
            return Ok(r);
        }
        return match proxy.media(&app.hot, token, now_secs()).await {
            Ok((b, kind)) => {
                app.metrics.media.gif_files.inc();
                Ok(bytes_response(b, kind, "private, max-age=86400, immutable"))
            }
            Err(GifError::NotFound | GifError::Request) => Err(status(StatusCode::NOT_FOUND)),
            Err(GifError::Unavailable) => Ok(unavailable()),
        };
    }
    let search = match (req.method(), path.as_str()) {
        (&hyper::Method::POST, "/v1/gifs/search") => true,
        (&hyper::Method::POST, "/v1/gifs/trending") => false,
        _ => return Err(status(StatusCode::NOT_FOUND)),
    };
    let (device, body) = app.authenticate_json(req).await?;
    let (q, offset, lang) =
        GifRequest::decode(&body, search).ok_or(status(StatusCode::BAD_REQUEST))?;
    let account = account_of(app, &device).await?;
    let s = proxy.settings();
    match Media::spend(
        &app.hot,
        &proxy.record("q", account.as_bytes()),
        3_600_000_000 / u64::from(s.searches_per_hour.max(1)),
        u64::from(s.search_burst),
        1,
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
    match proxy
        .page(
            &app.hot,
            q.as_deref().map(|q| (q, lang.as_str())),
            offset,
            now_secs(),
        )
        .await
    {
        Ok(b) => {
            app.metrics.media.gif_searches.inc();
            Ok(bytes_response(b, "application/json", "no-store"))
        }
        Err(GifError::Request) => Err(status(StatusCode::BAD_REQUEST)),
        Err(GifError::NotFound | GifError::Unavailable) => Ok(unavailable()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;

    fn gifs() -> Gifs {
        let s = GifSettings {
            base_url: "https://api.giphy.com".into(),
            ..GifSettings::default()
        };
        Gifs::new(
            s,
            Box::new(Giphy::new("K".into(), "pg-13".into())),
            &[1; 32],
        )
        .unwrap()
    }

    #[test]
    fn requests_carry_only_what_the_provider_needs() {
        let g = Giphy::new("k&y".into(), "pg-13".into());
        assert_eq!(
            g.search("cat & dog/ä", 24, "en"),
            "/v1/gifs/search?api_key=k%26y&q=cat%20%26%20dog%2F%C3%A4&limit=24&offset=24&rating=pg-13&lang=en"
        );
        assert_eq!(
            g.trending(0),
            "/v1/gifs/trending?api_key=k%26y&limit=24&offset=0&rating=pg-13"
        );
    }

    #[test]
    fn giphy_answers_parse_and_drop_what_is_missing() {
        let g = Giphy::new("k".into(), "g".into());
        let body = br#"{"data":[{"id":"a1","images":{"fixed_width":{"url":"https://media.giphy.com/a.gif","width":"200","height":"100","mp4":"https://media.giphy.com/a.mp4"},"fixed_width_still":{"url":"https://media.giphy.com/a_s.gif"}}},{"id":"b","images":{}}],"pagination":{"count":2}}"#;
        let out = g.parse(body).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].id.as_str(), out[0].width, out[0].height),
            ("a1", 200, 100)
        );
        assert_eq!(out[0].mp4.as_deref(), Some("https://media.giphy.com/a.mp4"));
        assert!(g.parse(b"not json").is_err());
    }

    #[test]
    fn media_tokens_are_bound_short_lived_and_only_for_the_providers_hosts() {
        let g = gifs();
        let t = g
            .wrap("https://media.giphy.com/media/x/200w.gif", 1_000)
            .unwrap();
        let token = t.strip_prefix("/v1/gifs/media/").unwrap();
        assert_eq!(
            g.unwrap_token(token, 1_000).unwrap().to_string(),
            "https://media.giphy.com/media/x/200w.gif"
        );
        assert!(
            g.unwrap_token(token, 1_000 + TOKEN_TTL).is_none(),
            "expired"
        );
        let mut bad = hex::decode(token).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(
            g.unwrap_token(&hex::encode(&bad), 1_000).is_none(),
            "tampered"
        );
        // Other hosts, other schemes and internal addresses are never wrapped.
        for url in [
            "https://evil.example/x.gif",
            "http://media.giphy.com/x.gif",
            "https://127.0.0.1/x.gif",
            "https://media.giphy.com.evil.example/x.gif",
            "",
        ] {
            assert!(g.wrap(url, 1_000).is_none(), "{url}");
        }
        // Another proxy's key: refused.
        let other = Gifs::new(
            GifSettings::default(),
            Box::new(Giphy::new("K".into(), "g".into())),
            &[2; 32],
        )
        .unwrap();
        assert!(other.unwrap_token(token, 1_000).is_none());
        assert!(g.unwrap_token("zz", 1_000).is_none());
    }

    #[test]
    fn requests_are_bounded() {
        assert_eq!(
            GifRequest::decode(br#"{"q":"cats","offset":24,"lang":"de"}"#, true),
            Some((Some("cats".into()), 24, "de".into()))
        );
        assert_eq!(
            GifRequest::decode(br#"{"offset":0}"#, false),
            Some((None, 0, "en".into()))
        );
        for (b, search) in [
            (&br#"{"q":""}"#[..], true),
            (br#"{"q":"a","offset":5000}"#, true),
            (br#"{"q":"a","lang":"eng"}"#, true),
            (br#"{"q":"a\u0000"}"#, true),
            (br#"{"offset":0}"#, true),
            (br#"{"q":"a"}"#, false),
            (br#"{"q":"a","x":1}"#, true),
        ] {
            assert_eq!(
                GifRequest::decode(b, search),
                None,
                "{}",
                String::from_utf8_lossy(b)
            );
        }
        let long = format!(r#"{{"q":"{}"}}"#, "é".repeat(65));
        assert_eq!(GifRequest::decode(long.as_bytes(), true), None);
    }

    #[test]
    fn caches_evict_by_entries_and_bytes() {
        let mut c = Cache::new(2, 100, Duration::from_secs(60));
        c.put([1; 32], Bytes::from_static(b"aa"), String::new());
        c.put([2; 32], Bytes::from_static(b"bb"), String::new());
        c.put([3; 32], Bytes::from_static(b"cc"), String::new());
        assert!(c.get(&[1; 32]).is_none());
        assert!(c.get(&[3; 32]).is_some());
        c.put([4; 32], Bytes::from(vec![0; 60]), String::new());
        assert!(
            c.get(&[4; 32]).is_none(),
            "over a quarter of the cache: not kept"
        );
        assert!(c.bytes <= 100);
    }

    #[test]
    fn media_types_pass_only_images_and_video() {
        assert_eq!(media_type("image/GIF; charset=x"), Some("image/gif"));
        assert_eq!(media_type("video/mp4"), Some("video/mp4"));
        assert_eq!(media_type("text/html"), None);
        assert_eq!(media_type(""), None);
    }
}
