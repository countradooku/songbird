//! Web Push for `UnifiedPush`: RFC 8291 message encryption (`aes128gcm`, RFC 8188) and RFC 8292
//! VAPID, to the endpoint of the user's own distributor.
//!
//! Every push carries the same small constant plaintext ([`PLAINTEXT`]), padded to a constant
//! record size, encrypted to the subscription's keys under a fresh ephemeral key and salt, with
//! `TTL`, `Urgency: high` and a constant `Topic` (so a distributor keeps only the latest).
//!
//! The endpoint is user supplied, so it is treated as hostile: https only, at most
//! [`MAX_ENDPOINT`] bytes of visible ASCII, no user info or fragment, port 443, and no host that is
//! or resolves to a loopback, private, link-local, shared, documentation, multicast or otherwise
//! reserved address (SSRF). The resolved address that passed the check is the one connected to.
//! Redirects are never followed. `allow_insecure_for_tests` lifts the address and port rules for
//! the mocks; it must never be set in production.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HOST, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::b64::encode_url;
use crate::breaker::{Admit, BreakerConfig, CircuitBreaker};
use crate::jwt::{Es256, pkcs8_from_pem};
use crate::net::{HttpConfig, h1_once, tls_connector};
use crate::{ConfigError, Outcome, Provider, Target, retry_after, unix_now};

/// The constant plaintext of every push.
pub const PLAINTEXT: &[u8] = b"{}";
/// The record's plaintext (content, delimiter and padding) is always this long.
pub const PADDED_LEN: usize = 32;
/// The constant `Topic` header.
pub const TOPIC: &str = "sb";
/// Endpoints longer than this are refused.
pub const MAX_ENDPOINT: usize = 2048;
/// RFC 8188 record size we declare.
const RECORD_SIZE: u32 = 4096;
/// At most this many resolved addresses are considered.
const MAX_ADDRS: usize = 16;

/// Web Push client settings. Holds no secret; the VAPID key is given to [`WebPush::new`].
#[derive(Clone, Debug)]
pub struct WebPushConfig {
    /// VAPID `sub`: a `mailto:` or `https:` contact for the push service operator.
    pub vapid_subject: String,
    /// VAPID token lifetime (`exp`), at most 24 hours.
    pub vapid_lifetime: Duration,
    /// `TTL`: how long the push service keeps an undelivered push, at most 28 days.
    pub ttl: Duration,
    /// Connections and timeouts (`connections` is unused: one connection per push).
    pub http: HttpConfig,
    /// Circuit breaker settings, applied per endpoint origin.
    pub breaker: BreakerConfig,
    /// Most origins with a breaker at once (bounded memory; attacker-chosen hosts).
    pub max_origins: usize,
    /// Allow loopback and private addresses and any port. Tests only.
    pub allow_insecure_for_tests: bool,
}

impl WebPushConfig {
    /// Production defaults with `vapid_subject`.
    #[must_use]
    pub fn new(vapid_subject: &str) -> Self {
        Self {
            vapid_subject: vapid_subject.to_owned(),
            vapid_lifetime: Duration::from_hours(12),
            ttl: Duration::from_hours(24),
            http: HttpConfig::default(),
            breaker: BreakerConfig::default(),
            max_origins: 4096,
            allow_insecure_for_tests: false,
        }
    }
}

/// A validated endpoint.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    host: String,
    port: u16,
    /// `host[:port]` as in the URL (the `Host` header).
    authority: String,
    path: String,
    ip: Option<IpAddr>,
}

impl Endpoint {
    /// The origin, for VAPID `aud` and the per-origin breaker.
    fn origin(&self) -> String {
        format!("https://{}", self.authority)
    }
}

/// Whether `ip` is anything but a public unicast address.
#[must_use]
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0                                   // "this network"
        || a == 10                           // private
        || a == 127                          // loopback
        || (a == 100 && (64..128).contains(&b)) // shared address space (CGNAT)
        || (a == 169 && b == 254)            // link-local
        || (a == 172 && (16..32).contains(&b)) // private
        || (a == 192 && b == 0 && c == 0)    // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)    // documentation
        || (a == 192 && b == 88 && c == 99)  // 6to4 relay anycast
        || (a == 192 && b == 168)            // private
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // documentation
        || (a == 203 && b == 0 && c == 113)  // documentation
        || a >= 224 // multicast, reserved, broadcast
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return forbidden_v4(v4);
    }
    let [s0, s1, s2, s3, s4, s5, s6, s7] = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96: judge the embedded address.
    if s0 == 0x64 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 {
        let [hi0, hi1] = s6.to_be_bytes();
        let [lo0, lo1] = s7.to_be_bytes();
        return forbidden_v4(Ipv4Addr::new(hi0, hi1, lo0, lo1));
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || s0 & 0xfe00 == 0xfc00           // unique local fc00::/7
        || s0 & 0xffc0 == 0xfe80           // link-local fe80::/10
        || s0 & 0xffc0 == 0xfec0           // site-local (deprecated) fec0::/10
        || s0 & 0xff00 == 0xff00           // multicast
        || (s0 == 0x2001 && s1 == 0x0db8)  // documentation
        || (s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 == 0) // discard-only 100::/64
        || s0 == 0x2002                    // 6to4: embeds an arbitrary IPv4 address
        || (s0 == 0x2001 && s1 == 0)       // Teredo: likewise
        || (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0) // IPv4-compatible
}

fn dns_name_ok(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Validates a user-supplied endpoint. `None`: never usable.
pub(crate) fn parse_endpoint(url: &str, insecure: bool) -> Option<Endpoint> {
    if url.is_empty() || url.len() > MAX_ENDPOINT || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    if url.contains('#') {
        return None;
    }
    let uri: Uri = url.parse().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let auth = uri.authority()?;
    if auth.as_str().contains('@') {
        return None;
    }
    let port = auth.port_u16().unwrap_or(443);
    if port != 443 && !insecure {
        return None;
    }
    let raw = auth.host();
    let (host, ip) = if let Some(v6) = raw.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip: Ipv6Addr = v6.parse().ok()?;
        (v6.to_owned(), Some(IpAddr::V6(ip)))
    } else if let Ok(v4) = raw.parse::<Ipv4Addr>() {
        (raw.to_owned(), Some(IpAddr::V4(v4)))
    } else {
        let host = raw.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
        if !dns_name_ok(&host) {
            return None;
        }
        // Names that only mean something inside a network (the host is lower-cased above).
        let tld = host.rsplit('.').next().unwrap_or_default();
        if !insecure
            && (!host.contains('.')
                || matches!(
                    tld,
                    "localhost" | "local" | "internal" | "arpa" | "lan" | "home"
                ))
        {
            return None;
        }
        (host, None)
    };
    if let Some(ip) = ip
        && !insecure
        && is_forbidden_ip(ip)
    {
        return None;
    }
    let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    Some(Endpoint {
        host,
        port,
        authority: auth.as_str().to_ascii_lowercase(),
        path,
        ip,
    })
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[&[u8]], out: &mut [u8]) -> Option<()> {
    Salt::new(HKDF_SHA256, salt)
        .extract(ikm)
        .expand(info, Len(out.len()))
        .ok()?
        .fill(out)
        .ok()
}

/// Content encryption key and nonce for `salt`, from the ECDH secret (RFC 8291 §3.4, RFC 8188
/// §2.2–2.3).
fn derive(
    ecdh_secret: &[u8],
    auth: &[u8; 16],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8; 16],
) -> Option<(Zeroizing<[u8; 16]>, [u8; 12])> {
    let mut ikm = Zeroizing::new([0u8; 32]);
    hkdf(
        auth,
        ecdh_secret,
        &[b"WebPush: info\0", ua_public, as_public],
        ikm.as_mut_slice(),
    )?;
    let mut cek = Zeroizing::new([0u8; 16]);
    hkdf(
        salt,
        ikm.as_slice(),
        &[b"Content-Encoding: aes128gcm\0"],
        cek.as_mut_slice(),
    )?;
    let mut nonce = [0u8; 12];
    hkdf(
        salt,
        ikm.as_slice(),
        &[b"Content-Encoding: nonce\0"],
        &mut nonce,
    )?;
    Some((cek, nonce))
}

/// RFC 8291 encryption of `plaintext` to (`ua_public`, `auth`) with the sender key `as_private`
/// and `salt`, in one record padded so that content, delimiter and padding are `pad_to` bytes
/// (or just content and delimiter, if longer).
pub(crate) fn encrypt(
    ua_public: &[u8; 65],
    auth: &[u8; 16],
    plaintext: &[u8],
    pad_to: usize,
    as_private: &PrivateKey,
    salt: &[u8; 16],
) -> Option<Vec<u8>> {
    let as_public = as_private.compute_public_key().ok()?;
    let as_public = as_public.as_ref();
    let secret = agreement::agree(
        as_private,
        UnparsedPublicKey::new(&ECDH_P256, ua_public),
        (),
        |s| Ok(Zeroizing::new(s.to_vec())),
    )
    .ok()?;
    let (cek, nonce) = derive(&secret, auth, ua_public, as_public, salt)?;

    let record_len = (plaintext.len() + 1).max(pad_to);
    if record_len + 16 > usize::try_from(RECORD_SIZE).ok()? {
        return None;
    }
    let mut record = Vec::with_capacity(record_len + 16);
    record.extend_from_slice(plaintext);
    record.push(2); // last-record delimiter
    record.resize(record_len, 0);
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, cek.as_slice()).ok()?);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut record,
    )
    .ok()?;

    let id_len = u8::try_from(as_public.len()).ok()?;
    let mut out = Vec::with_capacity(16 + 4 + 1 + as_public.len() + record.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(id_len);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&record);
    Some(out)
}

/// Decrypts a single-record RFC 8291 body as the user agent (`ua_private`, `auth`): for the mocks
/// and tests, to prove what a push carried.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn decrypt(ua_private: &[u8; 32], auth: &[u8; 16], body: &[u8]) -> Option<Vec<u8>> {
    let ua = PrivateKey::from_private_key(&ECDH_P256, ua_private).ok()?;
    let ua_public = ua.compute_public_key().ok()?;
    let salt: [u8; 16] = body.get(..16)?.try_into().ok()?;
    let id_len = usize::from(*body.get(20)?);
    let as_public = body.get(21..21 + id_len)?;
    let mut record = body.get(21 + id_len..)?.to_vec();
    let secret = agreement::agree(
        &ua,
        UnparsedPublicKey::new(&ECDH_P256, as_public),
        (),
        |s| Ok(s.to_vec()),
    )
    .ok()?;
    let (cek, nonce) = derive(&secret, auth, ua_public.as_ref(), as_public, &salt)?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, cek.as_slice()).ok()?);
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut record,
        )
        .ok()?;
    let end = plain.iter().rposition(|&b| b != 0)?;
    if plain.get(end) != Some(&2) {
        return None;
    }
    Some(plain.get(..end)?.to_vec())
}

/// A Web Push client.
pub struct WebPush {
    vapid: Es256,
    vapid_k: String,
    subject: String,
    vapid_lifetime: Duration,
    ttl: HeaderValue,
    tls: TlsConnector,
    connect_timeout: Duration,
    request_timeout: Duration,
    insecure: bool,
    breaker_cfg: BreakerConfig,
    max_origins: usize,
    breakers: Mutex<HashMap<String, Arc<CircuitBreaker>>>,
}

impl std::fmt::Debug for WebPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebPush")
            .field("insecure", &self.insecure)
            .finish_non_exhaustive()
    }
}

impl WebPush {
    /// A client signing VAPID tokens with `vapid_key_pem` (PKCS#8 PEM, P-256).
    pub fn new(cfg: WebPushConfig, vapid_key_pem: &[u8]) -> Result<Self, ConfigError> {
        let der = pkcs8_from_pem(vapid_key_pem)?;
        Self::with_pkcs8_der(cfg, der.secret_pkcs8_der())
    }

    /// As [`WebPush::new`], with the key as PKCS#8 DER.
    pub fn with_pkcs8_der(cfg: WebPushConfig, key_der: &[u8]) -> Result<Self, ConfigError> {
        let s = &cfg.vapid_subject;
        if !(s.starts_with("mailto:") || s.starts_with("https://"))
            || s.len() > 256
            || !s.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(ConfigError::Invalid(
                "vapid_subject must be mailto: or https:",
            ));
        }
        if cfg.vapid_lifetime.is_zero() || cfg.vapid_lifetime > Duration::from_hours(24) {
            return Err(ConfigError::Invalid(
                "vapid_lifetime must be at most 24 hours",
            ));
        }
        if cfg.ttl > Duration::from_hours(28 * 24) {
            return Err(ConfigError::Invalid("ttl over 28 days"));
        }
        if cfg.max_origins == 0 {
            return Err(ConfigError::Invalid("max_origins"));
        }
        cfg.http.validate()?;
        let vapid = Es256::from_pkcs8_der(key_der)?;
        let vapid_k = encode_url(vapid.public_key());
        Ok(Self {
            vapid,
            vapid_k,
            subject: cfg.vapid_subject,
            vapid_lifetime: cfg.vapid_lifetime,
            ttl: HeaderValue::from(cfg.ttl.as_secs()),
            tls: tls_connector(&cfg.http.roots, &[b"http/1.1"])?,
            connect_timeout: cfg.http.connect_timeout,
            request_timeout: cfg.http.request_timeout,
            insecure: cfg.allow_insecure_for_tests,
            breaker_cfg: cfg.breaker,
            max_origins: cfg.max_origins,
            breakers: Mutex::new(HashMap::new()),
        })
    }

    /// The VAPID public key (base64url, uncompressed P-256): the `applicationServerKey` clients
    /// subscribe with.
    #[must_use]
    pub fn vapid_public_key(&self) -> &str {
        &self.vapid_k
    }

    /// Whether `endpoint` would be accepted (for the API to refuse bad registrations early).
    #[must_use]
    pub fn endpoint_ok(&self, endpoint: &str) -> bool {
        parse_endpoint(endpoint, self.insecure).is_some()
    }

    fn breaker(&self, origin: &str) -> Arc<CircuitBreaker> {
        let mut m = self.breakers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(b) = m.get(origin) {
            return Arc::clone(b);
        }
        if m.len() >= self.max_origins {
            // Forget healthy origins first; if every one is unhealthy, forget them all rather
            // than grow.
            m.retain(|_, b| b.state() != crate::BreakerState::Closed);
            if m.len() >= self.max_origins {
                m.clear();
            }
        }
        let b = Arc::new(CircuitBreaker::new(self.breaker_cfg));
        m.insert(origin.to_owned(), Arc::clone(&b));
        b
    }

    fn vapid_header(&self, ep: &Endpoint) -> Option<HeaderValue> {
        let header = r#"{"typ":"JWT","alg":"ES256"}"#;
        let claims = serde_json::json!({
            "aud": ep.origin(),
            "exp": unix_now() + self.vapid_lifetime.as_secs(),
            "sub": self.subject,
        })
        .to_string();
        let jwt = self.vapid.sign(header, &claims)?;
        let mut v = HeaderValue::from_str(&format!("vapid t={jwt}, k={}", self.vapid_k)).ok()?;
        v.set_sensitive(true);
        Some(v)
    }

    /// Resolves the endpoint's host to the addresses that pass the SSRF rules (every answer is
    /// checked; the connection is made only to these).
    async fn resolve(&self, ep: &Endpoint) -> Result<Vec<SocketAddr>, Outcome> {
        if let Some(ip) = ep.ip {
            return Ok(vec![SocketAddr::new(ip, ep.port)]);
        }
        let lookup = tokio::time::timeout(
            self.connect_timeout,
            tokio::net::lookup_host((ep.host.as_str(), ep.port)),
        )
        .await;
        let addrs: Vec<SocketAddr> = match lookup {
            Ok(Ok(it)) => it.take(MAX_ADDRS).collect(),
            _ => return Err(Outcome::Retry { after: None }),
        };
        if addrs.is_empty() {
            return Err(Outcome::Retry { after: None });
        }
        // One forbidden answer taints the name (DNS rebinding, split answers).
        if !self.insecure && addrs.iter().any(|a| is_forbidden_ip(a.ip())) {
            tracing::warn!("web push endpoint resolves to a forbidden address; refused");
            return Err(Outcome::Failed);
        }
        Ok(addrs)
    }

    async fn deliver(&self, ep: &Endpoint, p256dh: &[u8; 65], auth: &[u8; 16]) -> Outcome {
        let Ok(as_private) = PrivateKey::generate(&ECDH_P256) else {
            return Outcome::Failed;
        };
        // A fresh random salt per push (RFC 8291), generated rather than filled in.
        let Ok(salt) = aws_lc_rs::rand::generate::<[u8; 16]>(&aws_lc_rs::rand::SystemRandom::new())
            .map(aws_lc_rs::rand::Random::expose)
        else {
            return Outcome::Failed;
        };
        // A key that is not a valid P-256 point can never be pushed to.
        let Some(body) = encrypt(p256dh, auth, PLAINTEXT, PADDED_LEN, &as_private, &salt) else {
            return Outcome::Unregistered;
        };
        let Some(vapid) = self.vapid_header(ep) else {
            return Outcome::Failed;
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri(ep.path.as_str())
            .header(HOST, ep.authority.as_str())
            .header(AUTHORIZATION, vapid)
            .header("ttl", self.ttl.clone())
            .header("urgency", "high")
            .header("topic", TOPIC)
            .header(CONTENT_ENCODING, "aes128gcm")
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(body)))
        else {
            return Outcome::Failed;
        };
        let send = async {
            let addrs = self.resolve(ep).await?;
            h1_once(&addrs, &ep.host, &self.tls, self.connect_timeout, req)
                .await
                .map_err(|e| {
                    tracing::debug!(error = %e, "web push request failed");
                    Outcome::Retry { after: None }
                })
        };
        let reply = match tokio::time::timeout(self.request_timeout, send).await {
            Ok(Ok(r)) => r,
            Ok(Err(o)) => return o,
            Err(_) => return Outcome::Retry { after: None },
        };
        match reply.status {
            s if s.is_success() => Outcome::Delivered,
            StatusCode::NOT_FOUND | StatusCode::GONE => Outcome::Unregistered,
            StatusCode::TOO_MANY_REQUESTS => Outcome::Retry {
                after: retry_after(&reply.headers),
            },
            s if s.is_server_error() => Outcome::Retry {
                after: retry_after(&reply.headers),
            },
            // Redirects are not followed; client errors will not fix themselves.
            _ => Outcome::Failed,
        }
    }
}

impl Provider for WebPush {
    async fn send(&self, target: &Target) -> Outcome {
        let Target::WebPush {
            endpoint,
            p256dh,
            auth,
        } = target
        else {
            return Outcome::Failed;
        };
        let Some(ep) = parse_endpoint(endpoint, self.insecure) else {
            tracing::debug!("web push endpoint refused by validation");
            return Outcome::Unregistered;
        };
        let breaker = self.breaker(&ep.origin());
        let admit = breaker.admit();
        if let Admit::Reject(after) = admit {
            return Outcome::Retry { after: Some(after) };
        }
        let o = self.deliver(&ep, p256dh, auth).await;
        breaker.record(admit, matches!(o, Outcome::Retry { .. }));
        o
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::{AsBigEndian as _, EcPrivateKeyBin};

    use super::*;
    use crate::b64::decode_url;

    fn d(s: &str) -> Vec<u8> {
        decode_url(&s.replace(' ', "")).unwrap()
    }

    // RFC 8291 §5 and Appendix A.
    const PLAIN: &str = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const AS_PUBLIC: &str = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
                             Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const UA_PUBLIC: &str = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
                             aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const ECDH: &str = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
    const CEK: &str = "oIhVW04MRdy2XN9CiKLxTg";
    const NONCE: &str = "4h_95klXJ5E_qnoN";
    const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
                        mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
                        pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

    fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
        v.try_into().unwrap()
    }

    #[test]
    fn rfc8291_appendix_a_vector() {
        let as_private = PrivateKey::from_private_key(&ECDH_P256, &d(AS_PRIVATE)).unwrap();
        assert_eq!(
            as_private.compute_public_key().unwrap().as_ref(),
            d(AS_PUBLIC).as_slice()
        );
        let ua_public: [u8; 65] = arr(&d(UA_PUBLIC));
        let auth: [u8; 16] = arr(&d(AUTH));
        let salt: [u8; 16] = arr(&d(SALT));

        // Intermediate values.
        let secret = agreement::agree(
            &as_private,
            UnparsedPublicKey::new(&ECDH_P256, &ua_public),
            (),
            |s| Ok(s.to_vec()),
        )
        .unwrap();
        assert_eq!(secret, d(ECDH));
        let (cek, nonce) = derive(&secret, &auth, &ua_public, &d(AS_PUBLIC), &salt).unwrap();
        assert_eq!(cek.as_slice(), d(CEK).as_slice());
        assert_eq!(nonce.as_slice(), d(NONCE).as_slice());

        // The whole body, byte for byte (no padding in the vector).
        let body = encrypt(&ua_public, &auth, &d(PLAIN), 0, &as_private, &salt).unwrap();
        assert_eq!(encode_url(&body), BODY.replace(' ', ""));
        assert_eq!(body.len(), 144);

        // And the receiver's side.
        let ua_private: [u8; 32] = arr(&d(UA_PRIVATE));
        assert_eq!(decrypt(&ua_private, &auth, &body).unwrap(), d(PLAIN));
    }

    #[test]
    fn constant_push_is_padded_and_round_trips() {
        let ua = PrivateKey::generate(&ECDH_P256).unwrap();
        let ua_public: [u8; 65] = arr(ua.compute_public_key().unwrap().as_ref());
        let bin: EcPrivateKeyBin<'static> = ua.as_be_bytes().unwrap();
        let ua_private: [u8; 32] = arr(bin.as_ref());
        // Random values: this test needs no fixed vector (D-0015).
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let random = || {
            aws_lc_rs::rand::generate::<[u8; 16]>(&rng)
                .unwrap()
                .expose()
        };
        let (auth, salt, wrong) = (random(), random(), random());
        let as_private = PrivateKey::generate(&ECDH_P256).unwrap();
        let body = encrypt(&ua_public, &auth, PLAINTEXT, PADDED_LEN, &as_private, &salt).unwrap();
        assert_eq!(body.len(), 86 + PADDED_LEN + 16);
        assert_eq!(decrypt(&ua_private, &auth, &body).unwrap(), PLAINTEXT);
        // A wrong auth secret does not open it.
        assert!(decrypt(&ua_private, &wrong, &body).is_none());
        // A public key that is not a curve point is refused.
        let mut bad = ua_public;
        bad[64] ^= 1;
        assert!(encrypt(&bad, &auth, PLAINTEXT, PADDED_LEN, &as_private, &salt).is_none());
    }

    #[test]
    fn endpoint_validation() {
        let ok = parse_endpoint("https://push.example.net/wpush/abc?x=1", false).unwrap();
        assert_eq!(ok.host, "push.example.net");
        assert_eq!(ok.port, 443);
        assert_eq!(ok.path, "/wpush/abc?x=1");
        assert_eq!(ok.origin(), "https://push.example.net");
        assert!(parse_endpoint("https://push.example.net:443/x", false).is_some());
        assert!(parse_endpoint("https://8.8.8.8/x", false).is_some());
        assert!(parse_endpoint("https://[2606:4700::1]/x", false).is_some());

        let long = format!("https://push.example.net/{}", "a".repeat(MAX_ENDPOINT));
        for bad in [
            "http://push.example.net/x",
            "https://user:pw@push.example.net/x",
            "https://push.example.net:8443/x",
            "https://push.example.net/x#frag",
            "https://push.example.net/a b",
            "https://localhost/x",
            "https://push.localhost/x",
            "https://intranet/x",
            "https://metadata.internal/x",
            "https://127.0.0.1/x",
            "https://10.1.2.3/x",
            "https://169.254.169.254/latest/meta-data",
            "https://192.168.0.1/x",
            "https://172.16.0.1/x",
            "https://100.64.0.1/x",
            "https://0.0.0.0/x",
            "https://[::1]/x",
            "https://[fe80::1]/x",
            "https://[fd00::1]/x",
            "https://[::ffff:127.0.0.1]/x",
            "https://[64:ff9b::a00:1]/x",
            "https://-bad-.example.net/x",
            "ftp://push.example.net/x",
            "",
            long.as_str(),
        ] {
            assert!(parse_endpoint(bad, false).is_none(), "{bad}");
        }
        // The test escape hatch lifts the address and port rules, not the scheme.
        assert!(parse_endpoint("https://localhost:8443/x", true).is_some());
        assert!(parse_endpoint("https://127.0.0.1:8443/x", true).is_some());
        assert!(parse_endpoint("http://localhost:8443/x", true).is_none());
    }

    #[tokio::test]
    async fn resolution_to_loopback_is_refused() {
        let key = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .unwrap();
        let wp = WebPush::with_pkcs8_der(WebPushConfig::new("mailto:a@b.example"), key.as_ref())
            .unwrap();
        // A name that passed the syntax rules but resolves to loopback (as a rebinding or
        // hostile DNS answer would).
        let ep = Endpoint {
            host: "localhost".into(),
            port: 443,
            authority: "localhost".into(),
            path: "/".into(),
            ip: None,
        };
        assert_eq!(wp.resolve(&ep).await, Err(Outcome::Failed));
    }

    #[test]
    fn forbidden_addresses() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "100.127.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.1.2.3",
            "198.18.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002::1",
            "2001::1",
            "::7f00:1",
        ] {
            assert!(is_forbidden_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "2606:4700::1111",
            "64:ff9b::808:808",
        ] {
            assert!(!is_forbidden_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
