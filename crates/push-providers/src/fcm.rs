//! Firebase Cloud Messaging HTTP v1.
//!
//! Every push is the same high-priority Android message with no notification and no data:
//! `{"message":{"token":…,"android":{"priority":"HIGH","collapse_key":"sb","ttl":"86400s"}}}`.
//! The app wakes, connects and fetches its mailbox.
//!
//! Authentication is an OAuth 2 access token obtained with a service-account JWT assertion
//! (RS256: `iss` client email, `scope` firebase.messaging, `aud` token URI, `iat`, `exp` one hour
//! later) exchanged at the token URI. The access token is cached until five minutes before it
//! expires; one refresh runs at a time. On `401` it is refreshed and the push retried once.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, StatusCode};
use serde::Deserialize;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::breaker::{Admit, BreakerConfig, BreakerState, CircuitBreaker};
use crate::jwt::{Rs256, pkcs8_from_pem};
use crate::net::{H2Pool, HttpConfig, Origin, Reply, h2_once, tls_connector};
use crate::{ConfigError, Outcome, Provider, Target, retry_after, unix_now};

/// Google's production endpoint.
pub const PRODUCTION: &str = "https://fcm.googleapis.com";
/// The OAuth scope FCM needs, and nothing more.
pub const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// The constant collapse key.
pub const COLLAPSE_KEY: &str = "sb";
const GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
/// Registration tokens longer than this are refused (they are about 160 characters today).
const MAX_TOKEN: usize = 4096;
/// Service-account files are a few KiB.
const MAX_ACCOUNT_JSON: usize = 64 * 1024;

/// A Google service account (the JSON key file's relevant fields and its RSA key).
pub struct ServiceAccount {
    project_id: String,
    client_email: String,
    token_uri: String,
    private_key_id: Option<String>,
    key: Rs256,
}

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct AccountFile {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    client_email: String,
    token_uri: String,
    private_key_id: Option<String>,
    private_key: String,
}

fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
}

impl ServiceAccount {
    /// From the service-account JSON key file Google issues.
    pub fn from_json(json: &[u8]) -> Result<Self, ConfigError> {
        if json.len() > MAX_ACCOUNT_JSON {
            return Err(ConfigError::Invalid("service account file too large"));
        }
        let mut f: AccountFile = serde_json::from_slice(json)
            .map_err(|_| ConfigError::Invalid("service account file"))?;
        let private_key = Zeroizing::new(std::mem::take(&mut f.private_key));
        if f.kind != "service_account" {
            return Err(ConfigError::Invalid("not a service account file"));
        }
        let mut sa = Self::new(
            &f.project_id,
            &f.client_email,
            &f.token_uri,
            private_key.as_bytes(),
        )?;
        if let Some(id) = f.private_key_id {
            if !id.bytes().all(|b| b.is_ascii_alphanumeric()) || id.len() > 128 {
                return Err(ConfigError::Invalid("private_key_id"));
            }
            sa.private_key_id = Some(id);
        }
        Ok(sa)
    }

    /// From its parts; `private_key_pem` is the PKCS#8 PEM RSA key.
    pub fn new(
        project_id: &str,
        client_email: &str,
        token_uri: &str,
        private_key_pem: &[u8],
    ) -> Result<Self, ConfigError> {
        let der = pkcs8_from_pem(private_key_pem)?;
        Self::with_pkcs8_der(project_id, client_email, token_uri, der.secret_pkcs8_der())
    }

    /// As [`ServiceAccount::new`], with the key as PKCS#8 DER.
    pub fn with_pkcs8_der(
        project_id: &str,
        client_email: &str,
        token_uri: &str,
        key_der: &[u8],
    ) -> Result<Self, ConfigError> {
        if !(1..=64).contains(&project_id.len())
            || !project_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ConfigError::Invalid("project_id"));
        }
        if !printable(client_email, 256) || !client_email.contains('@') {
            return Err(ConfigError::Invalid("client_email"));
        }
        Origin::parse_url(token_uri)?;
        Ok(Self {
            project_id: project_id.to_owned(),
            client_email: client_email.to_owned(),
            token_uri: token_uri.to_owned(),
            private_key_id: None,
            key: Rs256::from_pkcs8_der(key_der)?,
        })
    }

    /// The signed JWT assertion for the token request.
    fn assertion(&self) -> Option<String> {
        let header = match &self.private_key_id {
            Some(kid) => serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid }),
            None => serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
        }
        .to_string();
        let iat = unix_now();
        let claims = serde_json::json!({
            "iss": self.client_email,
            "scope": SCOPE,
            "aud": self.token_uri,
            "iat": iat,
            "exp": iat + 3600,
        })
        .to_string();
        self.key.sign(&header, &claims)
    }
}

/// FCM client settings.
#[derive(Clone, Debug)]
pub struct FcmConfig {
    /// [`PRODUCTION`] or a mock's URL.
    pub base_url: String,
    /// How long FCM keeps an undelivered message (`android.ttl`), at most 28 days.
    pub ttl: Duration,
    /// Connections and timeouts (also for the token endpoint).
    pub http: HttpConfig,
    /// Circuit breaker.
    pub breaker: BreakerConfig,
}

impl Default for FcmConfig {
    fn default() -> Self {
        Self {
            base_url: PRODUCTION.to_owned(),
            ttl: Duration::from_hours(24),
            http: HttpConfig::default(),
            breaker: BreakerConfig::default(),
        }
    }
}

struct AccessToken {
    header: HeaderValue,
    refresh_at: Instant,
    generation: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Deserialize)]
struct ErrorInner {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    details: Vec<ErrorDetail>,
}

#[derive(Deserialize)]
struct ErrorDetail {
    #[serde(rename = "errorCode", default)]
    error_code: String,
    #[serde(rename = "fieldViolations", default)]
    field_violations: Vec<FieldViolation>,
}

#[derive(Deserialize)]
struct FieldViolation {
    #[serde(default)]
    field: String,
}

enum Class {
    Done(Outcome),
    Unauthenticated,
}

/// An FCM HTTP v1 client.
pub struct Fcm {
    pool: H2Pool,
    account: ServiceAccount,
    send_url: String,
    token_origin: Origin,
    token_path: String,
    token_tls: TlsConnector,
    ttl: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    token: tokio::sync::Mutex<Option<AccessToken>>,
    breaker: CircuitBreaker,
}

impl std::fmt::Debug for Fcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fcm").finish_non_exhaustive()
    }
}

impl Fcm {
    /// A client for `account`'s project. Connects lazily.
    pub fn new(cfg: &FcmConfig, account: ServiceAccount) -> Result<Self, ConfigError> {
        if cfg.ttl > Duration::from_hours(28 * 24) {
            return Err(ConfigError::Invalid("ttl over 28 days"));
        }
        let origin = Origin::parse_base(&cfg.base_url)?;
        let send_url = origin.url(&format!(
            "/v1/projects/{}/messages:send",
            account.project_id
        ));
        let (token_origin, token_path) = Origin::parse_url(&account.token_uri)?;
        Ok(Self {
            pool: H2Pool::new(origin, &cfg.http)?,
            token_tls: tls_connector(&cfg.http.roots, &[b"h2"])?,
            send_url,
            token_origin,
            token_path,
            account,
            ttl: format!("{}s", cfg.ttl.as_secs()),
            connect_timeout: cfg.http.connect_timeout,
            request_timeout: cfg.http.request_timeout,
            token: tokio::sync::Mutex::new(None),
            breaker: CircuitBreaker::new(cfg.breaker),
        })
    }

    /// The breaker's state.
    #[must_use]
    pub fn breaker_state(&self) -> BreakerState {
        self.breaker.state()
    }

    /// The cached access token, fetching one if there is none, it is due, or it is the one
    /// (`stale`) FCM just refused. Concurrent callers wait for one fetch.
    async fn bearer(&self, stale: Option<u64>) -> Result<(HeaderValue, u64), Outcome> {
        let mut t = self.token.lock().await;
        if let Some(tok) = t.as_ref()
            && Instant::now() < tok.refresh_at
            && stale != Some(tok.generation)
        {
            return Ok((tok.header.clone(), tok.generation));
        }
        let (header, lifetime) = self.fetch_token().await?;
        let generation = t.as_ref().map_or(0, |tok| tok.generation + 1);
        // Refresh five minutes early (half-way for short-lived tokens).
        let early = if lifetime > 600 {
            lifetime - 300
        } else {
            lifetime / 2
        };
        *t = Some(AccessToken {
            header: header.clone(),
            refresh_at: Instant::now() + Duration::from_secs(early),
            generation,
        });
        Ok((header, generation))
    }

    async fn fetch_token(&self) -> Result<(HeaderValue, u64), Outcome> {
        let assertion = self.account.assertion().ok_or(Outcome::Failed)?;
        let body = Zeroizing::new(format!("grant_type={GRANT}&assertion={assertion}"));
        let req = Request::builder()
            .method(Method::POST)
            .uri(self.token_origin.url(&self.token_path))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .map_err(|_| Outcome::Failed)?;
        let sent = tokio::time::timeout(
            self.request_timeout,
            h2_once(
                &self.token_origin,
                &self.token_tls,
                self.connect_timeout,
                req,
            ),
        )
        .await;
        let reply = match sent {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "fcm token request failed");
                return Err(Outcome::Retry { after: None });
            }
            Err(_) => return Err(Outcome::Retry { after: None }),
        };
        if reply.status == StatusCode::TOO_MANY_REQUESTS || reply.status.is_server_error() {
            return Err(Outcome::Retry {
                after: retry_after(&reply.headers),
            });
        }
        if reply.status != StatusCode::OK {
            tracing::warn!(
                status = reply.status.as_u16(),
                "fcm token endpoint refused the service account"
            );
            return Err(Outcome::Failed);
        }
        let tok: TokenResponse =
            serde_json::from_slice(&reply.body).map_err(|_| Outcome::Failed)?;
        let access_token = Zeroizing::new(tok.access_token);
        if !printable(&access_token, 4096) || tok.expires_in < 2 {
            return Err(Outcome::Failed);
        }
        let mut header = HeaderValue::from_str(
            Zeroizing::new(format!("Bearer {}", access_token.as_str())).as_str(),
        )
        .map_err(|_| Outcome::Failed)?;
        header.set_sensitive(true);
        tracing::debug!("fcm access token refreshed");
        Ok((header, tok.expires_in.min(24 * 3600)))
    }

    fn body(&self, token: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "message": {
                    "token": token,
                    "android": {
                        "priority": "HIGH",
                        "collapse_key": COLLAPSE_KEY,
                        "ttl": self.ttl,
                    }
                }
            })
            .to_string(),
        )
    }

    fn classify(r: &Reply) -> Class {
        let err = || {
            serde_json::from_slice::<ErrorBody>(&r.body)
                .ok()
                .map(|b| b.error)
        };
        let code_is = |e: &ErrorInner, c: &str| e.details.iter().any(|d| d.error_code == c);
        let o = match r.status {
            StatusCode::OK => Outcome::Delivered,
            StatusCode::NOT_FOUND => Outcome::Unregistered,
            StatusCode::UNAUTHORIZED => return Class::Unauthenticated,
            StatusCode::BAD_REQUEST => match err() {
                // Our message is constant, so an invalid argument is the token, when FCM says so.
                Some(e)
                    if e.status == "INVALID_ARGUMENT"
                        && (e.details.iter().any(|d| {
                            d.field_violations
                                .iter()
                                .any(|v| v.field == "message.token")
                        }) || e.message.contains("registration token")) =>
                {
                    Outcome::Unregistered
                }
                _ => Outcome::Failed,
            },
            StatusCode::FORBIDDEN => match err() {
                // The token belongs to another sender: useless to us.
                Some(e) if code_is(&e, "SENDER_ID_MISMATCH") => Outcome::Unregistered,
                _ => Outcome::Failed,
            },
            StatusCode::TOO_MANY_REQUESTS => Outcome::Retry {
                after: retry_after(&r.headers),
            },
            s if s.is_server_error() => Outcome::Retry {
                after: retry_after(&r.headers),
            },
            _ => Outcome::Failed,
        };
        Class::Done(o)
    }

    async fn deliver(&self, token: &str) -> Outcome {
        if token.is_empty()
            || token.len() > MAX_TOKEN
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
        {
            return Outcome::Unregistered;
        }
        let body = self.body(token);
        let mut stale = None;
        for _ in 0..2 {
            let (auth, generation) = match self.bearer(stale).await {
                Ok(t) => t,
                Err(o) => return o,
            };
            let make = || {
                Request::builder()
                    .method(Method::POST)
                    .uri(self.send_url.as_str())
                    .header(AUTHORIZATION, auth.clone())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(body.clone()))
                    .ok()
            };
            let reply = match tokio::time::timeout(self.request_timeout, self.pool.send(make)).await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "fcm request failed");
                    return Outcome::Retry { after: None };
                }
                Err(_) => {
                    tracing::debug!("fcm request timed out");
                    return Outcome::Retry { after: None };
                }
            };
            match Self::classify(&reply) {
                Class::Done(o) => return o,
                Class::Unauthenticated => stale = Some(generation),
            }
        }
        tracing::warn!("fcm refused a freshly issued access token");
        Outcome::Failed
    }
}

impl Provider for Fcm {
    async fn send(&self, target: &Target) -> Outcome {
        let Target::Fcm { token } = target else {
            return Outcome::Failed;
        };
        let admit = self.breaker.admit();
        if let Admit::Reject(after) = admit {
            return Outcome::Retry { after: Some(after) };
        }
        let o = self.deliver(token).await;
        self.breaker
            .record(admit, matches!(o, Outcome::Retry { .. }));
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: u16, body: &str) -> Option<Outcome> {
        let r = Reply {
            status: StatusCode::from_u16(status).unwrap(),
            headers: hyper::HeaderMap::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
        };
        match Fcm::classify(&r) {
            Class::Done(o) => Some(o),
            Class::Unauthenticated => None,
        }
    }

    #[test]
    fn status_mapping() {
        assert_eq!(outcome(200, "{}"), Some(Outcome::Delivered));
        assert_eq!(
            outcome(
                404,
                r#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}"#
            ),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(
                400,
                r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token","details":[{"errorCode":"INVALID_ARGUMENT"}]}}"#
            ),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(
                400,
                r#"{"error":{"status":"INVALID_ARGUMENT","message":"x","details":[{"fieldViolations":[{"field":"message.token"}]}]}}"#
            ),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(
                400,
                r#"{"error":{"status":"INVALID_ARGUMENT","message":"bad ttl","details":[]}}"#
            ),
            Some(Outcome::Failed)
        );
        assert_eq!(
            outcome(
                403,
                r#"{"error":{"status":"PERMISSION_DENIED","details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}"#
            ),
            Some(Outcome::Unregistered)
        );
        assert_eq!(outcome(403, "{}"), Some(Outcome::Failed));
        assert_eq!(outcome(401, "{}"), None);
        assert_eq!(outcome(429, ""), Some(Outcome::Retry { after: None }));
        assert_eq!(outcome(503, ""), Some(Outcome::Retry { after: None }));
        assert_eq!(outcome(500, ""), Some(Outcome::Retry { after: None }));
    }

    #[test]
    fn service_account_json() {
        use aws_lc_rs::encoding::AsDer as _;
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        let der = KeyPair::generate(KeySize::Rsa2048)
            .unwrap()
            .as_der()
            .unwrap();
        let b64 = {
            // Standard base64 with line breaks, as PEM wants: re-alphabet the url encoding.
            let u = crate::b64::encode_url(der.as_ref())
                .replace('-', "+")
                .replace('_', "/");
            let pad = "=".repeat((4 - u.len() % 4) % 4);
            let s = format!("{u}{pad}");
            s.as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        let json = serde_json::json!({
            // A key generated by this test, not a credential.
            "type": "service_account", // nosemgrep: generic.secrets.security.detected-google-gcm-service-account.detected-google-gcm-service-account
            "project_id": "songbird-test",
            "private_key_id": "abc123",
            "private_key": pem,
            "client_email": "push@songbird-test.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string();
        let sa = ServiceAccount::from_json(json.as_bytes()).unwrap();
        assert_eq!(sa.project_id, "songbird-test");
        assert_eq!(sa.private_key_id.as_deref(), Some("abc123"));
        let dbg = format!("{sa:?}");
        assert!(!dbg.contains("PRIVATE") && !dbg.contains("abc123"), "{dbg}");

        let bad = json.replace("service_account", "user");
        assert!(ServiceAccount::from_json(bad.as_bytes()).is_err());
        let bad = json.replace("https://oauth2", "http://oauth2");
        assert!(ServiceAccount::from_json(bad.as_bytes()).is_err());
        assert!(ServiceAccount::from_json(&vec![b' '; MAX_ACCOUNT_JSON + 1]).is_err());
    }
}
