//! APNs over HTTP/2 with token-based authentication.
//!
//! Every alert push is the same: `{"aps":{"alert":{"title":…,"body":…},"mutable-content":1}}`
//! with the configured generic text, a constant `apns-collapse-id`, priority 10 and a 24-hour
//! expiry. The notification service extension on the device fetches and decrypts the real
//! content. `VoIP` pushes (incoming calls, `PushKit`) go on their own topic with an empty
//! payload and expiry 0: a call is delivered now or never.
//!
//! The provider token (ES256 JWT: `kid` key ID, `iss` team ID, `iat`) is minted once and reused
//! until it is 50 minutes old (Apple: refresh between 20 and 60 minutes, not more often). On
//! `403 ExpiredProviderToken` it is minted again and the push retried once.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, StatusCode};
use serde::Deserialize;
use tokio::time::Instant;

use crate::breaker::{Admit, BreakerConfig, BreakerState, CircuitBreaker};
use crate::jwt::{Es256, pkcs8_from_pem};
use crate::net::{H2Pool, HttpConfig, Origin, Reply};
use crate::{ConfigError, Outcome, Provider, Target, retry_after, unix_now};

/// Apple's production endpoint.
pub const PRODUCTION: &str = "https://api.push.apple.com";
/// Apple's development (sandbox) endpoint.
pub const SANDBOX: &str = "https://api.sandbox.push.apple.com";
/// The constant collapse identifier: many pushes to one device coalesce into one.
pub const COLLAPSE_ID: &str = "sb";
/// The `VoIP` payload: nothing (`PushKit` hands the app the push; the app asks the server).
pub const VOIP_BODY: &str = "{}";
/// Device tokens longer than this are refused (Apple's are 32 bytes today; leave room).
const MAX_TOKEN: usize = 100;

/// APNs client settings. Holds no secret; the signing key is given to [`Apns::new`].
#[derive(Clone, Debug)]
pub struct ApnsConfig {
    /// [`PRODUCTION`], [`SANDBOX`] or a mock's URL.
    pub base_url: String,
    /// Apple developer team ID (`iss`).
    pub team_id: String,
    /// Key ID of the `.p8` signing key (`kid`).
    pub key_id: String,
    /// The app's bundle ID (`apns-topic`; `<bundle>.voip` for `VoIP`).
    pub bundle_id: String,
    /// Generic alert title shown if the extension cannot run.
    pub alert_title: String,
    /// Generic alert body shown if the extension cannot run.
    pub alert_body: String,
    /// How long APNs keeps an undelivered alert (`apns-expiration`), at most 30 days.
    pub expiration: Duration,
    /// Provider token age at which a new one is minted, 20 to 60 minutes.
    pub token_refresh: Duration,
    /// Connections and timeouts.
    pub http: HttpConfig,
    /// Circuit breaker.
    pub breaker: BreakerConfig,
}

impl ApnsConfig {
    /// Production defaults for `team_id`, `key_id` and `bundle_id`.
    #[must_use]
    pub fn new(team_id: &str, key_id: &str, bundle_id: &str) -> Self {
        Self {
            base_url: PRODUCTION.to_owned(),
            team_id: team_id.to_owned(),
            key_id: key_id.to_owned(),
            bundle_id: bundle_id.to_owned(),
            alert_title: "Songbird".to_owned(),
            alert_body: "New message".to_owned(),
            expiration: Duration::from_hours(24),
            token_refresh: Duration::from_mins(50),
            http: HttpConfig::default(),
            breaker: BreakerConfig::default(),
        }
    }
}

fn alnum10(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn bundle_ok(s: &str) -> bool {
    (1..=155).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

struct ProviderToken {
    header: HeaderValue,
    minted: Instant,
    generation: u64,
}

/// An APNs client.
pub struct Apns {
    pool: H2Pool,
    key: Es256,
    team_id: String,
    key_id: String,
    topic: HeaderValue,
    voip_topic: HeaderValue,
    alert: Bytes,
    expiration: Duration,
    token_refresh: Duration,
    request_timeout: Duration,
    token: Mutex<Option<ProviderToken>>,
    breaker: CircuitBreaker,
}

impl std::fmt::Debug for Apns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apns").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct ApnsError {
    reason: Option<String>,
}

enum Class {
    Done(Outcome),
    ExpiredProviderToken,
}

impl Apns {
    /// A client signing with the `.p8` key `key_pem` (PKCS#8 PEM, P-256). Connects lazily.
    pub fn new(cfg: ApnsConfig, key_pem: &[u8]) -> Result<Self, ConfigError> {
        let der = pkcs8_from_pem(key_pem)?;
        Self::with_pkcs8_der(cfg, der.secret_pkcs8_der())
    }

    /// As [`Apns::new`], with the key as PKCS#8 DER.
    pub fn with_pkcs8_der(cfg: ApnsConfig, key_der: &[u8]) -> Result<Self, ConfigError> {
        if !alnum10(&cfg.team_id) {
            return Err(ConfigError::Invalid(
                "team_id must be 10 upper-case letters or digits",
            ));
        }
        if !alnum10(&cfg.key_id) {
            return Err(ConfigError::Invalid(
                "key_id must be 10 upper-case letters or digits",
            ));
        }
        if !bundle_ok(&cfg.bundle_id) {
            return Err(ConfigError::Invalid("bundle_id"));
        }
        if cfg.alert_title.len() > 100 || cfg.alert_body.len() > 200 {
            return Err(ConfigError::Invalid("alert text too long"));
        }
        if cfg.expiration > Duration::from_hours(30 * 24) {
            return Err(ConfigError::Invalid("expiration over 30 days"));
        }
        if !(Duration::from_mins(20)..=Duration::from_hours(1)).contains(&cfg.token_refresh) {
            return Err(ConfigError::Invalid(
                "token_refresh must be 20 to 60 minutes",
            ));
        }
        let alert = serde_json::json!({
            "aps": {
                "alert": { "title": cfg.alert_title, "body": cfg.alert_body },
                "mutable-content": 1
            }
        })
        .to_string();
        let topic =
            HeaderValue::from_str(&cfg.bundle_id).map_err(|_| ConfigError::Invalid("bundle_id"))?;
        let voip_topic = HeaderValue::from_str(&format!("{}.voip", cfg.bundle_id))
            .map_err(|_| ConfigError::Invalid("bundle_id"))?;
        Ok(Self {
            pool: H2Pool::new(Origin::parse_base(&cfg.base_url)?, &cfg.http)?,
            key: Es256::from_pkcs8_der(key_der)?,
            team_id: cfg.team_id,
            key_id: cfg.key_id,
            topic,
            voip_topic,
            alert: Bytes::from(alert),
            expiration: cfg.expiration,
            token_refresh: cfg.token_refresh,
            request_timeout: cfg.http.request_timeout,
            token: Mutex::new(None),
            breaker: CircuitBreaker::new(cfg.breaker),
        })
    }

    /// The breaker's state.
    #[must_use]
    pub fn breaker_state(&self) -> BreakerState {
        self.breaker.state()
    }

    /// The cached provider token, minting one if there is none, it is due, or it is the one
    /// (`stale`) APNs just called expired.
    fn bearer(&self, stale: Option<u64>) -> Option<(HeaderValue, u64)> {
        let mut t = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tok) = t.as_ref()
            && tok.minted.elapsed() < self.token_refresh
            && stale != Some(tok.generation)
        {
            return Some((tok.header.clone(), tok.generation));
        }
        let header = serde_json::json!({ "alg": "ES256", "kid": self.key_id }).to_string();
        let claims = serde_json::json!({ "iss": self.team_id, "iat": unix_now() }).to_string();
        let jwt = self.key.sign(&header, &claims)?;
        let mut value = HeaderValue::from_str(&format!("bearer {jwt}")).ok()?;
        value.set_sensitive(true);
        let generation = t.as_ref().map_or(0, |tok| tok.generation + 1);
        *t = Some(ProviderToken {
            header: value.clone(),
            minted: Instant::now(),
            generation,
        });
        drop(t);
        tracing::debug!("apns provider token minted");
        Some((value, generation))
    }

    fn request(&self, uri: &str, auth: &HeaderValue, voip: bool) -> Option<Request<Full<Bytes>>> {
        let (topic, kind, expiry, body) = if voip {
            (
                &self.voip_topic,
                "voip",
                0,
                Bytes::from_static(VOIP_BODY.as_bytes()),
            )
        } else {
            (
                &self.topic,
                "alert",
                unix_now() + self.expiration.as_secs(),
                self.alert.clone(),
            )
        };
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(AUTHORIZATION, auth.clone())
            .header("apns-topic", topic.clone())
            .header("apns-push-type", kind)
            .header("apns-priority", "10")
            .header("apns-collapse-id", COLLAPSE_ID)
            .header("apns-expiration", expiry.to_string())
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .ok()
    }

    fn classify(r: &Reply) -> Class {
        let reason = || {
            serde_json::from_slice::<ApnsError>(&r.body)
                .ok()
                .and_then(|e| e.reason)
                .unwrap_or_default()
        };
        let o = match r.status {
            StatusCode::OK => Outcome::Delivered,
            StatusCode::GONE => Outcome::Unregistered,
            StatusCode::BAD_REQUEST => match reason().as_str() {
                "BadDeviceToken" | "DeviceTokenNotForTopic" => Outcome::Unregistered,
                _ => Outcome::Failed,
            },
            StatusCode::FORBIDDEN => {
                if reason() == "ExpiredProviderToken" {
                    return Class::ExpiredProviderToken;
                }
                Outcome::Failed
            }
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

    async fn deliver(&self, token: &[u8], voip: bool) -> Outcome {
        if token.is_empty() || token.len() > MAX_TOKEN {
            return Outcome::Unregistered;
        }
        let uri = self
            .pool
            .origin()
            .url(&format!("/3/device/{}", hex::encode(token)));
        let mut stale = None;
        for _ in 0..2 {
            let Some((auth, generation)) = self.bearer(stale) else {
                return Outcome::Failed;
            };
            let sent = tokio::time::timeout(
                self.request_timeout,
                self.pool.send(|| self.request(&uri, &auth, voip)),
            )
            .await;
            let reply = match sent {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "apns request failed");
                    return Outcome::Retry { after: None };
                }
                Err(_) => {
                    tracing::debug!("apns request timed out");
                    return Outcome::Retry { after: None };
                }
            };
            match Self::classify(&reply) {
                Class::Done(o) => return o,
                Class::ExpiredProviderToken => stale = Some(generation),
            }
        }
        tracing::warn!("apns rejected a freshly minted provider token (clock or key problem)");
        Outcome::Failed
    }
}

impl Provider for Apns {
    async fn send(&self, target: &Target) -> Outcome {
        let Target::Apns { token, voip } = target else {
            return Outcome::Failed;
        };
        let admit = self.breaker.admit();
        if let Admit::Reject(after) = admit {
            return Outcome::Retry { after: Some(after) };
        }
        let o = self.deliver(token, *voip).await;
        self.breaker
            .record(admit, matches!(o, Outcome::Retry { .. }));
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: &str) -> Reply {
        Reply {
            status: StatusCode::from_u16(status).unwrap(),
            headers: hyper::HeaderMap::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
        }
    }

    fn outcome(status: u16, body: &str) -> Option<Outcome> {
        match Apns::classify(&reply(status, body)) {
            Class::Done(o) => Some(o),
            Class::ExpiredProviderToken => None,
        }
    }

    #[test]
    fn status_mapping() {
        assert_eq!(outcome(200, ""), Some(Outcome::Delivered));
        assert_eq!(
            outcome(410, r#"{"reason":"Unregistered"}"#),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(410, r#"{"reason":"ExpiredToken"}"#),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(400, r#"{"reason":"BadDeviceToken"}"#),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(400, r#"{"reason":"DeviceTokenNotForTopic"}"#),
            Some(Outcome::Unregistered)
        );
        assert_eq!(
            outcome(400, r#"{"reason":"BadTopic"}"#),
            Some(Outcome::Failed)
        );
        assert_eq!(outcome(400, "garbage"), Some(Outcome::Failed));
        assert_eq!(outcome(403, r#"{"reason":"ExpiredProviderToken"}"#), None);
        assert_eq!(
            outcome(403, r#"{"reason":"InvalidProviderToken"}"#),
            Some(Outcome::Failed)
        );
        assert_eq!(outcome(429, ""), Some(Outcome::Retry { after: None }));
        assert_eq!(outcome(503, ""), Some(Outcome::Retry { after: None }));
        assert_eq!(outcome(413, ""), Some(Outcome::Failed));
    }

    #[test]
    fn config_validation() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let ok = ApnsConfig::new("ABCDE12345", "KEY1234567", "eu.songbird.app");
        assert!(Apns::with_pkcs8_der(ok.clone(), key.as_ref()).is_ok());
        let mut c = ok.clone();
        c.team_id = "short".into();
        assert!(Apns::with_pkcs8_der(c, key.as_ref()).is_err());
        let mut c = ok.clone();
        c.bundle_id = "bad bundle\n".into();
        assert!(Apns::with_pkcs8_der(c, key.as_ref()).is_err());
        let mut c = ok.clone();
        c.token_refresh = Duration::from_mins(61);
        assert!(Apns::with_pkcs8_der(c, key.as_ref()).is_err());
        let mut c = ok;
        c.base_url = "http://api.push.apple.com".into();
        assert!(Apns::with_pkcs8_der(c, key.as_ref()).is_err());
    }
}
