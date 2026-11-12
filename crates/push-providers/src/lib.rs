//! Push provider clients for Songbird's push service (D-0036).
//!
//! Every push is identical whatever triggered it: no identifiers, no counts, no content. A push
//! only wakes the device, which then fetches its mailbox over its own encrypted connection.
//!
//! - [`apns::Apns`]: Apple Push Notification service over HTTP/2 with an ES256 provider token.
//! - [`fcm::Fcm`]: Firebase Cloud Messaging HTTP v1 with an OAuth 2 service-account token.
//! - [`webpush::WebPush`]: Web Push (UnifiedPush) with RFC 8291 message encryption and RFC 8292
//!   VAPID, to an endpoint the user chose (guarded against SSRF).
//!
//! Each client has a circuit breaker ([`breaker`]); when it is open, [`Provider::send`] answers
//! [`Outcome::Retry`] at once without touching the network.
//!
//! Nothing here logs or prints a token, an endpoint or a credential: [`Target`]'s `Debug` is
//! redacted and errors carry no URLs (invariant 6).
#![forbid(unsafe_code)]

pub mod apns;
pub mod b64;
pub mod breaker;
pub mod fcm;
mod jwt;
mod net;
pub mod webpush;

#[cfg(feature = "test-support")]
pub mod test_support;

use std::fmt;
use std::future::Future;
use std::time::Duration;

pub use breaker::{BreakerConfig, BreakerState};
pub use net::{HttpConfig, mozilla_roots};

/// Where a push goes. Built by the push service from a decrypted token record; never logged.
#[derive(Clone, PartialEq, Eq)]
pub enum Target {
    /// An Apple device token (raw bytes, as the app received them from `PushKit`/`UIKit`).
    Apns {
        /// The device token.
        token: Vec<u8>,
        /// A `PushKit` `VoIP` token (incoming call), rather than an alert token.
        voip: bool,
    },
    /// An FCM registration token.
    Fcm {
        /// The registration token.
        token: String,
    },
    /// A Web Push subscription (`UnifiedPush` distributor endpoint and the app's keys).
    WebPush {
        /// The push resource URL (user supplied: validated before any connection).
        endpoint: String,
        /// The user agent's P-256 public key, uncompressed (`p256dh`).
        p256dh: [u8; 65],
        /// The user agent's authentication secret (`auth`).
        auth: [u8; 16],
    },
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apns { voip, .. } => f
                .debug_struct("Apns")
                .field("token", &"<redacted>")
                .field("voip", voip)
                .finish(),
            Self::Fcm { .. } => f.debug_struct("Fcm").field("token", &"<redacted>").finish(),
            Self::WebPush { .. } => f
                .debug_struct("WebPush")
                .field("endpoint", &"<redacted>")
                .field("p256dh", &"<redacted>")
                .field("auth", &"<redacted>")
                .finish(),
        }
    }
}

/// What a send came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The provider accepted the push.
    Delivered,
    /// The token or subscription is no longer valid: delete it at once.
    Unregistered,
    /// Transient: try again later (rate limited, provider trouble, network, open breaker).
    Retry {
        /// How long the provider (or the breaker) asked us to wait, if it said.
        after: Option<Duration>,
    },
    /// Permanent and not about the token (bad credentials, rejected request, wrong target kind).
    /// Retrying will not help; alert on it.
    Failed,
}

/// A push provider.
pub trait Provider: Send + Sync {
    /// Sends the one constant wake-up to `target`. Never panics; every failure is an [`Outcome`].
    fn send(&self, target: &Target) -> impl Future<Output = Outcome> + Send;
}

/// A configuration that cannot be used. Carries no secret, no token and no URL.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A key could not be parsed or is not of the expected kind.
    #[error("invalid key: {0}")]
    Key(&'static str),
    /// A field is missing, malformed or out of bounds.
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

/// Seconds since the Unix epoch (JWT `iat`/`exp`, `apns-expiration`).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Parses `retry-after` given in seconds (the HTTP-date form is ignored), capped at one hour.
fn retry_after(headers: &hyper::HeaderMap) -> Option<Duration> {
    const MAX: u64 = 3600;
    let v = headers.get(hyper::header::RETRY_AFTER)?.to_str().ok()?;
    let secs: u64 = v.trim().parse().ok()?;
    Some(Duration::from_secs(secs.min(MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_debug_redacts_everything_identifying() {
        let t = [
            Target::Apns {
                token: vec![0xab; 32],
                voip: true,
            },
            Target::Fcm {
                token: "secret-fcm-token".into(),
            },
            Target::WebPush {
                endpoint: "https://push.example.net/abc".into(),
                p256dh: [4; 65],
                auth: [9; 16],
            },
        ];
        for t in &t {
            let s = format!("{t:?}");
            assert!(!s.contains("abab"), "{s}");
            assert!(!s.contains("secret"), "{s}");
            assert!(!s.contains("example"), "{s}");
            assert!(!s.contains("4, 4"), "{s}");
            assert!(s.contains("<redacted>"), "{s}");
        }
    }

    #[test]
    fn retry_after_parses_seconds_only() {
        let mut h = hyper::HeaderMap::new();
        assert_eq!(retry_after(&h), None);
        h.insert(hyper::header::RETRY_AFTER, "30".parse().unwrap());
        assert_eq!(retry_after(&h), Some(Duration::from_secs(30)));
        h.insert(hyper::header::RETRY_AFTER, "999999".parse().unwrap());
        assert_eq!(retry_after(&h), Some(Duration::from_secs(3600)));
        h.insert(
            hyper::header::RETRY_AFTER,
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&h), None);
    }
}
