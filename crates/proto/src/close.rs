//! WebSocket close codes and retry hints.
//!
//! Three ranges, after Pusher's (`docs/PROTOCOL.md` §2.4):
//!
//! - `4000–4099`: do not reconnect automatically (authentication failed, replaced by a newer
//!   connection, device removed, protocol violation). Reconnecting would fail again or fight the
//!   newer connection.
//! - `4100–4199`: reconnect with jittered exponential backoff (slow consumer, overload, rate
//!   limited, authentication timeout, server unavailable).
//! - `4200–4299`: reconnect now, to any node (drain for deploy).
//!
//! The close reason may carry a retry hint, `retry_ms=<decimal>`: the client waits at least that
//! long (plus jitter) before reconnecting.

/// Songbird close codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// The signature did not verify, or the device is unknown.
    AuthFailed,
    /// A newer connection for the same device took over (invariant 4).
    Replaced,
    /// The device was removed from its account.
    DeviceRemoved,
    /// The client broke the protocol (malformed frame, ACK beyond what was sent).
    ProtocolError,
    /// The client offered no protocol version this server speaks.
    UnsupportedVersion,
    /// The client could not keep up; it catches up from the mailbox after reconnecting.
    SlowConsumer,
    /// The server is overloaded (accept-rate limit, connection cap).
    Overloaded,
    /// No `Auth` within the authentication timeout.
    AuthTimeout,
    /// Too many frames or sends.
    RateLimited,
    /// A dependency (the mailbox store) is unavailable.
    Unavailable,
    /// The server is draining for a deploy; reconnect now.
    Draining,
    /// A code from a newer server: handled by its range.
    Other(u16),
}

/// What a client does after a close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconnect {
    /// Stop; surface the reason to the app.
    Never,
    /// Retry with jittered exponential backoff.
    Backoff,
    /// Retry immediately (with a small jitter).
    Now,
}

impl CloseCode {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::AuthFailed => 4000,
            Self::Replaced => 4001,
            Self::DeviceRemoved => 4002,
            Self::ProtocolError => 4003,
            Self::UnsupportedVersion => 4004,
            Self::SlowConsumer => 4100,
            Self::Overloaded => 4101,
            Self::AuthTimeout => 4102,
            Self::RateLimited => 4103,
            Self::Unavailable => 4104,
            Self::Draining => 4200,
            Self::Other(c) => c,
        }
    }

    /// From a wire value.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            4000 => Self::AuthFailed,
            4001 => Self::Replaced,
            4002 => Self::DeviceRemoved,
            4003 => Self::ProtocolError,
            4004 => Self::UnsupportedVersion,
            4100 => Self::SlowConsumer,
            4101 => Self::Overloaded,
            4102 => Self::AuthTimeout,
            4103 => Self::RateLimited,
            4104 => Self::Unavailable,
            4200 => Self::Draining,
            c => Self::Other(c),
        }
    }

    /// The reconnect rule for any close code, Songbird's or a standard one.
    #[must_use]
    pub const fn reconnect(code: u16) -> Reconnect {
        match code {
            4000..=4099 => Reconnect::Never,
            4200..=4299 => Reconnect::Now,
            // 41xx, standard codes (1001 going away, 1006 abnormal, 1011 internal…) and unknown
            // private codes: back off and retry.
            _ => Reconnect::Backoff,
        }
    }
}

/// Prefix of the retry hint in a close reason.
pub const RETRY_PREFIX: &str = "retry_ms=";

/// Formats a close reason carrying a retry hint (at most 19 bytes, well under the 123-byte limit).
#[must_use]
pub fn retry_reason(retry_ms: u32) -> String {
    format!("{RETRY_PREFIX}{retry_ms}")
}

/// Parses a retry hint from a close reason; `None` if there is none or it is malformed.
#[must_use]
pub fn parse_retry(reason: &str) -> Option<u32> {
    let digits = reason.strip_prefix(RETRY_PREFIX)?;
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn codes_round_trip_and_sit_in_their_range() {
        for c in [
            CloseCode::AuthFailed,
            CloseCode::Replaced,
            CloseCode::DeviceRemoved,
            CloseCode::ProtocolError,
            CloseCode::UnsupportedVersion,
        ] {
            assert_eq!(CloseCode::from_code(c.code()), c);
            assert_eq!(CloseCode::reconnect(c.code()), Reconnect::Never);
        }
        for c in [
            CloseCode::SlowConsumer,
            CloseCode::Overloaded,
            CloseCode::AuthTimeout,
            CloseCode::RateLimited,
            CloseCode::Unavailable,
        ] {
            assert_eq!(CloseCode::from_code(c.code()), c);
            assert_eq!(CloseCode::reconnect(c.code()), Reconnect::Backoff);
        }
        assert_eq!(
            CloseCode::reconnect(CloseCode::Draining.code()),
            Reconnect::Now
        );
        assert_eq!(CloseCode::reconnect(1006), Reconnect::Backoff);
    }

    #[test]
    fn retry_hints() {
        assert_eq!(parse_retry(&retry_reason(1500)), Some(1500));
        assert_eq!(parse_retry("retry_ms="), None);
        assert_eq!(parse_retry("retry_ms=-1"), None);
        assert_eq!(parse_retry("retry_ms=99999999999"), None);
        assert_eq!(parse_retry("bye"), None);
        assert!(retry_reason(u32::MAX).len() <= 123);
    }

    proptest! {
        #[test]
        fn parse_retry_never_panics(s in ".{0,40}") {
            let _ = parse_retry(&s);
        }
    }
}
