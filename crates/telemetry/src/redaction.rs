//! A tracing layer that refuses spans and events carrying sensitive field names (invariant 6).
//!
//! Decided per callsite from static metadata, so the cost is paid once per callsite at
//! registration, never per event. A refused callsite is disabled for every layer (the layer is a
//! global filter), counted in `songbird_telemetry_refused_callsites_total`, and in
//! [`RedactionMode::Panic`] it panics, so tests and CI fail loudly.
//!
//! This is a guard against mistakes, not a sanitizer: values formatted into the *message* are not
//! inspected. The other half of the defence is that IDs and secrets redact themselves in `Debug`
//! (see `songbird_types::id` and `songbird_types::secret`).

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::subscriber::Interest;
use tracing::{Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Field-name segments that are always sensitive. Names are split on `.`, `_` and `-`.
const SENSITIVE_SEGMENTS: &[&str] = &[
    "authorization",
    "bearer",
    "body",
    "ciphertext",
    "content",
    "cookie",
    "credential",
    "credentials",
    "email",
    "envelope",
    "ip",
    "ipv4",
    "ipv6",
    "jwt",
    "key",
    "mnemonic",
    "otp",
    "passphrase",
    "passwd",
    "password",
    "payload",
    "phone",
    "pin",
    "plaintext",
    "private",
    "secret",
    "seed",
    "token",
];

/// Segment sequences that are sensitive although each segment alone is not.
const SENSITIVE_SEQUENCES: &[&str] = &[
    "account_id",
    "account_ids",
    "client_addr",
    "device_id",
    "device_ids",
    "forwarded_for",
    "peer_addr",
    "remote_addr",
    "session_id",
    "socket_addr",
    "user_id",
    "username",
];

/// Whether a field, metric or label name is sensitive.
#[must_use]
pub fn is_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == "message" {
        return false;
    }
    if lower
        .split(['.', '_', '-'])
        .any(|seg| SENSITIVE_SEGMENTS.contains(&seg))
    {
        return true;
    }
    // `_a_b_c_` contains `_b_c_`: match whole segments only, anywhere in the name.
    let wrapped = format!("_{}_", lower.replace(['.', '-'], "_"));
    SENSITIVE_SEQUENCES
        .iter()
        .any(|s| wrapped.contains(&format!("_{s}_")))
}

/// What to do with a sensitive callsite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionMode {
    /// Disable the callsite and count it.
    Refuse,
    /// Panic at registration (tests).
    Panic,
}

static REFUSED_CALLSITES: AtomicU64 = AtomicU64::new(0);

/// Callsites refused since process start.
#[must_use]
pub fn refused_callsites() -> u64 {
    REFUSED_CALLSITES.load(Ordering::Relaxed)
}

/// The redaction layer.
#[derive(Debug, Clone, Copy)]
pub struct RedactionLayer {
    mode: RedactionMode,
}

impl RedactionLayer {
    /// A layer in the given mode.
    #[must_use]
    pub const fn new(mode: RedactionMode) -> Self {
        Self { mode }
    }

    fn offending(meta: &Metadata<'_>) -> Option<&'static str> {
        meta.fields()
            .iter()
            .map(|f| f.name())
            .find(|n| is_sensitive(n))
    }
}

impl<S: Subscriber> Layer<S> for RedactionLayer {
    fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
        match Self::offending(meta) {
            None => Interest::always(),
            Some(field) => {
                REFUSED_CALLSITES.fetch_add(1, Ordering::Relaxed);
                assert!(
                    self.mode != RedactionMode::Panic,
                    "sensitive field `{field}` in {} at {}:{} (invariant 6)",
                    meta.name(),
                    meta.file().unwrap_or("?"),
                    meta.line().unwrap_or(0),
                );
                Interest::never()
            }
        }
    }

    fn enabled(&self, meta: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        Self::offending(meta).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_names() {
        for bad in [
            "device_id",
            "peer.device_id",
            "ip",
            "client_ip",
            "remote_addr",
            "password",
            "auth_token",
            "api_key",
            "envelope",
            "Authorization",
            "x-forwarded-for",
            "account_ids",
            "device_id_seen",
        ] {
            assert!(is_sensitive(bad), "{bad} should be sensitive");
        }
        for ok in [
            "message",
            "device_count",
            "seq",
            "latency_ms",
            "listen",
            "admin_listen",
            "core",
            "bytes",
            "frames",
            "devices_online",
            "user_identity_changes",
        ] {
            assert!(!is_sensitive(ok), "{ok} should be allowed");
        }
    }
}
