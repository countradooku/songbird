//! `PUT /v1/messages` (D-0037, D-0044): a send for a client with no open WebSocket
//! (notification quick-reply, share extension, a socket that failed).
//!
//! - **Same frame, same path.** The body is a WebSocket `Send` frame, byte for byte, decoded with
//!   the same limits ([`songbird_send::LimitsConfig`]), and it goes through the same library as
//!   the WebSocket (`songbird-send`): reserved-prefix and duplicate checks, the device-list check,
//!   the idempotent store, routing and push. A retry with the same idempotency key over either
//!   transport is stored once.
//! - **Same answer.** A `200` carries a `SendResult` frame, the bytes the WebSocket would have
//!   sent, so clients reuse one decoder (accepted, device mismatch, rate limited, conflict, stale
//!   epoch, unavailable with a retry hint). HTTP statuses are for what happens before the send
//!   path: `401` authentication, `411`/`413` length, `400` not a `Send` frame, `503` no send path.
//! - **Signed, and authenticated before the body is read.** The signature covers the declared
//!   body digest, so the request is verified (time, nonce, device key, not disabled) from its
//!   headers first; only then is the body read, bounded by the declared `Content-Length` (at most
//!   the `Send` limit), and checked against the digest. An unauthenticated client cannot make
//!   `api` buffer a body.
//! - **The same rate limit, across every `api` node.** A per-device GCRA in `valkey-hot` with the
//!   WebSocket's `sends_per_sec` and `send_burst`, on Valkey's clock, under a keyed hash of the
//!   device (Valkey never sees the device ID; the key expires with the burst window).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use aws_lc_rs::hmac;
use songbird_mailbox::StoreSend;
use songbird_proto::frame::{RejectReason, SendFrame, SendStatus};
use songbird_proto::{ClientFrame, Limits, ServerFrame};
use songbird_router::Router;
use songbird_send::{LiveDirectory, Pusher, SendMetrics, SendPath};
use songbird_types::DeviceId;

/// The send path, behind an object-safe call: `api` holds whichever store and router the
/// deployment has (a send-only Iggy client and a publish-only Valkey router; in-process stores in
/// tests) without making the whole application generic. Not a hot path.
pub trait Submit: Send + Sync + 'static {
    /// Check, store, route; the `SendResult` status.
    fn submit<'a>(
        &'a self,
        sender: &'a DeviceId,
        frame: SendFrame,
        received: Instant,
    ) -> Pin<Box<dyn Future<Output = SendStatus> + Send + 'a>>;

    /// A server-signed system notice to `devices` (D-0044), through the same path.
    fn system<'a>(
        &'a self,
        signer: &'a songbird_send::system::SystemSigner,
        devices: &'a [DeviceId],
        kind: songbird_proto::system::Kind,
        body: &'a [u8],
        notice_id: [u8; songbird_proto::system::NOTICE_ID_LEN],
    ) -> Pin<Box<dyn Future<Output = Result<(), songbird_send::system::SystemError>> + Send + 'a>>;
}

/// What the send path needs, owned.
pub struct SendStack<M, R> {
    /// Devices and accounts, followed from the registry.
    pub directory: Arc<LiveDirectory>,
    /// The mailbox's store operation.
    pub mailbox: M,
    /// The router.
    pub router: R,
    /// Push wake-ups.
    pub push: Pusher,
    /// Counters (shared with [`Messages::metrics`]).
    pub metrics: SendMetrics,
    /// Franking and the contact gate (Prompt 4).
    pub policy: songbird_send::Policy,
}

impl<M, R> std::fmt::Debug for SendStack<M, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStack").finish_non_exhaustive()
    }
}

impl<M: StoreSend, R: Router> Submit for SendStack<M, R> {
    fn submit<'a>(
        &'a self,
        sender: &'a DeviceId,
        frame: SendFrame,
        received: Instant,
    ) -> Pin<Box<dyn Future<Output = SendStatus> + Send + 'a>> {
        Box::pin(async move {
            let path = SendPath {
                directory: &self.directory,
                mailbox: &self.mailbox,
                router: &self.router,
                push: &self.push,
                metrics: &self.metrics,
                policy: &self.policy,
            };
            path.send(sender, frame, received, &mut Vec::new()).await
        })
    }

    fn system<'a>(
        &'a self,
        signer: &'a songbird_send::system::SystemSigner,
        devices: &'a [DeviceId],
        kind: songbird_proto::system::Kind,
        body: &'a [u8],
        notice_id: [u8; songbird_proto::system::NOTICE_ID_LEN],
    ) -> Pin<Box<dyn Future<Output = Result<(), songbird_send::system::SystemError>> + Send + 'a>>
    {
        Box::pin(async move {
            let path = SendPath {
                directory: &self.directory,
                mailbox: &self.mailbox,
                router: &self.router,
                push: &self.push,
                metrics: &self.metrics,
                policy: &self.policy,
            };
            path.send_system(signer, devices, kind, body, notice_id)
                .await
        })
    }
}

/// `PUT /v1/messages`'s part of the application.
pub struct Messages {
    /// The send path.
    pub path: Box<dyn Submit>,
    /// Frame limits (the delivery nodes' `[delivery.limits]`).
    pub limits: Limits,
    /// Sustained sends per second per device (the WebSocket's `sends_per_sec`).
    pub sends_per_sec: u32,
    /// Burst (the WebSocket's `send_burst`).
    pub send_burst: u32,
    /// Keys the per-device rate-limit records, so `valkey-hot` cannot link them to device IDs.
    pub rate_key: hmac::Key,
    /// Counters.
    pub metrics: SendMetrics,
}

impl std::fmt::Debug for Messages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Messages")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Derives the rate-limit key from the router's cluster secret (HKDF, its own label).
///
/// # Errors
/// Only if HKDF refuses the length (never for 32 bytes).
pub fn rate_key(cluster_secret: &[u8; 32]) -> Result<hmac::Key, aws_lc_rs::error::Unspecified> {
    let mut k = [0u8; 32];
    aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, b"songbird-api-v1")
        .extract(cluster_secret)
        .expand(&[b"send-rate"], aws_lc_rs::hkdf::HKDF_SHA256)?
        .fill(&mut k)?;
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &k))
}

/// The `valkey-hot` key of a device's send rate: a keyed hash (no device ID).
#[must_use]
pub fn rate_record(key: &hmac::Key, device: &DeviceId) -> String {
    let tag = hmac::sign(key, device.as_bytes());
    let mut k = String::with_capacity(34);
    k.push_str("r:");
    k.push_str(&hex::encode(tag.as_ref().get(..16).unwrap_or_default()));
    k
}

/// GCRA on Valkey's clock: `ARGV[1]` the emission interval and `ARGV[2]` the burst tolerance,
/// both in microseconds. Returns 0 when allowed (and records it), else the wait in microseconds.
pub const GCRA: &str = "local t = redis.call('TIME') \
     local now = tonumber(t[1]) * 1000000 + tonumber(t[2]) \
     local tat = tonumber(redis.call('GET', KEYS[1]) or now) \
     if tat < now then tat = now end \
     local new = tat + tonumber(ARGV[1]) \
     local wait = new - tonumber(ARGV[2]) - now \
     if wait > 0 then return wait end \
     redis.call('SET', KEYS[1], new, 'PX', math.ceil((new - now) / 1000) + 1) \
     return 0";

/// The decoded `Send` frame of a request body, or `None` if it is anything else.
#[must_use]
pub fn decode(body: &bytes::Bytes, limits: &Limits) -> Option<SendFrame> {
    match ClientFrame::decode(body, limits) {
        Ok(ClientFrame::Send(s)) => Some(s),
        _ => None,
    }
}

/// The response body: the `SendResult` frame the WebSocket would have sent.
#[must_use]
pub fn result_frame(req_id: u32, status: SendStatus) -> bytes::Bytes {
    ServerFrame::SendResult { req_id, status }.to_bytes()
}

/// A rate-limited refusal with its retry hint.
#[must_use]
pub fn rate_limited(wait_us: u64) -> SendStatus {
    let ms = u32::try_from(wait_us.div_ceil(1000))
        .unwrap_or(u32::MAX)
        .max(1);
    SendStatus::Rejected {
        reason: RejectReason::RateLimited,
        retry_after_ms: ms,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn rate_records_are_keyed_and_reveal_no_device() {
        let k = rate_key(&[1; 32]).unwrap();
        let d = DeviceId::from_bytes([0xAB; 16]);
        let r = rate_record(&k, &d);
        assert_eq!(r.len(), 34);
        assert!(!r.contains("abab"));
        assert_eq!(r, rate_record(&k, &d));
        assert_ne!(r, rate_record(&rate_key(&[2; 32]).unwrap(), &d));
    }

    #[test]
    fn retry_hints_round_up_and_are_never_zero() {
        assert_eq!(
            rate_limited(1),
            SendStatus::Rejected {
                reason: RejectReason::RateLimited,
                retry_after_ms: 1
            }
        );
        assert!(matches!(
            rate_limited(20_001),
            SendStatus::Rejected {
                retry_after_ms: 21,
                ..
            }
        ));
    }
}
