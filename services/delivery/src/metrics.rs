//! Delivery metrics: aggregate counters only, no per-device or per-connection labels
//! (invariant 6). Per-core shards summed at scrape time (M3): cores counting the same event never
//! contend for a cache line.

use songbird_service::telemetry::sharded::{ShardedCounter as Counter, ShardedGauge as Gauge};
use songbird_service::telemetry::{Metrics, TelemetryError};

/// Every delivery metric.
#[derive(Debug, Clone, Default)]
pub struct DeliveryMetrics {
    /// Connections that completed the WebSocket upgrade.
    pub connections: Counter,
    /// Connections open now.
    pub connections_open: Gauge,
    /// Connections refused by the accept-rate limit or connection cap (closed 4101).
    pub connections_refused: Counter,
    /// TLS or HTTP upgrade failures and timeouts.
    pub handshake_failures: Counter,
    /// Authentications that succeeded.
    pub auth_ok: Counter,
    /// Authentications that failed (bad signature or unknown device, closed 4000).
    pub auth_failures: Counter,
    /// No `Auth` within the timeout (closed 4102).
    pub auth_timeouts: Counter,
    /// Older connections closed because the device connected again (4001).
    pub replaced: Counter,
    /// Envelopes stored (one per recipient device).
    pub envelopes_stored: Counter,
    /// Sends accepted.
    pub sends_accepted: Counter,
    /// Sends answered from the idempotency record (a retry).
    pub sends_replayed: Counter,
    /// Sends rejected (any reason).
    pub sends_rejected: Counter,
    /// Envelopes written to sockets from live notifications.
    pub delivered_live: Counter,
    /// Envelopes written to sockets from mailbox drains.
    pub delivered_drained: Counter,
    /// Live notifications dropped as duplicates.
    pub live_duplicates: Counter,
    /// Mailbox drains started (initial, gap, lag, safety sweep).
    pub drains: Counter,
    /// Notifications dropped because a session's inbox was full.
    pub routes_lagged: Counter,
    /// Envelopes stored for devices with no session (push jobs from milestone 5).
    pub routes_offline: Counter,
    /// ACKs processed (cumulative; deletes are batched by the mailbox).
    pub acks: Counter,
    /// Ephemeral events delivered to a session's lane.
    pub ephemeral_routed: Counter,
    /// Ephemeral events dropped (offline, lane full, or rate limited).
    pub ephemeral_dropped: Counter,
    /// Closed for falling behind (4100).
    pub slow_consumers: Counter,
    /// Closed for a protocol violation (4003).
    pub protocol_errors: Counter,
    /// Closed for exceeding the frame rate (4103).
    pub rate_limited: Counter,
    /// Mailbox operations that failed.
    pub mailbox_errors: Counter,
    /// Times delivery paused because the un-acked window was full.
    pub window_full: Counter,
}

impl DeliveryMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// [`TelemetryError`] if a name is refused by the redaction rules.
    #[allow(clippy::too_many_lines, reason = "a table: one entry per metric")]
    pub fn register(&self, m: &mut Metrics) -> Result<(), TelemetryError> {
        m.register(
            "delivery_connections_open",
            "WebSocket connections open",
            self.connections_open.clone(),
        )?;
        let counters: [(&str, &str, &Counter); 25] = [
            (
                "delivery_connections",
                "WebSocket connections accepted",
                &self.connections,
            ),
            (
                "delivery_connections_refused",
                "Connections refused by accept-rate limit or cap",
                &self.connections_refused,
            ),
            (
                "delivery_handshake_failures",
                "TLS or upgrade failures",
                &self.handshake_failures,
            ),
            (
                "delivery_auth_ok",
                "Successful device authentications",
                &self.auth_ok,
            ),
            (
                "delivery_auth_failures",
                "Failed device authentications",
                &self.auth_failures,
            ),
            (
                "delivery_auth_timeouts",
                "Authentication timeouts",
                &self.auth_timeouts,
            ),
            (
                "delivery_replaced",
                "Connections replaced by a newer one",
                &self.replaced,
            ),
            (
                "delivery_envelopes_stored",
                "Envelopes stored",
                &self.envelopes_stored,
            ),
            (
                "delivery_sends_accepted",
                "Sends accepted",
                &self.sends_accepted,
            ),
            (
                "delivery_sends_replayed",
                "Retried sends answered from the idempotency record",
                &self.sends_replayed,
            ),
            (
                "delivery_sends_rejected",
                "Sends rejected",
                &self.sends_rejected,
            ),
            (
                "delivery_delivered_live",
                "Envelopes delivered from live routing",
                &self.delivered_live,
            ),
            (
                "delivery_delivered_drained",
                "Envelopes delivered from mailbox drains",
                &self.delivered_drained,
            ),
            (
                "delivery_live_duplicates",
                "Live notifications dropped as duplicates",
                &self.live_duplicates,
            ),
            ("delivery_drains", "Mailbox drains", &self.drains),
            (
                "delivery_routes_lagged",
                "Notifications dropped on a full inbox",
                &self.routes_lagged,
            ),
            (
                "delivery_routes_offline",
                "Envelopes for devices without a session",
                &self.routes_offline,
            ),
            (
                "delivery_acks",
                "ACKs processed (deletes are batched by the mailbox)",
                &self.acks,
            ),
            (
                "delivery_ephemeral_routed",
                "Ephemeral events routed",
                &self.ephemeral_routed,
            ),
            (
                "delivery_ephemeral_dropped",
                "Ephemeral events dropped",
                &self.ephemeral_dropped,
            ),
            (
                "delivery_slow_consumers",
                "Connections closed as slow consumers",
                &self.slow_consumers,
            ),
            (
                "delivery_protocol_errors",
                "Connections closed for protocol violations",
                &self.protocol_errors,
            ),
            (
                "delivery_rate_limited",
                "Connections closed for exceeding the frame rate",
                &self.rate_limited,
            ),
            (
                "delivery_window_full",
                "Times delivery paused on a full un-acked window",
                &self.window_full,
            ),
            (
                "delivery_mailbox_errors",
                "Failed mailbox operations",
                &self.mailbox_errors,
            ),
        ];
        for (name, help, c) in counters {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}
