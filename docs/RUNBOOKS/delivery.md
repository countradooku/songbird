# Delivery service degraded modes (Prompt 2, milestone 1)

Metrics are on the private admin endpoint (`/metrics`, prefix `songbird_delivery_`). They are
aggregate counters only; nothing in them or in the logs identifies a device (invariant 6).

## Overload: connections refused (close 4101)

- Detection: `connections_refused_total` rising; clients report 4101 with a retry hint.
- Impact: new connections wait and retry with backoff; connected devices are unaffected; nothing
  is lost (mailboxes hold everything).
- Immediate actions:
  1. Check `connections_open` against `[delivery.session] max_connections` and the accept rate
     against `accepts_per_sec`.
  2. After an outage, a reconnect storm is expected: let the token bucket pace it. Do not raise
     the limits during the storm.
  3. If the cap is reached in steady state, add capacity (milestone 3: more cores; milestone 4:
     more nodes) rather than raising the cap past what the host can hold.
- Verification: `connections_refused_total` flat; load-generator `reconnect` scenario passes the
  checker against the same configuration.

## Slow consumers (close 4100) and lag

- Detection: `slow_consumers_total` (a socket made no write progress for `write_timeout_ms`,
  default 30 s); `window_full_total` (a device has `max_unacked`, default 256, envelopes in flight
  and delivery to it paused until it acknowledges); `routes_lagged_total` and `drains_total` (a
  session's inbox overflowed and it caught up from the mailbox).
- Impact: the slow device reconnects and drains its mailbox; nobody else waits (invariant 5).
- Immediate actions: none for isolated cases. A fleet-wide rise points at the network path or at
  the server's own write capacity: check CPU and `delivered_*` rates.
- Verification: `inv5_slow_client_never_slows_anyone_else` reproduces the mode.

## Store unavailable (sends rejected with reason 6, close 4104)

- Detection: `mailbox_errors_total` and `sends_rejected_total` rising.
- Impact: sends are rejected as retryable; clients keep their messages and retry with the same
  idempotency key; sockets stay open; delivery of already-stored envelopes resumes when the store
  returns (failed drains retry every second).
- Immediate actions: restore the store (milestone 2: SurrealDB runbook). Nothing to do on the
  delivery side.
- Verification: `inv8_store_unavailable_rejects_retryably_and_keeps_sockets`; rejected sends stop
  and the load-generator checker passes afterwards.

## Authentication failures (close 4000) or timeouts (4102)

- Detection: `auth_failures_total`, `auth_timeouts_total`.
- Impact: affected devices stop reconnecting (4000) and must re-register; timeouts back off and
  retry.
- Immediate actions: a sudden fleet-wide rise of 4000 after a deploy means a server-name or
  directory mismatch: roll back (`deploy-and-rollback.md`). A rise from few sources is probing:
  rate limits handle it; firewall at the edge if it persists.

## Deploy drain (close 4200)

- Detection: expected during rollouts; `connections_open` falls on the draining node.
- Impact: clients reconnect within ~0.5 s, to any node; nothing is lost.
- Procedure: SIGTERM; the server stops accepting, closes every session with 4200 at random times
  within `drain_window_ms` (default 2 s, must be below `shutdown_grace_secs`) and exits 0.
- Verification: `graceful_drain_closes_with_4200`; the smoke test's SIGTERM check.
