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
- Logs: `mailbox append failed; resending` and `mailbox read failed`, each with Iggy's numeric
  error code. A writer resends the same batch (same producer sequence, so it is written once)
  until Iggy confirms; sends wait up to `timeout_ms` (5 s) and are then rejected as retryable;
  clients retry with the same idempotency key.
- Immediate actions: check Iggy (`songbird-iggy` container logs, disk space on the data host,
  `/var/lib/songbird/iggy`). A full disk stops Iggy's affected shards (they refuse to commit and
  shut the server down rather than lose data): free space, restart the container; the mailbox
  replays and continues.
- Verification: `mailbox_errors_total` and `sends_rejected_total` flat again; the load-generator
  checker passes.
- Verification: `inv8_store_unavailable_rejects_retryably_and_keeps_sockets`; rejected sends stop
  and the load-generator checker passes afterwards.

## Mailbox writer fenced (node not ready)

- Detection: `/readyz` fails on a delivery node; log `mailbox writer fenced by another writer;
  stopping` with code 93 (`ProducerEpochFenced`) or 92.
- Cause: another delivery process started on the same Iggy topic and took the partitions over
  (one node per topic until M4).
- Immediate actions: make sure only one delivery node points at the topic; restart the node that
  should own it (it replays and takes a new producer epoch). Nothing is lost: the fenced writer
  wrote nothing after the takeover.

## Mailbox log unreadable (delivery does not start)

- Detection: delivery exits at start with `mailbox log unreadable: partition P, offset O, record
  version V`; `/readyz` never succeeds.
- Cause: the Iggy topic holds a record this build cannot read: written by an incompatible
  version (V differs from the build's record version) or corrupted. Replaying past it would lose
  counters and reuse `seq`s, which clients would drop as duplicates, so delivery refuses to
  start.
- Immediate actions: run the build that wrote the log (roll back), or restore the topic from a
  backup (next section). Never delete the record to get past it: that is the `seq` reuse the
  check prevents.

## Restoring the mailbox from a backup

- Restore the Iggy data directory, then raise `[delivery.mailbox] store_generation` by one
  before starting delivery: clients see the new generation in `Hello` and reset their resume
  points (PROTOCOL §3.6).
- Upgrading Iggy across a storage-format change (0.9 to 0.10 was one): stop delivery, let devices
  drain if possible, follow Iggy's upgrade notes; a fresh data directory loses pending envelopes,
  so treat it as a restore (raise `store_generation`).

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
