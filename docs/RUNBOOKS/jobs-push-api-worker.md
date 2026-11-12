# Jobs, push, api and worker (Prompt 2, milestone 5; D-0036)

Messages never depend on anything here: they are in the mailbox before any job exists. These
runbooks cover wake-ups, attachments and account deletion.

## Push jobs dropped (`delivery_push_dropped` rising)

- Detection: `delivery_push_dropped` increases; `delivery_push_jobs` flat while
  `delivery_routes_offline` rises.
- Impact: offline devices are not woken; their messages wait safely in the mailbox and arrive
  at their next connection (the app also connects on its own schedule).
- Immediate actions:
  1. Check `valkey-jobs` health and memory (`noeviction`: a full instance refuses writes).
  2. Check the `delivery` → `valkey-jobs` TLS and password (logs: "push jobs dropped").
- Recovery: wake-ups resume with the next message to each device; nothing to replay.
- Verification: `delivery_push_jobs` rises again; `push_results{result="sent"}` follows.

## Push provider outage or rate limiting

- Detection: `push_results{provider=…,result="retried"}` rising; a provider breaker open (logs);
  `songbird_jobs` delayed set (`ZCARD j:push:later`) growing.
- Impact: wake-ups delayed for that platform only; messages safe in mailboxes.
- Immediate actions: none needed; the breaker answers retries without network until the
  cool-down, and jobs back off with full jitter (up to 10 min).
- Recovery: automatic when the provider answers. Jobs that exhaust 12 attempts are
  dead-lettered (next runbook).
- Verification: `retried` falls, `sent` rises; `XLEN j:push` near zero.

## Dead letters (`j:dead` growing, any stream)

- Detection: alert on the dead-letter stream length (`XLEN j:dead`) or worker/push logs "job
  dead-lettered".
- Impact by stream: `push` — a wake-up lost (message safe); `cleanup` — an object kept until the
  30-day sweep deletes it; `deletion` — **an account deletion not finished**: treat as urgent.
- Immediate actions:
  1. Find the cause in the service logs (kinds only: "account deletion incomplete" with what was
     left: `Unavailable`, `Mailbox`, `Objects`, `Rows`).
  2. Fix the dependency (delivery's device link, RustFS, SurrealDB).
- Recovery: dead letters are sealed; re-queue them with `songbird-admin jobs redrive` (Prompt 13
  tooling; until then, `XRANGE j:dead` and `XADD j:<stream> * s <value>` for each entry whose `q`
  field names the stream). Every handler is idempotent.
- Verification: `worker_deletions_verified` rises; `XLEN j:dead` back to its previous value.

## Account deletion not completing

- Detection: `worker_deletion_retries` rising without `worker_deletions_verified`.
- Impact: the account's devices are already disabled (no new session authenticates, no `api`
  request is accepted); data waits for the job.
- Immediate actions: check that every delivery node's `[delivery.internal]` link is up and that
  the worker's certificate is a `worker.` name from the internal CA; check RustFS and SurrealDB.
- Recovery: the job retries with backoff; once the cause is fixed it completes and verifies.
- Verification: the registry holds no rows of the account, `Known` answers false for its
  devices, and `worker_deletions_verified` counted it.

## Outbox not draining

- Detection: rows accumulating in SurrealDB `outbox` (`SELECT count() FROM outbox GROUP ALL`).
- Impact: deletions accepted by `api` but not queued.
- Recovery: `api` relays every 2 s and the worker every sweep; fix `valkey-jobs`. A repeated job
  after a crash between queueing and removing the row is harmless (idempotent handlers).

## RustFS unavailable

- Detection: `api_errors` rising; uploads and downloads answer 503.
- Impact: attachments cannot be sent or fetched; messages unaffected; deletion jobs retry.
- Recovery: restore RustFS (D-0035); clients retry uploads with a new grant after expiry.

## Directory reload failing (delivery logs "directory version poll failed")

- Impact: new accounts cannot connect, and a deleted device could still authenticate until the
  registry is reachable (its open sessions were already closed by the deletion).
- Recovery: restore SurrealDB connectivity; the directory reloads within `poll_ms`.
