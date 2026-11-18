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

## `PUT /v1/messages` refusing sends (`api_sends_rejected` rising, reason 6)

The HTTP send path (D-0037, D-0044) answers `SendResult` reason 6 (unavailable, retry in 1 s)
in three degraded modes. Messages are never lost: nothing is stored, and the client retries with
the same idempotency key (or sends over its WebSocket once it reconnects).

- Detection: `api_sends_rejected` rises with `api_sends_accepted` flat; `api_errors` rises when
  the rate limiter is the cause; `api_send_mailbox_errors` when the store is.
- Causes and actions:
  1. **`valkey-hot` unreachable** (rate limiter and nonces): the limiter fails closed, so no send
     passes unmetered (and authentication already fails without nonces: 503). Restore
     `valkey-hot`; nothing to replay.
  2. **Partition owners unknown or unreachable** (`api` reads the leases from the router's Valkey
     every third of a lease): check the router Valkey, the delivery nodes' health, and that the
     delivery nodes list `api.` in `[delivery.cluster] senders` (otherwise every store is refused
     at the link handshake). During a failover expect a few seconds of reason 6.
  3. **A delivery node refusing `api`'s requests** (`IggyMailbox::sender_requests_refused`
     rising on the node): something in `api` asked for more than a store, which a sound `api`
     never does. Treat it as a possible compromise of the `api` host: rotate its link certificate
     (runbook `mtls-rotation.md`) and investigate.
- Verification: `api_sends_accepted` rises again; `api_sends_rejected` back to its usual rate
  (device mismatches and rate limits only).

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

## Registration refusing or throttling sign-ups (Prompt 3, D-0048)

Registration (`POST /v1/registration`) is the only unauthenticated write. Its degraded modes are
explicit; none affects existing accounts or messages.

- Detection: `api_registration_throttled` rising (429s), `api_registrations_refused` or
  `api_registration_invite_refused` rising, `api_registrations` flat; 503s with `api_errors`.
- Causes and actions:
  1. **`valkey-hot` unreachable**: throttles and challenge single-use fail closed, so every
     registration answers 503. Restore `valkey-hot`; nothing to replay (clients ask for a new
     challenge).
  2. **SurrealDB unreachable**: 503 at the last step; the challenge is spent, the client asks for
     a new one.
  3. **Verification saturated** (503 after a 2 s wait for a slot): many registrations at once.
     Check for a campaign (step 4) before raising `max_concurrent_verifications` (each slot holds
     `pow.memory_kib`).
  4. **A registration or guessing campaign**: `api_registration_invite_refused` and 429s from the
     deployment-wide budgets mean someone is guessing codes; leave invite-only mode on, lower
     `throttle.global_invite_failures_per_hour` if needed, and raise `pow.bits` by one (doubles the
     work; challenges carry their parameters, so no client release is needed).
  5. **Legitimate users throttled** (many people behind one carrier NAT range): raise
     `throttle.registrations_per_hour` and `registration_burst`; the deployment-wide caps remain.
- Switching invite-only mode off (owner's decision): set `[api.registration] invite_only = false`
  on every `api` node and restart them one by one; no migration. Codes still in the database are
  then ignored and expire.
- Issuing codes: `songbird-admin invites create --count N --uses U --days D --confirm <ns>/<db>`
  prints the codes once (hand them over through a channel you trust); the audit log records the
  count only. `songbird-admin invites grant --account <hex> --add N` gives one account more.
- Verification: `api_registrations` rising; a test registration with a fresh code answers 201.

## Usernames: lookups or claims failing (Prompt 3, M2, D-0049)

- Detection: `api_handle_throttled` rising (429s); 503s with `api_errors`; complaints that a
  username "does not exist" while its owner says it does.
- Causes and actions:
  1. **`valkey-hot` unreachable**: every username request answers 503 (throttles fail closed).
     Restore `valkey-hot`.
  2. **Someone found by name is "not found"**: by design for a missing or wrong username key,
     and for a username whose key-guessing budget someone spent (up to about ten hours). Ask the
     owner to share a link or QR code meanwhile; there is no operator override (an override
     would be an enumeration oracle).
  3. **Key verifications saturated** (503 after a 2 s wait): check
     `api_handle_guard_checks` for a campaign before raising `max_concurrent_key_checks` (each
     holds `key.memory_kib`).
  4. **A name taken by an impersonator**: add it to `[api.usernames] reserved` only for names
     that would pose as the service; disputes between people are an abuse process (Prompt 11),
     not a configuration change.
- Rotating `[api.usernames] secret` invalidates every username key verifier (users set their
  key again) and resets the throttles; do it only after a compromise of the secret.

## Key directory: fetches failing or devices out of prekeys (Prompt 3, M3, D-0050)

- Detection: `api_prekey_throttled` rising (429s); `api_prekey_last_resort` rising against
  `api_prekey_bundles` (sessions starting without one-time keys); 503s with `api_errors`.
- Causes and actions:
  1. **`valkey-hot` unreachable**: fetches answer 503 (throttles fail closed); uploads and counts
     still work. Restore `valkey-hot`.
  2. **Many bundles with last-resort keys**: either devices are not refilling (check
     `api_prekey_notices`; without `[api.keys] system_key` and `[api.send]` no notices go out,
     and clients rely on their own `GET /v1/keys` checks) or someone is draining a target (the
     per-target budget is doing its job; nothing to do unless it is broad, then look at the
     requesting accounts' throttle records' volume, not their identities).
  3. **Uploads refused with `signature` or `keys`**: a client bug or a client still sending
     Kyber1024 (type `0x08`); only ML-KEM-1024 is accepted (owner's decision, D-0050).
- Rotating `[api.keys] secret` resets the throttles and the notice marks (a burst of notices may
  follow); it invalidates nothing stored.

## Devices: linking failing or removed devices lingering (Prompt 3, M4, D-0052)

- Detection: `api_device_throttled` rising (429s); `api_device_refused` rising against
  `api_devices_linked`; `worker_deletion_retries` rising with `worker_devices_deleted` flat; 503s
  with `api_errors`.
- Causes and actions:
  1. **`valkey-hot` unreachable**: provisioning channels and every throttled device endpoint
     answer 503 (throttles fail closed). Restore `valkey-hot`. Open channels are lost, and users
     scan again.
  2. **Links refused with `token`**: the token expired (ten minutes), was used, or names another
     device. The user starts again from the primary. A spike across many accounts points to a
     client bug, not an attack: tokens are 256 random bits.
  3. **Lists refused with `devices`**: the client signed a list naming a device that is no longer
     enabled, or with keys that differ from the registry's. Clients must refetch `GET /v1/devices`
     and sign again. With `version`, the client is behind the stored version (another of the
     account's clients published one).
  4. **Removed devices not deleted**: the `DeleteDevices` job retries while delivery still knows
     the device or a store is unreachable (the same steps as "Account deletion not completing").
     A removed device is disabled from the moment it is removed, whatever the job's state.
- After a registry restore: devices removed after the backup are back and enabled. Clients
  refuse the restored list as a rollback. Tell affected primaries to sign a new list, which
  removes those devices again.

## Registry busy: write conflicts outlasting the retry budget (D-0093)

- Detection: `songbird_registry_busy_total` grows on `api`, `worker`, `push` or `delivery`; their
  logs say "registry busy: write conflicts outlasted the retry budget" (no identifiers); `api`
  answers 503 on the affected endpoints. `songbird_registry_conflict_retries_total` rising on its
  own is normal: SurrealDB is optimistic, and racing changes of one account lose and retry.
- Impact: the refused call wrote nothing (the transaction lost and was not committed); the caller
  may retry, and apps do on 503. Limits (devices, passkeys, invites, group rosters) stay exact:
  every change that a limit guards writes one row per account, so two racing changes can never
  both commit.
- Causes and actions:
  1. **One account hammered** (many concurrent changes to the same account, group or community):
     busy answers while SurrealDB's disk and CPU are normal, usually with an endpoint's throttle
     counters rising too (`api_device_throttled` for devices). The counters carry no endpoint or
     account (invariant 6): the 503s in `api`'s access metrics show which endpoint. The
     per-account throttles bound it; lower that endpoint's burst if it persists.
  2. **SurrealDB slow to commit** (busy across many endpoints at once): every commit waits for its
     fsync (`sync=every`), and SurrealKV counts commits still in flight or awaiting their fsync as
     conflicts (D-0093), so a slow disk turns one winner into several losses for each waiting
     writer. Check the SurrealDB host's disk latency and CPU (`process_cpu_seconds`,
     node metrics), then "Directory reload failing" and backup jobs competing for the disk.
- Verification: `songbird_registry_busy_total` flat; 503s from `api` back to their baseline.
