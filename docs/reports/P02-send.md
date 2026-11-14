# P02 — Realtime delivery core: the send library, `PUT /v1/messages`, system frames

- Date: 2026-11-14
- Prompt: [02-realtime.md](../prompts/02-realtime.md), "Sending from other services and clients
  without a socket" (amended by the owner on 2026-11-13, D-0037). The last item Prompt 2 needs
  before its final gate.
- Status: **built; stopped for the owner's review.** The Prompt 2 final gate and Prompt 3 have not
  been started.
- Design: D-0044, decided by the agent under the owner's standing instruction (D-0041).
- Branch: `claude/p02-send-crate-ef39ad`, on `main` at `8d2717f` (M7 gate approved).
- Machines:
  - Owner's Mac: Apple M5 Pro, 18 cores, 48 GiB, macOS 27.2.1; compose images as pinned, under
    podman (Iggy runs here now, so the Iggy live tests ran locally too).
  - VMPal VM `songbird-m7`: Apple Silicon host, arm64, 12 vCPUs, 32 GB, Ubuntu 26.04, kernel
    7.0.0-43-generic; the M7 baseline's host (`bench/m7/baseline-vmpal-arm64.json`).

## What was built

1. **`crates/send` (`songbird-send`)**: the send path as a library.
   - `SendPath::store`: reserved-prefix check, duplicate check, device-list check, idempotent
     store through the mailbox (`StoreSend`), metrics. `SendPath::route`: routing, push on
     offline. `SendPath::send` is both, for callers with nothing to write in between.
   - The device directory (`directory.rs`) and push wake-ups (`push.rs`) moved here from
     `delivery` (history kept with `git mv`); `delivery` re-exports them, so
     `songbird_delivery::{directory, push, Directory, Pusher}` still work.
   - `LimitsConfig` moved here: `[delivery.limits]` and `[api.send.limits]` are one struct.
   - `SendMetrics`, `PushMetrics`: `delivery` hands in clones of its own counters, so every
     `delivery_*` metric name is unchanged; `api` registers `api_*`.
2. **`delivery` on the library.** `on_send` keeps its order: rate limit, `store` (durable),
   `SendResult` queued, `route`, one flush. Why it is written that way is in the code: splitting
   `store` from `route` keeps the acknowledgement ahead of routing in one write; the path is
   built from field borrows, not an `Arc` clone (a reference count every core touches on every
   send would be a contended cache line); the recipient scratch list stays the session's.
3. **`PUT /v1/messages` in `api`** (`services/api/src/messages.rs`).
   - Body: the WebSocket `Send` frame, byte for byte, same limits. Answer: `200` with the
     `SendResult` frame the WebSocket would send; HTTP errors only before the send path (400, 401,
     411, 413, 503).
   - Signed like every `api` request, and **authenticated from the headers before the body is
     read**: `Content-Length` required and bounded, the signature (which covers the declared
     digest) verified, only then the body read and checked against the digest.
   - Rate limit: the WebSocket's 50/s, burst 200 per device, across every `api` node (GCRA in
     `valkey-hot` on Valkey's clock, keyed hash of the device, fails closed).
   - `[api.send]` configuration; without it the endpoint answers 503.
4. **How `api` reaches the partition owners (the open question): D-0044.** `api.` certificates
   are admitted to the delivery nodes' node links, **for the store of a send only**:
   - `songbird_link::serve_admitting`: one handler per certificate-name prefix.
   - Delivery nodes list the services that only send in `[delivery.cluster] senders`
     (`api.`, `calls.`, `worker.`; default none). Their handler serves `Store` and refuses and
     counts everything else, `PartDone` and key-store copies included.
   - `IggySender` (`crates/mailbox`): the store alone, on a node with no Iggy client, no key
     store, no master key, no lease. It reads the owners from the leases and splits a send with
     the owners' own routine (`store_on`, extracted from `IggyMailbox::store`).
   - `ValkeyRouter::publisher`: routing from `api` with no subscriber connections.
5. **Server-signed system frames** (`crates/proto/src/system.rs`, signer
   `crates/send/src/system.rs`). Notices travel as mailbox envelopes (durable, ordered, pushed)
   in a reserved format: magic, recipient device, issue time, notice ID, kind, body (at most
   1 KiB), Ed25519 signature over a domain-separated transcript. User envelopes that begin with
   the magic are refused (**new reject reason 9, `ReservedEnvelope`**). `SendPath::send_system`
   stores a notice for chosen devices, signed per device, with the notice ID as idempotency key.
   Kind 1, "device list changed", is defined; nothing emits it until Prompt 3 changes device lists.
6. Documentation: `docs/PROTOCOL.md` §1.2 (reason 9), §3.8, §3.9; threat model §1 (two rows),
   §3.5.1's node-link row, new §3.5.2, §6; runbook "`PUT /v1/messages` refusing sends";
   `config/dev/api.toml`.

## Tests

| Test | What it proves |
| --- | --- |
| `put_messages_is_signed_and_authenticated_before_the_body_is_read` | Auth: unsigned, body swapped after signing, replayed nonce, wrong path, unknown device all 401; no length 411, over-limit 413 before anything is checked; only accepted sends stored |
| `put_messages_holds_the_send_frame_to_the_websocket_limits_and_rate` | Limits: non-`Send` frame, oversize envelope, too many recipients 400; device mismatch and reserved envelope come back as `SendResult`s; burst then rate limited with a hint; buckets per device; recovers after a second |
| `a_send_retried_over_the_websocket_after_http_is_stored_once` | Idempotency with the WebSocket path in both orders; recipient sees each message once, in order; same key for other recipients refused |
| `an_offline_recipient_of_an_http_send_gets_a_push_wake_up` | Offline push from `api`; the online recipient gets it live through the shared router; the offline one finds it stored on connecting |
| `a_system_notice_reaches_the_device_signed_and_a_forged_one_never_does` | A notice is stored, delivered over the WebSocket and verifies under the server key; a forged one is refused over both transports |
| `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else` (Iggy cluster) | `IggySender` stores single- and multi-partition sends on the owner; the same send through a delivery node is a replay; fetch and ACK refused and counted; a `push.` identity cannot even store |
| `each_admitted_kind_of_peer_gets_only_its_own_handler` | Role admission on node links; a prefix without its dot admits nobody; an `api` certificate claiming a delivery name is refused |
| `the_send_path_checks_stores_once_and_routes`, `user_envelopes_in_the_system_frame_format_are_refused`, `system_notices_are_signed_per_device_stored_once_and_verify` | The library alone (memory mailbox, local router) |
| `system_frames_round_trip_and_sign_everything_but_the_signature` (fixed byte vector), `malformed_system_frames_are_refused`, `decoder_never_panics` (property test) | The system-frame format |
| `cluster_senders_admit_only_services_that_send`, `rate_records_are_keyed_and_reveal_no_device`, `retry_hints_round_up_and_are_never_zero` | Configuration and rate-limit details |

The five `send_api` tests run on the in-memory mailbox and on Iggy; they join the compose CI job
through `-p songbird-e2e` (SurrealDB, `valkey-hot`, Iggy), like the cluster test through
`-p songbird-mailbox`.

Run on the Mac, against the compose stack (Iggy, SurrealDB, both Valkeys, RustFS), the compose
job's commands: **217 of 218** in the first, `songbird-api` 8/8, `songbird-jobs` 12/12,
`songbird-push` 7/7. The one failure, `inv7_bounded_and_validated_input`, failed identically on
unmodified `main` on macOS: the test treated a refused oversized write as fatal, and macOS reports
the server's close as `ConnectionClosed` during the write (Linux lets it through and closes
after). Fixed in the test (`raw_send_refused`); its assertions are unchanged (close 1006, the
protocol error counted), and it now passes on macOS. Likewise
`reuseport_listeners_share_the_port_and_the_connections` (`crates/runtime`, not otherwise touched)
asserted that the kernel spreads connections over `SO_REUSEPORT` listeners, which Linux does and
macOS does not (it hands all 128 to one); that assertion now runs on Linux only, the port sharing
is still checked everywhere. `cargo xtask ci fast` on the Mac: **all checks passed** (rustfmt, clippy `-D warnings`, nextest
360 of 360, doctests, rustdoc, cargo deny, cargo audit, cargo vet, smoke of every service).

## Numbers

- **Allocations per message (M3 gate):** 5.20 (798 bytes) on this branch, the same as on `main`;
  budget 5.5.
- **`bench/m7/suite.sh` on the VM, `main` (`8d2717f`) against this branch, same session,
  `IGGY_TMPFS=1`** (the M7 baseline's host and settings; 30,000 TLS devices). Every scenario's
  checker passed on both (no loss, duplicate or reordering).

  | Figure | `main` | this branch | M7 baseline |
  | --- | --- | --- | --- |
  | Idle memory per connection | 33,320 B | 33,300 B | 33,360 B |
  | Steady (1,000/s) client p99 / p99.9 | 2,339 / 4,948 µs | 2,124 / 4,709 µs | 2,431 / 5,115 µs |
  | Steady store p99 (server) | ≤ 2 ms | ≤ 2 ms | ≤ 2 ms |
  | Steady CPU per 10,000 messages | 3.370 s | 3.369 s | 3.389 s |
  | Group (256 members) p99, delivery rate | 9,517 µs, 7,697/s | 9,991 µs, 7,955/s | 9,984 µs, 7,509/s |
  | Reconnect storm recovery | 16.4 s | 15.4 s | 15.5 s |

  **Max at 80,000 messages/s (8,000 devices), five runs each, alternating order:** delivered
  79,910–79,920/s on both (the load generator's ceiling, as in M7); client p99 `main` 2,714–3,239
  µs (mean 2,916), this branch 2,948–3,164 µs (mean 3,056): overlapping, not a significant
  difference (Mann–Whitney U = 8 for 5 + 5; the 5 % two-sided threshold is 2). **Server CPU per
  10,000 deliveries: 0.427 s on both** (0.421–0.432 against 0.423–0.429). The extraction adds no
  measurable cost. (The suite's own pass/fail line failed both trees alike, only because the
  first run used the script's default `MAX_RATE` of 40,000 against a baseline taken at 80,000,
  and the max-only runs lack the other scenarios' figures.)

## Open risks

- A compromised `api` can store envelopes into any mailbox over node links (as a compromised
  delivery node can); it cannot read, acknowledge or forget anything, mark parts stored, or forge
  notices. Ciphertext recipients cannot authenticate is dropped by them; it costs mailbox space
  until it expires.
- A device using both transports has two rate budgets (at most twice the per-device rate).
- `api` holds the delivery nodes' idempotency secret and the router's cluster secret. It needs
  both to give the same answers (replay detection, channel names); a compromised `api` learns no
  more than it already sees in the requests it handles, but can compute those keyed hashes.
- The system key is not deployed: nothing issues notices until Prompt 3. Its home (the issuing
  service's secrets) and rotation (`key_id`, apps pin current and next) are written down, not
  exercised.
- A send from `api` to several partitions leaves its remote parts' bookkeeping to the re-driver
  (about 2 s): each remote part's slot in the home record stays openable about 2 s longer than
  for a send through a delivery node (D-0031's "about a second").
- Clearing my contamination of the shared build cache: early in the work this worktree shared
  the main checkout's `target/` (cargo hashes workspace crates by their path relative to the
  workspace root, so worktrees collide there). I removed the workspace crates' artifacts from it
  (`cargo clean -p` for each, 31.5 GiB, dependencies kept); the main checkout rebuilds its own
  crates on its next build.

## What the owner needs to decide

1. Review D-0044's routing choice (`api.` on node links, store only).
2. Approve or refuse two threat-model rows (§1): a keyed hash of a device that sent over HTTP in
   `valkey-hot` for at most the burst window; system notices stored as envelopes.
3. Then the Prompt 2 final gate.
