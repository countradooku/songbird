# Songbird Realtime Backend — Master Build Prompt

## How to use this prompt

This document is the prompt. Give it to a coding agent (for example Claude Code at the root of the empty monorepo). It lives in the repo as `docs/prompts/02a-realtime-master.md` so every later session can re-read it.

- Run it milestone by milestone (section "Milestones"). Start each session with: *"Read docs/prompts/02a-realtime-master.md and docs/DECISIONS.md, then continue with milestone N."*
- The agent must stop at each gate and report numbers before moving on.
- Out of scope here, with their own prompts later: end-to-end crypto inside `app-core` (libsignal, OpenMLS), the NSH user interface, and the native iOS and Android modules.
- Everything below is addressed to the agent.

---

## 1. Mission and invariants

You are a senior Rust systems engineer building the server side of **Songbird**, a European end-to-end encrypted messenger. Build the fastest and most reliable messaging WebSocket backend you can, and prove every performance claim with a benchmark you wrote and ran.

The server never sees message content. It moves opaque, already-encrypted envelopes between devices. Speed must never break any of these invariants:

1. **Store before acknowledge.** An envelope is durably written to the mailbox before the sender is told "accepted" and before any routing.
2. **The mailbox is the only source of truth.** Everything in memory, in Valkey, or in transit between nodes may be lost at any moment without losing a message.
3. **Per-device ordering.** Each device sees its envelopes in strictly increasing `seq` order, with no gaps and no duplicates delivered to the app.
4. **Delete on ACK.** An envelope is hard-deleted once its device acknowledges it, and never kept longer than 30 days.
5. **One live connection per device** across the whole cluster.
6. **No slow client can slow anyone else.** A client that falls behind is disconnected and catches up from the mailbox.
7. **Nothing important lives only in one process's memory** except the socket itself.
8. **Minimal metadata.** No message content, sender identity or device IDs in logs. The sender's identity is used at send time for rate limits and never stored with the envelope.
9. **Every degraded mode is explicit**, tested, and documented in a runbook.

## 2. Locked decisions and libraries

These were decided by the project owner. Do not change them; if one blocks you, stop and explain why in `docs/DECISIONS.md`.

| Area | Choice | Notes for you |
| --- | --- | --- |
| Language | Rust, stable toolchain 1.88 or newer | redis-rs 1.x requires 1.88 (edition 2024) |
| WebSocket library | `sockudo-ws` | Tokio-based; Autobahn-compliant; optional `io-uring` (via `tokio-uring`), `http2` (RFC 8441), `http3` (RFC 9220), `mimalloc`, `rustls-*` features. Lock-free split streams via `tokio::io::split` |
| Valkey client | `redis-rs` with `tokio-comp`, `connection-manager`, `cluster-async`, `tokio-rustls-comp` | Runs inside per-core Tokio runtimes. Standalone async connections support `PUBLISH`/`SUBSCRIBE`; sharded `SSUBSCRIBE` is only on the cluster connection (`cluster-async`) |
| Database (mailbox, accounts, keys) | SurrealDB, single node now, TiKV cluster later | The only durable source of truth |
| Volatile state | Valkey | Per-device pub/sub channels, rate limits, job queue. Two instances: `valkey-hot` (no persistence) and `valkey-jobs` (AOF `everysec`, `noeviction`) |
| Object storage | RustFS (S3 API) | Encrypted attachments (30-day max), encrypted backup vaults |
| Routing between nodes | Valkey pub/sub, one channel per device (default; the Sockudo model) | Behind a `Router` trait. Plain PUBLISH/SUBSCRIBE on the single beta Valkey; sharded SPUBLISH/SSUBSCRIBE once Valkey is clustered. Direct node-to-node links and Apache Iggy are alternatives to benchmark later, not defaults |
| Push | Separate `push` service | Fed by the job queue; APNs, FCM, UnifiedPush |
| Jobs | Valkey Streams (consumer groups) | Learn from Sockudo's queue-driver code; jobs carry IDs only |
| Client wire protocol | Custom binary, versioned in `crates/proto` | No Pusher protocol. Learn from it (close-code ranges, connection state machine, signed auth) |
| Allocator | `mimalloc` as the global allocator | Benchmark against the system allocator once, record the result |
| Hosting | EU only (Hetzner first), Linux | Single server for the beta, sized for 20,000 accounts |

**Sockudo is a reference, not a dependency** (apart from `sockudo-ws`). Read its source for: horizontal scaling and adapter design, rate limiter, metrics, queue drivers, graceful shutdown, connection lifecycle. Take ideas and, where licence-compatible (MIT), small pieces of code with attribution. Do not import channels, presence, webhooks, or the Pusher protocol.

**Verify before use.** For every dependency, read the docs and source of the exact pinned version before writing code against it. Never invent an API. Record each pinned version and why in `docs/DECISIONS.md`.

## 3. Architecture and repository layout

### Services

- **`delivery`**: the WebSocket server. Authenticates devices, accepts sends over the socket, stores envelopes, routes them, streams them to devices, handles ACKs. The hot path; most of your effort goes here.
- **`api`**: HTTP (Axum) for everything that is not hot: account creation, device linking, key upload and fetch, attachment upload URLs, account deletion.
- **`push`**: consumes push jobs and talks to APNs, FCM and UnifiedPush. Holds the only copy of push credentials.
- **`worker`**: consumes the other jobs: attachment cleanup, 30-day expiry sweeps, account deletion, key rotation for crypto-shredding, backup scheduling and restore verification.

### Message flow

1. Device sends `Send` over its socket to the core that owns that socket.
2. The `send` crate validates: device list matches, idempotency key unseen, rate limits, MLS commit ordering (for group commits).
3. The `mailbox` crate stores one envelope per recipient device with a new per-device `seq`, using group commit (section 4).
4. Only after the write is durable: reply `Accepted` to the sender, then call `Router::route` for each recipient device.
5. The router delivers to the owning core in this node, or forwards to the owning node, or reports `Offline` (enqueue a push job).
6. The owning session writes to the socket. The device ACKs cumulatively; ACK deletes are batched.

### Monorepo layout

```
songbird/
  crates/
    proto/        wire frames, versioning, close codes (shared with clients)
    types/        ids, errors, config
    runtime/      thread-per-core launcher, core pinning, per-core context
    mailbox/      SurrealDB: store, seq allocation, fetch_after, batched ACK delete
    registry/     Valkey: per-device channels, takeover, re-subscribe
    router/       Router trait, Valkey pub/sub (default), direct links, Iggy (feature-gated)
    send/         send-path validation shared by delivery and api
    jobs/         Valkey Streams queue, outbox relay, retry/backoff
    telemetry/    metrics, tracing, no-PII guards
    client/       Rust delivery client (used by app-core and loadgen)
  services/
    delivery/  api/  push/  worker/
  tools/
    loadgen/      distributed load generator
    admin/        backup, restore, verify, drain, re-subscribe
  deploy/         OpenTofu + configuration management, no secrets
  docs/           prompts/, DECISIONS, PROTOCOL, THREAT_MODEL, RUNBOOKS/
  tests/          integration and chaos suites (docker compose)
```

Rules: server crates never depend on `client`, and `client` never depends on server crates; both share only `proto` and `types`. Every crate starts with `#![forbid(unsafe_code)]` unless a measured, reviewed exception is written down in `docs/DECISIONS.md`.

## 4. Performance engineering rules

### Thread-per-core, shared-nothing

- `crates/runtime` starts one OS thread per worker core, pinned with `core_affinity`, each running its own single-threaded Tokio runtime (or a `tokio-uring` runtime when the `io-uring` feature is on). Make the worker count configurable and leave cores free for SurrealDB and Valkey on the single beta server.
- Each worker binds its own listener with `SO_REUSEPORT` (via `socket2`), so the kernel spreads new connections across cores without a shared accept queue.
- Each core owns, with no sharing: its connections and sessions, timers, write buffers, one `redis-rs` connection (`ConnectionManager` or multiplexed), one SurrealDB client, and its links to peer nodes.
- **Within a node:** a lock-free concurrent map (benchmark `papaya` against `scc` and `dashmap`, pick by p99) maps `device -> (core, conn_id)`. A send for a device on another core goes to that core's bounded inbox (benchmark `tokio::sync::mpsc` against `kanal` and `crossbeam`).
- **Across nodes:** each core keeps its own Valkey subscription connection and subscribes to the channel of every device connected to it, so a published envelope lands directly on the owning core with no second hop.
- **No locks on the hot path.** No `Mutex` or `RwLock` between socket read and socket write. Metrics use per-core counters that are summed only when scraped.

### Zero-copy and allocation

- Envelopes are `bytes::Bytes` from the moment they are read. Group fan-out shares one buffer; it is never copied per recipient.
- Write frame header and payload with vectored writes. Reuse per-connection write buffers; allocate them lazily and release them when a connection goes idle.
- Steady-state delivery must not allocate per message. Prove it with `dhat` or `heaptrack` and keep that check in CI as a benchmark.
- `mimalloc` as global allocator (sockudo-ws has a `mimalloc` feature).

### Batching everywhere

- **Socket writes:** drain everything queued for a connection, write once, flush once per wakeup.
- **Mailbox writes:** per-core group commit. Collect stores for up to 1 ms or 256 items, write them in one SurrealDB transaction, then complete all waiting senders. Tune both limits by benchmark.
- **ACK deletes:** batch per core every 50–100 ms.
- **Valkey:** pipeline registry operations; never one round trip per message.
- **Valkey publishes:** pipeline the publishes for one send (one per recipient device) into a single round trip.

### Connections and timers

- No timer task per connection. Each core runs one sweep per second over a timing-wheel structure for heartbeat deadlines and auth timeouts.
- `TCP_NODELAY` on; WebSocket compression off (ciphertext does not compress, and per-connection compression windows cost memory).
- Measure memory per idle connection and keep the per-connection struct small; publish the number in every benchmark report.
- Accept-rate limiting per core (token bucket) so a reconnect storm after an outage cannot melt a node. Close frames carry a retry hint; clients use jittered exponential backoff.
- Kernel and system settings go in `deploy/` and the runbook: open-file limits, `somaxconn`, `tcp_max_syn_backlog`, ephemeral port range, `vm.overcommit_memory=1` for Valkey, IRQ and core affinity.

### Transport options (benchmark, do not assume)

- `io-uring` via sockudo-ws: benchmark against epoll on the target kernel. Check `tokio-uring`'s maintenance status first; if it is stale or slower, keep epoll as the default.
- TLS with `rustls` (aws-lc-rs provider), session resumption on. Kernel TLS offload is an optional experiment.
- HTTP/3 WebSockets (RFC 9220, sockudo-ws `http3`) is a later experiment for mobile network changes, not part of the beta.

### The SurrealDB write path is the real bottleneck

- Key mailbox records by `(device_id, seq)` so `fetch_after` is a single range scan.
- Allocate `seq` from a per-device counter inside the same transaction as the envelope write.
- Group commit (above) is mandatory. Measure SurrealDB writes per second on the target machine early (milestone 2), because it sets the ceiling for the whole system.

## 5. Protocol and component specifications

### Client wire protocol (`crates/proto`, documented in `docs/PROTOCOL.md`)

- WebSocket binary messages only, subprotocol `songbird.v1`, path `/v1/ws`.
- **Hot-path frames are hand-encoded**: a one-byte type, fixed-width fields, then the opaque envelope bytes. Device IDs are 16-byte binary, not strings. Frames: `Deliver{seq, envelope}`, `Send{req_id, idempotency_key, recipients[(device_id, envelope)]}`, `SendResult{req_id, result}`, `Ack{up_to_seq}`, `Ephemeral{to, payload}`.
- **Rare control frames use protobuf (`prost`)**: `Hello`, `Auth`, `AuthOk`, `Error`, device-list mismatch details.
- **Handshake:** server sends `Hello{nonce, server_time, protocol_versions, store_generation}`. Within 5 seconds the client sends `Auth{device_id, signature, last_acked_seq, client_version}`, where the signature is the device key over a domain-separated string containing the nonce and server name. Otherwise close.
- **Close codes** (Pusher-style ranges): 4000–4099 do not reconnect (device removed, auth failed, replaced), 4100–4199 reconnect with backoff (slow consumer, overload), 4200–4299 reconnect now (drain for deploy). Include a retry hint where relevant.
- **Heartbeat:** WebSocket ping every 25 s; drop after 60 s of silence.
- **Limits:** maximum inline envelope size (start at 64 KiB; larger content goes through attachments), maximum recipients per send, per-device frame and send rates. All configurable, all enforced before any allocation proportional to input.

### `delivery`

- **Connection lifecycle:** TLS, upgrade, Hello/Auth, then `attach` (claim the registry entry and close any older connection for the device on any node), then **subscribe before drain**: drain the mailbox from `last_acked_seq`, then stream live, deduplicating by `seq`.
- **Session algorithm:** next `seq` delivers inline; `seq` ≤ last sent is dropped as a duplicate; any gap or oversized envelope triggers a mailbox drain. A slow safety sweep (start at 120 s, jittered) catches forwards lost between nodes.
- **Backpressure:** bounded per-connection queue. When full, disconnect with a 41xx code. Ephemeral events (typing, presence) are dropped first and never stored.
- **Graceful drain on SIGTERM:** stop accepting, close sockets with 42xx spread over a configurable window to avoid a stampede, finish in-flight group commits, release registry entries, exit.

### `send`

- Device-list check per recipient account; on mismatch, reject with the missing, extra and stale devices so the client re-encrypts.
- Idempotency keys are stored durably in the same transaction as the envelopes (24-hour retention), so retries never duplicate.
- MLS commits for a group are ordered by a compare-and-set on the group's epoch in SurrealDB; exactly one concurrent commit wins and the losers are told so.

### `mailbox`

`store_batch`, `fetch_after(device, after_seq, limit)`, `ack_up_to(device, seq)` (hard delete), `expire_older_than(age)`. Optional feature: at-rest wrapping of stored envelopes with daily keys destroyed after 31 days (crypto-shredding).

### `registry`

- **Presence through subscriptions.** When a device attaches, its core first publishes a `close` control message on `device:<id>` (so any older connection on another node drops), then subscribes to `device:<id>`. When it detaches, the core unsubscribes. There is no separate device-to-node table: the subscriptions are the registry.
- **Offline detection for free.** `PUBLISH` returns the number of receivers; zero means the device is not connected anywhere, so the send path enqueues a push job.
- **Re-subscribe:** detect a Valkey restart or failover (connection reset, changed `run_id`) and re-subscribe every locally connected device in batches. Routing must heal itself without operator action.
- **Clustering later:** when Valkey becomes a cluster, switch to sharded `SPUBLISH`/`SSUBSCRIBE` through the redis-rs cluster connection, so each channel lives on one shard instead of being copied to all of them.

### `router`

`Router` trait with `ValkeyPubSub` as the default (one channel per device, as above; reuse the relevant parts of Sockudo's Redis adapter). Feature-gated alternatives to benchmark later: `DirectLinks` (per-core peer ports, batched framed TCP with mutual TLS, a device-to-node registry) and `Iggy` (one partition per node or core). Switch only if a benchmark shows the extra Valkey hop matters.

### `jobs`, `worker`, `push`

- **Jobs:** Valkey Streams with consumer groups, one stream per priority (push, cleanup, deletion, backup). Per-job ack, `XAUTOCLAIM` for stuck jobs, exponential backoff, a dead-letter stream with alerting. Every job idempotent; jobs carry IDs only. An outbox table in SurrealDB, relayed to Valkey, for jobs that must exist exactly when a database change commits (account deletion).
- **Worker:** attachment cleanup after all ACKs, 30-day expiry, account deletion across all stores, crypto-shredding key rotation, backup scheduling, automated restore verification.
- **Push:** per-device coalescing (APNs `apns-collapse-id`, FCM `collapse_key`, plus a short local debounce). iOS: alert push with `mutable-content: 1`, generic text, no identifiers. Android: high-priority FCM data push with no sensitive data. UnifiedPush via encrypted Web Push. Delete tokens reported as unregistered; circuit breaker per provider. Reserve a separate high-priority path for VoIP pushes (calls, later).

### `client` (Rust)

Connection state machine (connecting, connected, unavailable, failed), jittered exponential backoff honouring retry hints, dedupe by `seq`, cumulative ACKs after durable local storage, and the store-generation resend rule from section 6. `loadgen` is built on this crate, so the load test exercises the real client.

## 6. Disaster recovery

### Principles

- Only SurrealDB (accounts, devices, keys, groups, mailbox) and RustFS backup vaults hold state that cannot be rebuilt. Everything else — Valkey, routing, sessions, caches — must rebuild itself automatically.
- The whole environment can be recreated from `deploy/` plus backups, at a second EU provider, with one documented command.
- A backup that has not been restored automatically in the last 24 hours is treated as broken.

### Targets (proposed; the owner confirms them in `docs/DECISIONS.md`)

| Data | Beta (single server) | Later (multi-node) |
| --- | --- | --- |
| Accounts, devices, keys, groups | RPO ≤ 5 min, RTO ≤ 2 h | RPO ≈ 0 (replicated), RTO ≤ 15 min |
| Undelivered envelopes | May be lost on total server loss; recovered by clients (store generation, below) | RPO ≈ 0 (replicated) |
| User backup vaults (RustFS) | RPO ≤ 24 h, off-site copy | Three copies across zones |

### Store generation: surviving message loss on restore

- SurrealDB holds a `store_generation` number, sent to every client in `Hello`. Every restore from backup increments it.
- Clients keep each sent message until the recipient's end-to-end delivery receipt arrives (or 30 days pass).
- When a client sees a higher `store_generation`, it re-asserts its device registration and keys (idempotent calls) and resends every recent message that has no delivery receipt yet. Recipients drop duplicates by the message ID inside the encrypted payload.
- Result: a restore can lose server state, but users do not lose messages. Specify this in `docs/PROTOCOL.md` and implement it in `crates/client`.

### Failure matrix

Implement detection and the automatic response for every row, and write a runbook in `docs/RUNBOOKS/` for every row.

| Failure | Automatic response | Recovery |
| --- | --- | --- |
| `delivery` process crash | Supervisor restarts it; clients reconnect with backoff and drain | None needed |
| Delivery node lost | Its subscriptions vanish with its Valkey connection, so publishes to its devices report zero receivers (push); clients reconnect elsewhere | Replace node from `deploy/` |
| `valkey-hot` lost or restarted | Nodes route locally only and shorten the safety sweep (for example to 5 s); re-subscribe every local device when it returns | Automatic |
| `valkey-jobs` lost | Outbox relay re-creates critical jobs; push jobs are lossy by design | Restart from AOF; verify dead-letter stream |
| SurrealDB unavailable | Reject sends with a retryable error; keep sockets open; clients queue locally | Restart or fail over |
| SurrealDB data loss or corruption | Stop writes | Restore latest good backup, increment `store_generation`, run consistency checks |
| RustFS lost | Attachment uploads fail retryably; text keeps working | Restore vaults from off-site copy |
| APNs or FCM outage | Circuit breaker; messages stay in mailboxes | Automatic when provider returns |
| Whole server or provider lost | — | Rebuild at the second provider from `deploy/` and the off-site backup, within RTO |
| Bad deploy | Health checks fail the rollout; automatic rollback | Post-incident note |
| Operator error (deleted data, wrong command) | Admin tool requires confirmation and writes an audit log | Point-in-time restore |
| Compromise or ransomware | Off-site backups are immutable and use separate credentials | Rebuild clean, rotate every secret |

### Backups

- **Method:** find and document the recommended backup method for the pinned SurrealDB version and storage engine (do not assume). Run it at least every 5 minutes for incremental data, or use continuous log shipping if the engine supports it.
- **Encryption:** encrypt every backup with `age` before it leaves the server. Keep the private key offline in two places, never on the server.
- **Off-site and immutable:** store at a second EU provider with object lock (write-once) and credentials that the production servers do not have.
- **Retention:** account data 7 daily, 4 weekly, 3 monthly. Mailbox data at most 7 days, and covered by crypto-shredding where enabled, because undelivered envelopes must not outlive their 30-day promise in backups.
- **Verification:** a daily `worker` job restores the latest backup into a scratch environment, runs consistency checks (counts, checksums, a sample of reads) and alerts on failure.

### Drills

- Monthly: full restore drill, timed against the RTO.
- Quarterly game day: kill a delivery node under load, restart Valkey, fail over the database, rebuild everything at the second provider. Record results in `docs/RUNBOOKS/drills.md`.

### Secrets

APNs and FCM credentials, TLS keys and the node-to-node certificate authority live in a secrets manager, with an offline sealed copy. Each has a documented rotation procedure that has been executed at least once.

## 7. Security requirements

- **TLS everywhere.** Clients: rustls, TLS 1.3 only. Between nodes and to Valkey and SurrealDB: mutual TLS with a private certificate authority, on the private network only. Nothing but the client ports and the `api` port is reachable from the internet.
- **Device authentication** by signed challenge (section 5). No bearer tokens in URLs or logs.
- **Input limits before allocation.** Every decoder checks lengths against configured maximums before allocating. Decoders for client frames, peer frames and protobuf control messages are fuzzed with `cargo-fuzz` in CI (time-boxed per run, corpus kept in the repo).
- **Rate limits** per device and per IP range: frames, sends, username lookups, connection attempts. Rate-limit state in `valkey-hot`, with a local fallback when it is down.
- **No sensitive data in logs or metrics.** A lint or test fails the build if device IDs, account IDs or IP addresses appear in log statements on the hot path. Aggregate metrics only.
- **Supply chain:** `cargo-deny` (licences, advisories, duplicate versions) and `cargo-audit` in CI; pinned versions; `Cargo.lock` committed; reproducible release builds documented.
- **Unsafe code:** forbidden in Songbird crates unless a measured exception is recorded and reviewed (section 3).
- **Admin tooling** requires explicit confirmation for destructive actions and writes an audit log.
- Keep `docs/THREAT_MODEL.md` current: for each component, what an attacker who controls it can see and do.

## 8. Testing, benchmarks and targets

### Correctness first: the delivery checker

Build a checker into `loadgen`: every simulated device records every message ID it sent and every `seq` it received. At the end of any run, the checker proves for every device: nothing lost, nothing delivered twice to the app, strictly increasing order. **Every load, chaos and failover test must pass the checker.** A fast result with one lost message is a failure.

### Test layers

- **Unit and property tests** (`proptest`) for frame codecs and the session ordering algorithm (random interleavings of live frames, duplicates, gaps and drains).
- **`loom` tests** for any custom concurrency primitive.
- **Integration tests** with docker compose (SurrealDB, `valkey-hot`, `valkey-jobs`, RustFS): one named test per invariant in section 1.
- **WebSocket compliance:** run the Autobahn test suite against `delivery` itself, with our configuration.
- **Chaos tests:** `kill -9` delivery nodes under load, restart Valkey, pause SurrealDB, inject latency and packet loss between nodes (`tc netem` or toxiproxy). Verify recovery time and pass the checker.
- **Restore test:** take a backup under load, destroy the database, restore, increment `store_generation`; clients must resend and the checker must pass.
- **Fuzzing:** every decoder (section 7).

### Load and benchmarks

- `loadgen` runs distributed across several machines and drives the real `client` crate.
- Scenarios: idle connections at scale; steady 1:1 traffic; group fan-out (256 members); a reconnect storm of all connections at once; a 24-hour soak.
- Measure and report for each: p50, p99 and p99.9 send-to-deliver latency (same core, cross-core, cross-node), sustained messages per second, memory per idle connection, CPU per 10,000 messages, SurrealDB commits per second, time to recover from a reconnect storm.
- **Baselines on the same hardware:** Sockudo, and the sockudo-ws echo and broadcast examples with `websocket-bench`. Report how `delivery` compares.
- Micro-benchmarks with `criterion`; flamegraphs (`perf`) attached to every milestone report.

### Initial targets (validate and adjust with the owner)

- Server-side p99 send-to-deliver on one node under 2 ms at the beta's peak load, with group commit included.
- Cross-node p99 under 5 ms on the same datacenter network.
- No allocation per message in steady state.
- Full recovery from a reconnect storm of every beta connection within 60 seconds, with zero loss.

### CI

`cargo fmt --check`, `clippy -D warnings`, all tests, `cargo-deny`, `cargo-audit`, a short fuzz run, and a benchmark regression gate: fail the build if a tracked p99 or throughput number regresses by more than 10% against the stored baseline.

## 9. Milestones, working rules, definition of done

### Milestones and gates

Stop at every gate, write `docs/reports/M<n>.md` (what was built, tests, numbers with hardware and kernel version, flamegraph, open risks), and wait for the owner before continuing.

| # | Build | Gate |
| --- | --- | --- |
| M0 | Workspace, CI, docker compose, telemetry skeleton, `DECISIONS.md` with every pinned dependency verified against its source | CI green; decisions recorded |
| M1 | `proto` codecs and fuzzers; sockudo-ws server; handshake and auth; session algorithm on an in-memory mailbox; `client` crate; `loadgen` v0 with the checker | Autobahn passes; checker passes; first baseline numbers versus Sockudo |
| M2 | SurrealDB `mailbox` with group commit and per-device `seq`; `send` path (device lists, idempotency, MLS ordering); batched ACK deletes | Every invariant has a passing named test; SurrealDB commits per second measured |
| M3 | Thread-per-core `runtime`; `SO_REUSEPORT`; per-core resources; cross-core inboxes; lock-free device directory (benchmarked choices) | Throughput scales across cores (curve in report); zero allocation per message |
| M4 | Valkey pub/sub router (one channel per device, re-subscribe on reconnect); cross-node takeover; `DirectLinks` and `Iggy` routers behind features, benchmarked against it | Cross-node p99 reported; chaos kill tests pass the checker |
| M5 | `jobs` with outbox; `push` service; `worker`; `api` incl. RustFS attachment uploads | Offline device receives a push end to end; account deletion verified across every store |
| M6 | Backups, encryption, off-site immutable copies, daily restore verification, `store_generation` with client resend, runbooks, rebuild from `deploy/` at a second provider | Timed restore drill within RTO; restore test passes the checker |
| M7 | io\_uring versus epoll, allocator and TLS tuning, reconnect-storm protection, full load suite, 24-hour soak, threat model | Targets met, or gaps documented and accepted by the owner |

### Working rules for you

1. Re-read this file and `docs/DECISIONS.md` at the start of every session.
2. Read the docs and source of the exact pinned version before using any dependency. Never invent an API.
3. Write the invariant tests before the optimisation that could break them.
4. Every "benchmark X versus Y" choice is built behind a trait or cargo feature, measured on the same hardware, decided by p99 and throughput, and recorded with the numbers.
5. No performance claim without a benchmark you ran, stating hardware, kernel and configuration.
6. Never weaken an invariant in section 1 for speed. If a trade-off appears, stop and ask the owner.
7. Add a dependency only with a recorded reason; fewer dependencies is better.
8. Hot-path code gets comments explaining why it is written that way. Everything else stays simple.
9. No secrets in the repository, ever.

### Definition of done

- Every milestone gate passed and its report written.
- Every invariant in section 1 has a named, passing test, and the checker passes in every load, chaos and restore scenario.
- A timed disaster-recovery drill met the RTO, and every failure in the matrix has a tested runbook.
- One command reproduces the full benchmark suite and prints the comparison against the stored baseline and against Sockudo.
