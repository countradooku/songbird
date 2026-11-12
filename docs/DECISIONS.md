# Decisions

Every "X versus Y" choice, new dependency, `unsafe` exception and owner decision is recorded here,
newest first. Performance decisions cite the benchmark run (hardware, kernel, configuration, numbers).

## Template

```
## D-NNNN — <title>

- Date: YYYY-MM-DD
- Status: proposed | accepted | superseded by D-NNNN
- Decided by: owner | agent (with owner approval)
- Context: what forced the decision
- Options considered: X, Y, ...
- Evidence: benchmark runs, tests, proofs (with links)
- Decision: what was chosen
- Consequences: what this rules in or out; what to revisit and when
```

## Open owner decisions

- Group read receipts follow the read-receipt setting or not (Prompt 4).
- Public channels: build or not (Prompt 5).
- Inactivity deletion period (Prompt 3).
- WhatsApp interop legal gate (Prompt 14).
- Second EU provider: Scaleway proposed (D-0009). Confirm, or name another.
- Public domains: Songbird's client endpoints and the web domain for proxy links (D-0011). The
  upstream names in `deploy/proxy/proxy.example.toml` are placeholders until then.
- Licence for the repository (README says all rights reserved until chosen).
- Deployment access model: SSH as root with a key, through one bastion restricted to admin ranges
  (D-0014). Alternatives: WireGuard-only access, a non-root deploy user with sudo.
- GitHub environments `staging` and `production` with required reviewers, and their secrets
  (`SOPS_AGE_KEY`, `DEPLOY_SSH_KEY`), must be created by the owner before `deploy.yml` can run.
- Prompt 2, milestone 2 (report `docs/reports/P02-M2.md`):
  - D-0029: the mailbox store is Apache Iggy (owner's decision). Still to confirm: Iggy is
    pre-1.0 (storage format changed between 0.9 and 0.10); its container needs io_uring allowed
    in seccomp. (The 14 hours acknowledged ciphertext stayed on disk is answered by D-0031:
    unopenable within about a second of the ACK, deleted within minutes.)
  - D-0030: official Iggy SDK (owner's decision) brings 153 crates (exempted, audit backlog) and
    `ring` as an unused transitive dependency. Proposed wording for the constitution's locked
    stack: "All TLS and cryptographic operations we perform use rustls with aws-lc-rs. Another
    crypto library may appear only as a transitive dependency of an owner-approved crate, unused
    by our TLS or crypto paths, named in DECISIONS." Not written into the constitution until the
    owner approves it.
  - D-0025: own minimal SurrealDB client instead of the official SDK (264 crates); SurrealDB no
    longer holds the mailbox, but keeps accounts and devices from Prompt 3.
  - D-0028: benchmark compio (owner's suggestion) against per-core Tokio in M3; changing the
    runtime touches the locked stack. Decided: per-core Tokio stays (owner, after D-0032's
    measurement: compio +2–4 %); io_uring is measured again in M7.
- Prompt 2, milestone 3 (report `docs/reports/P02-M3.md`): gate approved by the owner on 2026-11-12.
- Prompt 2, milestone 4 (report `docs/reports/P02-M4.md`): gate approved by the owner on 2026-11-12. D-0034
  (Valkey routing, owned partitions over node links, replicated key stores) decided by the agent
  under the owner's delegation; the owner may revisit it. New dependency `redis` (with `arcstr`,
  `async-lock`, `xxhash-rust` under BSL-1.0), exempted pending audits.
- Prompt 2, milestone 5 (report `docs/reports/P02-M5.md`): approve the gate; approve two threat-model
  rows added beyond the two approved (the sealed job queue and the hashed request nonces, both
  forms of data already listed); D-0036 decided by the agent under the owner's standing
  instruction. Real APNs, FCM and UnifiedPush credentials are needed to test against the real
  providers (mocks only so far).
- D-0038: whether to store who invited whom for abuse handling (default: no, only per-user counts).
- D-0037: when the `send` crate is extracted, `api` (and `calls`, `worker`) must reach Iggy partition
  owners; admitting `api.` certificates to node links, or another route, is to be decided then.
- D-0035 (RustFS replaces Garage, owner's decision): the `rustfs/rustfs:1.0.5` image is pinned by
  tag only, because Docker Hub was unreachable from the agent's sandbox. Pin its digest in
  `deploy/compose/compose.yaml` and `deploy/ansible/group_vars/all.yml` before the next deployment
  (`docker buildx imagetools inspect rustfs/rustfs:1.0.5`).

## Decisions

## D-0038 — Prompt 3 amendment: invite-only registration

- Date: 2026-11-13
- Status: accepted (prompt amended; built in Prompt 3)
- Decided by: owner (prompt amendment)
- Context: the launch is invite-only. Registration abuse controls in Prompt 3 (proof of work,
  per-IP throttles) do not limit who joins, and an invite system is the usual place where a
  messenger quietly records its social graph.
- Decision: `docs/prompts/03-identity.md` gains an **Invite-only launch** item under "Also build":
  - a server-side invite-only mode, switchable off without a migration;
  - random invite codes stored only as hashes, single- or multi-use, with expiry, and
    rate-limited checks so codes cannot be guessed;
  - a per-user invite allowance (configurable, for example five) and admin-generated batches;
  - **who invited whom is not stored by default**: only per-user counts. Storing the link for
    abuse handling would need the owner's decision here and a threat-model row.
  - Tests: valid, expired, reused and guessed codes; quota limits; mode switched off.
- Consequences: Prompt 3 has not started, so nothing is built yet; its issue gains the item in
  Build and its tests in Gate. Open owner decision: whether to store inviter links for abuse
  handling (default no).

## D-0037 — Prompt 2 amendment: no internal network Send API; a `send` library and `PUT /v1/messages`

- Date: 2026-11-13
- Status: accepted (prompt amended; to build)
- Decided by: owner (prompt amendment)
- Context: Prompt 2 asked for an internal, mutual-TLS "Send API" so `api`, `calls` and `worker`
  could send through the store-then-route path. A network hop adds latency, a second protocol to
  secure, and a second path that can drift from the WebSocket's.
- Decision: `docs/prompts/02-realtime.md` replaces that item:
  - the **`send` crate** (validate, store, publish on the device's Valkey channel) is a library
    that `delivery`, `api`, `calls` and `worker` link directly, so every send takes the same
    tested path with no extra hop;
  - server-originated notices (for example "your device list changed") are server-signed
    system frames, never user messages;
  - for clients with no open WebSocket (notification quick-reply, share extension, failed
    socket), `api` exposes **`PUT /v1/messages`**, which takes the same encrypted envelopes as
    the WebSocket `Send` frame and calls the same crate.
  - The amended text says "store in SurrealDB"; the store is the mailbox, which is Apache Iggy
    since D-0029 (SurrealDB holds the registry), so the crate stores through the `Mailbox` trait.
- Evidence: no internal Send API exists in the code (searched 2026-11-13), so there is nothing
  to refactor. The worker's device link (D-0036, `[delivery.internal]`) is not a send interface:
  it accepts only `worker.` certificates and only Forget and Known.
- Consequences: still to build in Prompt 2, before its final gate:
  - extract the send path from `services/delivery/src/session.rs` (device-list check,
    idempotency, store, route, push on offline) into `crates/send`;
  - `api`'s `PUT /v1/messages` on it, signed like every `api` request, with the same limits as the
    `Send` frame; server-signed system frames in `crates/proto`;
  - `api`, `calls` and `worker` then need the mailbox and router connections `delivery` has.
    With Iggy partitions owned by delivery nodes (D-0034), a send from `api` reaches a
    partition's owner over node links like a non-owning delivery node does, which needs `api`
    nodes admitted to those links (today `delivery.` certificates only); to decide when built.

## D-0036 — Milestone 5: sealed jobs, push that leaks nothing, a minimal account registry, uploads through `api`, deletion proven across every store

- Date: 2026-11-12
- Status: accepted (design); built and measured in M5
- Decided by: owner for scope (a minimal account and device registry in SurrealDB now; push
  tokens and attachment records added to the threat model's list); design by agent under the
  owner's standing instruction ("think like a Proton founder or a top-tier engineer").
- Context: M5 builds `jobs` with an outbox, `push`, `worker` and `api` with RustFS uploads. Gate:
  an offline device receives a push end to end; account deletion verified across every store.
  No account store existed (delivery read a static file); the mailbox is Iggy (D-0029), owned
  per partition by delivery nodes (D-0034); RustFS listens on loopback behind an mTLS tunnel
  (D-0035), so clients can never reach it directly.
- Decision:
  - **Account registry (`crates/accounts`, SurrealDB).** Tables `account` and `device` (IDs,
    the Ed25519 auth key, a `disabled` flag), `directory:version` bumped by every change. Delivery
    loads its directory from SurrealDB and reloads it when the version changes (polled every
    second; the static file stays for development). Registration proper (usernames, keys, proof
    of work) is Prompt 3; until then accounts are created through an internal mutual-TLS endpoint
    of `api`.
  - **Jobs (`crates/jobs`, Valkey Streams on `valkey-jobs`).** One stream per kind (`push`,
    `cleanup`, `deletion`; `backup` arrives with M6), one consumer group each. Jobs carry IDs
    only, and **every job is sealed** (AES-256-GCM-SIV under a key derived from the jobs secret,
    bound to the stream and the job ID): `valkey-jobs` persists to disk, and a plaintext queue of
    device IDs would be a record of who was messaged when. Per-job `XACK` plus `XDEL` (an
    acknowledged job leaves memory and the AOF rewrite). Stuck jobs: `XPENDING … IDLE` then
    `XCLAIM` (instead of `XAUTOCLAIM`, because `XPENDING` also returns the delivery count, which
    bounds retries of a job that crashes its consumer). Failures: exponential backoff with full
    jitter through a delayed sorted set promoted by a Lua script; after the last attempt a
    dead-letter stream (capped) with a metric to alert on. Every handler is idempotent.
  - **Outbox.** A SurrealDB `outbox` table written in the same transaction as the change that
    needs a job (account deletion); a relay in `api` and `worker` moves rows to the stream and
    deletes them. A crash between the two repeats a job, which handlers tolerate.
  - **Delivery → push.** `Routed::Offline` enqueues a push job without touching the hot path:
    a per-core debounce (one job per device per window) and a bounded buffer flushed as one
    pipelined `XADD` batch; when Valkey is down the buffer drops and counts (the message is safe
    in the mailbox; the device fetches it at its next connection; runbook).
  - **Push tokens.** Registered through `api`, **sealed to the push service's X25519 public key**
    (ephemeral X25519, HKDF-SHA256, AES-256-GCM; `api` and `worker` hold only the public key, so
    only `push` can ever read a token), stored under a keyed hash of the device ID (HMAC-SHA256,
    push-index secret) so the table alone does not link a token to a device. Deleted at once when
    the provider reports the token unregistered, and with the device.
  - **Push service.** APNs (HTTP/2, ES256 provider token, `mutable-content: 1`, one generic alert
    text, constant `apns-collapse-id`), FCM HTTP v1 (OAuth 2 service-account token, high-priority
    data message with no data, constant `collapse_key`), UnifiedPush (Web Push, RFC 8291
    `aes128gcm` and RFC 8292 VAPID, constant body). Every push looks identical whatever caused
    it. Per-device debounce, a circuit breaker per provider, retries through the job queue.
    Provider credentials exist only in this service's configuration. All crypto through
    aws-lc-rs; HTTP/2 through `hyper`'s client connection API (adds `h2`).
  - **API without a framework.** `hyper` server directly (already in the tree), not Axum: a
    handful of endpoints, bodies bounded before reading, fewer crates to audit. Device requests
    are signed with the device's Ed25519 key over a domain-separated transcript (method, path,
    server name, timestamp, nonce, body digest); timestamps within 60 s and nonces single-use
    (keyed hash in `valkey-hot`, expiring). Account creation and test hooks are on a separate
    mutual-TLS listener.
  - **Attachments.** Uploads stream through `api` to RustFS (RustFS is never exposed): a grant
    fixes an exact padded size and how many recipient fetches are due; the upload must match the
    size exactly; object names are 32 random bytes (no identifiers). After upload the record holds
    no link to the uploader. Each download decrements the count; at zero a cleanup job deletes
    the object, and the worker deletes everything older than 30 days. Our own S3 client (SigV4
    with aws-lc-rs over `hyper`), instead of the AWS SDK and its dependency tree. Each service
    gets its own least-privilege RustFS credential (D-0035).
  - **Account deletion.** `api` disables the account's devices (sessions refused within a
    directory reload) and writes the outbox row in one transaction. The worker then, each step
    idempotent: asks delivery, over a mutual-TLS internal link that accepts only `worker.`
    certificates and only these operations, to close the devices' sessions and **forget** their
    mailboxes (pending entries acknowledged, so their keys are punctured, and counters dropped);
    deletes push tokens, pending upload
    grants and their partial objects, device and account rows; repeats the mailbox step after
    the directory has propagated; and verifies every store holds nothing (SurrealDB rows, mailbox
    state on the owner, push tokens, RustFS objects of pending grants). Attachments already sent
    are not linked to the account by design; they go when fetched or after 30 days. Backups are
    M6's.
- Implementation (refinements while building):
  - **No tombstones.** The design had a short tombstone so a send racing the deletion would skip
    the device; built instead: the worker forgets the mailboxes again once every node has
    reloaded its directory (`propagation_ms`, default 3 s), then verifies. Simpler (no new
    state in the writer, nothing that expires) and the verification proves the result.
  - **Mailbox `Forget` record** (sealed format 4; format 3 still read): acknowledges the
    devices' pending entries (keys punctured) and drops their counters; replay applies it, so a
    restart or a standby's takeover keeps nothing. Routed to the partition owner over node
    links (`Forget`, `Known`). `Mailbox::forget` and `Mailbox::knows` on every backend.
  - **Directory** swapped whole with `arc-swap` 1.9.5 (constitution: hot-reloaded state;
    readers take no lock; one new crate plus `rustversion`, a proc-macro).
    `Router::close_everywhere` closes a deleted device's session on every node.
  - **API**: `hyper` 1.12.0 directly; the `api` crate is a library so tests run it in process;
    a signed client (`songbird_api::client`) for tests and tools. A download counts its fetch
    when its last byte is handed to hyper (hyper stops polling a body at `Content-Length`, so
    end-of-stream never comes; found by the live test).
  - **Push service** (`services/push`, built on `crates/push-providers`): debounce keyed by the
    push-row hash (no device IDs in memory), first attempts only; an unregistered token's row
    is deleted only if it still holds the token that failed (a re-registration in between is
    kept); a VoIP token reported unregistered deletes the whole APNs row (the app re-registers).
  - `crates/valkey` holds the self-healing connection (moved from the router) and shared
    settings; `crates/accounts` the registry and push-token sealing; `crates/link::devices` the
    worker's request format.
- Evidence (Apple M5 Pro, 18 cores, 48 GiB, macOS 27.2.1; Docker 6.1.4 Linux VM; compose images
  as pinned; release build; loopback; [P02-M5 report](reports/P02-M5.md)):
  - Gate: `tests/e2e/tests/gate_m5.rs` `an_offline_device_receives_a_push_end_to_end` and
    `account_deletion_is_verified_across_every_store` pass (3 of 3 runs) on SurrealDB (registry
    and mailbox), valkey-hot, valkey-jobs and RustFS. Iggy cannot run on this machine (the Docker
    VM's kernel refuses io_uring even unconfined); the Iggy forget test
    (`forgotten_devices_leave_nothing_readable_and_no_counters`) and the gate on Iggy run in the
    Linux compose CI job.
  - Job queue: 74,800 enqueues/s (pipelined batches of 256), 166,600 consumed, acknowledged and
    deleted per second (`m5_numbers`).
  - Attachments through `api` to RustFS: 1 MiB upload p50 11.1 ms / p99 12.1 ms (90 MiB/s),
    download p50 3.2 ms / p99 3.7 ms; 16 MiB upload p50 114 ms / p99 120 ms (141 MiB/s),
    download p50 13.4 ms / p99 14.4 ms (1.2 GiB/s).
  - Live tests: `crates/jobs` (5), `crates/accounts` (3), `crates/s3` (5), `services/api` (3),
    `services/push` (1 covering bursts, calls, unregistered, retry, no identifiers); unit tests
    for sealing, signing, record and wire formats (Forget, Known), push-token sealing and every
    provider (RFC 8291 vector, SigV4 vectors).
- Consequences: Valkey still learns nothing (routing D-0034; jobs sealed); new metadata limited
  to the two rows the owner approved; the static directory is no longer the only source of
  devices, so `delivery` becomes deployable once Prompt 3 adds registration.
- Dependencies (s3): `crates/s3` (`songbird-s3`) adds no crate to `Cargo.lock`. It enables
  hyper 1.12.0's `client` feature in its own manifest (the workspace keeps `http1` and `server`);
  that feature's dependencies `want`, `pin-project-lite` and `smallvec` were already locked.
  Everything else (aws-lc-rs for HMAC-SHA256 and SHA-256, hyper-util 0.1.21's `TokioIo`,
  tokio-rustls, rustls, bytes, futures-core, hex, zeroize, thiserror) was already a workspace
  dependency. APIs read in the pinned sources first: hyper `client::conn::http1::{Builder,
  SendRequest::{ready, try_send_request, is_closed}}`, `TrySendError::take_message` and the h1
  dispatcher's body loop (it stops polling a body at `Content-Length`, so the upload body holds
  the completing chunk back until the source confirms its end); http-body 1.1.0 `Body`,
  `Frame`, `SizeHint`; aws-lc-rs 1.19.0 `hmac::{Key, sign, HMAC_SHA256}`, `digest::digest`;
  tokio-rustls 0.26.6 `TlsConnector::connect`. SigV4 is checked against AWS's published vectors
  (`get-vanilla`, `get-vanilla-query-order-key-case`, `get-vanilla-empty-query-key`, and the S3
  GET object, PUT object, GET lifecycle and list examples); `crates/s3/tests/rustfs_live.rs` runs
  against RustFS 1.0.5 in the compose job.
- Dependencies (push providers, `crates/push-providers`): one crate new to `Cargo.lock`, **`h2`
  0.4.20**, brought by enabling `hyper`'s `client` and `http2` features (HTTP/2 to APNs and FCM
  through `hyper::client::conn::http2`; Apple requires HTTP/2). Published by Sean McArthur like
  `hyper`, so covered in `cargo vet` by a `trusted.h2` entry under D-0016's rule; MIT. Its own
  dependencies were all in the tree already. Direct dependencies already in the tree, now in
  `[workspace.dependencies]`: `serde_json` 1.0.154 (service-account file, OAuth and provider error
  bodies, JWT claims; off the hot path, response bodies capped at 16 KiB before parsing) and
  `webpki-roots` 1.0.12 (Mozilla's roots compiled in, so the push service does not depend on the
  container's CA bundle; CDLA-Permissive-2.0, exception already in `deny.toml`). Not taken:
  `jsonwebtoken`, `p256`, `ring`, `base64` (JWTs, VAPID and RFC 8291 use our own 60-line
  unpadded base64url, tested against RFC 4648), `url` (endpoints parsed with `http::Uri` plus
  explicit checks). All signing, ECDH, HKDF and AES-GCM through aws-lc-rs 1.19.0; APIs read in the
  pinned sources (hyper 1.12.0 `client::conn::{http1,http2}`, `server::conn::{http1,http2}`;
  hyper-util 0.1.21 `rt::{TokioExecutor, TokioIo, TokioTimer}`; aws-lc-rs `agreement::{PrivateKey,
  agree}`, `signature::{EcdsaKeyPair, RsaKeyPair}`, `hkdf`, `aead::LessSafeKey`; http-body-util
  0.1.5 `Limited`; rcgen 0.14.10 for the mocks' test CA, behind the `test-support` feature).

## D-0035 — Object storage: RustFS replaces Garage

- Date: 2026-11-12
- Status: accepted
- Decided by: owner ("replace garage with rustfs"); a change to the constitution's locked stack.
- Context: Garage v2.5.0 (D-0007) was the S3 store for encrypted attachments and backup vaults.
  No Songbird crate talks to S3 yet (attachment uploads arrive in P02-M5), so the change touches
  only docker compose, CI, Ansible, secrets generation and the documentation.
- Options considered: keep Garage v2.5.0; RustFS 1.0.5 (Apache-2.0, written in Rust). No benchmark
  between the two was run; the owner chose RustFS directly. Upload throughput and p99 are measured
  on RustFS in P02-M5.
- Evidence (read from the RustFS 1.0.5 source and its GitHub releases and advisories, 2026-11-12):
  - Releases: 1.0.0 GA on 2026-09-16; 1.0.5 on 2026-11-10 (five patch releases in eight weeks).
  - 43 published GitHub security advisories since December 2025, mostly authorization flaws (IAM,
    bucket policies, presigned uploads, service accounts). Eight affect 1.0.0 or 1.0.1 and are
    fixed in 1.0.2, three of them high: Object Lock COMPLIANCE bypassed by force-deleting a bucket;
    the FTP, SFTP and WebDAV listeners bypass bucket policies; SSE-C objects expose the plaintext
    MD5 as their ETag. None is published against 1.0.5.
  - Defaults that matter here: the web console is on (`RUSTFS_CONSOLE_ENABLE`, default true); an
    update check calls `https://version.rustfs.com/latest.json` (`RUSTFS_CHECK_UPDATE`, default
    true); FTP, FTPS, SFTP and WebDAV are off by default; the "Connect" heartbeat runs only when
    `RUSTFS_CONNECT_*` is configured. The admin API is served on the S3 port. Root credentials come
    from `RUSTFS_ACCESS_KEY` and `RUSTFS_SECRET_KEY` (access key at least 3 characters, secret at
    least 8); the image entrypoint warns on the default `rustfsadmin` pair. Health: `/health/ready`.
    The image runs as uid 10001. A single data path skips the distinct-disk check, so single node,
    single disk needs no unsafe override.
- Decision: RustFS 1.0.5, single node and single disk (like Garage with replication factor 1), in
  compose and on the data host:
  - only the S3 API listens: `127.0.0.1:9000` on the data host, reached from the private network
    through one ghostunnel mutual-TLS tunnel on port 9010 (Garage needed three ports: RPC 3901,
    S3 3910 and admin 3913);
  - console, FTP, FTPS, SFTP, WebDAV and the update check set off explicitly; logs to stdout;
  - container without capabilities, `no-new-privileges`, data in `/var/lib/songbird/rustfs`
    owned by uid 10001;
  - secrets `rustfs_access_key` and `rustfs_secret_key` (generated by `deploy/bin/secrets-init`
    and `cargo xtask dev-env`) replace Garage's RPC secret, admin token and metrics token. No
    layout step: `cargo xtask compose up` and the data role no longer apply one.
- Consequences:
  - Objects stay client-side ciphertext, so an authorization flaw in RustFS exposes ciphertext,
    sizes and object names, not content. Keep it that way: object names carry no identifiers.
  - Watch RustFS advisories and upgrade promptly; the image digest is still to be pinned (see Open
    owner decisions).
  - P02-M5: give each service its own least-privilege RustFS credential instead of the root pair;
    prefer uploads through `api` or presigned PUT with an exact length (presigned POST and
    presigned uploads have had three advisories); do not enable SSE-C (plaintext-MD5 ETag
    advisory) or Object Lock until their fixes have aged.
  - Multi-node later (vault RPO, three copies across zones) needs RustFS distributed mode or site
    replication and `RUSTFS_RPC_SECRET`; decided when Prompt 10 arrives.
  - Developers with an existing `.env` run `cargo xtask dev-env --force`.

## D-0034 — Milestone 4: Valkey routing that sees nothing, owned partitions over node links, replicated key stores

- Date: 2026-11-12
- Status: accepted (design); built and measured in M4
- Decided by: agent under the owner's delegation ("choose the best variant for maximum speed and
  security; think like someone from Proton"; the owner dropped the Valkey-against-Iggy routing
  comparison)
- Context: M4 runs several delivery nodes. The master prompt's cross-node design assumed a shared
  SurrealDB mailbox; with Iggy (D-0029) every partition has exactly one writer, and with D-0031
  its key store is on that writer's disk.
- Options considered for the key store across nodes: (A) local disk only: a dead node's partitions
  wait for it and are lost with its disk; (B) the key store in persistent, replicated Valkey: fast
  takeover, but sealed keys in a networked store and deleted keys in its append-only file until a
  rewrite; (C) the owner replicates its key store to a standby node over a mutual-TLS link: fast
  takeover, keys never leave our nodes.
- Decision:
  - **Routing: Valkey pub/sub** (master prompt default), one channel per device, the
    subscriptions being the presence registry (`PUBLISH` returns 0: offline; a new connection
    publishes `close` before subscribing). Valkey learns nothing: channel names are keyed hashes of
    the device ID (HMAC-SHA256, cluster secret), payloads (envelope notifications, close) are
    sealed with a cluster key (AES-256-GCM-SIV, bound to channel and kind; HKDF from the cluster
    secret in the secrets store, rotatable), connections use TLS
    with the internal CA (D-0012). Re-subscribe in batches after a Valkey restart or failover.
  - **Mailbox partitions: one owner node each**, a lease in Valkey (renewed; expiry hands the
    partition over), Iggy producer epochs fencing any stale owner (D-0029). Sends, fetches and
    ACKs for a partition owned elsewhere go to the owner over **node links**: per-core framed TCP
    with mutual TLS (internal CA), so envelopes never pass through a third-party store.
  - **Key stores: option C, three copies.** The owner copies every key-store write to two
    standby nodes over node links, the second in another zone (D-0034 revision, after the owner
    asked whether Proton or Signal would accept one standby: no; three copies across failure
    domains is the norm). A new key window seals records only once at least one standby holds
    it; punctures follow within the key interval, so an acknowledged message is unopenable on
    every copy within about a second. On the owner's death its first live standby takes the
    lease and the partitions.
- From Sockudo's Redis Cluster work (sockudo/sockudo#510 and its sharded pub/sub transport),
  adopted: subscriber connections are pinged and replaced when silent (half-open connections
  otherwise miss messages); no single hot channel (our per-device names are keyed hashes, so they
  spread evenly over hash slots; any future node-wide channel is bucketed across slots); changes of
  channel layout (rotating the cluster secret, moving from `PUBLISH` to sharded `SPUBLISH` when
  Valkey becomes a cluster) roll out in adjacent-compatible phases (publish both, subscribe both,
  drop the old), duplicates during the overlap being dropped by `seq`; for the cluster, a
  slot-aware subscriber with one connection per shard primary (`redis-rs` exposes no sharded
  subscribe on its cluster client); no replica connections (the router never reads).
- Implementation (refinements found while building and chaos-testing):
  - Every Valkey connection used for commands (publishes, leases, members) is a self-healing
    multiplexed connection that drops itself on an I/O error, timeout or refusal and reconnects
    on the next command: `redis-rs` multiplexed connections stayed dead after a Valkey restart
    (chaos run 2 hung, leases lapsed and two nodes ran one partition until Iggy fenced it).
  - Leases: `SET NX PX` and Lua renew/release keyed by the holder; default lease 3 s. Members
    in a sorted set whose expiry scores come from Valkey's clock (a Lua script reads `TIME`), so
    no node clock matters. Placement by rendezvous ranking (SHA-256 of member and partition):
    the first should own the partition; its standbys are the next one and the next one in a
    zone neither of them is in.
  - Takeover of a free partition: the old owner's first live standby that holds a copy at once,
    the next a lease period later, anyone else after three. One extra lease period only if the
    owner may be alive: still a member, or Valkey just lost everything (each node notices when
    its own registration vanished). No wait after a graceful handover (`released` marker). A
    node still running a partition whose lease vanished takes it back with `SET NX` without
    restarting anything; it stops only if another node holds the lease.
  - Rebalancing: an owner hands a partition to the node ranked first for it once that node has
    been a member for two lease periods and holds the whole store (it is then the first
    standby), one partition per round; the handover is the graceful one.
  - Key-store replication: the paged key store's write returns a replica (the changed pages);
    a standby validates page names and epochs before applying. A new standby, or one a copy
    failed to reach, first gets the whole store, which also deletes key files it no longer
    lists. A node that has not been a standby of a partition for three lease periods deletes its
    copy. A window becomes usable only when the replicator reports a standby holding everything
    (or no other node is live).
  - Node links: a stopped server closes its open connections (a stopped node acknowledges
    nothing); a client fails calls on a connection the peer closed at once.
  - Close messages older than 30 s are ignored (a replayed close cannot evict a session).
- Dependencies: `redis` 1.8.1 (default features off; Tokio and rustls only), bringing `arcstr`,
  `async-lock` and `xxhash-rust` (the last under BSL-1.0, an OSI-approved permissive licence:
  exception in `deny.toml`); all four exempted in `cargo vet` pending audits (same footing as the
  other client libraries).
- Evidence (AMD Ryzen 9 7950X, three delivery nodes of 2 cores, Iggy on tmpfs, Valkey 9.1.3
  container, twelve partitions; [P02-M4 report](reports/P02-M4.md)): cross-node p99 0.7 ms at
  5,000 messages/s, 1.0 ms at 20,000, 2.0 ms at 50,000 (two of three messages crossing nodes);
  chaos phases (partition owner `kill -9`, Valkey restart without persistence, owner SIGTERM,
  two nodes killed at once, rolling restart) pass the checker with no loss, duplicate or
  reordering; failover about 3 s after a crash at a 3 s lease, 4.6 s with two nodes killed.
  Tests: `crates/router/tests/valkey_live.rs` (6, including dropping every Valkey connection
  mid-run), `crates/link/tests/link.rs` (4), `crates/mailbox/tests/iggy_cluster.rs` (8: remote
  partitions, standby takeover with nothing lost, graceful handover, leases lost with Valkey
  taken back without restarts, renewals after every connection dropped, a joining node takes
  its share, two nodes die at once, a window waits for a standby); placement and key-store
  copy unit tests; node-to-node requests fuzzed in `iggy_record`.
- Consequences: losing any two nodes loses no pending message (two standbys per partition);
  with fewer live nodes than copies, writes continue on the copies that exist; Valkey sees
  opaque channels and blobs only; the node link is new code with its own tests and fuzz target. DirectLinks for live routing stays an alternative to measure only if the
  Valkey hop shows in the cross-node p99.

## D-0033 — Unsafe exception: a test-only counting allocator

- Date: 2026-11-12
- Status: accepted
- Decided by: agent (constitution: an `unsafe` exception must be measured, reviewed and recorded)
- Context: M3's gate requires proving that steady-state delivery does not allocate per message,
  and keeping the proof in CI. Counting allocations needs a `GlobalAlloc`, which can only be
  implemented with `unsafe`; every Songbird crate forbids `unsafe_code`.
- Options considered: `dhat` (does the counting inside its own `unsafe`, but adds about eight crates
  to the audit backlog and counts process-wide, so the test's clients would be counted with the
  server); `heaptrack` or valgrind's DHAT (external tools, not a CI assertion; used to attribute the
  sites); our own allocator in a separate test-only crate.
- Decision: `crates/alloc-count` (`songbird-alloc-count`): a `GlobalAlloc` that forwards every call
  to `std::alloc::System` with the caller's own arguments and counts allocations on threads that
  opted in (a const-initialised thread-local flag, two relaxed atomics). Its lint table is the
  workspace's except `unsafe_code = "deny"`, allowed on the one `impl` with a `SAFETY` comment per
  block. No service depends on it; only `tests/e2e` (dev-dependency). Its own test checks the
  per-thread counting; the deep CI tier runs it under Miri. semgrep's `unsafe-usage` rule is waived
  on exactly those four lines (`nosemgrep` with the rule's id), nowhere else.
- Evidence: `tests/e2e/tests/allocations.rs` (budget 5.5 allocations per message; measured 5.20),
  valgrind DHAT attributing each site (report P02-M3).
- Consequences: one reviewed `unsafe` block family, test-only. Any new `unsafe` elsewhere still
  needs its own entry.

## D-0032 — Milestone 3: thread-per-core runtime, device directory, inboxes, metrics, compio

- Date: 2026-11-12
- Status: accepted; the runtime choice confirmed by the owner (2026-11-12: "let's stick with
  tokio")
- Decided by: agent, by benchmark (master prompt §4: "benchmark X against Y, decide by p99 and
  throughput")
- Context: M1 and M2 ran `delivery` on one current-thread Tokio runtime: one core.
- Hardware for every number below: AMD Ryzen 9 7950X (16 cores, 32 threads), 30 GiB, Linux
  7.3.1, Rust 1.99.1; NVMe with btrfs (zstd); loopback; same session. Load generator on other
  physical cores than the server.
- Decisions:
  - **Runtime** (`crates/runtime`): one OS thread per worker, pinned to its own CPU
    (`sched_getaffinity` order, so `taskset` and cgroup cpusets confine it), each running a
    current-thread Tokio runtime; one listener per worker with `SO_REUSEPORT` (`socket2`), bound
    on the main thread before workers start. Pinning uses `rustix` (already in the graph, safe
    API) instead of `core_affinity` (adds `num_cpus`, unmaintained since 2023). No new crates.
    `[delivery.runtime] workers` (0: every allowed CPU), `pin`, `backlog`, `storage_threads`.
  - **Storage runtime**: the mailbox runs on its own multi-thread runtime (`storage_threads`,
    default one per Iggy partition), so partition writers run in parallel beside the delivery
    cores; on the main thread they capped a node at about 216,000 messages/s and fell to 165,000
    with 8 cores.
  - **Device directory: papaya** (`bench/directory`, own lockfile; 200,000 devices, 98 %
    lookups, 2 % attach/detach churn):

    | Threads | Mutex<HashMap> | papaya | scc 3.8.8 | dashmap 6.2.1 |
    | --- | --- | --- | --- | --- |
    | 1 | 44.9 M ops/s | 29.8 M | 36.7 M | 39.0 M |
    | 4 | 11.3 M (p99 3.7 µs) | 112.4 M (p99 80 ns) | 100.8 M (80 ns) | 100.7 M (90 ns) |
    | 8 | 7.6 M (p99 8.5 µs) | 215.9 M (90 ns) | 187.2 M (81 ns) | 181.4 M (100 ns) |
    | 16 | 4.8 M (p99 30.6 µs) | 362.6 M (211 ns) | 134.9 M (381 ns) | 127.9 M (421 ns) |

    papaya has the highest throughput and the best p99 from 8 threads up (its p99.9 is 0.6–0.8 µs
    from epoch reclamation; scc's 0.1–0.5 µs); already in the graph through the Iggy SDK, vet
    exempted. Routing reads the session handle under papaya's guard without cloning it.
  - **Cross-core inbox: tokio mpsc kept.** At 2 M messages/s spread over 8 cores: p99 6–22 µs for
    tokio mpsc, 7–160 µs for crossbeam with a `Notify`, 0.87 ms for kanal; flat out, tokio and
    crossbeam both about 22–35 M msgs/s, kanal 13–15 M with 2–11 % drops. tokio mpsc needs no
    extra crate and is async-native; sessions keep their per-session bounded inboxes.
  - **Metrics: per-core shards** (`songbird_telemetry::sharded`): one value per core on its own
    128-byte line, summed at scrape; workers name their shard at start.
  - **compio: not adopted (D-0028; owner's decision).** Same sockudo-ws echo, 512 connections,
    4 in flight, 256 bytes (`bench/runtime-echo`): per-core Tokio 176,000–178,000 round trips/s
    on 1 core and 717,000–718,000 on 4; compio (io_uring) 180,000 and 745,000–748,000: +2–4 %,
    p99 alike. Against it: io_uring on the internet-facing service (a large kernel attack surface
    with a history of privilege-escalation bugs, and the seccomp relaxation the Iggy container
    already needs), a second runtime per core (the Iggy SDK is Tokio-only), compio is pre-1.0 with
    breaking minor releases. Revisit with io_uring against epoll in M7.
- Consequences: throughput scales with cores (report P02-M3: 70,600 messages/s on 1 core to
  626,000 on 8 with the in-memory mailbox); the Iggy curve and its limits are in the report.

## D-0031 — Mailbox deletion on acknowledgement: puncturable keys, then physical deletion within minutes

- Date: 2026-11-12
- Status: accepted (owner delegated: "I am letting you handle this like a Proton co-founder")
- Decided by: agent, under the owner's standing delegation for security and privacy calls
- Context: with D-0029 an acknowledged envelope left the index at once but stayed on disk, in
  the clear form the client sent (MLS ciphertext, plus its recipient device and `seq`), until
  its Iggy segment was deleted: about 14 hours by default. The owner asked for deletion on
  acknowledgement and "deleted after delivery too somehow", and for Songbird to be behind
  nobody. Iggy, like any append-only log, cannot remove one message from a segment.
- Options considered:
  - **Keep plaintext records, delete segments sooner.** Shorter segments and expiry only move
    the bound; a quiet node keeps its active segment for hours; no deletion at ACK time.
  - **A store with in-place deletes** (FoundationDB, as Signal uses, or Valkey). A delete there
    is logical: the bytes stay in the storage engine until its compaction, and in the SSD until
    garbage collection. It would also give up Iggy's throughput (D-0029).
  - **One random key per message in a key table.** Deletion is exact, but the key table grows
    and is rewritten per message: the same in-place-delete problem moved to a smaller file.
  - **Puncturable encryption (chosen).** Every record sealed under keys derived from a
    Goldreich–Goldwasser–Micali tree per time window; an ACK punctures the leaf, which removes
    the ability to derive it from anything kept. The key state is small when ACKs arrive in
    order and proportional to the pending messages otherwise. The log keeps only ciphertext
    that nothing can open.
- Decision (`crates/mailbox/src/iggy/{keys,sealed}.rs`):
  - **Sealed records** (record format version 3). Each window (10 minutes) has a random metadata
    key and a GGM tree of depth 24 (16.7 M slots; PRG: AES-256 on four counter blocks, aws-lc-rs).
    Each entry (envelope, recipient device, `seq`) is sealed under its own leaf key (AES-256-GCM,
    used once, so a constant nonce); a shared group body has its own slot, punctured with the
    record's last entry; each remote part of a multi-partition send has its own slot, punctured
    once stored on its partition. Record metadata (idempotency tag and fingerprint, times, MLS
    group and epoch, ACK checkpoints, counter snapshots) is sealed with the window's metadata key.
    The associated data binds every slot to its partition, window and position.
  - **Deletion on acknowledgement.** The ACK is written to the log first (merged into the next
    store append, or alone on the ACK tick), then the leaves are punctured in memory, and the key
    store on disk follows within `key_interval` (1 s): from then on nothing on the node — log,
    key store, master key together — can decrypt the entry, its recipient or its `seq`
    (`acknowledged_messages_cannot_be_decrypted_even_with_every_key` opens every record of every
    partition with every key on disk and finds the acknowledged messages in none). The log's ACK
    records are the authority: after a crash, replay punctures again.
  - **Key store** (one directory per partition, under `key_dir`, sealed with the node's master
    key, a 256-bit secret given by SecretRef). Slots written since the last write leave the tree
    for individual keys (a "mark"), so out-of-order ACKs cannot blow the tree up; those keys are
    kept in pages of 1,024 slots. A write is copy-on-write: changed pages go to new files named by
    the writer's epoch and the write's generation, then the head (windows, trees, marks, the page
    list with each page's generation and key count) replaces the old one atomically (fsync,
    rename, fsync of the directory), then the replaced files are deleted. Load refuses the store
    if any listed page is missing, sealed for another place or generation, or holds another number
    of keys: a lost page would otherwise make pending messages look acknowledged
    (`start_up_refuses_a_lost_key_page`). A new window is in the store before any record sealed
    with it is appended (invariant 1).
  - **Fencing and key uniqueness.** A new writer opens a fresh window (random keys) and writes
    the key store with its producer epoch before it appends anything; an older writer's writes are
    then refused (`KeyError::Fenced`, the writer stops as when Iggy fences it). Replay also marks
    every replayed record's slots as used. Found by the end-to-end restart run (174 messages lost):
    the key store lags the log by up to `key_interval`, a restarted writer handed out slots already
    used after the last write, so a new message got the same leaf key (and constant nonce) as an
    old one and acknowledging the old one destroyed the new one
    (`a_restart_never_reuses_key_slots` fails without the fix). Writes are serialised, so an older
    change set never lands after a newer one (a race found while making the store incremental: the
    periodic write and a new window's write could land out of order and drop the window). Window
    ids should carry the writer's epoch before M4 runs two writers at a handover.
  - **Physical deletion within minutes.** Pending entries older than `relocate_after` (15 min)
    are re-sealed forward by compaction (every minute); the low-water offset follows; a window
    is destroyed (metadata key and tree) once all its records are below it; Iggy deletes sealed
    segments below it after `message_expiry` (10 min), with 16 MiB segments. Delivered ciphertext
    leaves the disk about 25 minutes after delivery plus the time to fill a segment (on a quiet
    node, hours: still unopenable from the first second).
  - **Idempotency in its own topic** (`{topic}-idem`): the keyed tag, the recipient-set
    fingerprint (HMAC, server secret), the time and the log offset; no content, no device. Kept
    7 hours (6-hour retry window plus margin) so the mailbox log is not held for the idempotency
    window. A retry after delivery is a replay that returns `seq` 0 for the entries already
    acknowledged (nothing left to route).
- Evidence:
  - Correctness: 15 Iggy live tests (3 consecutive clean runs), 16 end-to-end invariant tests
    on Iggy, key-store unit tests (punctures, out-of-order ACKs, page rewrites, crash between
    pages and head, lost and misplaced pages, destroyed windows, fencing), the `iggy_record` fuzz
    target. End to end through `delivery` (report P02-M2 addendum): steady 1,000–80,000/s
    offered, reconnect storm, Iggy frozen for 8 s, restart: the checker found no loss,
    duplicate or reordering.
  - Cost of sealing (bench `STORE=iggyprod`, random envelopes, same machine, base = main
    `819d07e`): on this disk both versions are fsync-bound and indistinguishable (1,200–17,000
    sends/s for both, run to run); on tmpfs (CPU-bound ceiling) 341,000 against 432,000 sends/s
    at 128 senders (0.79×) and 428,000 against 863,000 at 1,024 senders (0.50×). Writer time at
    1,024 senders: append 67 %, sealing 14 %, applying 10 %, planning 4 %. One GGM expansion
    costs 136 ns; sealing a 256-byte entry 181 ns.
  - Key-store cost (release build, this disk): with 1 M pending entries the store is 36 MB; a
    write after 100 scattered ACKs replaces 100 pages (3.6 MB), holds the state lock 1.8 ms and
    takes 80 ms. The first, whole-file design rewrote 36 MB and held the lock 25 ms on every
    write (every 50 ms): about 720 MB/s of writes, found by measurement before merging.
  - Measurement note: the comparison benchmarks of M2 sent constant-byte envelopes; this disk is
    btrfs with zstd, which compressed them almost away, so plaintext stores looked several
    times faster than with real (incompressible) ciphertext. `bench/stores` and the load
    generator now send random bytes; M2's disk numbers are optimistic (report addendum).
- Consequences:
  - Ahead of the field as far as public documentation goes: Signal deletes a delivered message
    from its database (FoundationDB), WhatsApp and Threema delete on delivery; in each the
    bytes remain in the storage engine and the SSD until compaction and garbage collection.
    Here they are unopenable within about a second and gone from the log within minutes.
  - **The key store is part of the mailbox.** Losing `key_dir` (or the master key) loses every
    pending message: the log alone cannot be read. It must be on the same persistent disk as
    the node (not tmpfs), never in backups (a backup would keep keys that ACKs destroyed), and
    the master key in the secrets store (D-0010). A restored Iggy backup without its matching
    key store does not start (runbook).
    **Owner decision (2026-11-12): accepted** ("i accept the backup decision"): key stores are
    never backed up; a node that loses its disk loses its undelivered messages until M4
    replicates partitions, as the master prompt's beta targets allow (undelivered envelopes may
    be lost on total server loss; clients resend on a new `store_generation`).
  - **Limits.** Overwritten and deleted files can survive in SSD flash until garbage collection,
    so an attacker with the raw flash and the master key might recover an older key page: the
    data volumes must use full-disk encryption with a key that never touches the disk
    (Prompt 13 deploy work, issue to file). Keys in memory are wiped on drop, best effort.
    Record sizes, times and partitions stay visible in Iggy's message headers until the segment
    is deleted.
  - Sealing halves the CPU ceiling of a partition writer (above); the disk, not the CPU, bounds
    a node today. M3 (thread-per-core) should pipeline the writer (seal the next batch while the
    current one appends).
  - Write amplification: pending entries are rewritten every 15 minutes (relocation), and the
    key store writes about 36 bytes per new pending entry plus the pages its ACKs touch.
  - MSRV raised to Rust 1.95 for `File::lock` (D-0030 note).

## D-0030 — The official Apache Iggy SDK, and what it brings into the tree

- Date: 2026-11-12
- Status: accepted (owner: "hope you use official iggy sdk")
- Decided by: owner
- Context: the Iggy mailbox (D-0029) needs a client. The agent proposed its own minimal TCP client
  (as for SurrealDB, D-0025) because the SDK has no optional features: every transport (TCP, QUIC,
  HTTP, WebSocket) is compiled in, with `quinn`, `reqwest`, `tungstenite`, `ring` and 236 crates in
  all (154 new to the workspace). The owner chose the official SDK.
- Decision: `iggy = "=0.12.0"` (pinned with the server image 0.10.0), used over TCP only.
  - **Crypto and TLS stay on aws-lc-rs.** The SDK's TCP/TLS path installs aws-lc-rs as rustls's
    provider itself (`links/dial.rs`); our connection code installs it as the process default
    before the SDK builds any TLS configuration. `ring` is compiled in for QUIC (never enabled)
    and for request identifiers in the protocol layer; it is not used for our TLS or crypto.
    Proposed constitution wording in Open owner decisions.
  - **Logs (invariant 6).** The SDK logs server addresses and names at several levels. The crates
    `iggy`, `iggy_common` and `iggy_binary_protocol` are forced off in every log filter
    (`songbird_telemetry::SILENCED_TARGETS`, applied after the configured filter); the mailbox
    logs every SDK failure itself as a numeric error code. `inv6_no_identifiers_in_logs_or_metrics`
    captures at TRACE through the production filter.
  - **Supply chain.** `cargo vet`: 153 crates newly exempted (`supply-chain/config.toml`), four
    existing exemptions raised from safe-to-run to safe-to-deploy (`borsh`, `borsh-derive`,
    `fastrand`, `proc-macro-crate`), imports now fully audit 156 crates. Audit first: `iggy`,
    `iggy_common`, `iggy_binary_protocol`, `ring`, `bytemuck`. `cargo deny`: per-crate licence
    exceptions for `foldhash` (Zlib) and `webpki-roots`/`webpki-root-certs` (CDLA-Permissive-2.0,
    the Mozilla root list), both permissive; no global allow changed.
- Consequences: a large dependency tree for one TCP protocol; the SDK tracks the server, so
  upgrades move together (the SDK README: mixed versions and rolling upgrades are unsupported).
  Our own client stays an option once Iggy's protocol is stable (1.0).
- Note (2026-11-12): `iggy =0.12.0` needs Rust 1.95; the workspace MSRV (`rust-version`) is
  raised from 1.88 to 1.95 (1.88 was declared but never checked), which D-0031's key store also
  needs (`File::lock`). The pinned toolchain (D-0001) is newer and unchanged.

## D-0029 — Mailbox on Apache Iggy

- Date: 2026-11-12
- Status: accepted (owner: "go with iggy, build it for production")
- Decided by: owner, after the comparison below; design by agent
- Context: SurrealDB capped a node at about 7,000 end-to-end messages/s (D-0027). The owner asked
  to compare Apache Iggy with Redis/Valkey and take "the best and fastest".
- Evidence: same `Mailbox` trait and closed-loop workload for all stores, every write fsynced
  before the store answers, ACK deletes included, client-style idempotent retries, 8 s per run,
  two interleaved rounds, a `seq` check after each run (96 runs, all gap-free and duplicate-free).
  SurrealDB 4.0.1 (SurrealKV `sync=every`), Valkey 9.1.3 (AOF `appendfsync always`; one instance,
  and four sharded by device), Iggy 0.10.0 (topic `durability = persisted`, 4 shards); servers on
  CPUs 4–7. On this machine's disk (btrfs, 0.5–3.6 ms per fsync) and on tmpfs (no fsync cost:
  each store's own ceiling). Sends/s, best of two rounds:

  | Workload | SurrealDB | Valkey ×1 | Valkey ×4 | Iggy | Iggy, tmpfs | Valkey ×4, tmpfs |
  | --- | --- | --- | --- | --- | --- | --- |
  | 1 sender | 273 | 1,403 | 1,346 | 368 | 8,868 | 26,313 |
  | 128 senders | 6,272 | 36,261 | 42,346 | 15,612 | 444,717 | 259,046 |
  | 1,024 senders | 7,088 | 42,378 | 123,670 | 153,128 | 1,410,584 | 337,594 |
  | 10-device sends, 128 senders (entries/s) | 7,271 | 93,156 | 81,500 | 163,044 | 1,909,177 | 348,316 |
  | 100-device groups, 64 senders (entries/s) | 3,458 | 160,031 | 242,598 | 647,467 | 4,766,768 | 548,448 |

  Iggy has the highest ceiling by far and wins whenever batches form; Valkey has the lowest
  latency for a lone send. On this disk both have poor tails from btrfs fsync stalls: Iggy's
  p99.9 sits at 0.4–0.7 s from 16 senders up, Valkey's varies from 0.02 to 0.9 s. The reference
  hardware (Prompt 13) decides the tail. Script and raw output:
  `bench/stores` (`stores-matrix` runs reproduce it).
- Decision (production design, `crates/mailbox/src/iggy`):
  - **Log and partitions.** One topic, `partitions` partitions (default 4); a device belongs to
    one partition by a hash of its ID. One writer task per partition owns that partition's state:
    each device's last and acknowledged `seq`, the index of pending entries (log offsets, not
    ciphertext), idempotency tags (8-byte prefix to offset, about 30 bytes per send, verified
    against the record on a hit) and MLS epochs. Requests queued during an append form the next
    batch (natural group commit). Our own record format inside Iggy messages (`record.rs`,
    bounded decoder, fuzz target `iggy_record`).
  - **Durability.** Topic `durability = persisted`: Iggy fsyncs before it confirms; a send is
    acknowledged only after that (invariant 1).
  - **One writer per partition (fencing).** Each writer is an idempotent Iggy producer with a fixed
    id and a new epoch at every start, recorded in the log. Iggy refuses older epochs
    (`ProducerEpochFenced`): a second process cannot corrupt `seq`s; the fenced node reports not
    ready. A batch whose outcome is unknown is resent with the same producer sequence and written
    once. One delivery node per topic until M4 adds partition ownership across nodes.
  - **Multi-partition sends.** A send's home partition is its MLS group's, else the partition
    holding most of its recipients (so a 1:1 send or a send to one account is usually one
    append; a first version keyed the home by the idempotency key, which made almost every send
    two appends and flooded the re-driver after a restart, found by the end-to-end run). The home
    record holds the home devices' entries and the other partitions' parts; the parts are then
    stored on their partitions under the same tag (a send without a key gets a random internal
    tag).
  - **Idempotency.** Each tag is stored with a fingerprint (SHA-256, 16 bytes) of the send's whole
    recipient set; a reused key is a retry only when both match, otherwise reason 7. Reuse is
    detected wherever the new send shares a partition with the earlier one; a reuse for devices
    on entirely different partitions is stored as a new send (it never suppresses a message). A re-driver completes parts that failed,
    in the process after 2 s and after a restart from recent home records. A send is refused
    with nothing stored, or recorded and eventually stored for every recipient, without relying
    on the client to retry.
  - **MLS ordering.** The epoch check runs on the group's home partition writer; one commit per
    epoch wins (`mls_commits_are_ordered_by_epoch`).
  - **Start-up.** Each partition is replayed from its low-water offset to rebuild the state. A
    record that does not decode stops the start (`IggyMailboxError::Unreadable`): skipping it
    would lose counters and reuse `seq`s. Found by the end-to-end run: a first build skipped
    unreadable records with a warning, the record format then changed without a version bump,
    684,229 records were skipped, counters restarted and the clients dropped every new message
    as already seen (the checker reported them lost). The record version is now 2 and bumped
    on every format change.
  - **Compaction (every minute), off the write path.** Entries older than 30 days are dropped
    from the index (invariant 3); a compactor task reads the pending entries older than
    `relocate_after` (1 h) on its own connection, many records per poll, and the writer copies
    them forward in batches of about 1 MiB (at most 100,000 entries per pass); a counter snapshot (every
    device's last and acknowledged `seq`, MLS epochs, the producer epoch) is written, so no `seq`
    is ever reused although old records go; the low-water offset (an Iggy consumer offset, which
    also stops Iggy deleting segments past it) moves up to the oldest record still needed (pending
    entries, the 6-hour idempotency window, incomplete parts). Iggy deletes sealed segments below
    it after the topic's `message_expiry` (8 h).
  - **Container.** Iggy 0.10 needs io_uring; `deploy/compose/iggy-seccomp.json` is Docker's
    default profile (moby/profiles `seccomp/v0.1.0`, Apache-2.0) plus `io_uring_setup`,
    `io_uring_enter`, `io_uring_register`, nothing else. HTTP, QUIC and WebSocket listeners off;
    TCP with TLS on the private address (server-authenticated TLS and the root password; Iggy
    has no client certificates).
  - SurrealDB keeps its mailbox backend for development and comparison; deployments require Iggy
    (configuration validation).
- Evidence (correctness): `crates/mailbox/tests/iggy_live.rs` (10 tests: seq rules, idempotency
  across partitions, 1,000-device shared body, MLS ordering, 32 concurrent senders gap-free,
  restart rebuilds state and fences the old writer, compaction keeps counters across a restart,
  expiry, bulk ACKs, the re-driver in process and after a restart); the 16 end-to-end invariant
  tests on Iggy; record and state unit tests; fuzzing.
- Consequences:
  - **Deletion is not immediate on disk.** An acknowledged envelope leaves the index at once and
    the disk when its segment is deleted: by default up to about 14 hours (6-hour idempotency
    window plus 8-hour segment expiry). SurrealDB deleted on ACK. Shorter windows trade against
    the retry horizon (D-0021); owner to confirm (Open owner decisions). **Superseded by D-0031:**
    records are sealed under puncturable keys, an acknowledged entry is unopenable within about
    a second and its segment deleted within minutes (relocation after 15 minutes, 10-minute
    segment expiry, idempotency in its own topic).
  - Iggy is pre-1.0 (an Apache top-level project since August 2026); its storage format changed
    between 0.9 and 0.10, so upgrades need a migration plan (runbook).
  - Every pending entry costs about 32 bytes of memory in its writer, every device about 80
    bytes, every idempotency tag about 30 bytes; record payloads are cached up to `cache_mib`.

## D-0028 — Milestone 3 runtime candidates: per-core Tokio and compio

- Date: 2026-11-11
- Status: decided: stay on per-core Tokio (owner, 2026-11-12: "let's stick with tokio"), after the
  M3 measurement (D-0032: compio +2–4 % on an echo benchmark). io_uring against epoll is measured
  again in M7 (master prompt), on the reference hardware
- Decided by: owner suggestion, recorded by agent
- Context: the owner pointed out that sockudo-ws supports compio for true thread-per-core. The
  constitution locks "per-core single-threaded Tokio runtimes"; a different runtime is a
  locked-stack change.
- Decision: M3 builds both behind a feature: per-core current-thread Tokio with `SO_REUSEPORT`
  (the locked stack) and compio (io_uring/completion based; sockudo-ws `compio-runtime` feature,
  its own split streams). Decided by p99 and throughput on the same hardware; the owner approves
  any switch. Things to check first: compio's maintenance and release cadence, how the SurrealDB
  RPC client and Valkey (`redis-rs`, Tokio-only) run beside it (likely a Tokio side runtime per
  core or per node), and that the M2 flamegraph's kernel share (syscalls, softirq) is what
  completion I/O removes.
- Consequences: no runtime change before the benchmark.

## D-0027 — SurrealDB mailbox: one writer, cached counters with compare-and-set, bulk statements

- Date: 2026-11-11
- Status: superseded for deployments by D-0029 (the SurrealDB backend remains for development)
- Decided by: agent
- Context: master prompt §4: per-device `seq` in the same transaction as the write, group commit,
  batched ACK deletes, "measure SurrealDB writes per second early: it sets the ceiling".
- Evidence (AMD Ryzen 9 7950X, Linux 7.3.1, SurrealDB 4.0.1 in podman pinned to 4 cores,
  SurrealKV with `sync=every` on NVMe/btrfs; `crates/mailbox/examples/commit_bench.rs`;
  report P02-M2):
  - SurrealQL costs 0.1–1.5 ms per statement; the in-memory engine is barely faster than the
    durable one, so execution, not fsync, dominates (a bare durable one-row create is 0.9 ms).
  - First design (one transaction with `FOR` loops and closures computing `seq`s server-side):
    7.7 ms per lone send, 3,900 sends/s peak.
  - Final design: 3.3 ms per lone send, 12,000–14,000 one-recipient sends/s peak (256 per
    transaction), about 20,000 mailbox entries/s for group fan-out; a 1,000-device shared send
    takes 51 ms (554 ms before).
  - End to end through `delivery` (store, deliver, ACK delete) the node saturates at about
    7,150 messages/s; the checker passes in steady, reconnect-storm and SurrealDB-pause runs.
- Decision:
  - **Durability**: SurrealKV, `surrealkv:///data/songbird.db?sync=every` (compose, Ansible):
    every commit is fsynced before the mailbox answers (invariant 1). v4.0.1 opens `rocksdb:`
    paths as SurrealKV anyway, logging the sync mode, which is checked at start in the logs.
  - **One writer task per process** owns every write: store batches and ACK deletes are serial,
    so they never conflict with each other. Batches form from whatever queued during the
    previous commit (`max_wait` 0 measured best at every load; up to 256 sends).
  - **Counters**: `seqctr:[device].last` is cached in the writer; the writer computes every
    `seq`, record ID and row; one bulk `INSERT … ON DUPLICATE KEY UPDATE last = IF last =
    $input.prev { $input.last } ELSE { THROW }` advances counters only where they still hold
    the cached value. Another writer (a second node) makes it throw; the writer reloads and
    retries, so a `seq` is never reused or skipped. Acknowledgements live in `ackctr`, written
    only by ACK flushes (an early design that kept both in one record aborted every store and ACK
    transaction against each other: 55 s for a 1-second test).
  - **Statements per batch**: idempotency `INSERT`, counter `INSERT`, optional bodies, mailbox
    rows; a duplicate idempotency key fails the batch with `AlreadyExists`, the writer answers
    the replays and retries the rest; an MLS commit runs alone with its epoch check.
  - **ACK deletes**: merged per device, flushed every 50 ms (or at 4,096 devices) in one
    transaction: explicit entry IDs since the previous ACK, shared-body reference counts of the
    entries that went (bodies deleted at zero), `ackctr`. Queued ACKs are taken on every writer
    wake-up (found under load: a send-biased loop starved and then dropped them).
  - **Capacity** (`max_per_device`) is a soft limit from cached counters; it guards storage, it
    is not an invariant.
- Consequences: one writer per node caps the store at one transaction in flight; M3 tries
  several writers sharded by device (a send to devices of several shards goes to one, the
  counter guard keeps the others correct). Group fan-out is bounded by SurrealDB's per-row cost
  (~40–50 µs). TiKV (the master prompt's later cluster) may change every number here.

## D-0026 — Send path: device lists, shared bodies, MLS commit ordering

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: master prompt §5 `send` (device lists, idempotency, MLS ordering) and Prompt 2's
  "shared bodies for group fan-out".
- Decision:
  - **Wire**: `Send` gains a flags byte after the idempotency key: `0x01` MLS commit (followed
    by `group [16]`, `epoch u64`), `0x02` shared body (`count × device_id`, then one
    `len u32 | body`). Unknown flags are refused. New rejection reason 8 `StaleEpoch`
    (not retryable as is). Protocol v1 changed before any client shipped.
  - **Device lists**: every addressed device must exist (unknown ones are `extra`) and a send
    that addresses an account must address all its devices except the sender's own
    (`missing`); the answer is `SendResult` status 2 `DeviceMismatch` and nothing is stored.
    Accounts come from the static directory (an `account` per device, default: its own) until
    the identity service (Prompt 3) owns devices and key versions (`stale` stays empty until then).
  - **Shared bodies**: one `body:[id]` record per send with a reference count, one compact
    `mailbox:[device, seq]` entry per device linking to it; the server routes the same `Bytes`
    to every connected recipient. Deleted when the last device acknowledges or after 30 days.
  - **MLS ordering**: `mls_group:[group].epoch` compared and advanced in the same transaction
    as the store; exactly one of several concurrent commits from one epoch wins, the others get
    `StaleEpoch` and nothing stored. Who may commit to a group is Prompt 5's (group membership).
- Evidence: `tests/e2e` `send_path_device_lists_shared_bodies_and_mls_ordering`;
  `crates/mailbox/tests/surreal_live.rs` (`shared_body_is_stored_once`: 1,000 devices, one body,
  1,000 entries without ciphertext, body deleted after the last ACK;
  `mls_commits_are_ordered_by_epoch`: 10 concurrent commits, one wins); proto vectors.
- Consequences: senders learn the device list of an account they write to (as with Signal and
  WhatsApp); the server learns group IDs and epochs (16 opaque bytes chosen by clients).

## D-0025 — SurrealDB client: our own minimal RPC client, not the official SDK

- Date: 2026-11-11
- Status: accepted (owner may overrule)
- Decided by: agent
- Context: the mailbox needs SurrealDB from Rust. The official SDK `surrealdb` 4.0.1 with only
  `protocol-ws` and `rustls` pulls 264 crates (geo, argon2, a second WebSocket stack,
  tokio-tungstenite, webpki roots…), more than the whole workspace's tree, each needing a vet
  audit or exemption.
- Options considered: the SDK; HTTP `/sql` with JSON (binary envelopes do not survive JSON); our
  own client over the WebSocket RPC with CBOR.
- Evidence: the protocol was specified from the 4.0.1 sources (`surrealdb-rpc-4.0.1`
  `request.rs`, `response.rs`, `method.rs`; `surrealdb-types-4.0.1/src/cbor/convert.rs` for the
  tags; the SDK's `engine/remote/ws` for cross-checks) before writing code;
  `crates/surreal/tests/live.rs` against the pinned server (bytes, record IDs, per-statement
  errors, 200 pipelined requests); CBOR property tests and RFC 8949 vectors; fuzz target
  `surreal_cbor` (30 s, 1.46 M runs, no crash; nightly 10 min).
- Decision: `crates/surreal` (no new dependency): a bounded CBOR subset codec (definite lengths,
  depth 64, lengths checked against remaining input before allocating, trailing bytes refused)
  and a pipelined RPC client over `sockudo-ws` (subprotocol `cbor`, `/rpc`, `signin` as root,
  `use`, `query`), TLS through rustls with the internal CA. Server error messages can quote
  record IDs: `Display`/`Debug` show only the kind. Root credentials for now; a least-privilege
  database user is Prompt 12's.
- Consequences: we track SurrealDB's RPC protocol ourselves (pinned server version; live tests in
  CI's compose job catch drift).

## D-0024 — Milestone 1 decisions compared with Signal and WhatsApp; changes adopted

- Date: 2026-11-11
- Status: accepted
- Decided by: agent (the owner delegated D-0018, D-0020 and D-0021: "see how others would do
  that, like WhatsApp and Signal; if you have better ideas, do them")
- Context: the M1 gate report asked the owner to rule on three proposals.
- Evidence (primary sources, read 2026-11-11):
  - Signal-Server `main`, `websocket/WebSocketConnection.java`: one reactive stream per device
    from the message store; "new message" events only wake the reader; at most 256 messages sent
    and not acknowledged (`MESSAGE_SENDER_MAX_CONCURRENCY`); a slow client is never actively
    disconnected; a device connecting elsewhere is closed with 4409. The previous design
    (until 2024–2025) used a "new message available" flag plus a re-read of the store, the same as
    our lag flag. No server-side send idempotency: clients drop duplicates (libsignal
    `DuplicateMessageException`; Signal-Desktop dedupes by sender and timestamp). Devices
    authenticate the WebSocket with HTTP Basic and a random per-device token stored as a salted
    HKDF hash (`auth/SaltedTokenHash.java`): a bearer secret, no channel binding.
  - WhatsApp Encryption Overview (2026-10-30), "Transport Security": Noise Pipes with Curve25519;
    the client authenticates with a per-device static key pair and the server stores only the
    public key; Noise binds that authentication to the session by construction. The document
    does not say how retries are deduplicated or how slow clients are handled.
  - RFC 9266 (`tls-exporter` channel binding) is used by XMPP SCRAM-PLUS (XEP-0440); no messenger
    found using it with TLS, because WhatsApp gets the property from Noise.
- Decisions:
  1. **D-0020 accepted, plus a bounded un-acked window.** Keep "store is the truth, notifications
     are hints, a full inbox means re-read the mailbox" (Signal's earlier design). Add Signal's
     in-flight bound: at most `max_unacked` (default 256) envelopes sent and not acknowledged per
     connection; delivery pauses at the limit and resumes with a drain on the next ACK. This
     bounds memory per session regardless of socket progress. The write-stall close (4100) stays
     as the last resort, with the timeout raised from 10 s to 30 s for mobile networks (a stalled
     reader holds nobody else up).
  2. **D-0021 accepted, hardened.** Signal keeps no server-side idempotency, so our record is
     extra; it now holds HMAC-SHA256(server secret, key) instead of the key, lives 6 h (the
     client's retry horizon) instead of 24 h, and is scoped to the recipient devices: the same key
     for other recipients is refused (`SendResult` reason 7, not retryable) and stores nothing.
     Apps still drop duplicates by the message ID inside the envelope (as Signal's clients do),
     which covers retries after 6 h.
  3. **D-0018 accepted, with TLS channel binding.** A separate per-device Ed25519 key matches
     WhatsApp's separate static key and is stronger than Signal's bearer token (the server holds
     only public keys). The signed transcript now ends with the 32-byte RFC 9266 TLS exporter
     (label `EXPORTER-Channel-Binding`, no context), which gives what Noise gives WhatsApp: a
     relay that terminates TLS (misissued certificate, interception proxy) cannot reuse the
     device's signature on its own session to the server. TLS must therefore end at `delivery`
     itself (no TLS-terminating load balancer in front; `SO_REUSEPORT` spreading is in-process).
- Evidence for the changes: `tests/e2e` `unacked_window_bounds_in_flight`,
  `tls_connection_works` (a valid signature without this session's binding is refused with
  4000); `crates/mailbox` `retried_send_is_stored_once` (keyed hash, recipient scope);
  `crates/proto/tests/vectors.rs` (new transcript vector).
- Consequences: protocol v1 changes before any client ships (transcript, reason 7). Revisit
  the Noise alternative only if TLS termination ever has to move off the delivery host.

## D-0023 — Autobahn conformance: two passes, image pinned by digest

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: the M1 gate requires the Autobahn suite to pass against `delivery`'s own WebSocket
  configuration. The Songbird endpoint is binary-only and authenticated, so the suite runs against
  `songbird-delivery-autobahn`, an echo server built from the same upgrade code and
  `ws::ws_config` (same limits, timeouts, buffers, no compression). Production limits refuse
  messages over 1 MiB (invariant 7); the suite sends up to 16 MiB.
- Options considered: run everything and accept failures; raise the production limit; two passes.
- Evidence: `cargo xtask autobahn` (wstest 0.8.2, `crossbario/autobahn-testsuite@sha256:519915fb…`,
  run with podman 5.8.9 on the development machine, report P02-M1): production pass 493 cases,
  274 OK, 3 INFORMATIONAL, 216 UNIMPLEMENTED (groups 12 and 13, permessage-deflate, deliberately not
  offered), 0 FAILED; the 24 cases with 4–16 MiB messages (9.1.4–6, 9.2.4–6, 9.3.\*, 9.4.\*) are
  excluded there and run in the second pass with the limit raised to 16 MiB: 54 of 54 group-9
  cases OK. Run without the exclusion, those 24 are FAILED: the connection is failed on the frame
  header, before buffering.
- Decision: `cargo xtask autobahn` runs both passes, fails on any other outcome, and CI runs it on
  every push (`autobahn` job, reports kept 30 days). Docker or podman, whichever is installed.
- Consequences: a regression in framing, UTF-8 validation, close handling or fragmentation fails
  CI. Revisit if compression is ever offered (it should not be: ciphertext does not compress).

## D-0022 — Load generator v0, delivery checker and the milestone 1 baselines

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: M1 gate: "checker passes; first baseline numbers versus Sockudo".
- Decision: `tools/loadgen` drives the real `songbird-client` (one client task per simulated
  device), sends 1:1 traffic at a fixed total rate to random peers, acknowledges every delivery,
  and runs the checker (`tools/loadgen/src/checker.rs`): nothing lost, nothing delivered twice,
  `seq` strictly increasing and gap-free, per-sender FIFO, nothing unexpected. Each run tags its
  payloads with a random run ID, so messages an earlier run left in a mailbox are reported
  (`stale_from_earlier_runs`) instead of miscounted. The `reconnect` scenario drops one random
  connection every 20 ms and every connection at once halfway through. `echo` measures raw
  WebSocket round trips against any echo server. `tools/loadgen/bench/m1.sh` reproduces every
  gate number with the server pinned to CPU 0 and the load generator to CPUs 8–15.
- Baseline choice: the sockudo-ws library's own `simple_echo` example (3.1.1, built from the
  registry source, `TOKIO_WORKER_THREADS=1`) against `songbird-delivery-autobahn` (our upgrade and
  configuration, current-thread runtime), same client, same machine. The Sockudo *server* speaks
  the Pusher protocol (channels, HTTP publish API); a like-for-like driver is milestone 3 work,
  when `delivery` runs on all cores. **Owner decision (2026-11-11): the library baseline is
  accepted for M1.** The Pusher-protocol driver (`songbird-loadgen pusher`) stays for a later
  comparison against the Sockudo server (5.2.0, `sha256:802c27d7…`) if wanted.
- Evidence: report P02-M1 (AMD Ryzen 9 7950X, Linux 7.3.1, Rust 1.99.1).
- Consequences: every later load, chaos and failover run uses the same checker.

## D-0021 — Milestone 1 stand-ins: in-memory mailbox and in-process router; idempotency keys

- Date: 2026-11-11
- Status: accepted (idempotency record hardened by D-0024)
- Decided by: agent
- Context: M1 builds the session algorithm "on an in-memory mailbox"; SurrealDB is M2 and Valkey
  routing M4.
- Decision: `songbird-mailbox` defines the `Mailbox` trait (`store_batch`, `fetch_after`,
  `ack_up_to`, `expire_older_than`, `store_generation`) and ships `MemoryMailbox`;
  `songbird-router` defines the `Router` trait (`attach`, `detach`, `route`, `route_ephemeral`) and
  ships `LocalRouter`. Both stand-ins use one `std::sync::Mutex` each: a lock between socket read
  and socket write, which the constitution forbids on the hot path. It is accepted only for these
  stand-ins and disappears with SurrealDB group commit (M2) and the per-core directory (M3).
  `store_batch` takes the send's idempotency key and stores it with the resulting `seq`s (24 h at
  first; D-0024: keyed hash, 6 h, scoped to the recipients);
  a retry returns the original result (`replayed`) and is routed again (duplicates are dropped by
  the recipient session). The key is 16 random bytes chosen by the client and is not stored with
  the sender's identity. M2 moves it into the same SurrealDB transaction as the envelopes. The
  server's listener runs `expire_older_than(30 days)` hourly until the worker takes it over (M5).
- Evidence: `crates/mailbox/src/memory.rs` tests (gap-free per-device `seq`, never reused, all or
  nothing, retry stored once, expiry, property test of fetch ordering);
  `tests/e2e` `inv8_store_unavailable_rejects_retryably_and_keeps_sockets`.
- Consequences: M1 numbers measure the WebSocket and session path, not storage; the SurrealDB
  write path (M2) sets the real ceiling.

## D-0020 — Session algorithm and backpressure

- Date: 2026-11-11
- Status: accepted (owner delegated; extended with an un-acked window by D-0024)
- Decided by: agent
- Context: master prompt §5 `delivery`: subscribe before drain, deduplicate by `seq`, gaps trigger
  a drain, safety sweep, "bounded per-connection queue; when full, disconnect with a 41xx code".
- Options considered: (a) disconnect when the inbox is full, as written; (b) drop the notification,
  mark the session lagged, drain from the mailbox, and disconnect only when the socket itself
  stops accepting writes.
- Evidence: `services/delivery/src/ordering.rs` (`Cursor`, property test
  `every_seq_once_in_order`: random stores, dropped, duplicated and late notifications, inbox
  overflow, any page size: the socket sees every `seq` once, in order); `tests/e2e`
  `inv2_per_device_order_without_gaps_or_duplicates` (inbox of 8, four concurrent senders, a dropped
  connection) and `inv5_slow_client_never_slows_anyone_else`.
- Decision: (b). The router never blocks: `try_send` into a bounded inbox (default 256); on full
  it sets a lock-free lag flag and wakes the session, which drains the mailbox after its cursor.
  Ephemeral events use a separate lane (default 32) and are simply dropped. A socket write or
  flush that makes no progress for `write_timeout_ms` (default 10 s) closes the connection with
  4100 and a retry hint. Under (a), a session that is merely busy draining after a reconnect storm
  would be disconnected and reconnect into the same storm; under (b) it catches up, and nothing
  waits on it either way. The session attaches before its first drain; live `seq = cursor + 1` is
  sent inline, `seq ≤ cursor` dropped, anything else drains. Writes are fed and flushed once per
  wake-up (up to 64 live envelopes per batch). The safety sweep runs every 120 s ± 20 % per
  session (1 s while the store is failing).
- Consequences: invariant 5 holds without disconnect storms. Timers are Tokio timers per session
  for now; M3 measures a per-core sweep against them.

## D-0019 — Wire protocol v1: hand-encoded hot frames, prost control frames, close codes

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: master prompt §5 (client wire protocol), `docs/PROTOCOL.md` §1–§3.
- Decision: one WebSocket binary message per frame; type byte then big-endian fixed-width fields;
  hot frames hand-encoded (`Send`, `Ack`, `Ephemeral`, `Deliver`, `SendResult`); control frames
  (`Hello`, `Auth`, `AuthOk`, `Error`, `DeviceMismatch`) are protobuf via `prost` 0.14.5 derive
  on hand-written structs (no `.proto` build step, no `protoc`). Decoders check every length
  against `Limits` before allocating, reject trailing bytes (one encoding per frame) and return
  payloads as zero-copy `Bytes` slices. `Debug` never prints device IDs, keys or payloads
  (`prost(skip_debug)` plus manual impls). Close codes: 4000–4099 never reconnect, 4100–4199
  back off, 4200–4299 reconnect now; retry hint `retry_ms=<n>` in the close reason. Defaults:
  envelope 64 KiB, 1,024 recipients, `Send` 1 MiB, ephemeral 4 KiB, control body 4 KiB.
- Evidence: `crates/proto` unit and property tests (round trips, truncation, trailing bytes, limits
  before allocation, redacted `Debug`, test vectors); fuzz targets `proto_client_frame` and
  `proto_server_frame` (30 s each locally: 3.7 M and 3.0 M runs, no crash; nightly 10 min).
- Consequences: a `Deliver` frame is built by copying the envelope behind a 9-byte header (one copy
  per delivery). M3 removes it (zero allocation per message) by writing the header as its own
  vectored segment.

## D-0018 — Device authentication: Ed25519 challenge signature with aws-lc-rs

- Date: 2026-11-11
- Status: accepted (owner delegated; TLS channel binding added by D-0024)
- Decided by: agent
- Context: master prompt §5 handshake: the device signs a domain-separated string containing the
  nonce and server name.
- Options considered: XEdDSA with the libsignal identity key; a separate Ed25519 device
  authentication key; bearer tokens (forbidden).
- Decision: a per-device Ed25519 authentication key, verified with aws-lc-rs 1.19.0 (already in
  the tree through rustls, so no new cryptography crate). Transcript
  `"songbird.v1/device-auth\0" || len || server_name || nonce[32] || device_id[16] ||
  protocol_version`, server name from the client's own configuration. 32-byte nonce from the OS per
  connection; `Auth` within 5 s (4102 otherwise). An unknown device and a bad signature get the
  same close code (4000) and both run one signature verification (against a dummy key for an
  unknown device), so authentication is not a device-existence oracle. `Auth.last_acked_seq` also
  acknowledges, so a lost `Ack` frame still deletes. Milestone 1 reads public keys from a static
  file (`[delivery.directory] file`), refused by validation in staging and production.
- Evidence: `services/delivery/src/directory.rs` tests; `crates/proto/src/auth.rs` test vector;
  `tests/e2e` `inv9_server_side_authorization` (unknown device, other server name, replayed
  signature, wrong key: all 4000; the client stops instead of reconnecting).
- Consequences: Prompt 3 decides whether the authentication key stays separate from the identity
  key and replaces the static directory with the identity service.

## D-0017 — Dependencies of Prompt 2, milestone 1

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Constitution: no new dependency without a recorded reason; read the pinned version's
  source first.
- Evidence: APIs used were read in the registry sources of these exact versions before writing
  code: sockudo-ws `handshake::{parse_request, generate_accept_key, build_response}`,
  `WebSocketStream::from_raw_with_leftover`, its `Stream`/`Sink` implementations and `close`,
  `client::WebSocketClient::connect_raw`, `Config`/`ConfigBuilder`, `init_clock`, error variants;
  prost 0.14.5 `Message` and the derive's `skip_debug`; aws-lc-rs 1.19.0
  `signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519}`. `cargo deny` clean (advisories,
  licences, bans, sources); `cargo vet --locked`: 120 fully audited, 3 partially, 76 exempted.
- Decision (version, reason):
  - `sockudo-ws` 3.1.1, `default-features = false`, feature `tokio-runtime` only (locked stack).
    Not enabled: `permessage-deflate` (ciphertext does not compress), `http2`/`http3`/`io-uring`
    (later experiments), `mimalloc` (we install it ourselves). Its `simd` feature is a no-op in
    3.1.1 (SIMD paths are always compiled in). We use our own HTTP upgrade on top of its
    `handshake` module so a wrong path or subprotocol gets an HTTP error, and drive one unified
    stream per connection from a single task: no split, so no lock between read and write.
  - `prost` 0.14.5 (control frames; locked stack).
  - `futures-core`, `futures-sink` 0.3.34: the `Stream` and `Sink` traits only, to poll sockudo-ws
    without `futures-util`.
  - `aws-lc-rs` 1.19.0 as a direct dependency (device authentication; already in the tree).
  - Transitive, new to the lock file: `quanta` 0.13.0 and `raw-cpuid` 11.6.0 (sockudo-ws clock),
    `sha1` 0.11 with `digest`, `block-buffer`, `crypto-common`, `hybrid-array`, `typenum`,
    `const-oid` (the handshake's `Sec-WebSocket-Accept`), `tokio-util` 0.7.20, `prost-derive`
    0.14.5 with `itertools` 0.15 and `either`, and wasm-only crates pulled by `quanta`'s
    `web-sys` dependency (`wasm-bindgen*`, `js-sys`, `web-sys`, `futures-util`, `futures-task`,
    `slab`, never built for our targets).
  - cargo-vet: `either` (cuviper), `rustversion` (dtolnay), `slab` and `tokio-util` (Darksonn)
    are covered by trust entries under D-0016's rule (publishers already trusted); 22 crates are
    new exemptions in `supply-chain/config.toml`, 6 of them wasm-only. Highest-value audits to
    do: `sockudo-ws` (parses every client byte; contains `unsafe` SIMD masking), `prost`,
    `quanta`.
- Consequences: Songbird crates stay `#![forbid(unsafe_code)]`; the `unsafe` in sockudo-ws and
  quanta is a supply-chain risk tracked with the exemptions.

## D-0016 — cargo-vet: trust publishers that two or more imported organizations trust

- Date: 2026-11-11
- Status: accepted
- Decided by: agent (with owner approval; the owner accepted the 57 remaining exemptions as
  a recorded risk for the P01 gate)
- Context: P01 gate item "every pinned dependency verified": `cargo vet` had 38 crates fully
  audited and 129 exempted. The six imported audit sets were current; `cargo vet prune` removed
  nothing.
- Options considered: import the three remaining registry sets (actix, ariel-os, fermyon); trust
  publishers; audit crates ourselves; leave the exemptions.
- Evidence: the three extra sets vetted no additional crate, so they are not imported. `cargo vet
  suggest` showed 70 exempted crates published by people that two or more of Mozilla, ISRG,
  Bytecode Alliance, Google and Zcash trust outright.
- Decision: `supply-chain/audits.toml` trusts, for `safe-to-deploy` until 2027-11-11, the crates
  in our graph published by dtolnay, Kenny Kerr (kennykerr), epage, cuviper, seanmonstar, Amanieu,
  BurntSushi, rust-lang-owner, sunfishcode, alexcrichton, Darksonn, Thomasdezeeuw and the
  `taiki-e/pin-project-lite` GitHub team. A trust entry covers only versions that publisher
  released. Publishers trusted by one organization only (ctz, djc, Manishearth) are not trusted.
  No audits were certified: an audit entry claims a person read the code.
  Result: 110 crates vetted, 57 exempted.
- Consequences: trust entries expire on 2027-11-11 and must be renewed (`cargo vet trust`) or
  replaced. A new version from a different publisher fails `cargo vet` until audited or exempted.
  The 57 remaining exemptions include the TLS stack (rustls, rustls-webpki, ring, aws-lc-rs,
  aws-lc-sys, tokio-rustls, rcgen), the x509/asn1 parsers used by `tools/admin`, tracing, time,
  libc, getrandom, mimalloc and prometheus-client. Burning them down needs human audits or new
  imported audit sets; start with the TLS and allocation paths.

## D-0015 — CodeQL gates on its own SARIF; no code scanning upload

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: both CodeQL jobs failed on PR 17. The job token lacked `actions: read`, which
  codeql-action needs on a private repository, and code scanning is not enabled on this private
  repository (the code scanning API answers 403), so an upload could not succeed either.
- Options considered: enable GitHub Code Security (paid; owner action); drop CodeQL; run CodeQL
  with `upload: never` and gate on the SARIF.
- Decision: `codeql.yml` grants `actions: read` and `contents: read` only, runs analysis with
  `upload: never`, fails the job when the SARIF holds any result (each shown as an annotation), and
  keeps the SARIF as a 30-day artifact.
- Amendment (2026-11-11, owner-approved during P02 M1): `rust/hard-coded-cryptographic-value`
  flags the fixed nonce of the published device-auth test vector (`crates/proto/tests/vectors.rs`,
  `PROTOCOL.md` §13). The gate skips that one rule for files under a `tests/` directory only;
  checked against the run's SARIF (the same rule in `src/` still fails the job). Waived results
  are printed as `::notice` annotations so they stay visible. Unit tests that do not need a fixed
  value use random nonces instead.
- Consequences: no Security tab alerts or dismissal workflow; a false positive is fixed in code or
  excluded in the workflow. If code scanning is enabled later, switch back to uploading and grant
  `security-events: write`.

## D-0014 — Hosts: containers on host networking, nftables authoritative, bastion-only SSH

- Date: 2026-11-11
- Status: proposed
- Decided by: agent (awaiting owner approval)
- Context: Prompt 1 security: private network for every internal service, firewall allowing only
  client ports. Docker's default bridge publishes ports through its own NAT rules, which bypass a
  host INPUT policy.
- Options considered: Docker bridge plus `DOCKER-USER` rules; host networking with Docker's iptables
  management off; podman with quadlets; bare systemd units.
- Evidence: `deploy/ansible/roles/firewall/templates/nftables.conf.j2` (default drop, per-role
  public ports, internal ports from the private range only), validated by `nft -c` at deploy time;
  `deploy/tofu/modules/topology/tests/topology.tftest.hcl` proves edge exposes only 443, data
  hosts expose nothing, SSH only from admin ranges, never 0.0.0.0/0.
- Decision: every container uses host networking and binds to the private address (internal
  services) or the public one (client ports); Docker runs with `bridge: none`, `iptables: false`.
  Two firewall layers: the provider firewall (OpenTofu) and nftables (Ansible). SSH: only the
  bastion, only from `admin_cidrs` (held in SOPS); other hosts accept SSH only from the bastion's
  private address. Ansible connects as root with the deploy key (cloud-init disables passwords).
- Consequences: no container-to-container isolation by network namespace; isolation comes from
  users, read-only root filesystems, dropped capabilities and mTLS. Revisit root SSH (owner
  decision above).

## D-0013 — Release pipeline: reproducible, signed, attested; staged rollout with rollback

- Date: 2026-11-11
- Status: accepted (pending first tagged release in CI)
- Decided by: agent
- Context: Prompt 1: reproducible builds, signed artifacts, SBOM per release, staged rollout with
  automatic rollback on failed health checks.
- Options considered: Nix for hermetic builds; a pinned builder container plus path remapping and
  `--locked`; signing with a long-lived key versus Sigstore keyless.
- Evidence: `cargo xtask release --verify` builds every release binary twice in different target
  directories and fails unless all are bit-identical; local run on the development machine is in
  `docs/reports/P01-foundations.md`. `.github/workflows/release.yml` runs the same command inside
  `rust:1.99.1-trixie@sha256:8a4e90c7…` with `cargo-cyclonedx 0.5.10`.
- Decision: release binaries are built in the pinned builder image (`SOURCE_DATE_EPOCH` from the
  commit, `--remap-path-prefix` for the workspace and Cargo home, `-C strip=symbols`, `--locked`,
  toolchain from `rust-toolchain.toml`), verified twice, summed in `SHA256SUMS`, signed with cosign
  keyless (GitHub OIDC), and attested (SLSA provenance; CycloneDX SBOM per binary). Images are
  distroless (`gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222…`), pushed to GHCR, signed and
  attested. `deploy.yml` verifies signatures (`deploy/bin/verify-release`) before a staged
  rollout: one canary host, then 25 %, then the rest; any failed `/readyz` or a non-zero
  `songbird_telemetry_refused_callsites_total` rolls that host back and stops the rollout
  (`deploy/ansible/rollout.yml`).
- Consequences: reproducibility is proven per build, not assumed. Independent rebuilds by a third
  party are possible with the same image digest and commit. Nix remains an option if the
  container approach ever drifts.

## D-0012 — Internal mutual TLS certificate authority

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: mutual TLS CA for service-to-service traffic, rotation scripted from day one.
- Options considered: step-ca (online CA), OpenBao PKI, an offline CA in our own admin tool.
- Evidence: `tools/admin/tests/mtls.rs` completes a real TLS 1.3 mutual handshake with rustls
  (aws-lc-rs) using issued certificates and refuses a certificate from another CA;
  `tools/admin/src/ca.rs` tests check key modes 0600, chain layout, and that public names or
  addresses are refused.
- Decision: `songbird-admin ca` (rcgen 0.14.10 with aws-lc-rs). ECDSA P-256. Root CA 10 years,
  key only in `deploy/secrets/<env>.root-ca.sops.yaml` (owner recipient only). Intermediate 1 year,
  path length 0, name-constrained to `songbird.internal` and private/loopback ranges, in the deploy
  secrets. Leaves 30 days (at most 90), one per component per host, `serverAuth`+`clientAuth`.
  `deploy/ansible/rotate-certs.yml` renews leaves inside a 10-day window (or all with
  `force_rotate=true`) and restarts the affected components; site.yml runs it on every build.
  Valkey uses native TLS with required client certificates (TLS 1.3 only); Garage (single-node
  layout applied idempotently by the data role) has its S3 and admin
  APIs sit behind ghostunnel 1.11.5 mTLS tunnels (Garage replaced by RustFS behind one tunnel,
  D-0035); SurrealDB gets server TLS with password auth (it
  has no client-certificate authentication); Songbird services load their certificates when their
  internal listeners arrive (Prompt 2+).
- Consequences: no online CA to attack or keep available. Revisit if certificate volume grows
  (step-ca or OpenBao). Intermediate renewal is an owner task (runbook `mtls-rotation.md`).

## D-0011 — Censorship-resistant proxy

- Date: 2026-11-11
- Status: accepted (link domain open)
- Decided by: agent
- Context: Prompt 1 WhatsApp-parity item: a separately deployable TLS proxy anyone can run,
  forwarding encrypted bytes only, logging nothing, configured by a proxy link.
- Options considered: nginx `stream` with `ssl_preread` (Signal's design); HAProxy (WhatsApp's);
  a small Rust relay.
- Evidence: `services/proxy/tests/relay.rs` (client → outer TLS to the proxy → inner TLS to an
  upstream echo server, 200 KB round trip; unknown SNI refused; silent clients closed at the
  handshake timeout; plain HTTP probes get no HTTP or upstream data); `services/proxy/src/sni.rs`
  property tests and the `client_hello` fuzz target; `services/proxy/src/link.rs` tests and the
  `proxy_link` fuzz target.
- Decision: `songbird-proxy`, Rust with rustls (aws-lc-rs) and Tokio. Outer TLS with the
  operator's certificate (ALPN `h2`, `http/1.1` so it resembles a web server), then route by the
  inner `ClientHello` SNI to an allowlist of Songbird upstreams, then copy bytes both ways with an
  idle timeout. No logging code at all; Docker logging disabled in the operator compose file. The
  SNI scanner is bounded and allocation-free (scratch sized by `max_client_hello_bytes`). Multi-
  thread Tokio runtime (not on the Songbird hot path; operators run it on small VPSes). Links:
  `songbird://proxy#host[:port]` and `https://<web-domain>/proxy#host[:port]`, host in the
  fragment so the web server never learns it.
- Consequences: a single binary and image, no nginx config for operators to get wrong. A client
  using Encrypted Client Hello would expose only the public name to the proxy; the allowlist must
  then list that name. Proxy operators see client IPs (stated in the operator README and threat
  model).

## D-0010 — Secrets: SOPS with age

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: secrets never in plain files, documented rotation.
- Options considered: SOPS + age; OpenBao.
- Evidence: `deploy/bin/secrets-init` run end to end against a scratch key (report P01): 25 values
  encrypted, CA material decrypts and validates. `crates/types/src/secret.rs` tests: literal
  secrets in config files are rejected at parse time; world-readable secret files are refused;
  oversized ones are rejected before reading.
- Decision: SOPS 3.13.3 with age 1.3.2. Per environment, `deploy/secrets/<env>.sops.yaml`
  (recipients: owner + that environment's CI key) and `<env>.root-ca.sops.yaml` (owner only).
  `.sops.yaml` is generated from `deploy/secrets/recipients/*.txt`. Services never read secrets
  from config files: `SecretRef` is `{ file = … }` or `{ env = … }` only. Local development uses a
  generated, git-ignored `.env` with throwaway values (`cargo xtask dev-env`).
- Consequences: no secret server to run. OpenBao stays an option if dynamic secrets are needed.
  Rotation: `docs/RUNBOOKS/secrets-rotation.md`.

## D-0009 — Infrastructure as code: OpenTofu + Ansible; Hetzner and Scaleway

- Date: 2026-11-11
- Status: proposed (second provider needs owner confirmation)
- Decided by: agent
- Context: Prompt 1: a complete environment at Hetzner and, unchanged apart from provider
  variables, at a second EU provider.
- Options considered: NixOS (needs custom images or nixos-infect on both providers) versus Ansible
  on stock Debian 13; second provider Scaleway, OVHcloud, UpCloud.
- Evidence: `deploy/bin/validate-iac`: `tofu test` plans the beta (one host) and staging (six
  hosts) topologies at both providers against mocked APIs; topology rules tested; `ansible-lint`
  (production profile) and syntax checks pass.
- Decision: OpenTofu 1.13.9 (hcloud provider 1.70.2, scaleway 2.91.0, lock files with hashes for
  linux/darwin amd64/arm64). One provider-independent `topology` module (hosts, roles, private
  addresses from a fixed per-host `index` so adding a host never re-addresses or replaces another,
  public firewall rules) feeds two thin provider modules; environment files
  (`environments/*.tfvars`) are shared and provider files (`providers/*.tfvars`) hold only region
  and machine types. State: S3 backend at the *other* provider, with OpenTofu client-side state
  and plan encryption (passphrase in SOPS). Ansible core 2.21.6 (newest on the CI runner's Python
  3.12), ansible-lint 26.11.0, all Python packages hash-pinned; collections community.docker 5.4.0,
  ansible.posix 2.2.2, community.sops 2.5.1. Scaleway (France) as second provider: mature OpenTofu
  provider with VPC, IPAM and security groups, EU regions only.
  Tool downloads in CI are checksum-verified (`deploy/bin/install-tools`).
- Consequences: one command per provider (`deploy/bin/env-up <env> <cloud>`). The timed rebuild
  at the second provider is the gate drill; it needs the owner's provider accounts.

## D-0008 — Continuous integration: fast and deep tiers, everything pinned

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: CI running the constitution's quality bar, split into fast and deep checks.
- Decision: CI calls `cargo xtask` so local and CI runs are identical.
  Fast (`ci.yml`, every push and PR): rustfmt; clippy pedantic plus selected restriction lints with
  `-D warnings`; nextest; doctests; rustdoc `-D warnings`; cargo-deny; cargo-audit; cargo-vet;
  service smoke test (every service starts, `/readyz`, `/metrics` audited for sensitive names and
  refused callsites, clean exit on SIGTERM); docker compose environment health; distroless image
  build per service; Semgrep (`p/rust`, `p/secrets`, `.semgrep/songbird.yml`); IaC validation.
  CodeQL (`codeql.yml`, Rust and Actions, security-extended).
  Deep (`nightly.yml`): each fuzz target 10 minutes; ASan and TSan (nightly, `-Zbuild-std`); Miri
  on `songbird-types`; criterion benchmarks; the fast tier on a cold cache.
  Pins: actions by commit SHA (checkout v7.0.1 `3d3c42e5…`, upload-artifact v7.0.2 `cf430e03…`,
  download-artifact v8.0.2 `9000827c…`, rust-cache v2.9.3 `d1527c8f…`, install-action v2.90.3
  `cfdb7ed4…`, codeql-action v4.39.3 `33d7b85d…`, setup-buildx v4.4.1 `f87e5991…`, build-push
  v7.4.0 `c3c9e263…`, login v4.8.0 `8aa5831f…`, cosign-installer v4.1.3 `756fe2d2…`,
  attest-build-provenance v4.2.2 `4d101475…`, attest-sbom v4.1.0 `c6043329…`, setup-opentofu
  v2.0.2 `a1320f89…`). Tools: cargo-nextest 0.9.151, cargo-deny 0.20.2, cargo-audit 0.22.2,
  cargo-vet 0.10.2, cargo-fuzz 0.13.2, cargo-cyclonedx 0.5.10, Semgrep 1.185.0 by digest.
- Consequences: shared runners make nightly benchmark numbers trend-only; decisions use the
  reference hardware (Prompt 13).

## D-0007 — Local and CI environment: docker compose, images pinned by digest

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: compose for SurrealDB, `valkey-hot`, `valkey-jobs`, Garage, LiveKit, with
  health checks.
- Evidence: `cargo xtask compose up` on the development machine: all five containers healthy;
  SurrealDB refuses unauthenticated queries (403) and accepts the generated root credentials;
  Valkey refuses commands without the password; `valkey-jobs` reports `appendfsync everysec`;
  Garage reports "fully operational" after the single-node layout step; anonymous S3 is refused
  (403); LiveKit answers `OK`.
- Decision: `deploy/compose/compose.yaml`, every image by digest:
  SurrealDB v4.0.1 `sha256:408eb8e5c9436670525e2bc2634b1e50ba74ce1b447eaf0094c35f73b67f9cb6`;
  Apache Iggy 0.10.0 `sha256:176125a0580f526b0fee8b98ccf4ed5f77e243066183243d87282abce4851bf3`
  (added 2026-11-12, D-0029);
  Valkey 9.1.3-alpine3.24 `sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b`;
  Garage v2.5.0 `sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5`
  (replaced by RustFS 1.0.5 on 2026-11-12, D-0035);
  LiveKit v1.13.11 `sha256:25cd902de7cacbd5f1f779f6a6ac1eae20ba8f56b0935934ce6b0ab80d1e3d20`;
  ghostunnel v1.11.5 `sha256:65c4e34ec0ee0f30ea1f72b7411ec70a91c32fc50f067a8466ad2adb1e7420f2`
  (deployments). Both Valkeys use `noeviction`: silently evicting registry or rate-limit keys
  would break invariants 4 and 5, so a full Valkey must fail loudly instead. `valkey-hot` has no
  persistence; `valkey-jobs` AOF `everysec`. Host ports 47xxx on 127.0.0.1 (overridable with
  `SB_PORT_*`) to avoid clashing with other local stacks. Credentials are random per machine.
- Consequences: Prompt 2's integration tests start from `cargo xtask compose up`.

## D-0006 — Configuration: TOML plus environment overrides, strict and validated

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: configuration loading with validation; invariant 7 (bounded input).
- Options considered: `figment`, `config`, a small loader on `toml` + `serde`.
- Evidence: `crates/types/src/config.rs` tests: file then environment precedence; unknown fields
  and unknown override keys are errors; all violations reported at once with dotted paths;
  bounds on file size (checked before reading), override count, value length, key depth;
  multi-line override values rejected; error messages do not echo values. `config_toml` fuzz
  target.
- Decision: own loader (one dependency, `toml` 1.2.1, instead of a framework). Overrides are
  `SONGBIRD__SECTION__KEY=value`; values parse as TOML, else string. Staging and production refuse
  a non-private admin address and non-JSON logs.
- Consequences: no hot reload yet; `arc-swap` reload arrives with the first hot setting.

## D-0005 — Telemetry: non-blocking tracing, callsite redaction, prometheus-client

- Date: 2026-11-11
- Status: accepted for Prompt 1; per-core hot-path counters to be benchmarked in Prompt 2
- Decided by: agent
- Context: Prompt 1: tracing with a non-blocking writer, Prometheus metrics, a redaction layer that
  refuses known sensitive field names (invariant 6).
- Options considered: metrics facade + `metrics-exporter-prometheus` versus `prometheus-client`;
  redaction by rewriting values versus refusing callsites.
- Evidence: `crates/telemetry/tests/redaction.rs` (sensitive events and spans never reach the
  writer; panic mode fails loudly); `metrics.rs` tests (sensitive metric names rejected; exposition
  audit); `admin.rs` test (endpoints, 405, 404, oversized headers rejected). The smoke test checks
  every running service exposes `songbird_telemetry_refused_callsites_total 0`.
- Decision: `tracing-appender` non-blocking writer in **lossy** mode (a full buffer drops lines and
  counts them; logging never blocks a task). The redaction layer decides once per callsite from
  static field names (no per-event cost) and disables the callsite globally. `prometheus-client`
  0.26 (official OpenMetrics client, no exporter framework); admin endpoint on hyper 1.12 HTTP/1
  with header timeout, 8 KiB buffer, 32 headers, 64 connections. Semgrep rules
  (`.semgrep/songbird.yml`) catch sensitive log fields and unredacted IDs at review time.
- Consequences: field names matter; values formatted into the message text are not inspected,
  which is why IDs and secrets redact themselves in `Debug`.

## D-0004 — Dependencies of Prompt 1

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Constitution: no new dependency without a recorded reason; read the exact pinned
  version's source before use.
- Evidence: APIs used were read in the registry sources of these exact versions before writing
  code (getrandom `fill`, tracing-appender `NonBlockingBuilder`/`ErrorCounter`, prometheus-client
  `Collector`/`DescriptorEncoder`, toml `Table::try_into`, hyper `http1::Builder`, rustls
  `ServerConfig::builder_with_provider`, pki-types `PemObject`, rcgen `Issuer`/`CertifiedIssuer`,
  x509-parser `parse_x509_pem`). `cargo deny` (advisories, licences, bans incl. no OpenSSL,
  sources) and `cargo audit` clean; `cargo vet`: 38 crates fully audited through imported audit
  sets (Mozilla, Google, Bytecode Alliance, ISRG, Zcash, Embark), 129 exempted and listed in
  `supply-chain/config.toml` (burn-down is an open risk, report P01). Reduced to 57 by D-0016.
- Decision (version, reason): tokio 1.54.1 (runtime, locked stack); rustls 0.23.46 + aws-lc-rs
  1.19.0 / aws-lc-sys 0.47.0, tokio-rustls 0.26.6, rustls-pki-types 1.16.0 (TLS, locked stack);
  mimalloc 0.1.52 (allocator, locked stack); tracing 0.1.44, tracing-subscriber 0.3.23,
  tracing-appender 0.2.5 (logging); prometheus-client 0.26.0 (metrics); hyper 1.12.0, hyper-util
  0.1.21, http-body-util 0.1.5, bytes 1.12.1 (admin endpoint); serde 1.0.229, toml 1.2.1
  (configuration); thiserror 2.0.21 (error types); getrandom 0.4.3 (ID randomness straight from
  the OS); hex 0.4.3 (ID text form off the hot path); zeroize 1.9.1 (secrets wiped on drop);
  rcgen 0.14.10, x509-parser 0.18.1, time 0.3.55 (CA tool); clap 4.6.7, anyhow 1.0.104 (CLI only);
  proptest 1.12.0, tempfile 3.27.0 (tests); libfuzzer-sys 0.4 (fuzz crate, outside the workspace).
- Consequences: the server stack takes no OpenSSL (enforced by `deny.toml`).

## D-0003 — Identifiers: 16 random bytes, typed, redacted

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: IDs as 16-byte random values; invariant 6.
- Options considered: UUIDv4/v7 crates; ULIDs; plain random bytes.
- Evidence: `crates/types/src/id.rs` tests (round trips, wrong lengths rejected without
  allocation, `Debug` prints only the kind); `id_parse` fuzz target.
- Decision: `Id<K>` over `[u8; 16]` from `getrandom::fill`; kinds via `define_id!`; no timestamp
  or host data inside (v7-style IDs would leak creation time); `Debug` redacted, no `Display`;
  hex only through `to_hex_unredacted()`, which Semgrep forbids in log and format macros.
- Consequences: IDs are not time-sortable; ordering uses `seq`, never IDs.

## D-0002 — `crates/service`: one bootstrap for every service

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: five services need identical startup, health, metrics and shutdown; Prompt 1 lists
  only `types` and `telemetry`.
- Decision: `crates/service` provides `Service` and `main::<S>()`: CLI (`--config`,
  `--check-config`, `--version`), config load and validation, tracing, metrics, admin endpoint,
  SIGTERM/SIGINT drain with a configured grace period. It runs one current-thread Tokio runtime
  until `crates/runtime` (thread-per-core, Prompt 2) replaces it for the hot path.
- Consequences: Prompt 2 swaps the runtime under `run_service` without touching services.

## D-0001 — Workspace, toolchain and lints

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Decision: Cargo workspace (resolver 3, edition 2024, `rust-version = 1.88`); toolchain pinned
  to 1.99.1 in `rust-toolchain.toml` (reproducible builds; bump deliberately and record);
  layout `crates/`, `services/` (delivery, api, push, worker, calls, proxy), `tools/` (loadgen,
  admin), `xtask/`, `deploy/`, `docs/`, `tests/`, `fuzz/` (outside the workspace, nightly).
  Workspace lints: `unsafe_code = "forbid"`; clippy pedantic plus restriction lints
  (`unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `as_conversions`, `print_*`,
  `dbg_macro`, `todo`, `unimplemented`, `allow_attributes_without_reason`, …); CI denies warnings.
  Release profile: fat LTO, one codegen unit, `panic = "abort"`, stripped; `profiling` profile for
  flamegraphs. The proxy lives in `services/proxy` because it is a deployable binary, though third
  parties run it.
- Consequences: tests may unwrap and index (`clippy.toml`); production code may not.
