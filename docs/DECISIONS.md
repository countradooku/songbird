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

## Decisions

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
  checked against the run's SARIF (the same rule in `src/` still fails the job). Unit tests that do
  not need a fixed value use random nonces instead.
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
  APIs sit behind ghostunnel 1.11.5 mTLS tunnels; SurrealDB gets server TLS with password auth (it
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
  Valkey 9.1.3-alpine3.24 `sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b`;
  Garage v2.5.0 `sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5`;
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
