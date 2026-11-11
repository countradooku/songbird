# Threat model

Skeleton. Completed in Prompt 12; every prompt adds the threats for what it builds.

## 1. What the server may see

The exhaustive list of data the server may hold in plaintext. Anything not listed must not reach the
server in plaintext. Adding to this list requires the owner's approval.

| Data | Why the server needs it | Retention | Introduced by |
| --- | --- | --- | --- |
| Device ID | Authenticate the connection, address mailboxes | Life of the device | Prompt 2 (M1) |
| Device authentication public key (Ed25519) | Verify the connection challenge | Life of the device | Prompt 2 (M1) |
| Connection times and source IP | Accepting the TCP connection; rate limits | Memory only, for the connection's life; never logged or exported | Prompt 2 (M1) |
| Recipient device ID, `seq`, envelope size and store time per stored envelope | Store, order and deliver | Index: until acknowledged, at most 30 days. Iggy log on disk: until the segment holding it is deleted, by default up to about 14 hours after acknowledgement (D-0029) | Prompt 2 (M1, M2) |
| Envelope ciphertext | Store and relay (opaque, never decrypted) | As the row above | Prompt 2 (M1, M2) |
| Keyed hash (HMAC-SHA256, server secret) of a send's idempotency key, with a fingerprint (SHA-256) of its recipient set, the recipient devices and `seq`s; **not** the sender, never the key itself | Store a retried send once | 6 hours in the index; on disk with the send's record (D-0029) | Prompt 2 (M1), D-0021, D-0024 (owner delegated) |
| Sender device at send time | Authorization and rate limits | Memory only, for the request; never stored with the envelope | Prompt 2 (M1) |
| Device-to-account mapping (the device list of each account) | Device-list check on every send | Life of the device | Prompt 2 (M2); owned by Prompt 3 |
| Per-device counters: last `seq` allocated, last `seq` acknowledged | Ordering, delete on ACK, mailbox capacity | Life of the device | Prompt 2 (M2) |
| Shared group/channel bodies (ciphertext) | Store a group message once per partition | As envelope ciphertext | Prompt 2 (M2) |
| Snapshots of every device's last and acknowledged `seq` and every MLS group's epoch, in the Iggy log | Never reuse a `seq` after old records are deleted | Rewritten by every compaction; old copies deleted with their segments | Prompt 2 (M2), D-0029 |
| MLS group ID (16 opaque client-chosen bytes) and its current epoch | Order commits (one winner per epoch) | Life of the group | Prompt 2 (M2); group membership is Prompt 5 |

Prompt 1 adds two operational views, neither of which is user data on the server:

- **Aggregate metrics** on the private admin endpoint: counts and build information only. Metric
  and label names are checked against the redaction rules (D-0005); no per-device or
  per-connection labels.
- **Proxy operators** (third parties running `songbird-proxy`) see the IP addresses of people who
  connect to their proxy and when, but no content and no Songbird identifiers. This is outside
  Songbird's servers and is stated plainly in `deploy/proxy/README.md`.

## 2. Attackers

- Network attacker
- Malicious client
- Malicious group member
- Compromised server or operator
- Legally compelled provider
- Insider
- Supply-chain attacker

## 3. Components (STRIDE)

One subsection per component. Each threat names its mitigation and the test or proof that covers it.

### 3.1 Build, CI and supply chain (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Malicious or compromised crate | T, E | Supply chain | `Cargo.lock` + `--locked`; cargo-deny (advisories, licences, crates.io only, no OpenSSL), cargo-audit, cargo-vet (imported audits; exemptions listed) | `cargo xtask ci fast`; D-0004 |
| Retagged action or image | T | Supply chain | Actions pinned by commit SHA; images by digest; tool downloads checksum-verified | `.github/workflows/*`, `deploy/bin/install-tools`; D-0007, D-0008 |
| Tampered release artifact | T, S | Supply chain, insider | Reproducible build checked twice; cosign keyless signature on `SHA256SUMS`; SLSA provenance and SBOM attestations; signed images; deploy verifies before rollout | `cargo xtask release --verify`; `deploy/bin/verify-release`; D-0013 |
| Workflow token abuse | E | Malicious PR | Default `contents: read`; write scopes only on release/deploy jobs; `persist-credentials: false`; deploy needs environment approval | workflow files; CodeQL `actions` analysis |
| Secret committed to the repo | I | Insider (accident) | SOPS-only secrets; config files reject literal secrets; `.gitignore`; Semgrep `p/secrets` | `crates/types/src/secret.rs` tests; CI semgrep job |

### 3.2 Secrets and infrastructure (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Stolen OpenTofu state reveals infrastructure secrets | I | Provider, network | Client-side state and plan encryption; state stored at the other provider | `envs/*/main.tf` `encryption` block (enforced) |
| Exposed internal service | I, T, E | Network | Two firewall layers (provider + nftables default drop); internal ports only from the private range; host networking keeps nftables authoritative | `modules/topology/tests/topology.tftest.hcl`; `nft -c` validation at deploy |
| SSH brute force or key theft | S, E | Network | SSH only on the bastion, only from admin ranges (never 0.0.0.0/0, enforced by validation); keys only, no passwords | topology tests; cloud-init `sshd_config` |
| Lateral movement between services | S, E | Compromised host or component | Mutual TLS with per-component leaves from a name-constrained intermediate; Valkey requires client certificates; Garage behind mTLS tunnels; containers non-root, read-only, no capabilities | `tools/admin/tests/mtls.rs`; D-0012 |
| CA key theft | S | Insider, compromised CI | Root key owner-only and offline; intermediate in deploy secrets, decrypted only into a temporary directory during rotation; leaves ≤ 30 days | `deploy/ansible/rotate-certs.yml`; runbook `mtls-rotation.md` |

### 3.3 Service runtime common to every service (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Personal data in logs (invariant 6) | I | Insider, compromised log store | Redaction layer refuses sensitive field names per callsite; IDs and secrets redact themselves in `Debug`; Semgrep rules; smoke test and rollout fail if any callsite was refused | `crates/telemetry/tests/redaction.rs`; `id.rs`, `secret.rs` tests; `cargo xtask smoke` |
| Logging stalls request handling | D | Load | Non-blocking, lossy writer; drops counted | `songbird_telemetry_log_lines_dropped_total` |
| Admin endpoint abuse | I, D | Network (private) | Private address enforced in staging/production; header timeout, 8 KiB buffer, 32 headers, 64 connections, GET/HEAD only | `admin.rs` tests; `config.rs` tests |
| Malformed configuration or overrides | T, D | Operator error, compromised env | Size bounds before reading; unknown fields rejected; validation of every field; single-line overrides | `config.rs` tests; `config_toml` fuzz target |

### 3.4 Censorship-resistant proxy (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Proxy reads or alters traffic | I, T | Malicious proxy operator | Inner TLS is end to end between app and Songbird server; the proxy only sees ciphertext and the inner SNI | `services/proxy/tests/relay.rs` (nested TLS) |
| Proxy used as an open relay | E | Abuser | Inner-SNI allowlist of Songbird upstreams; anything else closed silently | `refuses_unknown_sni` test |
| Malformed ClientHello crashes or exhausts the proxy | D | Network | Bounded, allocation-free parser; scratch sized by configuration; handshake timeout; connection cap; idle timeout | `sni.rs` property tests; `client_hello` fuzz target; relay tests |
| Proxy identified by probing | I | Censor | Looks like an HTTPS server on the operator's domain (real certificate, ALPN h2/http1.1); non-TLS probes get nothing | `non_tls_probes_get_nothing` test. Residual risk: traffic analysis |
| Users' IPs logged by operator | I | Proxy operator | No logging code; operator compose disables Docker logs; documented honestly | `deploy/proxy/README.md` |
| Malicious proxy link | S, T | Phisher | Strict, bounded link parser; host in the URL fragment; app shows the proxy host before use (Prompt 9 UI requirement) | `link.rs` tests; `proxy_link` fuzz target |

### 3.5 Delivery service (Prompt 2, milestone 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Impersonating a device | S | Network, malicious client | Ed25519 signature over a transcript binding a fresh 32-byte nonce, the server name, the device ID, the protocol version and the TLS session (RFC 9266 exporter); TLS 1.3 | `inv9_server_side_authorization` (unknown device, other server name, replayed signature, wrong key); `tls_connection_works` (signature without this session's binding refused); `vectors.rs` |
| Relaying a device's login through a TLS-terminating man in the middle | S | Network with a misissued certificate, interception proxy | Channel binding: the device signs its own TLS session's exporter, which differs from the attacker's session to the server (D-0024) | `tls_connection_works` |
| Probing which device IDs exist | I | Malicious client | Unknown device and bad signature: same close code, same work (dummy-key verification) | `directory.rs` tests; `inv9_server_side_authorization` |
| Reading or deleting another device's mailbox | I, T, E | Malicious client | Every mailbox operation uses the authenticated device only; ACKs beyond what was sent close the connection | `inv3_delete_on_ack_and_expiry`; session code review |
| Sending to devices that do not exist, or one device twice | T | Malicious client | Recipients checked against the directory; duplicates refused; nothing stored on rejection | `inv9_server_side_authorization` |
| Memory exhaustion by large or malformed input | D | Malicious client | Limits checked before allocation; WebSocket layer refuses oversize frames from the header; upgrade request ≤ 8 KiB; fuzzed decoders | `inv7_bounded_and_validated_input`; `frame.rs` property tests; `proto_*` fuzz targets; Autobahn |
| Connection or reconnect floods | D | Botnet, reconnect storm | Accept-rate token bucket and connection cap (close 4101 with retry hint); handshake and auth timeouts; jittered client backoff | `accept_rate_limit_closes_with_retry_hint`; reconnect storm in the load generator |
| Frame or send floods from one connection | D | Malicious client | Per-connection token buckets: frames (close 4103), sends (rejected), ephemeral (dropped) | `bucket.rs` tests; session code |
| A slow or stalled reader holding others back, or server memory | D | Malicious or broken client | Bounded inboxes, non-blocking routing with lag flag and mailbox drain; at most 256 envelopes in flight per connection; write-progress timeout closes 4100 | `inv5_slow_client_never_slows_anyone_else`; `unacked_window_bounds_in_flight`; D-0020, D-0024 |
| Suppressing another send by reusing its idempotency key | T | Party that learned a key | Keys are 128 random bits seen only by sender and server (TLS); records are scoped to the recipient set by a fingerprint (reuse for others is refused, reason 7, where the sends share a partition; elsewhere it is stored as a new send, never suppressed) and kept 6 h under a keyed hash | `retried_send_is_stored_once` |
| Losing, duplicating or reordering messages | T | Faults, races | Store before acknowledge; per-device `seq`; attach before drain; cursor rule; idempotency keys; client dedupe by `seq` | `ordering.rs` property test; `inv1`, `inv2`, `inv8`; load-generator checker (steady and reconnect storm) |
| Identifiers or content in logs and metrics | I | Insider, log store | No per-device log fields; IDs and frames redact themselves in `Debug`; aggregate counters only | `inv6_no_identifiers_in_logs_or_metrics`; `frame.rs` `debug_output_hides_identifiers` |
| Bugs in the WebSocket library | T, D | Supply chain, malicious client | Pinned version; Autobahn in CI; our own upgrade and limits; vet exemption recorded for audit | `cargo xtask autobahn`; D-0017, D-0023 |
| Losing an acknowledged send (crash, power loss) | T | Faults | Iggy topic `durability = persisted` (fsync before it confirms); `SendResult` only after that; a send's remote parts recorded in its home record and completed by the re-driver | D-0029; `inv1_store_before_acknowledge` on Iggy; `redriver_completes_remote_parts_in_process_and_after_restart` |
| Reused or skipped `seq` with several writers | T | Faults, races, a second node | One writer per partition; Iggy fences older producer epochs; uncertain appends resent with the same producer sequence; counter snapshots before old records are deleted | `restart_rebuilds_state_and_fences_the_old_writer`; `compaction_relocates_and_keeps_counters_across_restart`; `concurrent_senders_get_gap_free_unique_seqs`; D-0029 |
| Racing MLS commits forking a group | T | Malicious or racing members | Epoch check on the group's home partition writer, recorded with the commit; one winner | `mls_commits_are_ordered_by_epoch` (Iggy and SurrealDB); `send_path_device_lists_shared_bodies_and_mls_ordering` |
| Malformed mailbox records read back from Iggy | T, D | Compromised data host, bugs | Bounded record decoder (counts checked against remaining bytes), fuzzed; unreadable records skipped and logged | `record.rs` tests; `iggy_record` fuzz target |
| Third-party client logs leaking addresses | I | Log store | Iggy SDK log targets forced off in every filter | `inv6_no_identifiers_in_logs_or_metrics` (TRACE through the production filter); D-0030 |
| A container escape through io_uring | E | Attacker who compromised Iggy | Iggy's seccomp profile adds only the three io_uring syscalls to Docker's default; `no-new-privileges`, all capabilities dropped; private address only | `deploy/compose/iggy-seccomp.json`; D-0029 |
| Malformed SurrealDB responses | T, D | Compromised database, network | Bounded CBOR decoder (depth, lengths before allocation), fuzzed; TLS with the internal CA outside development | `cbor.rs` tests; `surreal_cbor` fuzz target |
| A compromised database reads metadata | I | Insider, attacker on the data host | Holds only ciphertext and the metadata listed in §1; idempotency keys only as keyed hashes; no sender stored with envelopes | §1; D-0024 |

## 4. Server-enforced settings

## 5. Compliance notes (GDPR, age of digital consent per EU country)

## 6. Open risks

- No certificate revocation for internal leaves yet; mitigated by 30-day lifetimes and intermediate
  rotation (runbook `mtls-rotation.md`).
- SurrealDB and Iggy have server TLS and password authentication but no client-certificate
  authentication.
- Acknowledged ciphertext stays in Iggy segments for up to about 14 hours by default (D-0029; owner
  to confirm).
- Iggy is pre-1.0; the Iggy SDK added 153 exempted crates to the audit backlog (D-0030).
- cargo-vet: 57 of 167 crates are exempted rather than vetted; accepted by the owner (report P01, D-0016).
- Root SSH through the bastion (owner decision open, D-0014).
- The proxy is identifiable by traffic analysis; it is a reachability tool, not an anonymity tool.
- Delivery reads device keys and accounts from a static file (refused outside development and CI)
  until the identity service (Prompt 3) replaces it, so it is not deployable yet. Mailboxes are in
  Apache Iggy since M2 (D-0029).
- The delivery service connects to Iggy as the root user; a least-privilege user is Prompt 12's.
- One delivery node per Iggy topic until M4 (a second one is fenced and goes unready).
- sockudo-ws (parses every client byte, contains `unsafe` SIMD code) and quanta are exempted in
  cargo-vet, not audited (D-0017).
