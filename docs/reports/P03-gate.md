# P03 — Identity: the final gate (M7)

- Date: 2026-11-15
- Prompt: [03-identity.md](../prompts/03-identity.md), amended by D-0038.
- Status: **built; the gate, the M4b/M5/M6/M7 milestones and their threat-model rows await the
  owner's approval.** M4b–M7 were built in one pass at the owner's request ("lets do the rest of
  milestones in one", 2026-11-15) on branch `feat/p03-rest` (one PR).
- Reports:
  - approved: `P03-plan.md`, `P03-M1.md`, `P03-M2.md`, `P03-M3.md`, `P03-M3b.md`, `P03-M4.md`;
  - awaiting approval: `P03-M4b.md`, `P03-M5.md`, `P03-M6.md`, and this report for M7.
- Decisions: D-0047–D-0056.

## The gate, item by item

| Gate item | Met by | Evidence |
| --- | --- | --- |
| **Concurrency tests prove no one-time prekey is ever served twice under parallel claims** | M3, M3b | `no_one_time_prekey_is_ever_served_twice_under_parallel_claims`: 400 claims over 8 connections, 3 rounds; a non-atomic claim fails it at once. `no_key_package_is_ever_served_twice_under_parallel_claims`: 400 claims, 2 rounds. Further concurrency gates: invite uses, username claims, the device limit (40 racing requests for 6), PIN attempts (40 parallel guesses, 4 checked), transparency appends (160 over 8 connections) |
| **Fuzzed decoders for every key and certificate format** | every milestone | Fuzz targets, each run 60 s with nothing found and all in the nightly matrix: `registration_request`, `pow_challenge` (registration, invites, proof of work); `ed25519_key` (Ed25519 keys); `username` (username proofs and parser); `prekeys` (key uploads and bundles; XEdDSA, X25519, ML-KEM-1024); `keypackages` (MLS KeyPackages); `devices` (signed device lists, link requests, provisioning messages and envelopes, WebAuthn); `profile` (profile uploads, **sender certificates**); `kt` (transparency leaves, tree heads, proofs) |
| **Published test vectors** | every milestone | PROTOCOL.md §13: device-auth and registration transcripts; proof-of-work challenge; username hash and proof (**cross-checked with libsignal**); XEdDSA (**libsignal both ways**); MLS KeyPackages (**OpenMLS**); WebAuthn (**the W3C Level 3 vectors**); sender certificate (**OpenSSL**); transparency roots (**the CT reference roots**, independently recomputed) |
| **A written threat model for account takeover, enumeration and key substitution, each with its mitigation and test** | every milestone | THREAT_MODEL.md §3.8–§3.16, gathered below |
| D-0038 invite tests: valid, expired, reused and guessed codes; quota limits; mode switched off | M1 | `invites_valid_expired_used_up_unknown_and_revoked`, `racing_registrations_never_exceed_a_codes_uses`, `user_invites_spend_the_allowance_and_record_no_issuer`, the M1 registration live tests (mode off, guessed codes throttled) |

## Account takeover, enumeration, key substitution

| Threat | Mitigation | Test |
| --- | --- | --- |
| **Takeover** by squatting an ID | Server-drawn account and device IDs | `registration_creates_the_account_its_device_and_bumps_the_directory` |
| **Takeover** with a key that verifies anything (small order, torsion) | Every stored Ed25519 key canonical and of prime order (aws-lc-rs alone accepts the forgery) | `ed25519_public_key_ok` tests; fuzz `ed25519_key` |
| **Takeover** by linking a device | A single-use token only the primary gets; both new keys proven; a confirmation the server cannot forge; pending until a list signed by the account key names it; a PIN or passkey once set; the primary notified | `link_tokens_are_single_use…`, `the_confirmation_tag_verifies…`, `a_pin_gates_linking…`, `a_passkey_registers_and_approves_a_link…`, `a_linked_device_is_announced…` |
| **Takeover** by a linked or phished device acting account-wide | Only the primary deletes the account, exports, or changes factors; pending devices change nothing account-wide | `a_pending_device_changes_nothing_account_wide_and_only_the_primary_deletes`; the factor tests (403 `primary`) |
| **Takeover** by guessing the PIN | Attempts spent before the check; doubling locks; unusable after 20; Argon2id with a pepper | `racing_pin_guesses_never_exceed_the_free_attempts`; `a_pin_gates_linking…` |
| **Enumeration** by username lookup or timing | Exact match; one answer and one cost for absent, held, keyed and limited | M2's enumeration tests (timing bound, identical answers) |
| **Enumeration** through invite answers | One answer for unknown, expired, used and revoked codes | `invite_codes_valid_expired…` |
| **Enumeration** of devices | Unknown device and bad signature answer the same, with dummy-key work | `inv9_server_side_authorization`; `directory.rs` |
| **Key substitution** at registration or claim | Both keys sign one transcript; username proofs | M1 and M2 transcript and proof tests |
| **Key substitution** in the key directory | Every prekey and KeyPackage checked against the device's identity key or binding; the identity key fixed at first upload or at link | `honest_uploads_pass…`, `tampering_is_refused_with_its_reason`, `pending_devices_get_no_key_fetches` |
| **Key substitution** through the device list | Lists signed by the account identity key; versions only grow; entries must match stored keys | `a_device_links_through_the_qr_flow…` (another key, rollback, a removed device) |
| **Key substitution** by the server itself | Key transparency: every identity key and list logged; clients check inclusion and consistency; a fork is evidence | `clients_verify_the_transparency_log`; `a_forked_or_rewritten_log_is_detected` |
| Impersonating a sender in a sealed message | Short-lived certificates signed by the certificate key, bound to account, device and identity key | `certificate_vector`; `profiles_certificates_and_sealed_sends` |

## The prompt's build list

- **Accounts and usernames**: M1 and M2. libsignal's scheme was adopted and implemented, not
  linked (D-0047). Handles are unique (D-0049).
- **Registration abuse controls**: M1 (Argon2id proof of work, per-range throttles). Privacy Pass
  was evaluated in writing as a later option.
- **Account credentials**: per-device keys. Recovery belongs to Prompt 10's recovery key; the PIN
  and passkeys are ready to gate it.
- **Devices**: M4 (QR provisioning, the signed list, limits, removal, with the deletion job as the
  hook for Prompt 5's MLS removal).
- **Key directory**: M3 (PQXDH with ML-KEM-1024) and M3b (KeyPackages).
- **Encrypted profiles, profile links, sealed sender**: M5 (sealed sender behind its flag for
  Prompt 12).
- **Key transparency, security notifications**: M6. An own RFC 9162 log; `akd` is the recorded
  upgrade path (the owner is asked).
- **GDPR**: M7 (export; deletion of every store and backup within retention; inactivity at the
  owner's period).
- **WhatsApp parity**:
  - username key (M2), two-step PIN and passkeys (M4b), multiple accounts (M4b);
  - profile links (M5), security notifications (M6), invite-only launch (M1).
- **Security**: prekey exhaustion limits (M3), constant-time comparisons for secrets (access
  keys, PINs, tags), no enumeration (M1, M2).

## Runs

Run on the owner's Mac (Apple M5 Pro, macOS 27.2.1; compose stack under podman), 2026-11-15:

- `cargo xtask ci fast`: **all checks passed** (workflow policy, rustfmt, clippy `-D warnings`,
  nextest **498 passed**, doctests, rustdoc, deny, audit, vet, smoke of every service).
- The CI compose job's commands, without Iggy:
  - the first **208/208** (1 skipped; the flaky `send_api` rate test passed this time);
  - `songbird-api` **48/48**, `songbird-jobs` 12/12, `songbird-push` 7/7.
- After the review fixes below: `profile_live`, `kt_live`, `gate_p03` and `send_api` pass, and
  `ci fast` passes again (499 tests).
- Fuzz, 60 s each: `devices` (with WebAuthn) 3,075,994 runs; `profile` 27,911,844; `kt`
  10,997,069. Nothing found.
- The concurrency gates added in this pass: PIN guesses (40 parallel, 4 checked), transparency
  appends (160 over 8 connections, 3 of 3 runs).

## Security review

`security-review` over M4b–M7 (`git diff af41046..HEAD`; an independent reviewer, read-only):
**one finding at the bar, fixed.**

**The finding.** The replaced-avatar sweep selected avatars older than an hour, with a LIMIT,
and only then filtered out the current ones in Rust. Once 500 current avatars were that old,
every pass returned the same 500 rows and deleted nothing. Replaced encrypted avatars would have
stayed in `RustFS` beyond the hour the threat model promises. Fixed:

- replacing an avatar stamps `replaced_at` on the previous one in the same transaction, and the
  sweep selects only stamped rows;
- avatars are recorded (stamped) **before** the upload, so a failed or interrupted upload is
  swept too;
- regression test: `current_avatars_never_block_the_sweep`.

**Notes below the bar, fixed:**

- the inactivity query's missing `LIMIT`;
- a fresh transparency salt is now stored before any entry is logged under it.

**Notes recorded:**

- A sealed send to an account in the middle of its deletion can pass the access check while
  delivery's directory still lists its devices: a sub-second window on an account that is going
  away.
- Inactivity counts `api` use only (D-0056).

**Checked and found sound:**

- the link factor (checked against the token owner before the token is spent; a wrong or
  missing kind refused);
- PIN spend-before-check with write conflicts; the pepper; constant time;
- passkeys scoped to the account, challenges bound to the link transcript, compare-and-swap
  counters, single-use registration challenges;
- the WebAuthn verifier against the specification;
- primary-only gating;
- profile and avatar rules; certificate coverage;
- sealed sends (accounts deduplicated before the XOR, missing keys refused, reserved envelopes
  and MLS refused, the sentinel sender);
- the RFC 9162 verifiers step by step;
- the SurrealQL `format!` uses (static strings only);
- keyed Valkey names; export scope; deletion coverage.

## Open risks

These are gathered from the milestone reports and threat model §6:

- **Second factors**: the PIN does not stop a fully compromised `api` (hardware guess-limiting is
  issue #26). Passkeys sync through Apple or Google.
- **Sealed sender**: the server sees the sealed sender's IP address and timing; it is off until
  Prompt 12 verifies it.
- **Key transparency**:
  - it is a log, not a map: owners must check their own entries, and there is no external
    auditor yet;
  - the log, certificate and system keys are not deployed yet (secrets store).
- **Inactivity**: it counts `api` use only; warnings need push.
- **Locally**: Iggy stays stopped (the podman VM ran out of memory in M3b), so CI runs the Iggy
  tests. The timing-sensitive `send_api put_messages_holds_…` flakes under the full live suite on
  `main` too.

## The owner's decisions (asked)

1. **Approve the Prompt 3 gate** (this report, D-0056)?
2. **Approve M4b, M5 and M6** (`P03-M4b.md`, `P03-M5.md`, `P03-M6.md`; D-0053–D-0055).
3. **Confirm key transparency as the own RFC 9162 log, with `akd` as the upgrade path** (D-0055)?
4. **Approve the new threat-model §1 rows**:
   - the PIN verifier; passkeys (M4b);
   - profiles, access keys and avatars; keyed throttle records (M5);
   - the transparency log (M6);
   - last use and inactivity (M7).
