# P03 — Identity: plan, milestones and gates

- Date: 2026-11-15
- Prompt: [03-identity.md](../prompts/03-identity.md), amended by D-0038 (invite-only launch).
- Status: **agreed by the owner on 2026-11-15**, with every recommended answer below (D-0047).
  M1 and M2 built and their gates approved on 2026-11-15: reports `P03-M1.md` (D-0048) and
  `P03-M2.md` (D-0049). M3 built and its gate approved (`P03-M3.md`, D-0050); M3b (MLS KeyPackages) built and its gate approved
  (`P03-M3b.md`, D-0051).
- Base: `main` at `c377d4d` (CI on hosted runners, D-0045/D-0046).
- Skills: the environment offers general skills only (`security-review`, `code-review`,
  `simplify`); none is specific to Rust, fuzzing or benchmarking, and the repository has no
  project skills. `security-review` and `code-review` run on every milestone's diff before its
  report. Proposed, as the constitution suggests: a `songbird-invariants` project skill
  (`.claude/skills/`), a checklist of the nine invariants, the threat-model §1 rule and the
  identity rules below, run at every gate.

## What Prompt 3 starts from

- **Registry (D-0036).** `crates/accounts` holds `account` (ID, creation time, `deleting`) and
  `device` (account, Ed25519 authentication key, `disabled`) in SurrealDB, plus push tokens,
  upload grants, attachments and the outbox. Accounts are created only through `api`'s admin
  node link (`admin.` certificates); that stand-in stays for operators and tests.
- **Device authentication (D-0018, D-0024).** A per-device Ed25519 key signs a channel-bound
  challenge; the server holds only public keys. D-0018 left to Prompt 3 whether this key stays
  separate from the identity key.
- **Send path (D-0026, D-0044).** Device-list checks read the directory; the `stale` list stays
  empty "until the identity service owns devices and key versions". System frames exist, and kind
  1 "device list changed" is defined but emitted by nothing yet.
- **Deletion (D-0036, D-0041).** Outbox job across every store, verified, with a deletion journal
  that survives restores. Every new table in Prompt 3 joins it.
- **Open for Prompt 3:** D-0038 (store who invited whom?), the inactivity deletion period, and
  issue #23 (contact discovery without a server-side social graph; "an owner decision").

## Design choices that shape every milestone

These follow the prompt's wording and the owner's standing instruction (D-0041); each is recorded
as a decision in the milestone that builds it.

1. **Two kinds of identity key, as WhatsApp does.** The prompt asks for a device list "signed by
   the account identity key" and, per device, an identity key in the key directory. So:
   - the **account identity key** (Ed25519, verified with aws-lc-rs) signs the versioned device
     list; it is what users verify (safety codes) and what key transparency publishes;
   - each device has its own **device identity key** (libsignal format, Curve25519) used by
     PQXDH, listed in the signed device list. Removing a device revokes its key; no device ever
     needs another device's private identity key.
   - The device **authentication** key stays separate (answers D-0018): a transport credential,
     rotatable without touching identity, never used for end-to-end crypto.
2. **The server issues account and device IDs** (16 random bytes, D-0003): clients cannot choose
   or squat IDs.
3. **Every new store holds only keyed or slow hashes of secrets** (invite codes, username key,
   PIN), compares them in constant time, and answers unknown, wrong and rate-limited alike where an
   answer could enumerate.
4. **Every new row is a threat-model §1 row,** proposed in the milestone's report for the owner's
   approval, as in Prompt 2.

## Milestones and gates

Each milestone: its own branch and pull request, invariant and security tests written first, a
report `docs/reports/P03-Mn.md`, a decision record, CI green, then stop for the owner. The
prompt's gate is the final one (M7) and is met piece by piece along the way.

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **Registration, abuse controls, invite-only launch.** Public `POST /v1/registration` (challenge, then register): server-issued account and device IDs; the account identity key and the first device's authentication key, each with a proof of possession over a domain-separated transcript. Argon2id proof of work (stateless MAC'd challenge, single use, parameters measured so a phone takes a few seconds). Per-IP-range throttles (IPv4 /24, IPv6 /48; GCRA in `valkey-hot` under a keyed hash of the range). Invite-only mode (configuration switch, no migration); 128-bit random codes stored only as hashes, single- or multi-use, expiry, rate-limited checks; a per-user allowance; admin batches through `songbird-admin` over the admin link. Directory picks up new devices. Privacy Pass evaluated in writing as a later option. | Invite tests: valid, expired, reused and guessed codes, quota, mode off. Proof-of-work tests (forged, expired, replayed, wrong difficulty) and its timing on the hardware at hand. Throttle tests. Fuzzed registration and challenge decoders; vectors for both transcripts. Threat-model rows; account-takeover and enumeration rows for registration. |
| **M2** | **Usernames, username key, lookups.** Username registration, change and deletion, found only by exact match, the server storing a hash and a proof. **Unique handles** (owner, 2026-11-15, D-0049): Signal's construction without its discriminator, proofs in poksho's format. Username key: optional, rotatable, short numeric, slow-hashed, checked server-side before a stranger's first contact. Lookups rate-limited per account and per IP range; one answer shape and timing for absent, hidden and limited. Contact discovery per the owner's answer to #23. | Enumeration tests (timing within a bound, identical answers); rate-limit tests; fuzzed username decoders; SHO and proof vectors cross-checked with libsignal's. |
| **M3** | **Key directory (PQXDH).** Per device: device identity key, signed X25519 prekey, last-resort ML-KEM-1024 prekey, one-time X25519 and ML-KEM-1024 prekeys (ML-KEM-1024 only, owner 2026-11-15); every key and XEdDSA signature checked on upload. One-time prekeys claimed exactly once; refill notices as system frames; exhaustion limits per requester and per target. | **The prompt's concurrency gate:** parallel claims never hand out a prekey twice (live test on SurrealDB, many connections). Fuzzed key decoders; XEdDSA vectors with libsignal. Key-substitution rows. |
| **M3b** | **MLS KeyPackages** (split out by the owner, 2026-11-15): the same single-use pattern plus a last-resort package; how much the server parses and checks (OpenMLS or a minimal parser) evaluated first. | KeyPackages claimed once (concurrency test); fuzzed decoders; vectors. |
| **M4** | **Devices.** QR provisioning: the new device shows an ephemeral X25519 key; the primary sends an encrypted provisioning message through a short-lived, single-use channel on the server (bounded size and lifetime, the server sees only ciphertext). Signed, versioned device list (account identity key; versions only increase; the server refuses a list it cannot verify or that rolls back). Device limits (a configured default until Prompt 11's plans). Removal emits "device list changed" system frames to every contact device that needs them and a hook for Prompt 5's MLS removal. Two-step PIN and passkeys as second factors for linking and recovery. Multiple accounts on one device (per-account auth, keys, mailboxes, push registrations; the shared-token linkage documented). | Provisioning tests (expiry, replay, wrong recipient, size); device-list rollback and forgery refused; limit tests; PIN lockout tests; WebAuthn verification against published vectors; fuzzed device-list and provisioning decoders. Account-takeover rows for linking. |
| **M5** | **Encrypted profiles and sealed sender.** One encrypted, versioned profile blob per account (name, avatar pointer, about, status line, profile links), version checks, size bounds; encrypted avatars in RustFS through `api`. Sealed sender behind a flag: short-lived server-signed sender certificates; unidentified-access keys derived from the profile key, checked in constant time, so a send is authorized without the server learning the sender. | Profile version and size tests; sealed-sender authorization tests (wrong key, expired certificate, flag off); fuzzed certificate decoder; certificate vectors. |
| **M6** | **Key transparency and security notifications.** An append-only log from account (and username hash) to the account identity key and the device-list version, with inclusion and consistency proofs from `api`; Meta's `akd` (MIT/Apache-2.0, 0.13.0 of 2026-08-12, used by WhatsApp) evaluated against a smaller own log, measured, and chosen behind a trait. Identity-key and device-list changes reach clients through the device-list and transparency paths. | Proof verification tests (including a forked or rewritten log detected); fuzzed proof decoders; vectors. |
| **M7** | **GDPR and the Prompt 3 gate.** Export of everything the server holds about an account (signed request, bounded, every store); deletion through the outbox extended to every Prompt 3 store and verified; inactivity deletion at the owner's period. The written threat model for account takeover, enumeration and key substitution, each with mitigation and test; every key and certificate decoder fuzzed; vectors published; final report `P03-gate.md`. | **The prompt's gate**, all four items, plus the D-0038 invite tests. |

Order: M1 first because nothing can register outside the admin link without it and the invite
amendment is launch-critical; M1 needs no libsignal code (the account key is Ed25519), so it can
start while question 1 is open. M2 and M3 need question 1's answer. M3 carries the hardest gate
item and comes before devices, profiles and transparency, which all reference keys.

## For the owner (answered 2026-11-15, D-0047)

Every recommendation below was accepted: (1) A, implement the protocols; (2) user-chosen 6, 12
or 24 months, default 12; (3) not stored; (4) usernames, invite links and QR only; (5) pepper and
lockout; (6) primary plus 5; and a report for the Prompt 2 final gate (written and approved the same
day: `P02-final.md`).

### Decisions the prompt or DECISIONS leaves to you

1. **libsignal's licence.** libsignal is **AGPL-3.0-only** (root `Cargo.toml`
   `license = "AGPL-3.0-only"`, checked 2026-11-15) and Signal does not publish it on crates.io
   (the crates.io `libsignal-protocol` is an unrelated 2019 crate; `libsignal-core` does not exist
   there). Linking it makes the server AGPL and breaks `deny.toml`'s rules (permissive licences
   only, crates.io sources only). The prompt asks for "signature validation with libsignal's own
   crates" and libsignal's username scheme. Options:
   - **(A, recommended) Implement the protocols, not link the library.** The server verifies
     XEdDSA prekey signatures, the Ristretto username hash and its proof, and key formats with
     permissive crates (`curve25519-dalek`, BSD-3; ML-KEM through aws-lc-rs), byte-compatible with
     libsignal and proven so by vectors generated from libsignal in a tool outside the workspace.
     Keeps the licence decision open. More code of ours to review (a few hundred lines of
     verification, fuzzed, Kani where it fits).
   - **(B) Link libsignal as a git dependency** and license the server AGPL-3.0 (as Signal-Server
     is). Exact behaviour for free; decides the repository licence.
   The same question will come back for the apps: linking libsignal there makes them AGPL too.
2. **Inactivity deletion period.** Options: a user-chosen period with a default (recommended:
   choices 6, 12, 24 months, default 12; a warning notice before deletion); a fixed period; or none.
3. **D-0038: who invited whom.** Default (recommended): not stored; only each account's remaining
   allowance. Abuse handling then works on the abusive account itself, not its inviter.
4. **Contact discovery (issue #23).** Recommended: no address-book discovery; people find each
   other by exact username, invite link or QR only, so the server holds no address books. The
   alternative (private set intersection or enclave-based discovery) is a project of its own.

### Please confirm

5. **Two-step PIN: what "cannot be brute-forced on the server" can mean without hardware.** A
   short PIN under any slow hash falls to an offline search by whoever holds the database and
   its keys. Proposed: Argon2id with a per-account salt plus an HMAC pepper held in the secrets
   store (not in the database or its backups), at least 6 digits, attempt limits with lockout.
   That stops a database or backup thief; it does not stop a fully compromised `api`. Hardware
   guess-limiting is issue #26 (Prompt 10). What a compromised server gains is small: the device
   list is signed by the account key, so a server that knows the PIN still cannot add a device
   unnoticed.
6. **Device limit until Prompt 11's plans:** one primary plus 5 linked devices, configurable.

### Prompt 2

The Prompt 2 final gate and the two M5 threat-model rows were approved by the owner on
2026-11-15 (`P02-final.md`), so nothing from Prompt 2 blocks Prompt 3.
