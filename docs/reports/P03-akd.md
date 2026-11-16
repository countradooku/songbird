# P03 — Key transparency on `akd` (D-0057)

- Date: 2026-11-16
- Decision: the owner's, on 2026-11-16 ("we can use akd now"), replacing D-0055's own log.
- Status: **built (PR #55); approved by the owner on 2026-11-16** ("Approve D-0057").
- Branch: `feat/p03-akd`, on `feat/p03-rest` (PR #54).

## A correction first

D-0055 said `akd` adds 12 crates. Built with the features it actually needs, it adds **27 crates
to the cargo-vet exemptions** (imported audits cover seven more). Two things were missed:

- `akd` 0.13 does not compile without `public_auditing`, which brings protobuf and its build-time
  code generation (`protobuf-codegen`, `regex`, `which`, `tempfile`);
- it brings a second curve25519 and Ed25519 stack (`curve25519-dalek` 4.1.3, `ed25519-dalek`).

`cargo deny` passes: the licences are permissive. akd's `public_tests` helpers would have brought
an MPL-2.0 crate (`colored`); they are not used, and Songbird's own storage tests stand in for
them.

## What was built

1. **`crates/akd`**: akd's async `Database` on SurrealDB.
   - Records are in `akdrec` by binary ID; value states are in `akdval` by (label, epoch), with
     the label indexed.
   - Each batch is written in one transaction, the Azks record last, so a reader never sees an
     epoch half stored.
   - Retrieval follows akd's own rules.
   - An epoch commits only from the one before it: a compare and swap, which enforces the single
     writer.
   - Also: the VRF key from the secrets store; deterministic labels `kind || account`; values
     `HMAC(salt, context || kind || raw)`; signed epoch heads; proofs in akd's protobuf;
     `publish_pending`.
2. **Worker**: the only writer. It publishes one epoch per sweep from the registry's pending
   changes, driven by the generation each change bumps in its own transaction, then marks them
   published.
3. **`api`** (PROTOCOL.md §4.9):
   - akd's read-only directory, opened lazily once the worker has created it;
   - `GET /v1/kt/keys`, `GET /v1/kt/head` (signed by the log key);
   - `POST /v1/kt/lookup`, `/history` (newest 64), `/audit` (at most 1,000 epochs).
4. **GDPR**: `akd` 0.13 cannot tombstone, so values are salted and the salt is deleted with the
   account. The values then link to nothing. The labels keep the account ID and the epochs of its
   changes.
5. **Removed**: the own RFC 9162 log (`crates/kt`) and its tables.
6. Docs: PROTOCOL.md §4.9 and §13; threat model §1 row, §3.15 and open risks; D-0057;
   `[api.kt] vrf_key` and the worker's `kt_vrf_key`; fuzz target `kt` rewritten for akd's proof
   decoding.

## Tests

| Test | What it proves |
| --- | --- |
| `crates/akd` `published_epochs_verify_with_akds_own_client_checks` | Epochs published on SurrealDB, read by a separate reader. Lookup proofs verify with akd's `lookup_verify` and give the published value and version. They are refused for another label, against another epoch's root, and under another VRF key. Key history verifies with both versions, newest first. A label never published is refused. Audit proofs verify between epochs, and a rewritten epoch root fails |
| `crates/akd` `another_salt_never_matches_the_published_value` | From the review: one label per account and kind. Another salt (or another kind) never matches the published value |
| `crates/akd` `epochs_cannot_be_rewritten_and_racing_writers_never_both_commit` | From the review: rewriting epoch 1, or jumping ahead, is refused by the store. Two writers on separate connections publishing at once, 6 rounds: never both commit one epoch, and everything committed stays verifiable |
| `crates/akd` `the_store_keeps_akds_semantics` | Versions and epochs per label; every retrieval flag (max, min, specific version, specific epoch, at most an epoch); bulk versions; unknown labels; records round-trip unchanged |
| `crates/accounts` `kt_live` | Each change reported once, under a salt stored before it is reported; nothing once published; a change made while a pass publishes is not lost; deletion removes the salt |
| `services/api` `clients_verify_the_transparency_log` | Over HTTP, as a client does: the pinned keys; signed heads; a contact's identity key and device list by lookup proofs (another label or root refused); the identity key's history; an audit proof between two heads (a forked root fails); 404, 400 and the current head |
| `tests/e2e` `gate_p03` | Export and deletion still cover the transparency salt |
| Fuzz `kt` | 60 s, 436,288 runs, nothing found (before the review fixes) |

Run on the owner's Mac (compose stack under podman, without Iggy), 2026-11-16, after the review
fixes:

- `cargo xtask ci fast`: **all checks passed** (499 tests; deny and vet with the new
  exemptions).
- The CI compose job's commands, with `-p songbird-akd` added to the job:
  - the first group in two runs: 211/212 (the known flaky `send_api put_messages_holds_…`), then
    **212/212**;
  - `songbird-api` **48/48**, `songbird-jobs` 12/12, `songbird-push` 7/7.
- One live run under full parallel load failed `gate_p03 inactivity…` (it counted the shared
  push stream, which other gate tests drain) and once got a 503 from a sealed send. The
  inactivity test now checks the account's warning mark. Both tests pass 3 of 3 on their own.

## Security review

`security-review` over the integration (an independent reviewer, read-only): **one high and two
medium findings, all fixed.**

1. **High.** The first build put a server-chosen salt in the label. The server could publish a
   second label for an account under another salt and show contacts an attacker's key, while the
   owner's history stayed clean: equivocation no audit would catch. (The same flaw was in D-0055's
   own log.) Fixed:
   - deterministic labels (`kind || account`), so each account has one value per kind for
     everyone;
   - the salt moved into the value, where another salt cannot match it;
   - regression test `another_salt_never_matches_the_published_value`.
2. **Medium.** "One writer" was a comment. With several workers (rollouts run them), blind writes
   could overwrite an epoch, drop changes and sign two roots for one epoch. Fixed: the epoch
   compare-and-swap, with regression test
   `epochs_cannot_be_rewritten_and_racing_writers_never_both_commit`.
3. **Medium.** Values held the computable username hash, so a deleted account's history stayed
   findable in the database. Fixed: salted values.

**Notes below the bar, recorded:**

- `/v1/kt/audit` can be costly over 1,000 epochs (bounded and throttled).
- Every reader error is answered 404.
- Secrets in akd's VRF storage are not zeroized.

**Checked and found sound:**

- SurrealQL (only indices interpolated);
- atomic epochs; akd's retrieval rules;
- readers during a publish; the pending and published race;
- deletion paths; signed heads; no secrets in logs;
- clients cannot choose published values.

## Open risks

- There are 27 new exempted crates, including a second elliptic-curve stack, and protobuf code
  generation at build time.
- Records are stored as serde JSON, larger than a binary encoding would be. This can be changed
  later behind the same store.
- There is no external auditor yet. The log and VRF keys are not deployed; apps pin both.

## The owner's decisions (decided 2026-11-16)

The owner answered "Approve D-0057":

1. **Decided: the `akd` integration is approved** (this report, D-0057), with the corrected
   supply-chain cost (27 new cargo-vet exemptions).
