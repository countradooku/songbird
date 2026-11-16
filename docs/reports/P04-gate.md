# P04 — Messaging content and conversation features: the final gate

- Date: 2026-11-16
- Prompt: [04-messaging.md](../prompts/04-messaging.md).
- Status: **built; awaiting the owner's approval** of the gate, M1–M5 and the **seven
  threat-model §1 rows** (two from M3, three from M4, two from M5).
- Reports: `P04-plan.md` (agreed, D-0058), `P04-M1.md` to `P04-M5.md`, and this report.
- Decisions: D-0058 to D-0064 (D-0064: the security review's fixes).
- Branch: `claude/p04-messaging-202813`, one PR at the owner's request (D-0058).

## The gate, item by item

| Gate item | Met by | Evidence |
| --- | --- | --- |
| **Test vectors and the compatibility suite pass** | M1 | **33 byte-exact vectors** (`crates/content/vectors/v1`); the hex comes from the Rust types and the protobuf JSON is written by hand. `tools/content-vectors` (protox, an independent compiler) encodes every JSON to exactly that hex: 33 of 33, and a scratch copy with one field retyped fails. `compat.rs` decodes every version's vectors and a simulated newer writer's fields at three depths. Frame vectors for the new `Send` blocks (`send_frames_with_hints`) |
| **Poll and reaction convergence proven by property tests across random orderings** | M2 | `polls_converge_in_any_order`, `reactions_and_rsvps_converge_in_any_order` (and edits, deletes, pins, timers, policies): 512 cases each, two random orders, the second with random repeats; same state, same tally. A deliberately broken merge fails at once |
| **Franking verification has known-answer tests and a fuzzer** | M3, M5 | The commitment (`franking_commitment_known_answer`, `commitment_known_answer`) and the stamp (`stamp_known_answer`), each recomputed with Python's `hmac`/`hashlib`. Every refusal of verification (`tampering_keys_and_windows_are_refused`, sealed and group verdicts). Fuzz target `franking` (stamps and reports): 27,774,418 runs in 60 s, nothing found |
| **Message-request and block paths covered by integration tests, including abuse scenarios (request floods, report floods)** | M4, M5 | `gate_p04` (live: SurrealDB, `valkey-hot`, `RustFS`; WebSocket and HTTP):<br>• `contacts_requests_blocks_and_the_request_policy_end_to_end`;<br>• `request_floods_are_held_across_the_cluster_and_a_block_does_not_show`: one to many, many to one, one pair, across both transports, with a blocked sender seeing identical answers;<br>• `a_recipient_reports_a_message_and_only_moderators_can_read_it`;<br>• `report_floods_are_throttled_per_reporter`;<br>• `prompt_4_stores_are_exported_and_deleted_with_the_account`.<br>Unit level: 9 contact-gate tests in `crates/send`; `blocks_live` (1,020 racing blocks never exceed 1,000) |

## The rest of the prompt

| Prompt item | Where |
| --- | --- |
| `crates/content`: every listed message kind, sync messages, receipts, typing | M1 (`content.proto`, PROTOCOL §5.1–5.9) |
| Tallying and status that converge; batched, coalesced receipts; group aggregation with joins and leaves | M2 (PROTOCOL §5.5–5.6) |
| **The receipt load test** (1,024-member group) | M2: 47.2 % of envelopes with the 10 s window above 32 members, every device sending delivered receipts. The full matrix is in `P04-M2.md` |
| Message requests (access key or request; accept, block, report; rate-limited) | M4 (PROTOCOL §5.10) |
| Blocking (server-side drop for identified senders; client rule for sealed; what the server sees) | M4 (PROTOCOL §5.11) |
| Reporting with message franking | M3 (stamps), M5 (`POST /v1/reports`, PROTOCOL §5.13–5.14) |
| Disappearing and view-once hints | M3 (`EXPIRES`, all three mailboxes) |
| Rate limits per conversation type | M4 (direct, group, request, broadcast; channels at Prompt 5) |
| Broadcast lists | M4 (contacts only, one combined key, 256 accounts, hourly budget) |
| Restricted chat | M1 (`ChatPolicy`, PROTOCOL §5.9: carried, honestly not enforced) |
| Call history sync | M1 (`CallHistorySync`) |
| Client-only features (lock chat, storage, media overview, search, save, export, groups in common) | M1 (PROTOCOL §5.12: nothing prevents them, nothing added) |
| Group read receipts and the setting (owner's decision) | D-0058: they follow the setting, reciprocal |

## Runs

Run on the owner's Mac (Apple M5 Pro, macOS 27.2.1; compose stack under podman without Iggy),
2026-11-16, after the review's fixes:

- `cargo xtask ci fast`: **all checks passed**: workflow policy, rustfmt, clippy `-D warnings`,
  nextest **570 passed**, doctests, rustdoc, deny, audit, vet, and a smoke test of every service.
- The CI compose job's commands, without Iggy:
  - the first **191/191** (40 Iggy tests skipped);
  - `songbird-api` **52/52**, `songbird-jobs` 12/12, `songbird-push` 7/7;
  - the known flaky `send_api put_messages_holds_…` passed in this run.
- `tools/content-vectors`: **33 of 33** vectors agree with the independent compiler.
- Fuzz, 60 s each, nothing found:
  - `content` 5,659,194 runs;
  - `franking` (stamps and reports) 26,637,775 runs;
  - `proto_client_frame` (the new `Send` blocks) 14,763,233 runs;
  - `iggy_record` (sealed format 5) 288,707 runs.
- **Found while re-testing, and fixed:** the SurrealDB mailbox wrote `at` (and the new `exp`)
  with the service's clock but compared them with SurrealDB's `time::now()`. A skewed database
  clock broke `inv3_delete_on_ack_and_expiry`. Every time it compares is now the service's own,
  passed in. The bug predates Prompt 4; the deadline repeated it.
- The Iggy live tests (including `the_disappearing_hint_skips_drops_and_survives_a_restart`) run
  in CI's compose job: Iggy does not run on the owner's Mac (memory).
- **CI's first run on the PR** passed five checks and failed two on false positives. Both were
  fixed in code, with no waiver:
  - semgrep flagged `std::env::args` in `tools/content-vectors`, which now finds the repository
    from `CARGO_MANIFEST_DIR`;
  - CodeQL (`rust/hard-coded-cryptographic-value`) flagged the report domain, a public HKDF salt,
    reaching `Salt::new` through a parameter. `seal_with` and `open_with` now take a closed
    `provisioning::Domain` enum (`Provisioning`, `Report`) whose labels are written at
    `Salt::new`, as everywhere else in the workspace. The salts' bytes did not change, and
    callers can no longer pass an arbitrary domain.

  After the fixes, `ci fast` passed again (570), as did `gate_p04` (5/5) and the vector checker
  (33 of 33).


## Security review

An independent reviewer read the whole diff (`120c7a5..HEAD`), with no edits. It found **one high,
two medium, one low–medium and two low issues, all confirmed and fixed** (D-0064, with tests):

| Finding | Fix | Test |
| --- | --- | --- |
| **High:** a shared body skipped the contact gate and blocks: any stranger, or a blocked sender, could reach a closed account by sending a 1:1 ciphertext as a "group" body | Shared bodies are classified like broadcasts: every closed account needs its key in the combined `ACCESS` key until Prompt 5's membership checks | `groups_and_sealed_sends_are_not_classified_as_strangers`; `gate_p04` (refused without the keys, delivered with them) |
| **Medium:** a block showed through idempotency: a dropped request left no idempotency record, so reusing its key answered differently | A dropped send is stored whole, already expired, under its key (never fetched or routed, swept); the sender's transcript goes on under a derived key | `requests_from_a_blocked_sender…` (reuse for other devices and for a subset: reason 7; a retry: accepted, the transcript once) |
| **Medium:** a linked device could open the account ("anyone may send"), bypassing the primary-only loosening rule; blocks did not apply to open accounts | Opening is the primary's, checked in the profile's transaction; a new open lane drops senders the account blocked | `only_the_primary_opens_an_account_to_anyone`; `an_open_account_takes_anyone_but_its_blocks_still_apply` |
| **Low–medium:** the profile key sat inside the committed content, so a report would give moderators the sender's access key | Moved to `Plaintext.profile_key`, outside what a report reveals; the admin tool prints rendered messages only | `the_profile_key_travels_beside_the_committed_content`; 33 vectors (independent compiler 33 of 33) |
| **Low:** a sender missing from the snapshot was stamped as a sealed send | Refused as unavailable; only the sealed sentinel is sealed | `groups_and_sealed_sends…` (unknown sender) |
| **Low:** configuration gaps (a broadcast limit above its budget; a worker with another requests secret "verifying" deletions that missed block rows) | Validation; every node pins a keyed fingerprint of the requests secret and refuses to start on a mismatch | `a_node_with_another_requests_secret_is_detected` |

**Notes recorded, not changed:**

- a group message has one stamp, so its first reporter takes the report slot (a sybil member
  could take it first; the content still reaches moderators);
- a message can be reported again after its report is deleted;
- a sender's own retry past the deadline is routed live with the stored `seq`s;
- idempotency keys are not scoped to the sender (Prompt 2's design);
- a franking key that differs between delivery and `api` must be caught by the deployment
  runbook.

**Checked and found sound by the reviewer:**

- the frame flag rules;
- the reserved prefix on every path;
- the stamp MAC's coverage and domain separation;
- constant-time comparisons;
- the order of report verification;
- `seal_with` (a fresh ephemeral key per seal, the domain as the HKDF salt);
- the sealed endpoint's checks;
- block storage and its limit;
- request budgets spent before checks;
- deadlines in all three mailboxes (including Iggy's replay and re-driver);
- logs, metrics and `Debug` (no identifiers);
- the configuration required in staging and production;
- the GDPR export.


## Open risks

Gathered from the milestone reports and threat model §6:

- **Iggy was not run locally.** The deadline test runs in CI's compose job.
- **Requests:**
  - sybil accounts can use up a recipient's request budget for an hour;
  - ephemeral frames from strangers are not gated (encrypted, limited per connection);
  - until Prompt 5, group members prove they are contacts with their access keys;
  - a dropped send waits, expired and unreadable, in the recipient's mailbox until the next
    sweep.
- **Franking:**
  - sealed senders are claimed, not attested;
  - a holder of the franking key and the database could test candidate senders against
    undelivered envelopes.
- **Reports:** `api` sees reported content in memory; the moderation key must stay offline.
- **Receipts:** close to half the envelopes of a busy large group (a choice for the owner below).
- **Client rules** that apps must keep:
  - publish a profile at registration;
  - rotate the profile key on a block;
  - drop franked messages whose commitment does not open;
  - keep stamps for reports;
  - edit and delete windows; forwarding limits; restricted chats.

## The owner's decisions

1. **Approve the Prompt 4 gate** (this report) and M1–M5 (D-0059 to D-0063).
2. **Approve the threat-model §1 rows**, each marked "awaiting the owner's approval":
   - M3: a disappearing envelope's deadline; franking stamps;
   - M4: block rows; the request-policy flag and the access keys in every node's snapshot; keyed
     request and broadcast budget records;
   - M5: the sealed moderation queue; keyed report-budget records.
3. **Delivered receipts in large groups** (D-0060, optional):
   - **recommended:** keep every device sending them, and decide with Prompt 5's group tiers;
   - **alternative:** primaries only above 32 members, 34 % of envelopes instead of 47 %, with
     "delivered" then waiting for each member's primary.
4. **At deployment:** generate the moderation key (`songbird-admin reports keygen`) and keep it
   offline, and add the new secrets to SOPS:
   - the franking key;
   - the requests secret;
   - the moderation public key.
