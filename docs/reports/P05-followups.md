# P05 follow-ups — server-proposed removals, link proofs, a cluster-wide channel class

- Date: 2026-11-17
- Status: **approved by the owner on 2026-11-17** ("approve all"): the milestones, the
  review's fixes, the four threat-model §1 rows, D-0077's fallback and the `cluster_secret`
  rule. PR #60.
- What: the three follow-ups the owner approved as future work at the Prompt 5 gate
  (2026-11-17, `P05-gate.md`, "The owner's decisions" 4).
- Shape: one branch and one PR, a commit per milestone (owner: "full milestones in one PR"),
  plus the security review's fixes.
- Decisions:
  - D-0075: the delivery service as every group's external sender;
  - D-0076: link proofs;
  - D-0077: the cluster-wide channel class;
  - D-0078: the review's fixes.
- Machine: Windows 11 Pro 10.0.26300, AMD Ryzen 9 7950X, `rustc 1.99.1`; nightly 2026-11-11 to
  type-check the fuzz target. Live: SurrealDB v4.0.1 and Valkey 9.1.3 (the pinned images)
  under podman, memory mailbox.

## What was built

### 1. Server-proposed removal of devices that left the directory (D-0075)

- **Every group names the delivery service** as its only MLS external sender (RFC 9420
  `external_senders`):
  - an Ed25519 key `api` derives from the cluster secret, in `crates/groups/src/external.rs`,
    outside the verify-only OpenMLS provider (which still signs nothing);
  - the server refuses a group that does not name exactly that key, at creation and after
    every commit;
  - `POST /v1/groups/ds` serves the public key.
- **When a device leaves the directory, its groups are marked in the same transaction.** That
  covers a primary's new device list, a linked device removing itself, and both ways an
  account deletion starts.
- **`api`'s re-drive loop (every 5 s) then, for each marked group:**
  - confirms each candidate in the registry, never on its cached snapshot alone;
  - queues a signed external `Remove` per departed leaf, hand-encoded to RFC 9420 §6 and run
    through the group's own `PublicGroup` before it is stored;
  - fans the proposals out to the listed members.

  Any member's next commit includes them, and needs no role to.
- **The trust rule is the apps':** commit a server removal only for a device no longer in its
  account's signed device list (`roles::Change::external`, `Denied::Listed`). The server
  applies it too, and refuses every other external proposal.
- **Proposals do not outlive an epoch,** so a commit that leaves a departed device in the
  group marks the group again.
- **GDPR:** marks hold device IDs for seconds, and the final deletion strips them (`remnants`
  counts them).

### 2. A link proof members check (D-0076)

- **A link's secret yields a third key** (HKDF info `proof`), an Ed25519 seed. The link's
  creator commits the public key, under the link's handle, into the roles extension. That is
  version 2 of its encoding; version 1 is unchanged when there are no keys. Only the `links`
  role may publish or withdraw a key.
- **A joiner signs its external commit's authenticated data** with the link's key: `1 |
  handle | signature`, over the group, epoch, handle, device and new leaf key.
- **One rule (`links::verify`) runs on the server** for every join by link (403 `proof`,
  nothing spent), **and in apps** for every external commit from a new account.
- **The server keeps only `SHA-256(auth)`,** so it cannot make a proof. A server that admits
  someone without a link the members made forks itself from them.
- **Why a signature, not the MAC key the follow-up sketched** (the "equivalent" the owner
  allowed):
  - the encrypted group info is served to every link holder, so a MAC key there would let
    any of them prove for any link;
  - the server could not check a MAC, and would accept joins honest members then refuse.

### 3. A cluster-wide channel rate class (D-0077)

- **The class (1 post a second per channel, burst 10) is now one GCRA record in `valkey-hot`,**
  under an HMAC of the group ID (`q:c:<hex>`), spent through the gate both transports already
  share (`Gate::channel`). A delivery node's WebSocket path and `api`'s HTTP path hold a
  channel to one budget.
- **The per-node budget stays in front,** as a fast path: a node already over the class
  refuses without a round trip.
- **While `valkey-hot` is unreachable or slow, the per-node budget decides alone** (each post
  waits at most 250 ms). This is counted as `channel_rate_local_only`, with a runbook entry
  in `docs/RUNBOOKS/delivery.md`.
  - **Decided: fail to the per-node budget, not closed.** Channel admins are authorized
    posters, each also under its device's own budget, and failing closed would turn a
    Valkey outage into a channel outage. Message requests still fail closed: they protect
    people from strangers.

## Tests and runs

| Run | Result |
| --- | --- |
| `cargo fmt --check`; `cargo clippy --workspace --all-targets --locked -D warnings` | Clean |
| Workspace, `--profile ci`, live against SurrealDB and Valkey, partitioned as D-0069 (`api`, `jobs`, `push` one at a time with `-j 1`), at `8fbb640` | **653 passed**, 4 skipped (tests needing RustFS, `valkey-jobs` or Iggy) |
| After the review's fixes | See "Final runs" |
| Fuzz target `group_records` (now also link proofs and roles v2), nightly 2026-11-11 | Type-checks. **Not run**: fuzzing is only on the owner's go-ahead (one heavy job at a time on this PC). The nightly CI matrix runs it |

New tests, by milestone:

- **M1:**
  - `crates/groups`: `external` unit tests (RFC layout, signature, determinism) and the
    `roles` trust-rule test;
  - harness `server_removals.rs` (7):
    - proposal and removal through the next commit, on the server and every client;
    - a server removal of a listed device refused by members and the server, even when an
      owner commits it;
    - external `Add` refused;
    - groups must name exactly the service;
    - a commit that leaves the proposal out is proposed again;
    - a member with a stale view catches up on a held proposal;
    - empty leaves and a context without the service refused by apps;
  - live `devices_live::departing_devices_mark_the_groups_that_hold_them` and
    `gate_p05::departed_devices_are_removed_through_server_proposals`. The latter covers the
    HTTP key endpoint, a stale snapshot answered 503 and then 200, and nothing naming the
    deleted account afterwards.
- **M2:**
  - `links` and `roles` unit tests;
  - harness `link_proofs.rs` (5):
    - a valid join;
    - no proof, an unpublished link, a forged signature, and a proof for another device, each
      refused by the server and by members;
    - a rejoin needs no proof;
    - only the links role publishes keys;
    - a join that also removes someone is refused by the server and apps;
  - live `gate_p05::invite_links_and_join_requests`: 403 `proof`, and members checking
    Carol's proof. `parallel_joins_never_exceed_a_links_uses` joins with proofs.
- **M3:**
  - `crates/send`: `the_channel_class_is_shared_by_every_send_path` and
    `without_valkey_the_per_node_budget_decides_alone` (a down and a hanging store);
  - live `gate_p05::a_channels_rate_class_is_shared_by_the_websocket_and_http`: 24 posts
    over both transports, 10 to 12 admitted (each node alone would admit 10), no group ID in
    `valkey-hot`.

## Security review

An independent, read-only review of the whole diff (a separate agent, given the code and
the documents, not this report). It found no way for a server, member or outsider to forge a
link proof, or to get a listed member removed past an honest server. Its findings and what
was done (D-0078):

| # | Finding | Severity | Done |
| --- | --- | --- | --- |
| 1 | Apps checked only the link proof on external commits; under a malicious server, a join or "rejoin" could also remove another member's leaf | Medium | **Fixed:** one rule, `ds::check_external_commit`, run by the server and apps; test `a_join_may_remove_no_one_else_on_the_server_or_in_apps` |
| 2 | A member with a stale view dropped a valid server proposal, then could not process the commit that referenced it | Medium | **Fixed:** kept aside outside the OpenMLS store and judged again after a refresh; test `a_member_with_a_stale_view_catches_up_on_a_held_proposal` |
| 3 | A commit after an account's final deletion could put its device IDs back into a prune mark, holding the deletion job | Low–medium | **Fixed:** commits name only devices whose rows still exist; live test extended |
| 4 | One failing mark could hold the head of the prune queue | Low | **Fixed:** a failing mark goes to the back. Recorded: no per-mark lease (the work is idempotent) |
| 5 | Apps stored a server removal of an empty leaf | Low | **Fixed** |
| 6 | Apps did not check `external_senders` against the pinned key | Low | **Fixed:** apps run `extensions_allowed` with the pinned key |
| 7 | The channel class is charged before later failures; Valkey slower than 250 ms means per-node mode | Low | Recorded (threat model §6): stricter than configured, never looser |
| 8 | Ed25519 implementations could disagree on proofs under weak link keys | Info | **Fixed:** link keys must be honest points; PROTOCOL asks for strict verification |
| 9 | Groups made before D-0075 would need a migration | Info | Recorded: none exist in production |
| 10 | The external-sender key shares the cluster secret with fan-out keys; HKDF outputs not zeroized | Info | Recorded; the runbook forbids rotating the cluster secret while groups exist |

Found while fixing: a commit that leaves the service's proposal out while this node's snapshot
is stale would not have re-marked the group. It now re-marks from the queued proposals
(`pending_server_removals`).

## Final runs

On the final code (the review's fixes included), on the machine above:

| Run | Result |
| --- | --- |
| `songbird-groups` and the harness, `--profile ci` (with the convergence property test) | **64 passed** |
| `songbird-api`, `-j 1` | **52 passed** |
| `songbird-accounts` and `songbird-send`, live | **68 passed** |
| `gate_p05`, live, `SONGBIRD_REQUIRE_STACK=1` | **12 of 12** (10 from Prompt 5, all updated, and 2 new) |
| `cargo fmt --check`; `cargo clippy --workspace --all-targets --locked -D warnings` | Clean |

The full CI run on Linux is the PR's checks.

## Open risks

From the threat model §6, in short:

- **A group none of whose members comes back keeps departed leaves.**
- **The proposal queue.** A member can fill the 64-proposal queue, so the service's proposals
  wait for the next commit.
- **Key rotation.** The service's key follows the cluster secret, which must not be rotated
  while groups exist until key rotation is built (`docs/RUNBOOKS/secrets-rotation.md`).
- **Stale device lists.** A member whose view of a device list is stale refuses a valid
  server removal until it refreshes.
- **Leaked links.** A proof shows a link was held, not by whom.
- **The channel class falls back to per-node budgets** while `valkey-hot` is unreachable or
  slow.

## The owner's decisions (all approved on 2026-11-17)

1. **Approve the three milestones** (D-0075, D-0076, D-0077) and the review's fixes (D-0078).
2. **Approve four threat-model §1 rows** (`docs/THREAT_MODEL.md`, now marked "approved by
   the owner on 2026-11-17"):
   - the service's external-sender key in every group's context, and its queued removals
     (which leaf, until the next commit);
   - prune marks: the group, and for seconds the IDs of its devices that left;
   - invite links' handles and proof public keys in the roles extension;
   - a keyed hash of a channel's group ID with its next post time in `valkey-hot`.
3. **Approve D-0077's fallback:** while `valkey-hot` is down, channels post at the per-node rate
   rather than not at all.
4. **Note the operational rule** (D-0075): do not rotate the router's `cluster_secret` while MLS
   groups exist. Key rotation is a further follow-up if wanted.
5. **Optionally,** a fuzz run of `group_records` (link proofs, roles v2) on this machine before
   merging. The nightly CI matrix runs it regardless.
