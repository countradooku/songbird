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

- Prompt 4 (`P04-gate.md`): delivered receipts in groups above 32 members from primaries only
  (34 % of envelopes instead of 47 % in the busy case of the M2 load test), or from every device
  (recommended until Prompt 5's group tiers).

- Public channels: build or not (Prompt 5).
- WhatsApp interop legal gate (Prompt 14).
- Second EU provider (D-0009): Hetzner only for now (D-0042); the Scaleway code stays dormant.
- Public domains: the owner holds `songbird.chat` (D-0046). Still to decide: which names under it
  serve the client endpoints and the web domain for proxy links (D-0011). The upstream names in
  `deploy/proxy/proxy.example.toml` are placeholders until then.
- Licence for the repository (README says all rights reserved until chosen).
- Deployment access model: SSH as root with a key, through one bastion restricted to admin ranges
  (D-0014). Alternatives: WireGuard-only access, a non-root deploy user with sudo.
- D-0045 (CI on GitHub-hosted runners for the public repository): branch `ci/hosted-public` merged
  on 2026-11-15 (it carried PR 37, closed with it). Still the owner's: do **not** register the D-0039 runners for this
  repository; set the organization's Actions budget to $0 with "stop usage"; in the repository's
  Actions settings require approval for workflows from all external contributors (it was
  "first-time contributors" on 2026-11-14).
- D-0046 (public repository): enable secret scanning with push protection and private
  vulnerability reporting (the security-advisory link needs it; both were off on 2026-11-14),
  protect `main` (required checks and a review; a collaborator with write access exists), and
  choose a licence (none yet: the code is visible, all rights reserved).
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
- Prompt 2, milestone 5 (report `docs/reports/P02-M5.md`): gate approved by the owner on 2026-11-13.
  The two further threat-model rows (the sealed job queue and the hashed request nonces) were
  approved by the owner on 2026-11-15 with the Prompt 2 final gate; D-0036 decided by the agent under the owner's standing
  instruction. Provider credentials (2026-11-13): an APNs sandbox key and a least-privilege FCM
  service account exist outside the repository and were verified against Apple and Google;
  waking a real device waits for the apps; production keys go to SOPS at deployment.
- D-0037 / D-0044 (report `docs/reports/P02-send.md`): **approved by the owner on 2026-11-14**
  ("Approve both"): D-0044's routing (`api.` admitted to node links for the store of a send
  only) and its two threat-model rows. Prompt 2's final gate (report `docs/reports/P02-final.md`):
  **approved by the owner on 2026-11-15** ("Approve all four"). Prompt 2 is done; its go-live checks
  (24-hour soak, durable latency on the `ccx33`, the 2-hour RTO drill) run after every phase is finished.
- Prompt 3, milestone 1 (report `docs/reports/P03-M1.md`, D-0048): gate **approved by the owner
  on 2026-11-15**, with its four threat-model §1 rows (account identity key and invite count;
  invite code hashes; keyed IP-range throttle records; used challenge nonces).
- Prompt 3, milestone 2 (report `docs/reports/P03-M2.md`, D-0049): gate **approved by the owner
  on 2026-11-15** ("Approve both"), with its four threat-model §1 rows (username hashes;
  username key verifiers; username links; keyed throttle records).
- Prompt 3, milestone 3 (report `docs/reports/P03-M3.md`, D-0050): gate **approved by the owner
  on 2026-11-15** ("Approve both"), with its two threat-model §1 rows (device public keys and
  prekeys; keyed throttle records).
- Prompt 3, milestone 3b (report `docs/reports/P03-M3b.md`, D-0051): gate **approved by the owner
  on 2026-11-15** ("Approve both"), with its threat-model §1 row (KeyPackages). M4 split by the
  owner (2026-11-15): M4 (devices: QR linking, the signed device list, limits, removal) then M4b
  (two-step PIN, passkeys with Songbird's own minimal WebAuthn verifier, multiple accounts on one
  device).
- Prompt 3, milestone 4 (report `docs/reports/P03-M4.md`, D-0052): gate **approved by the owner
  on 2026-11-15** ("Approve both"), with its four threat-model §1 rows (the signed device list
  and device flags; link token hashes; provisioning channels; keyed throttle records).
- The rest of Prompt 3 in one pass (owner, 2026-11-15: "lets do the rest of milestones in one"):
  M4b (D-0053), M5 (D-0054), M6 (D-0055) and M7 (D-0056, the final gate `P03-gate.md`) on one
  branch and one PR (#54). **Approved by the owner on 2026-11-16** ("i approve everything"): the
  Prompt 3 gate, M4b–M7 and the six threat-model §1 rows. The owner also decided to **adopt
  `akd` for key transparency now** (D-0057, built in PR #55, **approved by the owner on 2026-11-16**).
  Prompt 3 is done.
- D-0035 (RustFS replaces Garage, owner's decision): the `rustfs/rustfs:1.0.5` image is pinned by
  tag only, because Docker Hub was unreachable from the agent's sandbox. Pin its digest in
  `deploy/compose/compose.yaml` and `deploy/ansible/group_vars/all.yml` before the next deployment
  (`docker buildx imagetools inspect rustfs/rustfs:1.0.5`).

## Decisions

## D-0064 — Prompt 4: the independent security review's findings, fixed

- Date: 2026-11-16
- Status: accepted; built (report `P04-gate.md`, "Security review"); amends D-0059, D-0061,
  D-0062 and D-0063; awaiting the owner's approval with the gate
- Decided by: agent, at the owner's bar
- Context: the review of `120c7a5..HEAD`, by an independent read-only reviewer, found one high,
  two medium, one low–medium and two low issues, all confirmed against the code.
- Decision (the fixes):
  1. **High: a shared body skipped the contact gate and blocks.** A send with the shared-body
     flag reached any closed account with no key, no request budget and no block check.
     - Fix: a shared body is classified like a broadcast. Every closed account it reaches needs
       its key in the combined `ACCESS` key, which the frame now allows with a shared body; a
       request is never a shared body.
     - There is no allocation when every account is open (the development directories and the
       allocation gate). Prompt 5 replaces this with group membership.
  2. **Medium: a block could be detected through idempotency.** A dropped request wrote no
     idempotency record, so reusing its key (for other devices, or a subset) answered
     differently.
     - Fix: a dropped send now stores the whole send, under its own key, already expired: never
       fetched or routed, swept. The record and every answer match a delivered send's.
     - The sender's own envelopes go on live under a derived key. The expired copy waits for the
       next sweep (minutes); the risk is listed in threat model §6.
  3. **Medium: a linked device could open the account,** bypassing the primary-only loosening
     rule, and blocks never applied to open accounts.
     - Fix: opening the account (false to true) is refused unless the primary asks, checked in
       the profile's transaction (`put_profile_as`).
     - Sends to an open account go through a new `Open` lane, where the gate drops those from
       senders it blocked. That is one registry lookup, for open accounts only.
  4. **Low–medium: the profile key was inside the committed content,** so a report would hand
     moderators the sender's profile key, and with it its access key.
     - Fix: it moves to `Plaintext.profile_key`, beside the franking key, outside what a report
       reveals. `Content` field 5 is reserved.
     - There are now 33 vectors (new: `plaintext_accept`), and the independent compiler agrees.
     - `songbird-admin reports open` prints the rendered message, not raw bytes.
  5. **Low: a sender missing from the snapshot was stamped as sealed.** It is now refused as
     unavailable (retry); only the sealed endpoint's sentinel is sealed.
  6. **Low: configuration gaps.**
     - `max_broadcast_accounts` must not exceed `broadcast_burst`.
     - Every node pins a keyed fingerprint of the requests secret in the registry, and a node
       with another secret refuses to start. A worker with the wrong secret could otherwise "verify"
       a deletion that missed the block rows.
     - A franking key that differs between delivery and `api` stays a deployment check (runbook).
  7. **Notes:**
     - keyed tags are now length-framed;
     - the directory loader's comment is corrected;
     - group-report dedupe (the first reporter takes a shared body's slot), re-reporting after
       deletion and replays past a deadline are recorded in the gate report.
- Evidence:
  - new unit tests:
    - shared bodies need every closed member's key;
    - an unknown sender is refused;
    - open accounts take anyone, but their blocks apply;
    - a dropped request's key, reused for other devices or a subset, gets reason 7 as an
      undropped one does, and a retry is answered as a retry with the sync transcript once;
    - the profile key never appears in the committed bytes;
  - `blocks_live`: only the primary opens an account; a node with another secret is detected;
  - `gate_p04`: a shared body refused without the keys and delivered with them;
  - `tools/content-vectors` 33 of 33; all suites re-run (`P04-gate.md`).
- Consequences: groups need their members' profile keys (shared inside the group) until
  Prompt 5. A dropped send briefly occupies the recipient's mailbox, unreadable, until the next
  sweep.

## D-0063 — Prompt 4, milestone 5: reporting with message franking; reports sealed to an offline moderation key

- Date: 2026-11-16
- Status: accepted; built (report `P04-M5.md`, and the Prompt 4 gate `P04-gate.md`); awaiting the
  owner's approval of the gate and the two threat-model §1 rows
- Decided by: agent, under the owner's plan (D-0058) and standing instruction (Proton-level bar)
- Context: Prompt 4: "The reporter submits the plaintext and the franking opening; the server
  verifies the commitment it stamped at send time, then queues a minimal report for moderation
  with short retention. Nothing else about the conversation is revealed."
- Options considered:
  - **Storing reports in the clear** for moderators was rejected: the registry and its backups
    would hold message plaintext. Reports are sealed to a moderation key whose private half stays
    offline, so the servers can verify and queue but never read them back.
  - **Naming the reporter in the report** was rejected as more than moderation needs; repeat
    reports are stopped by the keyed stamp ID and the budget.
  - **Several messages (context) per report** was rejected: the prompt says nothing else about
    the conversation, and each message carries its own stamp, so an app may send several reports.
  - **Decoding the content on the server** to check it is a message was rejected (the server
    never links `songbird-content`); moderators decode it in `songbird-admin`.
- Decision:
  - `POST /v1/reports` with the binary body of PROTOCOL §5.14 (`songbird_proto::report`, fuzzed).
  - **Checks, in order:** the reporter's budget (spent first), the franking key, the 30-day
    window, the stamp (sender attested or sealed; this recipient or a group), then the commitment
    (constant time).
  - **The minimal report:** eight fields, sealed with `seal_with("songbird.v1/report", …)`. The
    row is named by a keyed hash of the stamp's tag (one per message), kept 30 days (at most 90),
    and swept by the worker.
  - **`songbird-admin reports`:** `keygen`, `list`, `open` (decrypt and decode) and `delete`
    (audit-logged).
  - `[api.reports]` is required in staging and production, and needs `[api.requests]` and
    `[api.send] franking_key`.
- Evidence (Apple M5 Pro, macOS 27.2.1):
  - verification known answers (identified, sealed, group, other reporter, other sender, other
    words or key or commitment or time, forged tag, unknown or previous key, too old, future);
  - the commitment's known answer equals `songbird_content`'s, and the live test checks both
    implementations agree on random keys;
  - `gate_p04` live:
    - a request reported by its recipient, queued sealed;
    - duplicate 409; another reporter, other words or another sender 403; garbage 400;
    - only the moderation key opens it, the content is not in the clear, and no reporter is in
      it;
    - floods give 204, 409 ×4, 429 ×2;
    - export and deletion of Prompt 4's stores;
  - admin seal and open tests; fuzz `franking` (with reports), 60 s: 27,774,418 runs.
- Consequences: a moderation key for the owner to generate and hold offline; two threat-model §1
  rows. Reports of sealed sends name a claimed sender only.

## D-0062 — Prompt 4, milestone 4: the contact gate, message requests, blocking, rate limits per conversation type, broadcast lists

- Date: 2026-11-16
- Status: accepted; built (report `P04-M4.md`); awaiting the owner's approval of the gate and the
  three threat-model §1 rows
- Decided by:
  - owner: access key or request (D-0058 §3); tighten from any listed device, loosen from the
    primary (D-0058 §4);
  - agent: the design below.
- Context: Prompt 4's server part: message requests the recipient controls, rate-limited; a
  server-side drop of blocked identified senders with block lists stored as little as possible;
  rate limits per conversation type; broadcast lists rate-limited as bulk.
- Options considered:
  - **A contact list on the server** was rejected: it is a social graph. The sender proves
    contact by holding the recipient's access key, which only contacts hold (D-0054).
  - **Checking access keys with a store query per send** was rejected (hot path). The directory
    snapshot every node already holds (D-0036) gains each account's key, open flag and request
    policy; profile and policy changes bump its version.
  - **Blocks as account IDs** were rejected. They are keyed hashes of the pair, with a keyed
    owner tag and a per-owner counter, and the full list syncs between the user's devices in
    encrypted content.
  - **Telling a blocked sender** was rejected (WhatsApp does not either). To keep the block
    invisible:
    - its requests are accepted and dropped;
    - the budgets are spent before the block check;
    - the timing difference is stated as an open risk.
  - **Requests over HTTP only** were rejected: one gate behind a trait (`songbird_send::Gate`),
    used by the WebSocket and `PUT /v1/messages` alike.
- Decision:
  - **Lanes** (PROTOCOL §5.10): sync, direct, broadcast, request, group, sealed, decided from the
    snapshot. No allocation for 1:1 sends; access keys compared in constant time. Reason 10
    ("access required") and 11 ("invalid request").
  - **The gate** (`RegistryGate`):
    - budgets per sender, per pair and per recipient for requests, and accounts per hour for
      broadcasts. These use a cost-weighted GCRA in `valkey-hot` under keyed names and fail
      closed;
    - then the request policy and the block row in SurrealDB.
    The keys derive from `[api.requests]` and `[delivery.requests] secret` (and the worker's
    `requests_secret`).
  - **Endpoints:** `PUT`/`DELETE /v1/blocks`, `GET`/`PUT /v1/account/requests`, with D-0058's
    tighten/loosen rule.
  - **Per-class rate limits:** group sends get their own budget within the per-device one (10 a
    second, burst 40, on both transports). Requests and broadcasts are budgeted per account
    across the cluster. Channels wait for Prompt 5.
  - **GDPR:**
    - the worker deletes an account's block rows by owner tag and verifies none are left;
    - the export reports the policy and the block count;
    - the policy flag goes with the account row.
  - **Static development directories** treat every account as open, so the delivery invariants,
    load and allocation tests are unchanged; a registry directory is closed by default.
  - `SEALED_SENDER` moves into `songbird-send`; the sealed endpoint refuses `ACCESS`/`REQUEST`.
- Evidence (Apple M5 Pro, macOS 27.2.1; compose stack under podman without Iggy):
  - `crates/send`, 22 tests, among them every lane's rules, silent drops, floods (one to many,
    many to one, one pair), a blocked sender seeing the same budgets, broadcasts (keys, size,
    budget), groups and sealed sends unaffected, and no gate meaning unavailable;
  - `blocks_live` (2): keyed rows; 1,020 racing adds never exceed 1,000; deletion by owner; the
    policy and profiles bump the directory;
  - `gate_p04` (2, live): every rule end to end over the WebSocket and HTTP, with
    stamps verified, the linked device refused to loosen, and floods held cluster-wide;
  - the earlier live tests updated to the contact flow (`registration`, `gate_m5`, `send_api`)
    pass, and the non-live suite passes (555).
- Consequences:
  - Apps must publish a profile at registration and handle reasons 10 and 11.
  - Blocking rotates the profile key (a client rule).
  - Three threat-model §1 rows.
  - `[api.requests]`, `[delivery.requests]` and the worker's `requests_secret` are required in
    staging and production.
  - The open risks (timing, sybil recipient budget, snapshot reloads, ephemeral frames) are in
    threat model §6; shared bodies, idempotency and open accounts were fixed by D-0064.

## D-0061 — Prompt 4, milestone 3: franking stamps and disappearing envelopes; the `Send` frame's hints

- Date: 2026-11-16
- Status: accepted; built (report `P04-M3.md`); awaiting the owner's approval of the gate and the
  two threat-model §1 rows
- Decided by: agent, under the owner's plan (D-0058) and standing instruction (Proton-level bar)
- Context: Prompt 4 asks for reporting with message franking (the server verifies the commitment
  it stamped at send time) and for an envelope flag that expires undelivered envelopes early.
  Both need something the server can see; the content stays opaque.
- Options considered:
  - **Hints inside the ciphertext** were rejected: the server would have to parse client content.
  - **A new protocol version** was rejected while no app exists. Instead, v1's `Send` frame gains
    four optional blocks behind new flag bits. Unknown bits stay refused, and each block appears
    only with its flag, in a fixed order, so there is still one encoding per frame.
  - **A stamp that names the sender** was rejected: it would store the sender with the envelope in
    the clear (threat model §1, "never stored with the envelope"). It is a MAC over the accounts
    instead.
  - **A deadline in a server-written envelope header** was rejected: Iggy rebuilds its index from
    record metadata, without opening envelopes. The deadline goes into the records instead (sealed
    format 5).
  - **A new Iggy record kind for dropped entries** was rejected as unnecessary: an expired
    entry's key is punctured, so replay leaves it out (punctured slots are absent), and the
    deadline in the metadata re-drops anything a crash left unpunctured.
- Decision:
  - **Frame:** `ACCESS 0x04` (16-byte key), `REQUEST 0x08`, `FRANKED 0x10` (32-byte commitment),
    `EXPIRES 0x20` (`u32` seconds, 1 to 30 days). Access or request, never both, and neither on a
    shared body; a request is never an MLS commit. Reasons 10 (access required) and 11 (invalid
    request) are defined here and enforced in M4.
  - **Stamps:** envelopes for another account are stored as `stamp ‖ envelope`, with a MAC by the
    franking key over the key ID, commitment, time, sender and recipient accounts (zeros where
    unknown or shared). The sender's own devices are not stamped. One allocation per stamped
    envelope; unfranked sends are unchanged.
  - **Reserved prefix:** `F5 53 42` covers system frames, stamps and any later server format.
  - **Deadlines:** `StoreRequest::expires_after`, kept by every mailbox:
    - memory: per entry;
    - SurrealDB: `exp` with an index;
    - Iggy: in the store metadata and the relocated slots (format 5; 3 and 4 still read), carried
      over node links (wire 2) and by the re-driver.
    Fetch skips expired entries, and the sweep deletes them (Iggy punctures their keys).
  - **Keys:** `[delivery] franking_key` and `[api.send] franking_key` (+ `previous_franking_keys`
    for reports), required in staging and production. Without a key a franked send is refused as
    unavailable.
- Evidence (Apple M5 Pro, macOS 27.2.1):
  - the stamp's known answer, recomputed with Python's `hmac` and `hashlib`;
  - stamps bound to key, sender, recipient, time and commitment; own devices unstamped; shared
    bodies once; sealed without a sender; forged prefixes refused;
  - frame vectors and flag rules, with proptest round trips including hints;
  - deadlines in the memory mailbox, SurrealDB (live) and the Iggy state (unit; the Iggy live
    test runs in CI);
  - fuzz: `franking` 14,180,569 runs, `proto_client_frame` 7,624,430 and `iggy_record` 147,775 in
    30 s each, nothing found.
- Consequences: no new dependency. Iggy's sealed format is 5 and the node-link wire format is 2;
  every node of a cluster runs one build. Two threat-model §1 rows for the owner.

## D-0060 — Prompt 4, milestone 2: order-independent chat state and message status; receipt batching sized by measurement

- Date: 2026-11-16
- Status: accepted; built (report `P04-M2.md`); awaiting the owner's approval of the gate
- Decided by:
  - owner: group read receipts follow the setting; 24-hour edit and delete windows (D-0058);
  - agent: the semantics below.
- Context: Prompt 4 asks that polls tally the same on every device whatever the arrival order
  ("last vote per voter wins, by a per-voter counter"), proven by property tests; statuses that
  only move forward; batched and coalesced receipts; group aggregation as members come and go;
  and a measured share of receipt traffic in a 1,024-member group.
- Decision:
  - **Convergence by construction:**
    - per-author slots keep the greatest `(counter, value)`: reactions, votes, RSVPs, edits;
    - shared chat state takes the greatest `(time, author, message ID)`: pins, timer, policy;
    - every state is a function of the set of operations.
  - **Closing a poll fixes its result:**
    - the author's close lists each voter's counter as the author saw it;
    - only those votes count afterwards, so a late vote cannot make devices disagree;
    - closes by others, or naming another poll, are dropped.
  - **Edit and delete windows** are judged from the messages' own times, never from arrival.
  - **Status:** each recipient's greatest receipt. A group's audience is fixed at send time;
    members who leave are dropped, and joiners are never counted.
  - **Batching window:** 1 s, and **10 s in groups above 32 members**, chosen from the load test
    below. Every device that saves a message sends a delivered receipt, which keeps "at least
    one device" exact.
- Evidence (Apple M5 Pro, macOS 27.2.1, release build):
  - property tests, 512 cases each, two random orders with random repeats: polls (with closes,
    forged closes and invalid votes), reactions and RSVPs, edits and deletes, pins, timers and
    policies, and statuses (forward only);
  - a broken merge ("the last arrival wins") fails at once;
  - known cases: a closed poll, group ticks as members leave and join, a receipt lifting a failed
    message, 200 unread messages giving one read receipt, splitting above 512, the setting off.
  - **Load test** (`tests/e2e/tests/receipts_load.rs`): the real coalescer drives the real send
    path. Setup: 1,024 members with 2 devices each; 60 messages in an hour; 20 % of devices offline
    and catching up; 3 chat openings per member. Receipt share of all envelopes:

    | Traffic | Window | Delivered from | Receipts |
    | --- | --- | --- | --- |
    | Steady, random authors | 1 s or 10 s | every device | 72.6 % |
    | Steady, random authors | 1 s or 10 s | primaries only | 62.6 % |
    | Bursts of two people chatting | 1 s | every device | 65.9 % |
    | Bursts of two people chatting | 1 s | primaries only | 51.0 % |
    | Bursts of two people chatting | **10 s** | **every device** | **47.2 %** (chosen) |
    | Bursts of two people chatting | 10 s | primaries only | 34.3 % |

    Receipts go to each author only (the prompt's rule), so they batch only across one author's
    messages, and "read up to here" saves little in a big group whose messages have many
    authors (9,624 read receipts for 47,360 messages read in the chosen case).
- Consequences: no new dependency. Large groups see receipt envelopes close to half of all
  traffic. Delivered receipts from primaries only would save another 13 points, at the cost of
  "delivered" waiting for the primary; this is left to the owner (P04 gate) and to Prompt 5's
  group tiers.

## D-0059 — Prompt 4, milestone 1: the encrypted content schema (`crates/content`), never linked by a service

- Date: 2026-11-16
- Status: accepted; built (report `P04-M1.md`); awaiting the owner's approval of the gate
- Decided by: agent, under the owner's plan (D-0058) and standing instruction (Proton-level bar)
- Context: Prompt 4 asks for the content inside the encrypted payload, "specified so future apps
  interoperate exactly": protobuf, versioned, tolerant of unknown fields, never decoded by the
  server, with byte-exact vectors and a compatibility suite.
- Options considered:
  - **Types generated at build time** (`prost-build` with `protoc`) was rejected. It needs
    `protoc` on every build machine and puts generated code out of review. Instead, `prost`
    types are written by hand, field for field, as `crates/proto` already does. The `.proto` file
    is the specification, and an independent compiler proves the two agree.
  - **Signal's single `DataMessage` with every part optional** was rejected in favour of `oneof`
    kinds: a message is exactly one thing (a message, a reaction, an edit…), which makes
    validation and app code unambiguous.
  - **UTF-16 offsets for spans** (Signal) were rejected in favour of UTF-8 bytes:
    one unambiguous unit, checkable on character boundaries.
- Decision:
  - **Layers:**
    - the session layer's ciphertext;
    - a padded `Plaintext` (`0x80 0x00*` to a multiple of 160 bytes);
    - `Plaintext { content bytes, franking key }`;
    - `Content` (version, required version, message ID, time, profile key, and one body: data,
      receipt, typing, sync or request response).
  - **Franking commitment:** `HMAC-SHA256(franking_key, "songbird.v1/franking\0" || content)`
    over the exact content bytes. The server stamps it (M3); a report submits the bytes and the
    key (M5).
  - **Validation after decoding:** every list, string and ID bound written in the `.proto`, with
    sizes checked before decoding. Unknown fields, kinds and enum values are accepted, so a newer
    writer is never refused. `required_version` drives "update to see this".
  - **Message IDs:** 16 random bytes per message; (author, ID) deduplicates resends.
  - **The server never decodes content:** no service or server crate may depend on
    `songbird-content`, enforced by a test over every manifest.
  - **`Debug` prints type names only** (invariant 6 in apps too).
- Evidence (Apple M5 Pro, macOS 27.2.1):
  - 16 tests in `crates/content`: padding, franking known answer (recomputed with Python's
    `hmac`), bounds, a newer writer's fields at three depths, unknown kinds and enums, the
    manifest check, and property tests;
  - **33 vectors** in `vectors/v1/vectors.json`. Their protobuf JSON is written by hand
    (`make_json.py`) and their hex comes from the Rust types. `tools/content-vectors` (protox
    0.10.0 and prost-reflect 0.16.5, outside the workspace) compiles `content.proto` and
    encodes each JSON to exactly that hex, with no unknown field on decoding: **33 of 33**. With
    one field retyped (`sint32` to `int32`) it fails at once;
  - fuzz `content`, 60 s: 7,892,926 runs, nothing found.
- Consequences: no new dependency in the workspace (`prost`, `aws-lc-rs`, `thiserror`); the tool
  brings `protox` and `prost-reflect` outside it. Apps generate their types from
  `content.proto`, and attachment pointers are extended by Prompt 6.

## D-0058 — Prompt 4: the plan, and the owner's decisions it needed

- Date: 2026-11-16
- Status: accepted (owner, 2026-11-16)
- Decided by: owner (each answer below), on the agent's plan `docs/reports/P04-plan.md`
- Context: Prompt 4 leaves group read receipts to the owner (the open decision above); its
  message-request rule changes how identified sends are admitted (PROTOCOL §3.1); blocks and the
  request policy are account-wide changes (D-0052); edit and delete limits are product choices.
- Decisions:
  1. **Plan agreed:** five milestones on one branch and one PR (the owner's request for speed):
     M1 the content schema (`crates/content`); M2 convergence and message status; M3 franking
     and disappearing envelopes; M4 message requests, blocking, rate limits per conversation
     type, broadcast lists; M5 reporting and the Prompt 4 gate.
  2. **Group read receipts follow the read-receipt setting**, reciprocal, as in Signal.
  3. **Contact gate:** every send to another account carries that account's access key (the
     account is open, or the key is in the send) or goes as a message request: rate-limited,
     franked, blockable. Blocking rotates the profile key (a client rule).
  4. **Blocks and the request policy:** any listed device may tighten them (block, refuse
     requests); only the primary may loosen them (unblock, accept requests again). Pending
     devices change nothing.
  5. **Edit window and delete for everyone: 24 hours each**, as in Signal.
- Consequences: identified sends between accounts need the access key from Prompt 4 on, so every
  account should publish a profile (with its access key) at registration; apps must handle the new
  refusal reason by sending a request or fetching the new profile key.

## D-0057 — Key transparency on Meta's akd (supersedes D-0055's own log)

- Date: 2026-11-16
- Status: accepted; built (report `P03-akd.md`, PR #55); **approved by the owner on 2026-11-16**
  ("Approve D-0057"), with the corrected supply-chain cost; supersedes D-0055's own log
- Decided by:
  - owner: adopt `akd` now ("we can use akd now", 2026-11-16);
  - agent: the integration below.
- Correction to D-0055: `akd` 0.13 with the features it needs adds **27 crates to the audit
  backlog** (cargo-vet exemptions), not the 12 measured with its defaults. Two things were
  missed:
  - its `public_auditing` feature is required to compile (it imports `akd_core::proto`
    unconditionally) and brings protobuf code generation at build time (`protobuf-codegen`,
    `regex`, `which`, `tempfile`);
  - it brings a second curve25519/Ed25519 stack (`curve25519-dalek` 4.1.3, `ed25519-dalek`).
  Imported audits cover seven of the new crates. The licences are permissive. The `public_tests`
  helpers (MPL-2.0 `colored`) are not used, so the licence policy is unchanged.
- Decision:
  - **Storage**: akd's `Database` on SurrealDB (`crates/akd`). Records are in `akdrec` by binary
    ID; value states are in `akdval` by (label, epoch) with the label indexed. Each `batch_set`
    is one transaction with the Azks record last. The retrieval rules match akd's in-memory store.
  - **Configuration**: WhatsApp v1. The VRF key comes from the secrets store (worker
    `kt_vrf_key`, api `[api.kt] vrf_key`).
  - **Labels**: `kind || account`, deterministic, so each account has one label per kind and
    everyone is shown the same value.
  - **Values**: `HMAC(salt, context || kind || raw)`, with a random per-account salt given to
    whoever asks and deleted with the account. This keeps deletion unlinkable, because `akd`
    0.13 cannot tombstone. A different salt cannot match the published value.
  - From the security review: the first build put the salt in the label. A server could then
    publish a second label for an account and show contacts a different key than the owner saw.
  - **Writer**: the worker publishes one epoch per sweep from the generation-driven pending list
    (D-0055's mechanism kept). **One writer is enforced by the store**: an epoch commits only from
    the one before it (a compare and swap on `akdhead` in the epoch's transaction). Rollouts run
    several workers.
  - **Readers**: `api` uses akd's read-only directory, opened lazily. It serves keys, signed
    heads (log key) and lookup, history (newest 64) and audit (at most 1,000 epochs) proofs in
    akd's protobuf.
  - **Removed**: the own RFC 9162 log (`crates/kt`) and its tables. The fuzz target `kt` now
    covers akd's proof decoding.
- Evidence:
  - `akd_live`: epochs published and read by a separate reader; lookup, history and audit
    verified with akd's client checks; refused under another label, root or VRF key and for a
    rewritten history; the store's semantics;
  - `kt_live` (pending and published);
  - `clients_verify_the_transparency_log` over HTTP;
  - `gate_p03`;
  - fuzz `kt`.
- Consequences: 27 new exemptions; protobuf generated at build time; a VRF key and a log key for
  the secrets store. No external auditor yet.

## D-0056 — Prompt 3, milestone 7: GDPR export, deletion across every Prompt 3 store, inactivity deletion; the Prompt 3 gate

- Date: 2026-11-15
- Status: accepted; built (report `P03-gate.md`, PR #54); **the Prompt 3 gate approved by the owner
  on 2026-11-16**
- Decided by:
  - owner: the inactivity period, user-chosen from 6, 12 or 24 months with a default of 12 and
    a warning first (D-0047);
  - agent: the design below.
- Decision:
  - **Export** by the primary only (as deletion, D-0052): one JSON document of every registry
    store. Derived secrets (the PIN and username-key verifiers) are reported as present, not
    given out. Sealed push registrations are reported as present. What cannot be attributed to
    the account is listed with its retention.
  - **Deletion**: the existing outbox job extended to avatar objects; the registry deletion
    extended to passkeys, avatars and link tokens. Profile, PIN, device list and transparency
    salt go with the account row; the job verifies all of it.
  - **Inactivity**:
    - "use" is any signed `api` request, recorded at most daily through a keyed mark in
      `valkey-hot`;
    - warnings are wake-up pushes a month and a week before the end, which make the app
      reconnect;
    - at the end, the same deletion as a user's own.
- Evidence: `an_account_is_exported_then_deleted_from_every_prompt_3_store` and
  `inactivity_warns_a_month_and_a_week_before_then_deletes` (`tests/e2e/tests/gate_p03.rs`,
  against SurrealDB, `RustFS` and both Valkeys). The Prompt 3 gate is in `P03-gate.md`.
- Consequences: none new beyond the fields listed in the threat model row. Inactivity is
  measured from `api` use, so apps must call `api` at least daily while in use.

## D-0055 — Prompt 3, milestone 6: key transparency as Songbird's own RFC 9162 log; akd recorded as the upgrade path

- Date: 2026-11-15
- Status: accepted; built (report P03-M6, PR #54); **gate approved by the owner on 2026-11-16**. The
  owner's answer on the choice of log: **"we can use akd now"**, so `akd` replaces the own log
  (D-0057, next); this log stays the interim and the test reference until then.
- Decided by: agent (rest of Prompt 3 in one pass), for the owner to confirm
- Options and evidence:
  - **Meta's `akd` 0.13.0** (MIT/Apache-2.0, used by WhatsApp): a verifiable map with VRF-private
    labels, non-membership and history proofs. It adds **12 crates** to the tree (`akd`,
    `akd_core`, `async-recursion`, `ed25519-dalek`, `ed25519`, `protobuf`, `sha2`, …), so a
    second Ed25519 and SHA-2 stack. It needs its async `Database` trait implemented on
    SurrealDB, a VRF key with its own lifecycle, and epoch publishing. Weeks of integration.
  - **An own RFC 9162 log**: about 500 lines, aws-lc-rs only, proofs checkable by any CT
    library. It is a log, not a map: no non-membership proofs, and a server could withhold an
    account's newest entry from one reader (but not rewrite history without a detectable fork).
- Decision (recommended): **the own log now, behind the same endpoints, with `akd` as the
  upgrade** when non-membership and label privacy are worth its integration.
  - The log covers identity keys, device lists and usernames.
  - Subjects are salted HMACs, so deleting an account's salt leaves its entries unlinkable
    (GDPR), while the log stays append-only.
  - Logging is driven by a generation bumped in each change's transaction and reconciled by the
    worker.
  - Appends are serialized on the head row; only perfect-subtree hashes are stored.
  - Heads are signed by a dedicated log key at serving time.
- Evidence:
  - the CT reference roots (independently recomputed; the size-8 root is the published value);
  - every inclusion and consistency proof up to 70 leaves, with tampering refused;
  - a forked log detected;
  - 160 concurrent appends over 8 connections yield one consistent tree;
  - logging once per change; deletion unlinks;
  - a client's checks over HTTP;
  - fuzz `kt`.
- Consequences: new crate `songbird-kt`; `[api.kt]` with a log key for the secrets store. No
  external auditor yet (a later operational decision).

## D-0054 — Prompt 3, milestone 5: encrypted profiles, avatars and sealed sender behind a flag

- Date: 2026-11-15
- Status: accepted; built (report P03-M5, PR #54); **gate approved by the owner on 2026-11-16**
- Decided by: agent (rest of Prompt 3 in one pass, at the owner's request)
- Decision:
  - **Profiles.** One opaque blob encrypted by the client under its profile key, at most 8 KiB,
    whose version must grow. Avatars go to RustFS (encrypted, at most 512 KiB, random ID); only
    an account's current avatar is served, and replaced ones are swept after an hour.
  - **Unidentified-access key.** `HKDF-SHA256(salt "songbird.v1", profile key, info
    "unidentified-access")[..16]`, stored with the profile, with an "anyone may send" flag.
  - **Sealed sends** (`PUT /v1/messages/sealed`):
    - unsigned, authorized by the XOR of the closed recipient accounts' keys, compared in
      constant time;
    - no MLS commits;
    - throttled per IP range and per recipient account;
    - the send path is entered with a sentinel sender that no device has.
  - **Sender certificates.** Ed25519 by a dedicated certificate key (not the system key, so
    rotating either does not touch the other), carrying the account, device, device identity key
    and expiry; lifetime 24 hours.
  - **Off by default** (`[api.profiles] sealed_sender`). Prompt 12 verifies it before it is
    switched on.
- Evidence:
  - the certificate vector (`certificate_vector`), cross-checked with OpenSSL 4.1;
  - live tests (`profile_live`; `profiles_certificates_and_sealed_sends`: versions, fetch,
    certificates, sealed with the right, wrong, missing or combined keys, open accounts, the
    device check, the flag off);
  - fuzz `profile`.
- Consequences: new settings `[api.profiles]` and a certificate key for the secrets store. No new
  dependency.

## D-0053 — Prompt 3, milestone 4b: two-step PIN and passkeys as second factors for linking; multiple accounts per installation

- Date: 2026-11-15
- Status: accepted; built (report P03-M4b, PR #54); **gate approved by the owner on 2026-11-16**
- Decided by:
  - owner: the PIN as Argon2id + pepper + lockout, at least 6 digits (D-0047); Songbird's own
    minimal WebAuthn verifier (2026-11-15);
  - agent: the design below.
- Decision:
  - **Where the factor applies.** Once an account has a PIN or a passkey, a link request must
    carry one. This is the step a QR-scan phisher cannot complete. Recovery (Prompt 10) will
    require the same.
  - **PIN.** 6 to 12 digits, Argon2id under a pepper derived from the key directory's secret.
    - Every attempt is spent in the account row's transaction before it is checked, so parallel
      guesses cannot exceed the limit.
    - 5 free attempts, then locks of `60 s · 2^(k-1)` up to a week; unusable after 20 until the
      primary sets a new PIN.
    - The comparison is constant-time.
  - **Passkeys.** Songbird's own verifier (about 400 lines, fuzzed): ES256 and EdDSA; no
    attestation trusted; user verification required by default; signature counters
    compare-and-swapped. Registration takes a single-use challenge. The link assertion's
    challenge is derived from the link transcript, so it needs no server state and cannot be
    replayed onto another link.
  - **Only the primary** manages factors.
  - **Multiple accounts.** Each account on an installation is its own account on the server, with
    nothing shared. A shared APNs token links them at the push service; this is documented, and
    per-account registrations are used where the platform allows.
- Evidence:
  - the W3C WebAuthn Level 3 test vectors (ES256 with no attestation, Ed25519 with packed
    attestation) pass, with their refusals;
  - `racing_pin_guesses_never_exceed_the_free_attempts` (40 parallel guesses: 4 checked);
  - live HTTP tests for PIN lockout, passkey linking and account isolation;
  - fuzz `devices` (now including WebAuthn).
- Consequences: no new dependency (`serde_json` is added to `songbird-keys` from the workspace).
  `[api.keys.devices]` gains PIN and WebAuthn settings, and passkeys stay off (503) until
  `rp_id` is set.

## D-0052 — Prompt 3, milestone 4: QR provisioning, linking with a confirmation the server cannot forge, and a signed, versioned device list

- Date: 2026-11-15
- Status: accepted; built (report P03-M4, PR #52); **gate approved by the owner on 2026-11-15**
  ("Approve both"), with its four threat-model rows
- Decided by: owner for scope (M4 split: PIN, passkeys and multiple accounts in M4b, 2026-11-15)
  and the limit (primary + 5, D-0047); design by agent under the owner's standing instruction
  (Proton-level bar)
- Context: Prompt 3, "Devices": QR provisioning through a short-lived channel that sees only
  ciphertext; a signed, versioned device list the server refuses to roll back; device limits;
  removal with "device list changed" frames and a hook for Prompt 5's MLS removal.
- Options considered:
  - Signal's model (the primary sends the account identity private key to the new device) was
    rejected: every linked device could then sign device lists. Here only the primary holds the
    account identity key, and every device has its own identity key (D-0048).
  - Linking authenticated by the token alone was rejected. The server sees the token in the link
    request, so it could link keys of its own. The new device also MACs its keys under a
    confirmation key that only the sealed provisioning message carries. The primary checks the
    tag before vouching for the device.
  - An unsigned list kept by the server was rejected: the server could add devices.
  - The server notifying contacts was rejected: it keeps no social graph (sealed sender comes in
    M5). Only the account's own devices are notified; contacts learn through the send path's
    device check and list fetches.
- Decision:
  - **Provisioning channel** in `valkey-hot`: a 128-bit bearer ID under a keyed hash; one message
    of at most 4 KiB, written once, read once (long poll up to 25 s), gone after ten minutes.
    Sealing is client-side (`songbird_keys::provisioning`: X25519, HKDF-SHA256, AES-256-GCM); the
    server never holds a provisioning key.
  - **Link tokens**: 256-bit, hash stored, single use, ten minutes, primary only. A token
    reserves a server-chosen device ID and counts toward the limit while outstanding.
  - **Link request**: both new keys proven (Ed25519 and XEdDSA) over a transcript binding the
    token, the device ID and the server, plus the confirmation tag. The identity key is fixed at
    link time.
  - **Pending devices**: a linked device authenticates at once, but is outside the send check
    and its keys are not served until a list signed by the account identity key names it
    (`Directory::with_pending`; key fetches skip it).
  - **The device list**: binary, at most 16 entries, Ed25519 by the account identity key over a
    domain-separated body, versions strictly increasing. The server checks the signature, the
    account, the limit, the version, and that every entry matches an enabled device's stored keys
    with the right primary flag. Devices left out are disabled in the same transaction, and a
    `DeleteDevices` outbox job deletes them from every store as account deletion does.
  - **Removal**: by a list, or a linked device removing itself; never the primary (nor a legacy
    first device without the flag).
  - **Account-wide authority** (found by the security review): before M4 every account had one
    device, so `DELETE /v1/account`, usernames and invites never asked which device called. Now
    **only the primary deletes the account** (checked in the deletion's transaction), and **a
    pending device changes nothing account-wide** (usernames, the username key and link,
    invites). Otherwise a device linked by phishing a QR scan could delete the account
    irreversibly before the primary removes it. Listed linked devices keep the account-wide
    changes they had (M4b's second factors may narrow this).
  - **Device limit** under races: every change to an account's devices writes the account row
    in its transaction, so concurrent changes conflict and retry.
  - **Notices**: `DeviceListChanged` (system notice kind 1, signed by the system key) to the
    account's other devices on link, list and removal.
  - The MLS removal hook for Prompt 5 is the `DeleteDevices` job and the list change: removed
    devices are named by the list diff that clients see.
- Evidence (Apple M5 Pro, macOS 27.2.1; compose stack under podman; report P03-M4):
  - `crates/accounts` `devices_live` (6). Among them, **40 concurrent token requests over eight
    connections for a limit of 6 grant exactly 5; without the account-row write all 40
    succeeded**.
  - `services/api` `devices_live` (4): the QR flow over HTTP, every refusal, throttles.
  - `tests/e2e` (2): the notice over a WebSocket and the send check before and after listing;
    removal verified across every store.
  - Unit tests of the formats, proofs, provisioning seal and directory.
  - Fuzz `devices` (60 s, 1,611,017 runs).
- Consequences:
  - Losing the primary means deleting the account until M4b's recovery and a primary transfer
    exist.
  - Until key transparency (M6), a first-time contact trusts the server for the account identity
    key.
  - A registry restore brings back devices removed after the backup; clients refuse the old list
    as a rollback, and the primary must sign again.
  - New settings `[api.keys.devices]` with defaults. No new dependency.

## D-0051 — Prompt 3, milestone 3b: MLS KeyPackages checked by Songbird's own parser, bound to the uploading device, served once

- Date: 2026-11-15
- Status: accepted; built (report P03-M3b); **gate approved by the owner on 2026-11-15** ("Approve
  both"), with its threat-model row
- Decided by: owner (own focused parser over OpenMLS on the server, 2026-11-15); design by agent
- Context: Prompt 3: "Same pattern for MLS KeyPackages (single use, plus a last-resort package)";
  the plan said "parsed and signature-checked with OpenMLS", and the owner split this out of M3
  to evaluate that first.
- Options and evidence: OpenMLS 0.9.2 with `openmls_rust_crypto` resolves to **194 crates, about
  109 new to the tree**, including RustCrypto and libcrux (two more cryptography stacks),
  `bindgen` and `clang-sys` at build time, and `rayon`; a focused parser needs none (Ed25519 and
  X25519 checks already in `songbird-keys`, aws-lc-rs for signatures and SHA-256). Opaque storage
  (size only) would let a device publish packages naming another device.
- Decision (the owner's choice): **Songbird's own parser** (`crates/keys/src/mls.rs`, about 400
  lines, fuzzed) checking RFC 9420's encoding strictly, mls10, ciphersuites `0x0001`/`0x0003`,
  honest keys (init ≠ encryption key), a **basic credential naming the uploading device**,
  capabilities, a current and bounded lifetime (≤ 100 days), and both `SignWithLabel` signatures;
  `last_resort` (extension type 10, as OpenMLS writes it) decides which packages are last resort,
  so no client flag can disagree with the package; storage under `KeyPackageRef`. The credential
  identity is the 16-byte device ID (Prompt 5 maps devices to accounts through the signed device
  list, M4).
  - Proven against OpenMLS: `tools/openmls-vectors` (outside the workspace) makes packages with
    OpenMLS; Songbird accepts its X25519/Ed25519 ones with OpenMLS's own `KeyPackageRef`,
    recognises its last-resort one, refuses its P-256 one, and refuses every single flipped byte.
  - An encoder (`mls::encode`) for clients and tests; the checker accepts what it builds.
  - Storage and claims as M3's prekeys (D-0050): single-use packages claimed by deleting one
    record; expired ones never served and swept; the last-resort one beyond them; the same
    throttles (separate records) and per-target budget; `KeyPackagesLow` (system notice kind 3).
  - No new dependency.
- Evidence (Apple M5 Pro, macOS 27.2.1; compose stack under podman; report P03-M3b):
  `mls_vectors.rs` (OpenMLS packages; every flipped byte); `mls` unit tests (minimal varints,
  `SignContent`, encode/check); `crates/accounts` live (single use, expiry, last resort, bounds,
  deletion; **400 concurrent claims over eight connections, two rounds: each package served
  once, none twice, none lost**); `services/api` `keys_live` (bound to the device, served once,
  every refusal); fuzz `keypackages` (60 s, 2,041,036 runs).
- Consequences: the server accepts only X25519/Ed25519 ciphersuites until Prompt 5 decides on a
  post-quantum one (issue #24); the allow-list is one constant to extend. Clients must still
  validate KeyPackages fully.

## D-0050 — Prompt 3, milestone 3: the PQXDH key directory; XEdDSA and ML-KEM-1024 checked on upload; one-time prekeys claimed exactly once

- Date: 2026-11-15
- Status: accepted; built (report P03-M3); **gate approved by the owner on 2026-11-15** ("Approve
  both"), with its two threat-model rows
- Decided by: owner for scope (M3 split: MLS KeyPackages in M3b) and the post-quantum format
  (ML-KEM-1024 only); design by agent under the standing instruction (D-0041)
- Context: Prompt 3's key directory: per device an identity key, a signed prekey, a last-resort
  post-quantum prekey, one-time EC and post-quantum prekeys as libsignal's PQXDH needs; one-time
  prekeys claimed atomically and never handed out twice; refill signals; signature validation;
  exhaustion protection (rate limits per requester and per target). Its gate: concurrency tests
  that prove no one-time prekey is ever served twice under parallel claims.
- Owner's decisions (2026-11-15): **split M3**, MLS KeyPackages (and the OpenMLS question) in
  M3b; **ML-KEM-1024 only** (type `0x0A`, the NIST standard), not libsignal's default
  pre-standard Kyber1024 (`0x08`).
- Decision:
  - **Formats are libsignal's** (X25519 `0x05 || u`, ML-KEM-1024 `0x0A || ek`, XEdDSA over the
    serialization), so a PQXDH implementation reads them unchanged.
  - **XEdDSA implemented from libsignal's code and specification** (D-0047), in `crates/keys`:
    libsignal and Songbird agree byte for byte (same public key from a private key, the same
    signature for the same randomness) and each verifies the other's signature. Stricter than
    libsignal in one place: `s` must be canonical (libsignal reduces any `s` below 2^253), so a
    signature has a single encoding; honest signers are unaffected.
  - **Every key checked before storing**: X25519 keys honest (canonical, on the curve, prime
    order); ML-KEM keys pass FIPS 203's modulus check. Found while building: **aws-lc-rs 1.19
    accepts an encapsulation key with a coefficient ≥ q**, so the check is ours, with a test
    that asserts aws-lc-rs's behaviour (as M1's for its Ed25519 identity-point forgery).
  - **The identity key is set once per device** and never replaced; a new identity is a new
    device (M4's signed device list, M6's key transparency).
  - **Claims**: one transaction-free delete per attempt, `DELETE ONLY otpk:[device, id] RETURN
    BEFORE`, among up to 16 random candidates: whoever deletes the record gets it; a racing claim
    gets nothing or loses the write conflict and tries another. Proven by the gate test (400
    concurrent claims over eight connections, three rounds: every one-time key served once,
    none twice, none lost), whose power was checked by a deliberately non-atomic claim (read,
    then delete): it served a key twice and the test failed at once.
  - **Exhaustion**: fetches 240 an hour per requesting account (burst 60) and 1,200 per IP range;
    one-time claims 60 an hour per target account across all requesters (burst 30), beyond
    which fetches answer with the last-resort key only, leaving the one-time keys for later.
  - **Refill**: a device left below 10 one-time keys of either kind gets a system notice, kind 2
    `PrekeysLow` (`ec u16 | kem u16`), signed by the system key (D-0044) and sent through the
    send path `api` already links, at most once an hour (a keyed one-hour mark in
    `valkey-hot`). `Submit` gains `system` for it. The system key is optional configuration:
    without it (or without `[api.send]`) clients rely on `GET /v1/keys`.
  - **Deletion**: an account's devices' one-time prekeys are deleted with it and counted by the
    worker's verification.
  - Moved from the plan's M3 row: the send path's `stale` list (D-0026) needs device-list
    versions, which M4's signed device list brings.
  - No new dependency (`curve25519-dalek` and aws-lc-rs's ML-KEM, both in the tree).
- Evidence (Apple M5 Pro, macOS 27.2.1; compose stack under podman; report P03-M3): the gate test
  above; `crates/keys` XEdDSA (tampering, a non-canonical `s`, dishonest keys) and ML-KEM tests;
  `xeddsa_vectors.rs`; `crates/proto` key formats (strict decoding, the longest upload);
  `crates/accounts` live (identity once, bounds, duplicates, last-resort fall-back, deletion);
  `services/api` `keys_live` (4) and `keys` unit test (every kind of tampering refused);
  `tests/e2e` `a_device_low_on_prekeys_is_told_once`; fuzz `prekeys` (60 s, 641,996 runs).
- Consequences: a client stack must speak ML-KEM-1024 (libsignal's `mlkem1024` feature, if a
  client uses libsignal). Sessions started after a target's one-time budget is spent use the
  last-resort key (no one-time X25519 key): the PQXDH spec's degraded but defined mode.

## D-0049 — Prompt 3, milestone 2: unique usernames as Ristretto hashes with poksho proofs, a username key that never confirms existence, resettable links

- Date: 2026-11-15
- Status: accepted; built (report P03-M2); **gate approved by the owner on 2026-11-15** ("Approve
  both"), with its four threat-model rows
- Decided by: owner for the product choices (below); design by agent under the standing
  instruction (D-0041)
- Context: Prompt 3: "Usernames are changeable and found only by exact match. Evaluate
  libsignal's username scheme (the server stores a hash plus a proof, never the username
  itself) and adopt it unless a recorded reason says otherwise. Username lookups are
  rate-limited per account and per IP range", plus WhatsApp's username key. D-0047: implement
  Signal's protocols, do not link libsignal.
- Owner's decisions (2026-11-15):
  1. **Unique handles**, one person per name, as WhatsApp's. The owner first chose Signal's
     `nickname.NN`, then asked how other companies and Proton would do it, and chose unique
     handles "built Signal-grade underneath". The reasons, as put to the owner: the
     discriminator buys little privacy (the hash cannot be salted, and two digits multiply a
     guess by about 99), invites look-alike impersonation (`radu.42` and `radu.24`), and Discord
     dropped discriminators in 2023 because people could not remember them; the username key
     (WhatsApp's answer to enumeration) presumes unique names; WhatsApp switchers expect them.
  2. **A missing or wrong username key answers exactly like "not found".**
  3. **Resettable username links** are built.
- Recorded reason for departing from libsignal's scheme: with unique handles there is no
  discriminator, so libsignal's hash (three generators over nickname, discriminator and a
  SHA-512 scalar) and its statement do not apply. Songbird keeps the construction and changes
  only what the format forces:
  - `hash = s·G`, `s = SHA-512("songbird.v1/username\0" || lower-cased name) mod l`, `G` squeezed
    from libsignal's SHO under a Songbird label (nobody knows its discrete logarithm);
  - the claim proof is a standard **poksho** proof (poksho's label, statement encoding,
    transcript and nonce derivation) of `hash = s·G`.
- Evidence of compatibility (libsignal at commit `8be00c2`, AGPL, built only in a scratch tool
  outside the workspace, `tools/libsignal-vectors`):
  - Before the format changed, this implementation with libsignal's own constants reproduced
    libsignal's username hashes and proofs exactly: 12 of 12 (the SHO sequence, six names with
    hash and proof at fixed randomness, five more hashes), proof nonces included.
  - After: `Sho` matches libsignal's published vector and a longer sequence (tests); libsignal's
    poksho produces, for Songbird's statement and randomness, the same generator, hash and proof
    bytes as Songbird, and verifies Songbird's proof.
- Design:
  - **Format:** 3 to 32 ASCII letters, digits, `_`, `.`; starts with a letter; no `..`, no final
    `.`; unique in lower case. ASCII only (no look-alike letters from other scripts).
  - **Claims** (`PUT /v1/username`): proof checked, reserved names refused by hash, one
    transaction (racing claims conflict and retry); the previous name is **held 30 days**,
    naming no account, so nobody can grab it to pose as its owner; the link goes. Every attempt
    spends a per-account budget (2 an hour, burst 5), so probing which names are taken is slow.
  - **Lookups** (`POST /v1/username/lookup`, signed; the hash in the body, never a URL): exact
    match; 120 an hour per account, 600 per IP range; one answer, 404, for unknown, held, key
    missing, key wrong and budget spent; the registry reads the same rows whether or not the
    name exists; a keyed lookup always runs one Argon2id check (against a dummy verifier when
    nothing is to be checked) and always makes one atomic check-and-spend of the name's guessing
    budget (a single Lua step, so concurrent guesses cannot share a token; found by the review).
    An account being deleted is found by nobody.
  - **Username key:** 4 to 10 digits; `salt || Argon2id(19 MiB, t = 2, secret = pepper)`; the
    pepper and the throttle key by HKDF from `[api.usernames] secret` (secrets store). Key
    guesses that find nothing: 1 an hour per username across all requesters, burst 10.
  - **Links:** the server stores up to 256 bytes of ciphertext under a new random 16-byte handle
    per upload (a reset), deleted with a username change or the account; it never sees the key.
  - **Deletion:** account deletion holds the username (no account named) and deletes the link;
    the worker's verification counts both; the worker sweeps holds that ended.
  - No new dependency: `curve25519-dalek` (D-0048) with its default features still off; `argon2`
    (D-0048) now also in `api`.
- Evidence (Apple M5 Pro, macOS 27.2.1; compose stack under podman; report P03-M2):
  `crates/keys` username tests (rules, tampering, a non-canonical scalar, case) and vectors;
  `crates/accounts` live: unique, held, swept, 16 racing claims with one winner, keys, links,
  deletion (3 of 3 runs); `services/api` live `usernames_live` (6), including keyed lookups at
  the production Argon2id cost taking the same time whether or not the name exists (means
  0.1916 s against 0.1926 s in a debug build, ratio 0.995); fuzz `username` (60 s, 653,381 runs,
  nothing found).
- Consequences: the server holds username hashes, which anyone can test guesses against; a
  common name is found by trying it (recorded in the threat model). Name disputes and
  impersonation by people are an abuse process (Prompt 11). Key transparency (M6) will publish
  username hash to identity key, so a recycled name shows a new key.

## D-0048 — Prompt 3, milestone 1: registration with Argon2id proof of work, honest keys only, invites that record no social graph

- Date: 2026-11-15
- Status: accepted; built (report P03-M1); **gate approved by the owner on 2026-11-15**, with
  its four threat-model rows
- Decided by: agent, under the owner's standing instruction (D-0041) and the Prompt 3 decisions
  (D-0047)
- Context: Prompt 3 asks for accounts without phone numbers, an Argon2id proof of work "tuned so
  a phone solves it in a few seconds", per-IP-range throttles, and (D-0038) an invite-only launch.
  Until now accounts were created only through `api`'s admin link (D-0036); D-0018 left open
  whether the device authentication key stays separate from the identity key.
- Decision:
  - **Keys.** An account has an **account identity key** (Ed25519, aws-lc-rs; it will sign the
    versioned device list in M4 and is what users verify and key transparency publishes, as
    WhatsApp's account signature key is). Each device keeps a separate **authentication key**
    (answers D-0018: a transport credential, rotatable without touching identity, never used end
    to end) and, from M3, its own device identity key for PQXDH. The server draws account and
    device IDs.
  - **Only honest public keys.** Every Ed25519 key the server stores must be the canonical
    encoding of a prime-order point (`crates/keys`, on `curve25519-dalek`). Found while building:
    aws-lc-rs 1.19 accepts a signature under the identity point for any message (`R = sB`), and
    with it anyone could authenticate as a device registered with that key. The admin link now
    refuses such keys too.
  - **Proof of work** (`crates/pow`): stateless challenges (51 bytes, HMAC tag from the
    registration secret, 10-minute life, single use by burning the nonce in `valkey-hot`);
    `solutions` strictly increasing counters, each an Argon2id(v1.3, `m`, `t`, p = 1) output with
    `bits` leading zeros. Several easy solutions instead of one hard one keep a phone's time
    predictable. Defaults 16 MiB, t = 1, 4 bits, 8 solutions (128 evaluations). The server checks
    everything cheap first (length, throttles, tag, age, keys, signatures), burns the nonce, then
    verifies off the runtime with bounded concurrency, stopping at the first failure.
  - **Throttles:** GCRA in `valkey-hot` on Valkey's clock, under HMAC keys of the IP range
    (IPv4 `/24`, IPv6 `/48`, IPv4-mapped folded), per range and deployment-wide, for challenges,
    registrations and refused invite codes. Fail closed.
  - **Invites** (D-0038, D-0047): 120-bit codes (24 Crockford symbols), stored as
    `SHA-256("songbird.v1/invite\0" || code)` with uses and expiry only; one transaction consumes a
    use and creates the account (SurrealDB's write conflict lets one of several racing
    registrations commit; the others retry). Users create single-use codes from an allowance (5,
    configurable); operators create batches with `songbird-admin invites create`. One answer for
    every refused code; revocation by whoever holds the code. Invite-only mode is a setting.
  - **New devices and the directory:** delivery reloads the registry within a second, so a client
    connecting right after registering can be refused (4000). Rather than let unauthenticated
    connections trigger registry lookups on delivery, clients retry 4000 for 10 s after
    registering (`ClientConfig::new_device_grace`; PROTOCOL.md §4.1). Found by the end-to-end
    test.
  - **Privacy Pass, evaluated as a later option:** blind-signed tokens (RFC 9576–9578) would let
    a trusted issuer vouch for "a human passed a check" without linking the check to the account.
    Today there is no issuer to trust and no check other than the proof of work and invites, so
    tokens would add a protocol and a key to rotate for nothing; revisit when the launch opens
    (a token per verified device attestation, App Attest / Play Integrity, is the likely issuer)
    or when proof of work stops deterring bots.
- Dependencies (new to the tree, each with its reason):
  - `argon2` 0.6.0 (RustCrypto, MIT OR Apache-2.0), the prompt's Argon2id; aws-lc-rs has none.
    Default features off (`alloc` only). Brings `blake2` 0.11.0 and `base64ct` 1.8.3 (compiled);
    `password-hash` and `phc` appear in `Cargo.lock` only (optional, not enabled). Contains
    `unsafe` (aligned allocation of the memory blocks, segment views for lanes); read in the
    pinned source. Output checked against the reference `argon2` command (vector in PROTOCOL.md §13).
  - `curve25519-dalek` 5.0.0 (BSD-3-Clause), default features off: point decompression and
    order checks aws-lc-rs does not expose; the library the owner's D-0047 names for XEdDSA and
    the username hash. `curve25519-dalek-derive` (x86-64 backend) and `fiat-crypto` (an optional
    backend, lock only) come with it.
  - All eight are **exempted in `cargo vet`** pending audits (no imported audit covers these
    versions), like the other client libraries (D-0016); audit backlog: argon2 4,022 lines,
    blake2 1,561, base64ct 3,651, curve25519-dalek 38,745.
- Evidence (Apple M5 Pro, 18 cores, 48 GiB, macOS 27.2.1; compose images as pinned, under
  podman; report P03-M1):
  - Argon2id per evaluation (release, one core, median of 41): 4 MiB 1.39 ms, 8 MiB 2.25 ms,
    16 MiB 4.23 ms, 32 MiB 9.08 ms; t = 2 at 16 MiB 8.17 ms. Default parameters: solve over 30
    challenges p10 0.29 s, median 0.48 s, p90 0.76 s, max 0.82 s; verification of all 8 solutions
    31.4 ms. A phone core is several times slower than this Mac's; "a few seconds" there is an
    estimate until the apps exist, and challenges carry their parameters, so retuning needs no
    client release (`cargo run --release -p songbird-pow --example timing`).
  - Tests: `crates/pow` (4, vector), `crates/keys` (4), `crates/proto` registration (5 plus the
    §13 vector test), `crates/accounts` live (4 new: registration, invites valid/expired/used
    up/unknown/revoked, 24 racing registrations for 1 and 5 uses, allowance and no issuer; 3 of 3
    runs), `services/api` live `registration_live` (8: the D-0038 invite cases, guessing
    throttled before any work, quota and revocation, mode off, replay/forgery/wrong work, keys,
    throttles, no configuration), `tests/e2e` `registration` (registered accounts connect and
    talk; a stranger still stops); fuzz targets `registration_request`, `pow_challenge`,
    `ed25519_key` (60 s each: 32.5 M, 14.6 M, 3.4 M runs, nothing found).
- Consequences: delivery is deployable without operator steps for accounts. Four threat-model §1
  rows, approved by the owner on 2026-11-15. Phone timing to measure when the apps exist. A registry restore revives
  invite codes used after the backup until they expire. Per-range throttles count everyone
  behind one carrier NAT as one client (generous numbers, deployment-wide caps behind them).

## D-0047 — Prompt 3: the plan, and the owner's decisions it needed

- Date: 2026-11-15
- Status: accepted (owner, 2026-11-15)
- Decided by: owner (each answer below), on the agent's plan `docs/reports/P03-plan.md`
- Context: Prompt 3 leaves the inactivity period and the inviter link (D-0038) to the owner;
  issue #23 asks the owner how people find each other; and the prompt asks for libsignal's own
  crates, which are AGPL-3.0-only (root `Cargo.toml`, checked 2026-11-15) and not published on
  crates.io by Signal (the crates.io `libsignal-protocol` is an unrelated 2019 crate), while
  `deny.toml` admits permissive licences and crates.io sources only.
- Decisions:
  1. **Plan agreed:** seven milestones, each with its own branch, pull request, report and
     decision: M1 registration and invites; M2 usernames; M3 key directory (the concurrency
     gate); M4 devices, PIN, passkeys; M5 profiles and sealed sender; M6 key transparency; M7
     GDPR and the Prompt 3 gate.
  2. **libsignal: implement the protocols, do not link the library.** The server verifies
     XEdDSA, the Ristretto username hash and proof, and key formats with permissive crates
     (`curve25519-dalek`, aws-lc-rs's ML-KEM), byte-compatible with libsignal, proven by vectors
     generated from libsignal by a tool outside the workspace. The repository licence stays open.
     (The same question returns for the apps.)
  3. **Inactivity deletion:** the user chooses 6, 12 or 24 months; default 12; a warning notice
     before deletion (built in M7).
  4. **Who invited whom: not stored** (D-0038's default); only each account's remaining
     allowance. Abuse is handled on the abusive account.
  5. **Contact discovery (issue #23): none from address books.** People find each other by exact
     username, invite link or QR code; the server holds no address books.
  6. **Two-step PIN:** Argon2id with a per-account salt plus an HMAC pepper held in the secrets
     store (not in the database or backups), at least 6 digits, attempt limits with lockout.
     It stops a database or backup thief, not a fully compromised `api`; hardware guess limits
     are issue #26 (Prompt 10). A server that learns a PIN still cannot add a device unnoticed:
     the device list is signed by the account identity key.
  7. **Device limit until Prompt 11's plans:** one primary and 5 linked devices, configurable.
  8. **Prompt 2's final gate:** the owner asked for a report against the master prompt's
     definition of done; it was written and approved the same day in another session
     (`docs/reports/P02-final.md`, with the two M5 threat-model rows).
- Consequences: Prompt 3 departs from the prompt's "libsignal's own crates" with this recorded
  reason; the vectors from libsignal carry the compatibility proof. No address-book upload
  endpoint will exist.

## D-0046 — The repository moves to the `songbirdchat` organization and becomes public; domain `songbird.chat`

- Date: 2026-11-14
- Status: accepted (owner); done on 2026-11-14: the repository is `songbirdchat/songbird` (GitHub
  Free organization) and **public**.
- Decided by: owner (created the organization `songbirdchat` and registered `songbird.chat`;
  `songbird` and `getsongbird` were taken on GitHub). Organization name matches the domain.
- Decision: the repository's home is `github.com/songbirdchat/songbird`; images are published to
  `ghcr.io/songbirdchat/<service>`. Every reference in the tree points there (`Cargo.toml`
  `repository`, `deploy/ansible/group_vars/all.yml` registry, `deploy/bin/verify-release` default,
  `deploy/proxy` image and its cosign identity, `deploy/ci-runner` registration,
  `scripts/github-setup`, the security-advisory link). `CODEOWNERS` keeps `@countradooku`: it names
  the owner as a person. Reports under `docs/reports` keep the old name as history.
- Consequences:
  - Release signatures are keyless (D-0013): the certificate identity is the workflow path in the
    repository, so `cosign verify` checks `https://github.com/songbirdchat/songbird/...`. No release
    has been made yet, so no signature carries the old identity.
  - Public: anyone can read the code and open pull requests, so CI runs only on GitHub-hosted
    runners (D-0045). Checked on 2026-11-14 before and after: no secret in any of the 136 commits
    (pattern scan for age, PEM, GitHub, AWS, Google and Slack keys; the hits are AWS's published
    example key and PEM templates in tests), and none of the APNs or FCM identifiers. Public with
    it: the runner host's name in D-0039, commit author e-mail addresses, the full design and
    threat model (by intent: security rests on keys, not on secrecy of the design).
  - Write access: the owner (admin) and one collaborator (write) on 2026-11-14.
  - `scripts/github-setup/setup.py` finds the project board through the `ProjectV2Owner` interface,
    which matches an organization as well as a user; the board on the personal account is not
    moved by it (a new one is created under the organization when the script runs).
  - Which names under `songbird.chat` serve clients and proxy links is still open (D-0011).

## D-0045 — CI on GitHub-hosted runners only, for a public repository; self-hosted runners retired

- Date: 2026-11-14
- Status: proposed: implemented on branch `ci/hosted-public` (which also merges D-0039's branch,
  PR 37, for its scripts and the rootless Autobahn option); accepted when the owner merges it.
- Decided by: owner ("i dont have money for that, we must continue locally"; then moved the
  repository to `songbirdchat` and made it public, D-0046; "Yes, rework it" for hosted runners);
  layout by agent.
- Context: D-0039's runners were never merged into `main`, so Prompt 2's pull requests (M2 to M7
  and the send library) ran every `ci` and `codeql` job on GitHub-hosted `ubuntu-24.04` while the
  repository was private. From 2026-11-12 to 2026-11-14 that billed **4,178 minutes** (job start
  and end times, rounded up per job): `ci` on pull_request 1,881 (56 runs), `codeql` on
  pull_request 863, `ci` on push to main 770, `codeql` on push 424, `nightly` 158. The free 2,000
  minutes went, then the overage; at 07:32 UTC on 2026-11-14 every job failed before starting
  ("recent account payments have failed or your spending limit needs to be increased", run
  43571585635). A first version of this decision moved everything to the self-hosted runners.
  The owner then made the repository public. That changes both sides: standard GitHub-hosted
  runners cost nothing for a public repository (the 08:59 UTC nightly, run 43578342236, ran its
  12 jobs on hosted runners after the 07:32 refusals), and anyone can now open a pull request
  whose code, and whose copy of the workflows, would run on whatever runner it names, including
  a persistent self-hosted runner on a shared VPS. GitHub advises against self-hosted runners for
  public repositories. Storage limits stay: Actions cache 13.2 GB against 10 GB (rust-cache 11.6 GB
  in 15 entries, 7.6 GB of it from pull-request branches; image layer caches 1.6 GB in 199
  entries).
- Options considered: self-hosted runners for every job with a same-repository guard (a fork's
  pull request can delete the guard in its copy of the workflow; outside code on a machine that
  keeps state between jobs); self-hosted for scheduled jobs only (`workflow_dispatch` still lets
  any writer run any branch there); GitHub-hosted runners for everything (chosen: free, a fresh VM
  per job, nothing of ours to compromise).
- Decision:
  - **Standard GitHub-hosted runners only**, pinned image `ubuntu-24.04` (the `-arm` variant is
    allowed). No self-hosted runner, no larger runner (billed even for public repositories), no
    `-latest`. The D-0039 runners are not registered for this repository.
  - **Pull requests from forks run CI** like any other: with a read-only token
    (`contents: read`, `persist-credentials: false`), no secrets, and no `pull_request_target` or
    `workflow_run`. Secrets appear only in `release.yml` and `deploy.yml`, which run only on a
    pushed tag or by hand. Approval before an outside contributor's workflows run is a repository
    setting for the owner (recommended: all external contributors).
  - **Triggers:** `ci` (quality bar, compose integration, Autobahn, Semgrep, IaC) on pull requests
    and pushes to `main`, docs-only changes skipped. CodeQL (Rust and Actions, security-extended)
    on pull requests, pushes to `main`, weekly and on demand; it still fails on any finding
    (D-0015) and, outside pull requests, uploads to code scanning, which a public repository has
    for free (the API answered "no analysis found", not D-0015's 403). Container images moved out
    of `ci` into `images.yml`: pull requests that touch `deploy/docker/**` or the workflow,
    nightly at 02:23 UTC, and on demand (six builds of the whole workspace on every push before).
  - **Concurrency everywhere:** a new push to a pull request cancels its older `ci` and `codeql`
    runs; every commit on `main` is checked to the end; `images` and `nightly` runs supersede
    older ones.
  - **Storage inside the free limits:** `Swatinem/rust-cache` saves only on `main` (pull requests
    restore it); image builds use no Actions cache and upload no build record; `junit` and the
    Autobahn reports are uploaded only when the job fails, and nightly fuzz and benchmark
    artifacts are kept 14 days (the default was 90).
  - **Enforced, not remembered:** `cargo xtask workflows` (the first step of `cargo xtask ci
    fast`, `xtask/src/workflows.rs`) fails on a runner that is not a standard hosted Ubuntu image
    (self-hosted, a label list, an expression, `-latest`, a larger runner), on `secrets.` outside
    `release.yml` and `deploy.yml`, on those two gaining a trigger other than a pushed tag or
    `workflow_dispatch`, on `pull_request_target` or `workflow_run`, on an action not pinned to a
    full commit SHA (or a docker action without a digest), on top-level permissions other than
    `contents: read`, and on a workflow without a concurrency group (release excepted). 14 tests,
    one of them over the repository's own workflows; it rejects both `main`'s private-repo layout
    (21 violations under the first version's rules) and the self-hosted layout.
- Evidence: `cargo nextest run -p xtask` (14 passed); `cargo xtask ci fast` on the branch (macOS
  arm64, 2026-11-14): workflow policy, rustfmt, clippy, doctests, rustdoc, deny, audit, vet and
  smoke pass; nextest 357 of 359, the two failures being Linux-only behaviour that fails the same
  way on `main` on macOS (`reuseport_listeners_share_the_port_and_the_connections`: macOS does not
  spread `SO_REUSEPORT` connections, `[0, 0, 0, 128]`; `inv7_bounded_and_validated_input`:
  `ConnectionClosed`); the minute, cache and run figures above from the GitHub API on 2026-11-14.
- Consequences:
  - CI costs nothing while the repository is public. If it goes private again, the free 2,000
    minutes return as the limit and this decision must be revisited before the next pull request.
  - D-0039 is superseded; its scripts stay for a private forge (Forgejo) later, never for this
    public repository.
  - Fork pull requests can spend our hosted time but not our money or secrets; the approval
    setting is the brake on abuse.
  - A broken image from a crate change shows up in the nightly `images` run, not in the pull
    request.
  - The owner should set the Actions budget to $0 with "stop usage" on the organization, so a
    larger runner or a return to private cannot bill anything.

## D-0044 — The send library: `api` stores on partition owners over node links, admitted for the store of a send only; system frames signed and in a reserved format

- Date: 2026-11-14
- Status: accepted; built (report P02-send); **approved by the owner on 2026-11-14** ("Approve
  both": this decision and its two threat-model rows).
- Decided by: agent, under the owner's standing instruction (D-0041: "think like someone from
  Proton or a big corp"), then approved by the owner; D-0037 left the route from `api` to the
  partition owners to decide when the send crate was built.
- Context: D-0037 replaced the internal Send API with a `send` library linked by `delivery`,
  `api`, `calls` and `worker`, plus `PUT /v1/messages`. The mailbox is Iggy with one owner node per
  partition (D-0029, D-0034); a send must be stored by its partitions' owners. `api` is the
  internet-facing service most likely to be compromised.
- Options considered for how `api` reaches the owners:
  - **(A) Admit `api.` certificates to the delivery nodes' node links**, as a delivery node that
    does not own a partition reaches the owner today. Same wire, same code path, one hop. Risk:
    the node link serves every mailbox operation and key-store copies.
  - **(B) A send link on delivery nodes that accepts `api.` and runs the send path there.** It is
    the internal network Send API the owner removed in D-0037 (a second protocol, a second hop,
    a second path that can drift from the WebSocket's).
  - **(C) `api` owns partitions or writes Iggy itself.** Puts key stores and the master key on the
    internet-facing host, and a second writer per partition; refused outright.
  - **(D) Queue sends in Valkey for a delivery node to store.** Acknowledging before the mailbox
    holds the send breaks invariant 1 (the database is the only durable truth); refused.
- Decision: **(A), with authorization per kind of peer**, so `api` gets exactly what it needs:
  - **Node links admit by role.** `songbird_link::serve_admitting` takes one handler per
    certificate-name prefix (prefixes must end with a dot); a peer is served only by its own
    kind's handler. Delivery nodes keep every operation; peers listed in
    `[delivery.cluster] senders` (only `api.`, `calls.`, `worker.` may be listed; default none)
    get a **store-only handler**: `Store` is served, everything else (`Fetch`, `Ack`, `Count`,
    `Expire`, `Forget`, `Known`, `KeyStore`, and `PartDone`) is refused and counted
    (`IggyMailbox::sender_requests_refused`, runbook entry).
  - **`api` holds no mailbox.** `IggySender` (in `crates/mailbox`) implements only the store
    (`StoreSend`, a one-method trait every `Mailbox` also has): no Iggy client, no key store, no
    master key, no lease, no membership. It reads the partition leases (one `MGET` every third of
    a lease; the lease value names the owner) and points each partition at its owner. It splits a
    send with the owners' own routine (`store_on`, shared with `IggyMailbox`) and the delivery
    nodes' idempotency secret, so a retry over the other transport is a replay. It never sends
    `PartDone`: the home partition's re-driver completes a sender's multi-partition bookkeeping
    (about 2 s later), so a compromised `api` cannot mark another send's part stored early.
  - **Routing from `api`** uses `ValkeyRouter::publisher`: the delivery nodes' channel naming and
    sealing, no subscriber connections.
  - **One send path.** `crates/send` holds the device-list check, the reserved-prefix and
    duplicate checks, the idempotent store, routing, push on offline (`Pusher`, moved from
    `delivery`) and the device directory (moved from `delivery`, re-exported there). `delivery`
    calls `SendPath::store`, writes `SendResult`, then `SendPath::route`, then flushes once: the
    same order and the same allocations as before; `SendPath` is a set of borrows (no `Arc`
    clone per send: a reference count shared by every core would be a contended cache line).
  - **`PUT /v1/messages`.** Body: a WebSocket `Send` frame byte for byte, under the same
    `LimitsConfig`. Signed like every `api` request, and **authenticated from the headers before
    the body is read** (the signature covers the declared digest; `Content-Length` required and
    bounded first). Answer: `200` with the `SendResult` frame the WebSocket would send; HTTP errors
    only before the send path. Rate limit: the WebSocket's per-device numbers, counted across all
    `api` nodes in `valkey-hot` by a GCRA on Valkey's clock, under a keyed hash of the device
    (key from HKDF of the router's cluster secret); fails closed.
  - **System frames** (`crates/proto::system`, signer in `crates/send::system`): server notices
    travel as mailbox envelopes (durable, ordered, pushed) in a reserved format: an 8-byte magic,
    the recipient device, issue time, random notice ID (the send's idempotency key), kind, a body
    of at most 1 KiB, and an Ed25519 signature by the system key over a domain-separated
    transcript. The send path refuses user envelopes that begin with the magic (new reject reason
    9, `ReservedEnvelope`), so system frames are never user messages in either direction. `proto`
    stays free of cryptography (clients verify with their own aws-lc-rs); the system key is not
    deployed until a service issues notices (Prompt 3: "device list changed").
- Evidence (Apple M5 Pro, 18 cores, 48 GiB, macOS 27.2.1; compose images as pinned, under podman;
  report P02-send):
  - Allocation gate unchanged: 5.20 allocations (798 bytes) per message, before and after
    (`server_allocations_per_message_stay_within_budget`, budget 5.5).
  - Live tests on Iggy, SurrealDB, Valkey and RustFS on this Mac: 217 of 218 in the compose job's
    first command (the exception, `inv7_bounded_and_validated_input`, failed identically on
    `main` on macOS; the test is now robust to how macOS reports a refused write),
    `songbird-api` 8, `songbird-jobs` 12, `songbird-push` 7; `cargo xtask ci fast` passes.
  - New tests: `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else` (Iggy cluster),
    `each_admitted_kind_of_peer_gets_only_its_own_handler`, five `send_api` end-to-end tests on
    Iggy (auth, limits and rate, idempotency across transports, offline push, system frames),
    send-path and system-frame unit tests with a fixed byte vector.
  - `bench/m7/suite.sh` on the VMPal VM `songbird-m7` (arm64, 12 vCPUs, kernel 7.0), `main`
    against this branch in one session, `IGGY_TMPFS=1`, checker PASS everywhere: steady p99
    2,339 against 2,124 µs, CPU per 10k messages 3.370 against 3.369 s, group p99 9,517 against
    9,991 µs, storm recovery 16.4 against 15.4 s; at 80,000/s (five runs each) p99 means 2,916
    against 3,056 µs, ranges overlapping (Mann–Whitney U = 8, not significant), server CPU per
    10k deliveries 0.427 s on both. No measurable cost from the extraction.
- Consequences: `api` can send with no new protocol and no extra hop, and can neither read nor
  delete anyone's messages; a compromised `api` can still store envelopes into mailboxes (as a
  compromised delivery node can: ciphertext recipients drop; threat model §6). `calls` and
  `worker` link the same crate and are admitted the same way when they send. Two threat-model
  rows, approved by the owner on 2026-11-14. A device using both transports has two rate budgets (at most
  twice the per-device rate).

## D-0043 — Milestone 7: the beta's load profile, how the targets are measured, where

- Date: 2026-11-13
- Status: accepted; results in report P02-M7. The owner approved the M7 gate on 2026-11-13,
  accepting this profile and the soak's move to the beta server.
- Decided by: agent, under the owner's delegation (D-0041: "think like someone from Proton or a
  big corp"); the master prompt leaves the targets to "validate and adjust with the owner"
- Context: M7's gate is "targets met, or gaps documented and accepted by the owner". The prompt
  states targets "at the beta's peak load" without defining that load, and the reference
  hardware (the beta server, a Hetzner `ccx33`: 8 dedicated vCPUs, 32 GB) does not exist yet.
- Decision:
  - **The beta's peak, defined.** 20,000 accounts at about 1.5 devices each: **30,000
    connections**, every one online at once (the worst case, not the average). **1,000 sends a
    second** 1:1 (about 4 messages a second for every 100 online people, several times a
    messaging app's evening peak) and **20 group sends a second** to 256-member groups (5,100
    deliveries a second). All with TLS 1.3 and the production session limits.
  - **What each target means, and how it is measured:**
    - *Server-side p99 send-to-deliver under 2 ms* is measured where it arises: from a `Send`
      frame read to the send durably stored, group commit included
      (`songbird_delivery_store_seconds`, a lock-free per-core histogram). Routing and the
      socket write add tens of microseconds. The load generator's client-observed latency is
      reported beside it as an upper bound.
    - *Recovery from a reconnect storm of every beta connection within 60 s, zero loss*:
      `loadgen --scenario storm` drops all 30,000 connections at once under peak traffic and
      times until the last device is connected again; the checker must pass.
    - *No allocation per message*: the M3 gate test stays (routing, writes and ACKs allocate
      nothing; the send path's five allocations are budgeted at 5.5).
    - *Cross-node p99 under 5 ms*: measured in M4 (cluster mode); not repeated unless the code
      on that path changes.
  - **Where:** a Linux VM on the owner's Mac (VMPal; Apple Silicon, arm64, 12 vCPUs, 32 GB,
    Ubuntu 26.04, kernel 7.0) runs the whole suite (`bench/m7/suite.sh`). It is not the
    reference hardware: an arm64 VM and a laptop. Its virtual disk takes about 9 ms per fsync
    (macOS flushes to its SSD on every one), so durable latency on it says nothing about a
    server's NVMe. The suite therefore runs Iggy's data in memory (`IGGY_TMPFS=1`) to measure
    the software path, as P02-M3 did, and the durable figure is a go-live check on the `ccx33`
    with the same command.
  - **Baselines:** each host class keeps its own baseline file; the suite fails when a tracked
    figure is more than 10 % worse. CI keeps the deterministic gates (allocations per message,
    the checker in every live test); timing gates need a quiet, fixed machine, so they run where
    the suite runs, not on shared CI runners.
- Results (report P02-M7):
  - **io_uring against epoll, measured again** (kernel 7.0, arm64, `bench/runtime-echo`): epoll
    9% faster on 1 core and 16% on 4, with lower p99. **epoll stays** (D-0028); io_uring adds
    kernel attack surface for a gain that is, at best, a few percent on other machines.
  - **mimalloc against glibc:** equal at light load, mimalloc's p99 27% lower at 80,000/s.
    **mimalloc stays.**
  - **ACK checkpoints** no longer take an Iggy write of their own under traffic; the beta's p99
    store latency dropped from ≤3 ms to ≤2 ms.
  - The 24-hour soak did not run (the owner's Mac cannot stay up a day). **The owner accepted the
    gap: the soak (`bench/m7/soak.sh`) runs on the beta server before launch**, a go-live check
    beside the durable-latency run of `bench/m7/suite.sh`.
- Consequences: the targets can be checked against definitions that are written down; the
  reference-hardware run (durable storage, x86) remains a go-live step.

## D-0042 — Hetzner only: off-site backups and OpenTofu state at Hetzner Object Storage

- Date: 2026-11-13
- Status: accepted (supersedes the provider choice in D-0040 and D-0041)
- Decided by: owner ("we dont use scaleway. only hetzner for now"); the agent designed the
  Hetzner setup
- Context: D-0040 and D-0041 put the off-site backups, and D-0009 the OpenTofu state of Hetzner
  environments, at Scaleway. The owner uses Hetzner only.
- Evidence (Hetzner's documentation, read 2026-11-13: Object Storage FAQ "Buckets & objects" and
  "S3 credentials"):
  - Object Lock with retention in **compliance mode**, set at bucket creation; versioning;
    lifecycle policies; console "Protection" against bucket deletion.
  - A key reaches every bucket **of its own project**; across projects, a bucket policy grants
    individual keys specific actions (`arn:aws:iam:::user/p<project>:<access key>`; `NotAction`
    is not supported). Keys are created in the console only.
  - Bucket settings take up to 15 minutes to apply everywhere.
- Decision:
  - **Backups:** Hetzner Object Storage in **Helsinki** (`hel1`), another location than the
    servers, so a site loss cannot take both.
    - Project `songbird-<env>-backups`: the bucket, and one key, the owner's admin key.
    - Project `songbird-<env>-backup-keys`: the writer, journal and verifier keys, and nothing
      else. The bucket policy grants writer and journal only `PutObject`/`PutObjectRetention`
      under `registry/` and `deletions/`, the verifier only reads and lists. So the data host and
      the worker still cannot read, list, delete or reconfigure, as in D-0040 and D-0041.
    - Compliance-mode Object Lock, versioned, expiry per prefix one day after its lock, console
      Protection on.
    - `deploy/bin/backups-up <env> apply` configures it (owner-run, AWS CLI against Hetzner's S3
      API; Hetzner Object Storage has no OpenTofu resources), and `check` proves with each key
      that Hetzner enforces every limit, the admin key unable to delete a locked version
      included, before the bucket is used. `deploy/bin/backups-policy selftest` runs in
      `validate-iac`. The Scaleway OpenTofu root is removed.
  - **OpenTofu state** of every environment: Hetzner Object Storage in Helsinki, in a project
    that holds only state.
  - **Code defaults:** `hel1.your-objectstorage.com:443`, region `hel1` (Ansible, `songbird-admin`,
    the worker's journal).
  - The Scaleway environment code (D-0009) stays, dormant, for a second provider later.
- Consequences: backups, state and servers share one provider and account. Different projects,
  keys and locations cover a compromised server, a lost location and operator error; they do not
  cover losing the Hetzner account itself (suspension, a legal order against Hetzner). Accepted by
  the owner for now. Cheap cover, optional: the owner downloads the newest monthly backup with the
  verifier key to an encrypted offline disk once a month (runbook step 10). Revisit when a second
  provider is added.

## D-0041 — Owner delegation of the M6 decisions; the deletion journal

- Date: 2026-11-13
- Status: accepted
- Decided by: agent, under the owner's explicit delegation ("i let you chose. think like someone
  from proton or a big corp"); the owner stated they have only a Hetzner VPS
- Context: report P02-M6 left five decisions to the owner: the gate, D-0040's four choices, the
  threat-model row for backups, a deletion journal, and what going live needs.
- Decisions:
  1. **M6 gate: approved under delegation, effective when PR #38's CI is green** (the bar the
     owner applied to M5). Met on 2026-11-13: 13 of 13 checks passed; merged as `d7894b5`. An author approving their own gate is weak separation of duties; the
     green CI on Linux, with the Iggy path and the new live tests, is the independent check.
  2. **D-0040's choices confirmed:**
     - RPO 5 minutes and RTO 2 hours for the registry.
     - **Superseded by D-0042 (owner: Hetzner only).** ~~Off-site at a different company from
       production.~~ Production is at Hetzner, so the backups go to Scaleway (EU, Object Lock in compliance mode, cents a month at this size).
       Backups at the production provider fail exactly when they are needed: account suspension,
       a legal order against the provider, a provider-wide incident. Hetzner Object Storage was
       not chosen even as a stopgap: nothing is deployed yet, so there is no gap to fill, and a
       stopgap tends to stay. If production ever moves to Scaleway, the backups move to the
       other provider (to build then).
     - The mailbox is never backed up.
     - The owner's identity is offline. A hardware key is not required: one paper copy in a
       safe, and one passphrase-encrypted copy (`age -p`) on a USB stick at a second place, the
       passphrase in the owner's password manager.
  3. **The threat-model row (deleted accounts in encrypted backups up to 93 days) is approved.**
     The master prompt's retention (7 daily, 4 weekly, 3 monthly) needs it; what makes it
     acceptable is that a restore can no longer bring a deleted account back (4).
  4. **The deletion journal is built.** Erasure (GDPR Art. 17, and the product's promise) must
     survive a restore.
     - Before deleting anything, the worker puts an empty tombstone in the backup bucket:
       `deletions/<time>-<HMAC-SHA256(journal key, account ID)>`, locked in compliance mode for 93
       days (as long as the oldest backup that can hold the account), expired the day after.
     - The worker's credential can only put under `deletions/` (bucket policy); it is required
       in staging and production (configuration validation), so no deployed worker deletes
       without a tombstone.
     - `songbird-admin backup restore` reads the journal key **before** restoring (no key: it
       refuses, unless `--no-journal`, which is audit-logged), then, after the import, starts the
       deletion again, through the outbox, of every restored account with a tombstone. The
       worker then clears every store again. Account IDs are random and never reused, so a
       tombstone's age does not matter; only `--before` (after a compromise) limits which count.
     - A tombstone holds no account ID: without the journal key a reader of the bucket learns
       only that some account was deleted at some time. That is a new §1 row, approved here.
  5. **Going live** needs, from the owner (provider per D-0042): the Hetzner backup projects
     and keys, the owner's age public key, and a second small Hetzner server for the
     verification environment (about EUR 4 a month). Nothing is deployed yet, so nothing is
     needed now.
- Evidence: `a_deletion_after_the_backup_survives_the_restore` (RustFS, SurrealDB, age: the
  account deleted after the backup comes back disabled with its deletion queued, the others
  untouched; a restore without the key refuses before touching anything);
  `account_deletion_is_verified_across_every_store` now also checks the tombstone and that it
  holds no identifier; the backups root's `tofu test` (journal writer limited to
  `deletions/*`).
- Consequences: the worker needs the journal's put-only key and the journal key; restores need
  the journal key (environment SOPS). A restore after a compromise uses `--before` for the
  journal too: tombstones written by an attacker holding the worker's key could otherwise
  delete accounts. Deployment templates for the services' own sections (the worker's included)
  are still to write; until then the validation refuses a deployed worker without the journal.

## D-0040 — Milestone 6: backups that hold no messages, age-encrypted off-site copies, store generation with client resend

- Date: 2026-11-13
- Status: accepted; built and measured in M6 (report P02-M6); the four choices below confirmed
  under the owner's delegation (D-0041)
- Decided by: agent under the owner's standing instruction ("think like a Proton founder")
- Context: master prompt §6 and milestone M6. What holds state that cannot be rebuilt changed
  since the prompt was written: the mailbox is Apache Iggy (D-0029) with per-message keys that are
  never backed up (D-0031); SurrealDB holds the account registry (D-0036); RustFS holds
  attachments (30 days at most) and, from Prompt 10, users' backup vaults.
- SurrealDB 4's recommended method (read 2026-11-13 in SurrealDB's "Backups & recovery" and
  `surreal db export` documentation): logical export (`surreal db export`, restored with
  `surreal db import`), optionally with volume snapshots; no point-in-time recovery or incremental
  backups (each export is one moment); copying SurrealKV files is safe only with the datastore
  closed; a dump holds no access signing keys and no record history (Songbird uses neither).
- Owner choices (recommendations, awaiting confirmation):
  1. Targets as proposed in §6: registry RPO ≤ 5 min, RTO ≤ 2 h; vaults RPO ≤ 24 h.
  2. Off-site, write-once copies at Scaleway Object Storage (Object Lock, EU), confirming D-0009.
     **Superseded by D-0042: Hetzner Object Storage, another project and location.**
  3. **The mailbox is never backed up.** Its envelopes could not be opened anyway (D-0031: keys
     never backed up); after a restore clients resend what has no delivery receipt (store
     generation). No message ciphertext outlives its delivery or 30 days in a backup.
  4. The age identity that can decrypt backups is held offline by the owner, in two places
     (a hardware key and a paper copy); never on a server.
- Decision (design):
  - **What is backed up:** the SurrealDB registry, by `surreal db export` every 5 minutes, through
    `songbird-admin backup`. Not backed up: the mailbox (above), Valkey (rebuilds itself; the
    outbox re-creates critical jobs), attachments (transient ciphertext; a resend after a restore
    re-uploads), secrets (SOPS in the repository already). Vaults join when Prompt 10 builds them.
  - **Encryption:** with the reference `age` tool (pinned, checksum-verified), to two recipients:
    the owner's offline identity and the restore-verification identity (below). No custom crypto.
  - **Off-site and immutable:** uploaded with S3 Object Lock in compliance mode, retention set
    per object (5-minute exports 24 h; the first export of each day 7 days, of each week 4 weeks,
    of each month 3 months), expiry by the bucket's lifecycle rule. The production credential can
    only put objects: it can neither read, list nor delete them, so a compromised server can
    neither read old backups (which hold deleted accounts until retention ends) nor destroy them.
  - **Daily restore verification:** not on production (a decryption key there would let an
    attacker recover deleted accounts from backups). This departs from the master prompt's
    "daily `worker` job" on purpose: the `worker` runs on production hosts. A separate verification job with its own
    read-only credential and its own age identity restores the latest export into a scratch
    SurrealDB, runs consistency checks (counts, references between devices and accounts, a sample
    of reads), and alerts when the latest verified backup is older than 24 hours. Its identity is
    rotated by re-encrypting nothing: new exports use the new recipient; old ones age out.
  - **Store generation:** stored in SurrealDB (`store:g`), read by delivery at startup
    and followed like the directory; every restore, and every loss of the mailbox, increments it
    (`songbird-admin generation bump`, part of the restore runbook). Clients that see it grow
    reset their cursor (built in M1) and resend every message without a delivery receipt from the
    last 30 days, reusing each message's idempotency key (a mailbox that survived replays it; a
    lost one stores it again); recipients drop repeats by the message ID inside the envelope.
  - **Drills:** `bench/m6/restore-drill.sh` times a full restore on the compose stack under load:
    back up, destroy SurrealDB and Iggy data, restore, bump the generation, let clients resend;
    the delivery checker must pass. The gate's timed drill runs it.
- Implementation (M6):
  - `songbird-admin backup run|verify|restore`, `generation show|bump`, `accounts import`;
    restore, bump and import need `--confirm <namespace>/<database>` and write an append-only
    audit log; restore only into an empty database.
  - **Restores trust the server's records, not the uploader's:** the writer key can put, and a
    put to an existing name makes a new current version on a versioned bucket, while the age
    recipients are public. So a compromised data host could replace an older backup with one
    of its own. Restores read the first stored version of each name, chosen by the server's
    `LastModified`; a name written twice, or a backup named for another time than it was
    stored at, fails verification and is never restored; `--before` restores from before a
    compromise.
  - The backup timer exports as a SurrealDB database user with the `VIEWER` role.
  - Off-site: `deploy/tofu/envs/backups`, an owner-only root (its own state and an
    Organization-level key, not the deploy pipeline's): a dedicated Scaleway project, a
    versioned bucket with compliance-mode Object Lock, expiry per tier one day after its lock, a
    writer limited to `PutObject`/`PutObjectRetention` and a verifier limited to reading.
  - Verification runs on a host in an environment of its own (topology role `verify`, which the
    topology module refuses beside production roles), set up by the owner with
    `backup-verify.yml`; its identity and read key are in an owner-only SOPS file.
  - The client keeps a bounded send log (100,000 messages, 30 days) and remembers receipts that
    arrive before its own `SendResult`, so a confirmed message is never resent.
- Evidence: report P02-M6; `bench/m6/restore-drill.sh` (3,000 devices at 5,000/s: outage 1.23 s,
  checker PASS; without resend 11,581 lost); `an_overwritten_backup_is_never_restored_and_verify_reports_it`;
  the tofu test of the backups root.
- Consequences: backups contain account and device metadata only (encrypted, write-once,
  unreadable from production); recovery of undelivered messages depends on clients (Prompt 4's
  delivery receipts make it complete; until then the Rust client keeps its own send log). Needs
  from the owner: confirmation of the four choices, a Scaleway project with Object Storage, and
  the age identity's public key.

## D-0039 — CI on a self-hosted runner, isolated, with Forgejo to follow

- Date: 2026-11-13
- Status: superseded by D-0045 (the repository became public: GitHub-hosted runners cost nothing,
  and a self-hosted runner must never run code from outside pull requests); the scripts stay for a
  private forge later
- Decided by: owner (GitHub Actions minutes exhausted; "do both, runner first": a self-hosted
  runner now, a move to self-hosted Forgejo next); setup by agent.
- Context: the private repository's 2,000 free monthly minutes ran out during M5. The nightly
  workflow and six image builds per push were the largest consumers.
- Decision:
  - **Runners** on the owner's Hetzner VPS (`coolify.sockudo.io`, Falkenstein; 8 x86 cores,
    16 GB, Ubuntu 24.04), which also runs Coolify and the Sockudo docs. Two runners
    (`songbird-1` with the `songbird-stack` label for jobs that start the compose stack or bind
    fixed ports, one at a time; `songbird-2`), as systemd services.
  - **Isolation:** an unprivileged `ci` user with its own **rootless Docker** daemon: CI jobs
    cannot see or reach the host's Docker (verified: `permission denied` on the host socket, zero
    containers visible). Caps through systemd slices: runners 6 cores and 7 GB, the rootless
    daemon and its containers 4 cores and 5 GB. Runner units with `NoNewPrivileges`,
    `ProtectSystem=full`, private `/tmp`. No Songbird production secrets on the host.
  - **Not ephemeral:** an ephemeral runner re-registers for every job, which needs a long-lived
    GitHub token on the host; persistent runners on a private repository that only the owner
    pushes to keep less on the box. Registration tokens (one hour) are fetched with `gh` and
    passed over SSH, never stored.
  - **Rootless details:** AppArmor profile for `rootlesskit` (Ubuntu 24.04 restricts unprivileged
    user namespaces); containers reach the host's loopback through `10.0.2.2`, used by
    `cargo xtask autobahn` when `SONGBIRD_AUTOBAHN_HOST` is set; rustup 1.29.3 from upstream,
    checksum-verified (Ubuntu's 1.26 cannot install the toolchain `rust-toolchain.toml` names
    without arguments).
  - **Workflows:** `ci`, `codeql` and `nightly` run on the runners; `release` and `deploy` stay on
    GitHub-hosted runners (rare; they sign and attest releases). Docs-only pull requests skip
    `ci` and `codeql`.
  - Reproducible: `deploy/ci-runner/provision.sh` and `add-runner.sh` (idempotent).
  - Runner units use `KillMode=mixed`, not GitHub's suggested `process`: with a private `/tmp`, a
    listener that outlived a restart kept taking jobs in a namespace whose `/tmp` was gone (the
    first CI run's CodeQL and Ansible jobs failed on it).
- Consequences: no minute limits; CI depends on one VPS (a dead VPS means local checks until it is
  rebuilt from the scripts). The host's other workloads share the kernel. Next: Forgejo
  (self-hosted forge and Forgejo Actions), with GitHub kept as a private mirror; that move is
  recorded when made.

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
- Status: accepted (prompt amended); built (D-0044, report P02-send)
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
    readers take no lock; one new crate plus `rustversion`, a proc-macro). `arc-swap` is exempted
    in `cargo vet` pending an audit (its publisher is not trusted by two imported sets, D-0016),
    like the other client libraries; `h2`'s publisher record is in `supply-chain/imports.lock`.
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
  - **Amendment (2026-11-13, owner): Podman for development.** Under Podman (the macOS development
    machine's engine) Iggy could not start: Fedora's SELinux policy denies io_uring to containers,
    and compose sends `iggy-seccomp.json`'s contents where Podman's compatibility API expects a
    path. `cargo xtask compose` detects Podman (`docker version` names the Podman Engine;
    `SONGBIRD_COMPOSE_PODMAN=0|1` forces it) and adds `deploy/compose/compose.podman.yaml`, which
    runs the Iggy container alone with `label=disable` and `seccomp=unconfined`, keeping
    `no-new-privileges` and the loopback-only port. Development only: servers run Iggy under
    Docker with the strict profile (Ansible, unchanged). Evidence: on Podman 6.1.4 (Fedora CoreOS
    VM, kernel 7.2.7) all six compose services healthy; the Iggy mailbox suite (16), the M5 gate
    on Iggy (2) and the invariant tests on Iggy (16) pass.
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
  `security-events: write`. Done in D-0045: the repository is public, so code scanning is free;
  CodeQL still gates on its SARIF and, outside pull requests, also uploads it.

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
  reference hardware (Prompt 13). Amended by D-0045: container images in their own workflow
  (image changes, nightly, on demand) instead of on every push; `cargo xtask workflows` enforces
  the pins, hosted runners only, and where secrets may appear.

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
