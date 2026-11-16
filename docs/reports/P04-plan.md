# P04 — Messaging content and conversation features: plan, milestones and gates

- Date: 2026-11-16
- Prompt: [04-messaging.md](../prompts/04-messaging.md).
- Status: **agreed by the owner on 2026-11-16**, with every recommended answer below (D-0058).
  Built on one branch: M1 (`P04-M1.md`, D-0059), M2 (`P04-M2.md`, D-0060), M3 (`P04-M3.md`,
  D-0061), M4 (`P04-M4.md`, D-0062), M5 and the final gate (`P04-M5.md`, `P04-gate.md`, D-0063):
  awaiting the owner's approval.
- Base: `main` at `120c7a5` (Prompt 3 done, D-0057).
- Way of working (owner, for speed): every milestone on **one branch and one PR**, each with its
  own commit, tests, report `docs/reports/P04-Mn.md`, decision record (D-0058 onward), PROTOCOL
  sections and threat-model rows marked "awaiting the owner's approval"; a final gate report; an
  independent security review of the whole diff; `cargo xtask ci fast` and the live suites before
  asking. Nothing is pushed or merged without the owner.
- Skills: the environment offers general skills only (`security-review`, `code-review`,
  `simplify`); none is specific to Rust, protobuf or fuzzing, and the repository still has no
  project skills. `security-review` runs (as an independent read-only reviewer) over the whole
  diff before the gate. The `songbird-invariants` checklist proposed in P03 is still worth
  writing; it is not part of this prompt.

## What Prompt 4 starts from

- **Envelopes are opaque.** A `Send` frame (PROTOCOL §1.2) carries one ciphertext per device or
  one shared body; the server checks limits, the device list and the reserved system-frame
  prefix, stores, acknowledges and routes. Nothing in the frame says what kind of conversation a
  send belongs to, and every authenticated device may send to every account.
- **Sealed sender** (D-0054, behind its flag): a send authorized by the XOR of the recipient
  accounts' 16-byte access keys (derived from the profile key, which only contacts hold), or by
  the account's "anyone may send" flag.
- **Mailboxes** (memory, SurrealDB, Iggy): undelivered envelopes expire after 30 days, measured
  from the store time; nothing per envelope.
- **No content schema.** PROTOCOL §5 is empty. Recipients "drop repeats by the message ID inside
  the envelope" (§3.6), but no message ID is defined yet.

## Design choices that shape every milestone

1. **The server never decodes content.** `crates/content` is a library for apps and tests; no
   service depends on it (a `cargo deny` ban and a test enforce it). Everything the server must
   act on is a small, fixed, bounded field of the `Send` frame, never a guess about the ciphertext.
2. **What the server must see is added to the frame, explicitly.** Prompt 4 extends the v1 `Send`
   frame with four optional blocks behind new flag bits (unknown bits stay refused; one encoding
   per frame):
   - `ACCESS`: the combined access key;
   - `REQUEST`: this send is a message request;
   - `FRANKED`: a 32-byte franking commitment;
   - `EXPIRES`: a disappearing timer, in seconds.
   No app exists yet, so v1 is extended rather than versioned; the rule is recorded.
3. **Contacts are proven by the access key, not by a server-side social graph.** The server keeps
   no contact lists. A sender proves it is a contact by holding the recipient's access key, which
   the recipient hands out by sharing its profile key (on accepting a request, or to its
   contacts). Everything else is a request, rate-limited, franked and blockable.
4. **Whatever the server keeps is minimal, keyed or sealed:**
   - block entries as keyed hashes of the (blocker, blocked) pair;
   - reports sealed to an offline moderation key;
   - throttle records as keyed hashes with short lifetimes.
   Each becomes a threat-model §1 row for the owner.
5. **Order-independent state by construction.** Every replicated piece of chat state is defined
   as a function of the set of messages received, never of their order:
   - polls, RSVPs and reactions: last write per author wins, by the author's own counter;
   - pins and timers: a total order on (time, author, message ID).
   Property tests prove it over random orderings and duplicates.

## Milestones and gates

One branch, one PR, a commit per milestone. The prompt's gate is the final one and is met piece
by piece.

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **`crates/content`: the encrypted content schema.** `content.proto` as the specification, with `prost` types matching it and strict validation after decoding (bounds on every repeated field, string and byte length). The schema covers:<br>• the plaintext container: version, a "required version" for "update to see this", franking key, padding to 160-byte buckets;<br>• message IDs (16 random bytes) and references (author account, message ID);<br>• text with formatting spans (UTF-8 byte ranges) and mentions; replies; reactions; edits; delete for everyone; the forwarded marker and its counter;<br>• voice notes, attachment pointers (the fields Prompt 6 extends), contact cards, location pins;<br>• polls, events and RSVPs, pins with duration, disappearing-timer changes, view-once, nudges, sticker references, group and channel system messages, call events;<br>• profile-key sharing (how a request is accepted), message-request responses, restricted-chat policy;<br>• delivery, read and played receipts (batched); typing (ephemeral lane);<br>• sync messages: sent transcripts, read and viewed state, starred, archived, muted and pinned chats, settings, block list, call history, request responses.<br>The PROTOCOL §5 text, including the client-only features (lock chat, free storage, media overview, search, save to photos, export, groups in common) checked against the schema. | Byte-exact test vectors (`crates/content/vectors/v1`); the compatibility suite (every version decodes every older version's vectors, and a newer writer's unknown fields are ignored); `content.proto` cross-checked by an independent compiler (`protox` and `prost-reflect`, in a tool outside the workspace, as for libsignal and OpenMLS); fuzz target `content`; a test that no service links the crate. |
| **M2** | **Convergence and message status (reference semantics, client-side, in `crates/content`).** Covers:<br>• poll tallying (last vote per voter by the voter's counter; closing carries the author's vote heads, so the final result is fixed whatever arrives late); events and RSVPs; reactions (add, replace, remove);<br>• edits (window, history), delete for everyone (time limit), pins (duration), timers, forwarding limits;<br>• the status machine (sending, sent, delivered, read, played, failed: forward only); receipt coalescing ("read up to here", one receipt per conversation per window);<br>• group "Message info" (two ticks when every member has a device that received it, blue when every member read it, members joining and leaving in between);<br>• the read-receipt setting, reciprocal, applied to groups per the owner's answer. | Property tests: polls, reactions, RSVPs, pins and timers converge over random orderings and duplicates; statuses only move forward in any receipt order; batching and coalescing tests; group aggregation with joins and leaves. The **receipt load test**: receipt envelopes as a share of all envelopes in a 1,024-member group, from the real coalescer driving the real send path, with the numbers in the report. |
| **M3** | **Server hints in the `Send` frame: franking and disappearing envelopes.**<br>• **Franking:** the sender commits to the plaintext (`HMAC-SHA256(franking key, content)`, the key inside the ciphertext). The server stamps each envelope for another account with `HMAC(server franking key, commitment ‖ time ‖ sender account ‖ recipient account)`. A sealed send has no sender in the stamp. The stamp is inserted in a reserved, server-only envelope prefix, so a user can never forge one. Recipients drop content whose commitment does not open.<br>• **Disappearing and view-once:** `EXPIRES` gives every envelope of the send a deadline. All three mailboxes record it, never deliver past it (a `seq` skipped only where an envelope expired, as §3.3 already allows), and delete it at the deadline even if the device never connects. In Iggy this needs a new record kind, because expiry there was a cumulative acknowledgement. | Franking known-answer tests (stamp and commitment, independently recomputed); the fuzzed franked-envelope and frame decoders; expiry tests on every mailbox (never delivered after the deadline, deleted without the device; the Iggy tests in CI, where Iggy runs); the allocation gate unchanged for unfranked sends and measured for franked ones. |
| **M4** | **Message requests, blocking, rate limits per conversation type, broadcast lists.**<br>• The directory snapshot gains each account's access key and policy, so the contact check costs no store round trip on the WebSocket's hot path.<br>• Every send is classified by what the server can see:<br>  – **sync**: the sender's own account only;<br>  – **direct**: one other account, with the access key or open;<br>  – **bulk**: a broadcast list, several other accounts with the combined key, up to 256 accounts by default;<br>  – **group**: a shared body;<br>  – **request**: one other account, no key, `REQUEST` set, franked.<br>  A send to another account with neither key nor `REQUEST` is refused with a new reason.<br>• **Requests** pass a gate: per-sender, per-pair and per-recipient throttles across the cluster (keyed records in `valkey-hot`), the recipient's policy (everyone or nobody), and the recipient's block entries. Blocked and refused requests are dropped silently and answered as accepted, so a block cannot be detected.<br>• **Blocking:** `PUT/DELETE /v1/blocks`, stored as keyed hashes of the pair. Blocking also rotates the profile key (a client rule), so a blocked contact's access key stops working and only the request path, where the block applies, is left. Sealed senders are blocked client-side by their certificate.<br>• **Limits per class:** direct and group stay per connection, in memory (no new hot-path cost). Bulk and requests are counted per account across nodes. A "channel" class waits for Prompt 5, the first point where the server can tell a channel from a group. | Integration tests over the WebSocket and HTTP:<br>• every lane's rules;<br>• blocked senders dropped without being told;<br>• **request floods** (one sender to many recipients, many senders to one recipient, one pair) held to their limits;<br>• broadcast limits;<br>• refusal reasons;<br>• the live gate on SurrealDB and `valkey-hot`; fuzzed frames.<br>Existing invariant, allocation and latency tests unchanged: the static development directory treats its accounts as open. |
| **M5** | **Reporting with message franking, then the Prompt 4 gate.**<br>• `POST /v1/reports`, from a listed device: the stamp, the claimed sender, the franking key, the reported content and a reason.<br>• The server checks the stamp (and that the reporter is the stamp's recipient), the commitment (constant time) and the report window (30 days). It then stores a **minimal report** (the content, the attested or claimed sender, the reason, the times) **sealed to an offline moderation key** (X25519, AES-256-GCM), with no reporter, no conversation and no other message.<br>• Reports are kept 30 days, then swept; duplicates are refused by a keyed hash of the stamp; report floods are throttled per account.<br>• `songbird-admin` lists, opens (with the moderation key) and deletes reports.<br>• GDPR export and deletion cover blocks and the request policy.<br>• Final gate report `P04-gate.md`. | Known-answer tests for verification (good, wrong key, wrong recipient, expired, tampered content or commitment); fuzz target `report`; **report floods** and duplicate reports refused; sealed reports open only with the moderation key; deletion and export cover every new store; **the prompt's gate**, all four items. |

Order: M1 and M2 need no server change and fix the content every later milestone refers to (the
franking key's place, receipts, profile-key sharing). M3 adds the frame fields that M4's lanes
and M5's reports rely on. M4 holds the abuse paths that M5's report-flood tests extend.

## Decisions taken in the design (recorded with each milestone, for the owner to see)

- **Franking attributes identified senders only.** A sealed send carries no sender for the server
  to stamp, and a recipient can re-use a certificate it was sent, so for sealed messages a report
  proves the content and the delivery but not the sender. Requests are never sealed, so a
  stranger's messages are always attributable.
- **Reports go to a moderation key the servers do not hold.** `api` verifies in memory and stores
  only the sealed report, so a database or backup thief, or an operator without the offline key,
  reads nothing.
- **Formatting spans count UTF-8 bytes.** Signal counts UTF-16 code units. Bytes are unambiguous
  and simple to validate; apps convert.
- **The server stamps time.** Edit windows and delete limits use the franking stamp's time,
  written by the server, when both messages carry one; otherwise they use the sender's clock.
  Either way a modified client can ignore the window on its own device, as in Signal and
  WhatsApp.
- **Restricted chats are carried, never enforced by the server.** PROTOCOL says plainly that a
  modified client can ignore them.
- **What waits for later prompts, with its hook in place:**
  - group authorization and a stranger's group invite (Prompt 5). Until then a shared-body send
    is limited by its rate class only, and clients show an invite from a non-contact as a
    request;
  - channel rate limits (Prompt 5);
  - view-once attachments deleted after one fetch (Prompt 6's grants).

## For the owner (answered 2026-11-16, D-0058)

Every recommendation was accepted: (1) group read receipts follow the setting; (2) access key
or request; (3) tighten from any listed device, loosen from the primary; (4) 24 hours for both.

1. **Group read receipts** (the open decision in DECISIONS). Recommended: they follow the
   read-receipt setting, reciprocal, as Signal does. WhatsApp always sends them in groups.
2. **Contact gate.** Recommended: every send to another account carries that account's access
   key or goes as a message request, which is rate-limited, franked and blockable. This is the
   prompt's wording, and it changes how existing identified sends are admitted. The alternative
   is Signal's: only sealed sends need the key, identified sends always pass, and requests are a
   folder on the client.
3. **Who may change blocks and the request policy.** These are account-wide, so D-0052's rule
   applies. Recommended: any listed device may tighten (block, refuse requests), and only the
   primary may loosen (unblock, accept requests again), so a stolen linked device cannot unblock
   a stalker.
4. **Edit window and delete for everyone.** Recommended: 24 hours for both, as Signal does.
   WhatsApp uses 15 minutes for edits and about 60 hours for deletes.
