# P05 — Groups, roles, communities and channels: plan, milestones and gates

- Date: 2026-11-16
- Prompt: [05-groups.md](../prompts/05-groups.md); issue #24 (post-quantum groups) folds in.
- Status: **agreed by the owner on 2026-11-16** ("Approve all"), with every recommended answer
  below (D-0065).
- Base: `main` at `c5a14d1` (Prompt 4 done, PR #57).
- Way of working (proposed, as Prompt 4): every milestone on **one branch and one PR**
  (`claude/p05-groups`). Each milestone gets its own commit, tests, report
  `docs/reports/P05-Mn.md`, decision record (D-0066 onward), PROTOCOL §6 text and threat-model
  rows marked "awaiting the owner's approval". Then a final gate report, an independent security
  review of the whole diff, and `cargo xtask ci fast` plus the live suites before asking.
  Nothing is pushed or merged without the owner.
- Skills: the environment offers general skills only (`security-review`, `code-review`,
  `simplify`). None covers MLS, Rust concurrency testing or fuzzing, and the repository still
  has no project skills. `security-review` runs as an independent read-only reviewer over the
  whole diff before the gate. Proposed again: a `songbird-invariants` checklist skill under
  `.claude/skills/`. Prompt 5 adds the most new invariants so far (one commit winner per epoch,
  roster equals tree, role checks), so this is the prompt where it pays off. It is not part of
  the plan unless the owner asks.

## What Prompt 5 starts from

- **The send path orders commits but knows no members.** A `Send` with flag `0x01` carries
  `group [16]` and `epoch u64`. The mailbox advances `mls_group:[group].epoch` by compare-and-set
  in the same transaction as the store, so one commit per epoch wins and the rest get reason 8
  `StaleEpoch` (D-0026). Anyone may commit to any group ID.
- **Shared bodies are gated by contact keys, not membership.** Until Prompt 5, a shared body
  reaching a closed account needs that account's access key in `ACCESS` (D-0064). Groups
  therefore share every member's profile key, which Prompt 5 replaces with roster checks.
- **KeyPackages are checked by Songbird's own parser** (D-0051). The owner chose it over OpenMLS
  because OpenMLS with `openmls_rust_crypto` resolves to 194 crates, including two more crypto
  stacks. The credential identity is the uploading device's ID, and ciphersuites are limited to
  `0x0001` and `0x0003` (classical).
- **Content is ready.** Group system messages, receipts with the 10 s window above 32 members,
  and convergent pins and timers come from Prompt 4. The roles they will check come from this
  prompt.

## Findings that shape the plan

1. **The server has to track the public tree, so a focused parser is not enough this time.** To
   verify a member's handshake signature, the server needs the `GroupContext` (tree hash,
   transcript hash). That means holding the whole public ratchet tree and applying every
   proposal and update path as RFC 9420 specifies. This is about ten times the size of D-0051's
   KeyPackage parser, and it is security-critical. OpenMLS ships exactly this as `PublicGroup`
   (validation for a delivery service that is not a member).
2. **The 194 crates came from the crypto providers, not from OpenMLS.** The core crate
   `openmls 0.9.2` depends on `openmls_traits`, `tls_codec`, `serde`, `serde_bytes`,
   `thiserror`, `zeroize`, `log`, `rayon` and `openmls_serialization_helpers` (crates.io,
   checked 2026-11-16). Every crypto backend is optional. With a **Songbird provider on
   aws-lc-rs** (implementing `OpenMlsCrypto`), OpenMLS adds no new crypto stack. The count gets
   measured with `cargo tree` before anything is merged.
3. **Post-quantum is reachable on our stack.** aws-lc-rs 1.19.0 (pinned) has `kem::ML_KEM_768`,
   `digest::SHA3_256`, X25519, ChaCha20-Poly1305 and HKDF-SHA256. That is everything X-Wing
   (ML-KEM-768 + X25519) needs for the ciphersuite OpenMLS names
   `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`. **To verify in M1:** its code point in
   0.9.2 and that our provider interoperates byte for byte with OpenMLS's libcrux provider
   (tested in `tools/openmls-vectors`, outside the workspace). Signatures stay Ed25519.
   Authentication cannot be harvested now and broken later; confidentiality can.
4. **What the server can and cannot enforce.** Handshake messages (`PublicMessage`) and the
   authenticated sending device are visible to the server. Application messages
   (`PrivateMessage`) show only group ID, epoch and content type. So the permission matrix
   splits:

   | Permission | Enforced by the server | Enforced by clients |
   | --- | --- | --- |
   | Edit group info (metadata blob, roles extension) | Yes: commit validation, blob replace | Yes |
   | Add and remove members | Yes: proposals in the commit | Yes |
   | Approve join requests | Yes: the API | Yes |
   | Manage invite links | Yes: the API | Yes |
   | Send messages (announcement-only) | Yes: the sending device's role, on the send path | Yes |
   | Change roles | Yes: the roles extension in the commit | Yes |
   | Start group calls | Yes, in Prompt 7: the call token is issued by role | Yes |
   | Pin messages | **No**: inside the ciphertext | Yes |
   | Delete others' messages | **No**: inside the ciphertext | Yes |

   Every cell gets a negative test in the client harness. Every server-enforced cell also gets
   one on the server. For the two client-only cells, the server-side test proves the server
   never needs to see them. Signal and WhatsApp work the same way.
5. **The roster is metadata, and the plan says so plainly.** A `PublicMessage` commit carries
   the leaf credentials (device IDs), so an MLS delivery service that authorizes membership
   necessarily knows who is in which group. The constitution allows this ("group membership
   changes it must order"). It is still a social graph on the server, the one thing D-0062
   refused for contacts. Signal avoids it with zkgroup credentials and group send endorsements,
   but then the server cannot reject unauthorized handshakes, which this prompt requires. The
   plan keeps the roster, keeps nothing else (no names, no avatars, no settings in the clear),
   and records the trade-off in the threat model (question 2).

## Architecture

- **`crates/groups`** (new): the delivery-service logic, pure and fuzzed.
  - OpenMLS `PublicGroup` behind a Songbird trait, with the aws-lc-rs provider.
  - Songbird's authorization on top: the roles extension, the permission matrix, and group
    policy (size limit, external-commit rules, announcement mode).
  - A compact **roster projection**: device → account → role, plus the epoch.
- **One authority for the epoch.** The group record in SurrealDB (`group:[id]`) holds:
  - the epoch;
  - the public state as **RFC 9420 wire bytes** (`GroupInfo` + ratchet tree), never OpenMLS's
    internal serde format, so an OpenMLS upgrade cannot strand stored groups;
  - the roster projection;
  - the encrypted metadata blob and its version;
  - a bounded log of recent commits for catch-up.

  A commit is validated, authorized and written with compare-and-set on the epoch in one
  transaction, together with an outbox row. Its fan-out is then stored in the mailbox under an
  idempotency key derived from `(group, epoch)`, and only then acknowledged. A crash in between
  is re-driven from the outbox: exactly once, store before acknowledge (invariant 1). The
  mailbox's own `mls_group` epoch (D-0026) is retired for these groups. No app has shipped, so
  nothing needs migrating.
- **The hot path stays OpenMLS-free.** An application send parses the `PrivateMessage` prefix
  (group ID, epoch, content type) with no allocation. It checks the sending device against the
  cached roster (role, announcement mode, epoch within a small in-flight window) and **fans out
  from the roster on the server**. The client no longer lists device IDs, so a removed member
  never gets a byte, and the frame shrinks. OpenMLS runs only on the commit path, which is rare
  next to messages. Roster caches are versioned by epoch, and a newer epoch on a send forces a
  reload.
- **Welcomes** go to the devices named by the Add proposals' KeyPackages (credential = device
  ID, D-0051), matched by `KeyPackageRef`. The server keeps no record of who claimed which
  package.
- **Multi-device:** each device is a leaf. A newly listed device joins its account's groups by
  external commit, which is authorized because its account is in the roster and the device is
  in the signed list (D-0052). A device removed from the list loses sending at once (roster
  check against the directory), and members commit its removal.

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **The MLS delivery service core.**<br>• The aws-lc-rs `OpenMlsCrypto` provider: classical `0x0001` and X-Wing.<br>• `crates/groups` with OpenMLS `PublicGroup`.<br>• The group record and outbox in SurrealDB; the epoch authority moved from the mailbox.<br>• Wire: group commit and group application flags; a commit bundle with Welcomes and a `GroupInfo`; reason 8 returning the winning epoch.<br>• Welcome routing; the catch-up log.<br>• KeyPackage parser extended to the chosen post-quantum suite (size limit raised from 2,048 bytes).<br>• **Simulated OpenMLS client harness** (`tests/groups`): joins, removals, concurrent commits, lost-device rejoin. | Provider known answers and byte-for-byte interop with OpenMLS's own provider (`tools/openmls-vectors`).<br>**Concurrent-commit races never fork:** N clients commit on one epoch, exactly one wins, all converge (live, SurrealDB). Property tests: every honest client ends at the same epoch and roster as the server, over random interleavings.<br>Crash between store and fan-out is re-driven exactly once.<br>Fuzz targets for every handshake decoder (`mls_public_message`, `mls_private_prefix`, `mls_welcome`, `mls_group_info`, `commit_bundle`).<br>`cargo tree` count recorded. |
| **M2** | **Roles, permissions, metadata, change log.**<br>• The roles `GroupContext` extension (private range, every client verifies it) mirrored on the roster.<br>• The permission matrix above, with owner / admin / moderator / member / read-only.<br>• Announcement-only sends enforced on the send path.<br>• The encrypted, versioned metadata blob, replaced only by permitted roles (compare-and-set on its version).<br>• External commits for rejoining, if group policy allows.<br>• The signed, encrypted change log for newly linked devices.<br>• D-0064's interim group lane replaced by membership. | **A negative test for every cell of the matrix on the client harness and, where the server can see the action, on the server.** "Admin approval", "only admins edit info" and "only admins send" each traced to a cell. A removed member's sends refused and never delivered. Property test: the server's roster equals the roles extension that every client derives. |
| **M3** | **Invite links and join requests.**<br>• Link secrets of 32 random bytes, stored only as keyed hashes, with expiry, maximum uses and revocation.<br>• An optional admin-approval queue.<br>• Joining by external commit, authorized by the link.<br>• The metadata key travels in the link's fragment, never to the server.<br>• Lookups throttled per account and IP range (keyed records, as in P03/P04) and constant-time.<br>• A Welcome to a stranger still goes as a message request (§5.10). | Guessing tests (wrong secrets cost budget and reveal nothing about existence); expiry, maximum uses and revocation races (parallel joins never exceed maximum uses); every approval and refusal path; fuzzed link and request decoders. |
| **M4** | **Communities, private channels, tiers and benchmarks.**<br>• Communities: opaque ID links (community → groups, announcement group), with shared admins authorized by the announcement group's roles; names encrypted.<br>• Private channels: MLS groups whose subscribers are read-only, with a channel rate class and no receipts.<br>• Group tiers and the receipt rule (question 5).<br>• **Benchmarks** of commit, Welcome and server validation (time and bytes) at 1,024 and 5,000 members, classical and X-Wing, and the private-channel cap they imply. | Benchmarks recorded with hardware, kernel and configuration; the channel cap set from them. Community admin cells tested negatively. Channel rate class held. |
| **M5** | **The gate.** Public channels only if the owner says yes (question 4), then GDPR export and deletion of every new store, the security review, and `P05-gate.md`. | The prompt's gate, item by item. |

Order: M1 is the foundation every later milestone authorizes against. M2 makes the roster
meaningful. M3 and M4 are independent of each other once M2 lands.

## For the owner

Recommended answer first. One word ("approve all") takes every recommendation, as with
Prompt 4.

1. **OpenMLS on the server, with Songbird's own aws-lc-rs provider.** Recommended. Unlike
   KeyPackages, commit validation needs the full RFC 9420 tree logic. OpenMLS's `PublicGroup` is
   the tested implementation, and without its crypto backends it adds no crypto stack (finding
   2). D-0051's KeyPackage parser stays as the upload check. The alternative, our own tree
   validator, means several thousand lines of security-critical code to write and get audited.
2. **The server keeps the roster** (devices, accounts, roles, epoch) and nothing else in the
   clear. Recommended, as the prompt and constitution describe. It is required for server-side
   authorization. A new threat-model §1 row is needed. The alternative is Signal's encrypted
   roster with zero-knowledge credentials: months of work, a new dependency (zkgroup), and the
   server could no longer reject unauthorized handshakes.
3. **Post-quantum by default (issue #24):** every new group uses X-Wing. Recommended, unless
   M4's benchmark shows commits or Welcomes too large at 1,024 members, in which case I come
   back to you with the numbers. Signatures stay Ed25519. The alternative is classical now with
   an upgrade path later, which leaves group history open to harvest now, decrypt later.
4. **Public channels: not in Prompt 5.** Recommended. Unencrypted posts break "the server never
   sees content". Hosting public content also brings EU Digital Services Act duties
   (notice-and-action, transparency reports) and a moderation operation. Private channels ship
   now. Public channels get their own decision, with legal review, later. Note that in a private
   channel, subscribers can see each other's devices (MLS leaves), so it suits audiences that
   know each other. Broadcasting to strangers is what public channels would be for.
5. **Delivered receipts in large groups** (the decision deferred from Prompt 4). Recommended
   tiers:
   - **up to 32 members:** every device sends delivered receipts (1 s window);
   - **33 to 1,024 members:** primaries only (10 s window). In the Prompt 4 busy case that is
     34 % of envelopes instead of 47 %;
   - **channels:** no delivered or read receipts at all.

   The cost of "primaries only": in large groups, "delivered" waits for the member's phone.
6. **Client-only cells.** Pinning and deleting others' messages are enforced by clients only
   (finding 4), as in Signal and WhatsApp. Please confirm this is acceptable for the gate's
   "both client harness and server" wording.
7. **Way of working:** one branch, one PR, a commit per milestone, as in Prompt 4. Recommended.
