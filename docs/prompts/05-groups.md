# Prompt 5 — Groups, roles, communities and channels

*File: `docs/prompts/05-groups.md` · Skills: MLS and applied cryptography review, distributed systems, Rust concurrency testing.*

**Goal:** end-to-end encrypted groups with real roles and permissions, communities and channels, enforced both by every member's client and by the server where the server can see the action.

**Build:**

- **MLS delivery service** using OpenMLS for validation. Handshake messages (proposals, commits) travel as MLS `PublicMessage` so the server can verify who changes membership and whether they are allowed to; application messages travel as `PrivateMessage`. Commits are ordered by compare-and-set on the group epoch: exactly one concurrent commit wins, the rest are rejected with the winning epoch. Welcome messages are routed to joining devices; external commits allow a member's lost device to rejoin, if group policy allows.
- **Server-side group record:** group ID, epoch, the roster the server needs for authorization and fan-out, and an encrypted, versioned metadata blob (name, description, avatar pointer, settings) that only permitted roles may replace.
- **Roles and permissions:** owner, admin, moderator, member, read-only. A permission matrix covering: edit group info, add and remove members, approve join requests, manage invite links, pin messages, send messages (announcement-only mode), start group calls, delete others' messages, change roles. Roles live in an MLS group-context extension (so every client verifies them) and are mirrored on the server roster (so the server rejects unauthorized handshake messages). Write negative tests for every cell of the matrix.
- **Invite links and join requests:** random link secrets stored only as hashes, with expiry, maximum uses, revocation, and optional admin approval through a join-request queue. Lookups are rate-limited and resistant to guessing.
- **Limits:** group size limit (start at 1,024, configurable); benchmark commit and Welcome costs at 1,024 and 5,000 members and record them.
- **Communities:** a container of groups with shared admins and an announcement group. The server stores only opaque links between IDs; names and descriptions are encrypted.
- **Channels:** one-to-many broadcast where only admins post.
  - *Private channels:* MLS groups with subscribers as read-only members, up to a benchmarked cap.
  - *Public channels* are an owner decision: posts signed by the channel key but not encrypted, stored once in a channel log that subscribers read with their own cursor (no per-subscriber mailbox entries). Build them only after the owner approves, and record the privacy trade-off in the threat model.
- **Fan-out** uses the shared-body storage from Prompt 2.

**Also build (WhatsApp parity):**

- **Member change history** ("View member changes"): every membership and role change is an authenticated MLS commit, so clients build the history locally. Add a signed, encrypted change log to the group state so newly linked devices can show it too.
- **Admin approval for new members, "only admins can edit group info", "only admins can send"**: confirm each maps to a cell of the permission matrix with a negative test.
- **Group calls started from the group header and call links in groups** reuse Prompt 7.

**Tests:** a harness of simulated OpenMLS clients that drives the delivery service through joins, removals, concurrent commits, role changes, lost-device rejoin and invite links; property tests that all honest clients end at the same epoch and roster; fuzzing of every handshake decoder.

**Gate:** every permission rule has a passing negative test on both client harness and server; concurrent-commit races never fork a group; benchmarks for 1,024-member groups and a large private channel recorded and accepted by the owner.
