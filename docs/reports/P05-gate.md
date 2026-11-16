# P05 — Groups, roles, communities and channels: the final gate

- Date: 2026-11-16
- Prompt: [05-groups.md](../prompts/05-groups.md).
- Status: **built; awaiting the owner's approval** (the items under "The owner's decisions").
  M1 was approved on 2026-11-16 ("Approve all three").
- Reports: `P05-plan.md` (agreed, D-0065), `P05-M1.md` to `P05-M4.md`, and this report.
- Decisions: D-0065 to D-0074 (D-0074: the security review's fixes).
- Branch: `claude/p05-groups`, one PR at the owner's request (2026-11-16: "solve all milestones
  in one PR").
- Machine: Windows 11 Pro 10.0.26300, AMD Ryzen 9 7950X, `rustc 1.99.1`; nightly 2026-11-11 for
  fuzzing. Live: SurrealDB v4.0.1 and Valkey 9.1.3 under podman.

## The gate, item by item

| Gate item | Met by | Evidence |
| --- | --- | --- |
| **Every permission rule has a passing negative test on both client harness and server** | M2–M4 | **Commit-borne cells** (`tests/groups/tests/matrix.rs`, 8 tests): add, remove, the policy (send, edit info, add, approval, calls), promotion, demotion, owners, stale entries, channels. Each is refused on the server (`Forbidden`) and by a client running `roles::authorize`, and accepted for a role that may.<br>**API cells**, live `gate_p05`: sending (reason 14), editing info (403), links (403 for a member), approving and declining requests (404 for outsiders), every community cell (`communities_are_run_by_the_announcement_groups_admins`).<br>**Client-only cells** (pin, delete others', D-0065 §6): `roles` unit tests. Calls: Prompt 7. |
| **Concurrent-commit races never fork a group** | M1, M3 | Live: five members commit over HTTP at once, round after round; one 200 per epoch, every client at the same epoch (`concurrent_commits_over_http_have_one_winner_per_epoch`). Joins by link race the same way (`parallel_joins_never_exceed_a_links_uses`). In-process: `honest_clients_always_agree_with_the_server`, random interleavings of adds, removals and races. |
| **Benchmarks for 1,024-member groups and a large private channel recorded and accepted by the owner** | M4 | `P05-M4.md`: commit, Welcome and server validation, time and bytes, at 1,024, 2,048 and 5,000 members, X-Wing and classical. **For the owner to accept**, with the caps they set (1,024 devices per group, 2,048 per channel). |

## The rest of the prompt

| Prompt item | Where |
| --- | --- |
| MLS delivery service: `PublicMessage` handshakes, `PrivateMessage` application messages, epoch compare-and-set, Welcome routing, external commits for lost devices | M1 (D-0066, D-0067; PROTOCOL §6.1–6.5) |
| Server-side group record: ID, epoch, roster, encrypted versioned metadata | M1, M2 (§6.7) |
| Roles in an MLS group-context extension, mirrored on the roster | M2 (D-0070; §6.6) |
| Invite links (hashes only, expiry, uses, revocation) and join requests; lookups throttled and guessing-resistant | M3 (D-0071; §6.8) |
| Group size limit (1,024, configurable); commit and Welcome costs at 1,024 and 5,000 | M1, M4 (D-0072) |
| Communities (opaque links, shared admins, an announcement group, encrypted names) | M4 (§6.9) |
| Private channels (read-only subscribers, a benchmarked cap); public channels | M4 (§6.10). Public channels not built (D-0065 §4) |
| Fan-out on the shared-body storage | M1 (`send_server_shared`, group sends) |
| Member change history, for devices that join later | M2 (the signed, encrypted change log) |
| "Admin approval", "only admins edit info", "only admins send" | M2, M3 (each a matrix cell with a negative test) |
| Group calls and call links | Prompt 7 (the `call` policy role is in place) |
| Tests: the harness; property tests; fuzzing of every handshake decoder | M1–M5 (`tests/groups`; `convergence.rs`; `mls_wire`, `mls_commit`, `group_records`) |
| GDPR for every new store | M5 (D-0073) |

## Runs

All on the machine above, at `621d8d7` plus this report.

| Run | Result |
| --- | --- |
| `cargo fmt --check`; `cargo clippy --workspace --all-targets --locked -D warnings`; workflow policy | Clean (`cargo xtask ci fast`'s first three steps) |
| `cargo nextest run --workspace --locked --profile ci` (registry suites live against SurrealDB and Valkey; tests needing RustFS skip) | **635 passed**, 4 skipped |
| `gate_p05`, live, `SONGBIRD_REQUIRE_STACK=1` | **10 of 10**: creation, commits and fan-out; races; crash re-drive; roles, metadata, change log and leaving; invite links and requests; parallel joins; communities; the export and deletion; a made-up KeyPackage refused; outsiders get 404 |
| Groups, harness and send | 76 (matrix, convergence property tests, lifecycle, channel cap, tiers, channel rate class) |
| Fuzzing, nightly 2026-11-11, ASan | `group_records`: 999,912 runs in 61 s, nothing found. `mls_wire` and `mls_commit` (M1): 8,477,711 and 254,179 runs. All three are in the nightly CI matrix |
| The scale benchmark (`tests/groups/tests/scale.rs`, release) | The tables in `P05-M4.md` |

The full CI run on Linux is the PR's checks.

## Security review

An independent, read-only review of the whole Prompt 5 diff (a separate agent, given the code
and the documents, not this report's conclusions). Its findings and what was done (D-0074):

| # | Finding | Severity | Done |
| --- | --- | --- | --- |
| 1 | Changing the default role changed every unnamed member's role unchecked: an admin could make everyone an owner, then demote the real owner | High | **Fixed:** a default-role change is a role change for every member it applies to (`the_default_role_moves_everyone_it_names`) |
| 2 | An added KeyPackage was not bound to its device: a member could add a leaf under another device's ID with its own keys and speak as that device | High | **Fixed:** only KeyPackages the device published (claimed single-use, or last-resort) may be added; else 403 `key_package` (live `a_member_cannot_add_a_leaf_it_made_up_for_another_device`) |
| 3 | A group whose only owner's devices are all gone froze for good | Medium | **Fixed:** succession whenever no owner is left, from the highest role left (`a_vanished_owner_has_successors_too`) |
| 4 | `/v1/groups/state` (a whole-tree rebuild) had no budget; role checks read the whole state | Medium | **Fixed:** a read budget per device; role checks read the roster only |
| 5 | A fan-out could stall for good if a recipient left the directory between attempts | Medium | **Fixed:** an idempotency conflict means the earlier store completed |
| 6 | Outsiders' commits were processed before the membership check, and answered 400 (revealing the group) | Low–medium | **Fixed:** 404 before any work (live `outsiders_get_the_answer_for_no_group`) |
| 7 | Any member could change `required_capabilities` | Low | **Fixed:** it must stay exactly Songbird's |
| 8 | Role checks for metadata, links, requests and communities read before the write | Low | Recorded as a risk: one in-flight action by a just-demoted admin can land |
| 9 | Succession went to whoever committed first, even a read-only subscriber | Low | **Fixed** with 3 (the highest role left) |
| 10 | No per-account cap on creating groups; no group deletion; the roster cache keeps live groups | Low | Recorded as a risk |
| 11 | PROTOCOL said join requests were the `links` role's; the code uses `add` | Low (docs) | **Fixed** (§6.6) |

Plausible, not proven: different directory views on server and client could make a client
refuse a commit the server accepted, until the client refreshes; one member can fill the
64-proposal queue until the next commit. Both are threat-model §6 risks. The channel budget's
map grows only for channels that post, cleaned when full.

Checked and found sound by the review:

- **Crypto:** the provider never signs or decrypts.
- **Signatures:** `GroupInfo` and change-log signatures are verified against the committer's
  new leaf.
- **External commits:** limited to rejoining one's own device, or joining by link with the
  default role.
- **Concurrency:** epoch, revision and link-use compare-and-set, all in the commit's
  transaction.
- **SurrealQL:** parameterised throughout.
- **Links:** constant-time comparison and one 404.
- **Fan-out keys:** server-derived.
- **Send path:** the prefix parser and the roster checks.
- **Parsers:** bounded before allocating.
- **GDPR:** covered.

## Open risks

From the threat model §6, in short:

- The roster is metadata: the server knows which devices (and accounts) share a group, and
  with communities which groups belong together (D-0065 §2).
- Rosters are cached for a second: a removed device can post at its last epoch for that long.
- Whether a joiner held a usable link is the server's word; every member sees the join.
- Full-path X-Wing commits on a fresh tree are large (1.2 MiB at 1,024 leaves).
- The channel rate class is per node.
- After an account's deletion its devices' leaves stay in group state until a member commits
  their removal.

## The owner's decisions

1. **Approve the gate**, with M2–M5.
2. **Accept the benchmarks and the caps** they set: 1,024 devices per group, 2,048 per private
   channel, with X-Wing by default (`P05-M4.md`, "What the numbers decide").
3. **Approve the threat-model §1 rows** "awaiting the owner's approval":
   - M2: the roles in group state; the encrypted metadata; the change-log entries;
   - M3: invite links; pending join requests (naming the account that asks);
   - M4: communities;
   - the review (D-0074): claimed KeyPackage references, kept until the packages expire.
4. **Follow-ups**, proposed, not built:
   - server-proposed removal of deleted accounts' devices (MLS `external_senders`, D-0073);
   - a link proof members can check themselves (D-0071);
   - a cluster-wide channel rate class (D-0072).
