# P07 gate — Voice and video calls with LiveKit

- Date: 2026-11-17
- Prompt: [07-calls.md](../prompts/07-calls.md); plan [P07-plan.md](P07-plan.md) (D-0085)
- Milestones: [M1](P07-M1.md) (D-0086), [M2](P07-M2.md) (D-0087), [M3](P07-M3.md) (D-0088),
  [M4](P07-M4.md) (D-0089), [M5](P07-M5.md) (D-0090); the security review's fixes (D-0091)
- Branch `claude/p07-calls`, PR #62. Status: **approved by the owner on 2026-11-17** ("all green you can merge"), with the nine threat-model §1 rows.

## The gate, item by item

| Gate item | Result | Evidence |
| --- | --- | --- |
| Authorization negative tests: non-members | **Pass** | A non-member cannot start or join a group's call (404, with or without the group's ID); a member below the `call` role cannot start (403); strangers cannot call closed accounts or join 1:1 calls (404): `group_calls_admit_the_roster_and_drop_removed_members_mid_call`, `one_to_one_calls_admit_only_the_two_accounts` |
| Expired tokens | **Pass** | LiveKit's own check refuses a token expired 5 minutes ago, one signed with another secret and one for another key: `expired_and_forged_tokens_are_refused_by_livekit` |
| Removed members mid-call | **Pass** | The commit removing Bob disconnects him from LiveKit at once; his tickets are refused; reconnecting with the token he still held, he is cut off again by the join's webhook (D-0091); with the media keys alone (no SFU removal) he decodes nothing after the commit (harness) |
| E2EE verified by the harness | **Pass** | `tools/calls-harness` on LiveKit's Rust SDK: calls connect and decrypt; the SFU lists the tracks as AES-GCM encrypted; a participant with the wrong key decodes nothing; a real MLS removal rotates the keys to the next index, Bob keeps decoding, Carol decodes nothing ([M4](P07-M4.md)) |
| Capacity per node and a sizing table | **Pass**, on a 4-CPU container standing for a host | Eight `lk perf load-test` runs: rooms × participants, CPU and bandwidth per participant, low-data versus normal, `tc netem` loss and latency; per-host table ([M5](P07-M5.md)): ≈ 170 1:1 video calls, ≈ 350 low-data, ≈ 900 audio, ≈ 9 full 32-person video rooms or ≈ 2 full 128-person audio rooms. To be re-run on the production host class from a separate load host |

Everything else the prompt asks for:

| Item | Where |
| --- | --- |
| LiveKit cluster from `deploy/`, multi-node through Valkey (compatibility verified), TURN/TLS on 443, recording and egress disabled | M4; `two_livekit_nodes_share_rooms_through_valkey` |
| `services/calls` with `livekit-api`; random rooms; short single-room tokens with the least grants; per-call pseudonyms; caps (32 video, 128 audio); rooms closing when empty | M2 |
| Signalling as encrypted content; ephemeral ringing; missed calls through the mailbox; `VoIP`/high-priority wake-ups; no ringing for non-contacts | M1 (schema), M2 (wake-ups), PROTOCOL §8.5 |
| E2EE with keys from Signal (1:1) and the MLS exporter per epoch (groups), specified with test vectors; no server holds a media key | M1, PROTOCOL §8.2, §13; independent Node.js check; OpenMLS test |
| SFU only, never peer-to-peer | LiveKit has no peer-to-peer path; PROTOCOL §8 |
| Call links: hashed secrets, expiry, lobby with admission | M3 |
| Webhooks: signature-verified, cleanup and capacity only, short retention | M3; a real LiveKit webhook verified |
| Low-data mode, measured | PROTOCOL §8.9, M5 (≈ 4× less per camera) |

## Tests and checks run (Windows 11 Pro 10.0.26300, Ryzen 9 7950X, podman)

- `cargo xtask ci fast` with SurrealDB and Valkey: workflow policy, rustfmt, clippy (pedantic,
  `-D warnings`), nextest **730 of 732**; the other two are the known timing-sensitive live tests
  CI runs one at a time, and pass that way (`-j 1`). Then, after the review's fixes: clippy and
  rustfmt over the workspace, doctests, rustdoc `-D warnings`, `cargo deny` (advisories, bans,
  licences, sources ok), `cargo audit` (clean), `cargo vet` (14 new crates exempted pending
  audits, D-0087).
- `gate_p07` live against LiveKit `v1.13.11`, SurrealDB and `valkey-hot`: **7 of 7** (the real
  webhook and two-node tests need a capture and a second node; both were run, M3 and M4).
- `songbird-calls` unit tests 7 of 7; `songbird-content` call tests 12 of 12 and content vectors;
  `call_keys` (OpenMLS); `tools/call-vectors/check.mjs` 10 of 10; `tools/content-vectors` 38 of 38.
- The harness: all checks passed (M4).
- Fuzz targets `call_message` and `call_records` **built** (nightly, cargo-fuzz), **not run**:
  fuzzing runs with the owner's go-ahead, one job at a time.

## Security review

An independent agent read the whole diff (code, configuration, documents), without running
anything. It found one high, four medium, seven low and three informational findings; all but the
four recorded in D-0091 ("Not changed") are fixed, with tests where they are behaviour:

| Finding | Fix | Test |
| --- | --- | --- |
| High: a removed member rejoins with a token it still holds | Deny set + `participant_joined` webhook disconnects | the group gate test reconnects Bob with his old token |
| A group-call claim race splits a group across rooms | Record before claim; 15 s grace; compare-and-delete; refresh on join | the webhook test (young pointer, then replaced) |
| Strangers' calls to open accounts ring (`VoIP`) | Wake only with the access key; per-pair wake budget | the 1:1 gate test (no wake for a stranger) |
| One device fills a lobby; declines keep places | One place per device; declines delete; Lua scripts | the link gate test (same handle twice) |
| Missing budgets on group joins and link tickets | Ticket budget on every ticket; poll budget on every link request | — |
| Low (seven) and deployment (four) | D-0091 §6, §7 | `participant_tokens_grant_the_least`, `ringing_is_capped` |

## Threat model

Nine new §1 rows, all **approved by the owner on 2026-11-17**: a live 1:1 call (the two accounts, for the
call's life, at most 24 h), a live group call, LiveKit's own state, call budgets, the LiveKit
secret (M2); call links, lobbies, webhook marks (M3); the deny set (D-0091). §3.24 holds the
STRIDE rows.

## For the owner

1. **Approve the gate**: M1–M5 and the review's fixes (D-0086 to D-0091).
2. **Approve the nine threat-model §1 rows.** The one that changes what the server knows: for a
   live 1:1 call, `valkey-hot` holds who calls whom, at most 24 hours (D-0085 §1, your choice).
3. **Before production** (no decision needed now, listed so nothing is forgotten):
   - the names under `songbird.chat` for signalling (`calls.`) and TURN (`turn.`), their public
     certificates and DNS (`turn.` must point at each host's second IPv4);
   - `[api.calls]` on every `api` node and `[calls]` on every calls host (secrets in SOPS:
     `calls_secret`, `livekit_api_*`, `livekit_valkey_password`);
   - re-running the load tests from a separate host against the production calls class;
   - a fuzz run of `call_message` and `call_records` with your go-ahead.

Prompt 7 is done once you approve and the PR merges.
