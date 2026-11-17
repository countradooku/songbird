# P07 — Voice and video calls with LiveKit: plan, milestones and gates

- Date: 2026-11-17
- Prompt: [07-calls.md](../prompts/07-calls.md)
- Status: **agreed by the owner on 2026-11-17**, every recommended answer below (D-0085).
- Base: `main` at `d9a4191` (Prompt 6 done, PR #61).
- Way of working (the owner, 2026-11-17: "full milestone one PR"): one branch and one PR
  (`claude/p07-calls`). Each milestone gets its own commit, tests, report `docs/reports/P07-Mn.md`,
  decision record (D-0086 onward), PROTOCOL §8 text and threat-model rows marked "awaiting the
  owner's approval". Then a final gate report, an independent security review of the whole diff,
  and `cargo xtask ci fast` plus the live suites, one heavy job at a time. Nothing is merged
  without the owner.
- Skills: the environment offers general skills only (`security-review`, `code-review`,
  `simplify`); none covers WebRTC, applied cryptography or load testing, and the repository has no
  project skills. `security-review` runs as an independent read-only reviewer over the whole diff
  before the gate.

## What Prompt 7 starts from

- `services/calls` is an empty service (configuration, `/metrics`, health, drain).
- `deploy/` already runs LiveKit `v1.13.11` (pinned by digest) in compose (one node, dev and CI)
  and in Ansible (a `calls` host role; nftables opens ICE/TCP 7881, TURN/TLS 5349, TURN/UDP 3478
  and media 50000–60000). No Redis store, no TURN/TLS on 443, no webhooks.
- Prompt 4 has `CallEvent` (a call's outcome in the chat) and `CallHistorySync`; nothing for
  ringing. Prompt 3 has the access key (contact proof, §5.10) and the APNs `VoIP` token; the job
  `Push { call: bool }` exists, but nothing sets `call`.
- Prompt 5 has the group roster on the server, the roles extension with its `call` role and
  `Roles::may_start_call`.

## Findings that shape the plan

1. **`livekit-api`'s server-API client would bring `ring` and `reqwest`.** Its `services` feature
   pulls `reqwest` and, with rustls, the `ring` provider; the constitution wants rustls on
   aws-lc-rs. Its `access-token` and `webhooks` features alone bring about 110 crates, almost all
   already in the tree (prost, serde, base64, `jsonwebtoken` with HMAC only). The room service is
   Twirp: a protobuf `POST /twirp/livekit.RoomService/<Method>` with a bearer token. So `calls`
   uses `livekit-api` for tokens and webhook verification, and its own ~200-line Twirp client on
   our hyper and rustls (aws-lc-rs), with `livekit-protocol`'s generated messages.
2. **Who calls whom is new metadata.** A 1:1 call that names the callee tells the server that the
   two accounts talk, which sealed sender otherwise hides for messages. The prompt asks the server
   to admit only the invited account's devices, so the server must know the callee. It can keep
   that knowledge short: a record in `valkey-hot` for the call's life, never in SurrealDB, never
   logged, keyed by a hash of the room name. Question 1.
3. **LiveKit's own state can be made to say nothing.** Room names are random 16-byte IDs. A
   participant's identity is an HMAC of the room and the device under a server key: stable within
   one room (rejoins keep their keys), unlinkable across rooms, and recomputable by the server
   when it must remove a device, so no table maps pseudonyms to devices. Names, metadata and
   attributes stay empty; the token forbids changing them.
4. **Removing a member mid-call needs the SFU and the keys.** The MLS commit that removes a
   device gives the group a new epoch and so a new call key, which the removed device cannot
   derive. Until every member switches, the SFU still forwards to it, so `api` also asks LiveKit
   to remove that participant when it accepts the commit, and refuses it a new token.
5. **Per-sender keys, not one shared key.** LiveKit's frame cryptor builds each frame's IV from
   the track's SSRC, timestamp and a counter. With one key shared by everyone, two senders with
   the same SSRC would reuse IVs under AES-GCM. Deriving each sender's key from the call secret
   and its participant identity removes that risk at no cost; receivers derive the key from the
   identity LiveKit shows them.
6. **Call links need a way to exchange keys with strangers.** People joining by link are not in
   the MLS group and may have no session with each other. Signal's answer: link holders exchange
   their account and device over the link's encrypted channel, then send each other per-sender
   keys over ordinary Signal sessions, and rotate them on every join and leave. The alternative
   derives one media key from the link secret: simpler, but anyone who ever held the link can
   decrypt, and removal relies on the SFU. Question 2.
7. **Valkey and LiveKit.** LiveKit speaks the Redis protocol through `go-redis` and keeps its
   room routing there, with unprefixed keys and pub/sub channels. Sharing `valkey-hot` would let
   LiveKit's credentials touch Songbird's routing state. Compatibility gets measured (M4); the
   plan runs a dedicated Valkey for LiveKit either way. Question 4.
8. **TURN over TLS on 443 needs its own address.** Signalling (`wss`) and TURN/TLS both want 443
   with different certificates; LiveKit's documented ways are a second domain on a second IP, or
   an L4 SNI router. A second IPv4 per calls host is the simplest. Question 4.
9. **Low-data mode is the client's choice.** Bitrate caps and simulcast layers are chosen when
   the app publishes and subscribes; the server only has to allow simulcast, dynacast and Opus
   DTX/RED, and keep congestion control on. The load tests measure bandwidth per mode.
10. **The harness needs libwebrtc.** LiveKit's Rust SDK (`livekit` 0.11) builds against a
    prebuilt libwebrtc (hundreds of MB, downloaded at build time). It goes in
    `tools/calls-harness`, outside the workspace like `tools/libsignal-vectors`, so no service
    links it and CI's fast tier stays fast.

## Architecture

- **Key schedule** (`crates/content`, module `call`, client-side, never linked by a service):
  - Every call has a 16-byte `call_id` (also the LiveKit room name, hex) and a 32-byte epoch
    secret per key epoch:
    - **1:1:** a random `call_secret` in the encrypted offer (Signal session);
      `epoch_secret = HKDF-SHA256(salt = call_id, ikm = call_secret, info = "songbird call 1:1 v1")`.
    - **Group:** `epoch_secret = MLS-Exporter("songbird call v1", call_id, 32)` at the group's
      current epoch; a commit (any membership change) gives a new one.
    - **Link (if question 2's recommendation):** each sender's own random key, sent over Signal
      sessions, new on every join and leave.
  - `sender_key = HKDF-Expand(epoch_secret, "songbird call sender v1" ‖ len ‖ identity, 32)`,
    handed to LiveKit's key provider at `key_index = epoch mod 16`. Data channels use the same
    keys (LiveKit E2EE covers both).
  - Signalling schema: `CallMessage { offer, answer, decline, busy, hangup, key_update }` in
    `Content`, validated like every other message; `CallEvent` (exists) for history.
  - Test vectors in PROTOCOL §8, cross-checked by an independent implementation (Python
    `cryptography`), proptests, and a fuzz target for the signalling decoder.
- **`services/calls`** becomes a library and a binary:
  - library (used by `api` for `/v1/calls/…`): the LiveKit token minter (`livekit-api`,
    `access-token`), the Twirp room client (own, aws-lc-rs), pseudonyms, call and link records in
    `valkey-hot`, the authorization rules;
  - binary on the calls host: the webhook receiver (`livekit-api`, `webhooks`), signature
    verified, used for cleanup and capacity metrics only, never stored; a sweep for records whose
    room is gone.
- **Endpoints** (`api`, device-signed like every request):
  - `POST /v1/calls` 1:1: names the callee, carries the contact proof (the callee's access key) or
    the callee is open; creates the room with random ID, caps and empty timeouts; answers the call
    ID and the caller's token; optionally queues `VoIP` / high-priority wake-ups for the callee's
    devices (budgeted).
  - `POST /v1/calls/group`: a roster member whose role ≥ `call` starts the group's call (one per
    group, keyed by a hash of the group ID); members join it. Ringing is limited to groups of at
    most 32 accounts.
  - `POST /v1/calls/join`: a token for an existing call: 1:1 only for the two accounts' devices;
    group only for current roster members (role ≥ `min(call, member)`).
  - `POST /v1/calls/links`, `…/links/join`, `…/links/admit`, `…/links/revoke`: call links (below).
  - Tokens: one room, `roomJoin`, publish (camera, microphone, screen share), subscribe, publish
    data; no admin, no metadata updates; **2 minutes**, the time to connect (LiveKit refreshes a
    connected participant's token itself).
- **Call links:** the link carries a 32-byte root secret in its fragment. The client sends the
  server `HKDF(root, "songbird call link id v1")`, which the server stores only as its SHA-256,
  with the room, an expiry (at most 30 days, default 24 h) and whether a lobby is on; the creator
  keeps an admin token (hash stored, like packs) and no account is linked. Joiners are
  device-authenticated (rate limits) and, with the lobby on, wait until an admin admits them; the
  admin's devices see waiting joiners only as opaque lobby handles plus an encrypted card the
  joiner wrote under `HKDF(root, "songbird call link key v1")`.
- **Removal mid-call:** when `api` accepts a commit that removes devices from a group with a live
  call, it computes their pseudonyms and calls `RemoveParticipant`; their join is refused from then
  on.
- **Ringing:** live ringing goes over the ephemeral lane; an offline device gets a stored offer
  with a short `EXPIRES` (60 s) and a `VoIP`/high-priority wake-up; a missed call goes through the
  mailbox as `CallEvent`. Offers from non-contacts arrive by the request lane, which apps never
  ring for, and the server queues no wake-up without the contact proof.
- **LiveKit:** multi-node through its own Valkey; TURN/TLS on 443; egress, ingress, recording and
  SIP off; webhooks to `calls` on loopback; room caps, simulcast, dynacast, Opus DTX/RED allowed;
  `node_ip` from the inventory; only the SFU path (no peer-to-peer exists in LiveKit, and the
  token grants nothing that would allow it).
- **Logs:** room names, pseudonyms, call IDs and link handles never appear in logs or metrics.

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **The key schedule and signalling schema** (`crates/content`): `CallMessage`, the 1:1, group and link key derivations, `sender_key`, the key-index rule. | Test vectors in PROTOCOL §8 cross-checked independently; proptests (keys differ per identity, epoch and call; rotation never reuses a key index within the ring); fuzz target `call_message`. |
| **M2** | **Calls core:** the token minter, the Twirp room client, pseudonyms, call records, `/v1/calls`, `/v1/calls/group`, `/v1/calls/join`, caps, empty timeouts, wake-ups, removal mid-call. | Live tests against LiveKit: **non-members refused, expired tokens refused by LiveKit, a removed member is disconnected mid-call and cannot rejoin**, a 1:1 call admits only the two accounts, a non-contact cannot create a call to a closed account, caps hold; token claims snapshot-tested. |
| **M3** | **Call links and webhooks:** links with hashed secrets, expiry, lobby and admission; the webhook receiver (signature verified) for cleanup and capacity metrics. | Link create, join, lobby, admit, revoke, expiry live tests; forged, stale and replayed webhooks refused; records gone after `room_finished`; fuzz target `call_link` (request decoders). |
| **M4** | **LiveKit cluster and the E2EE harness:** two LiveKit nodes on a dedicated Valkey (compatibility recorded), TURN/TLS 443, Ansible; `tools/calls-harness` on LiveKit's Rust SDK with E2EE on. | The harness proves calls connect and media decrypts; a participant with the wrong key decodes nothing; keys rotate on a membership change and the removed participant's old key no longer decodes. |
| **M5** | **Load, sizing and the gate:** LiveKit's load tester for rooms × participants, CPU and bandwidth per participant, low-data versus normal mode, `tc netem` loss and latency; GDPR for the new stores; the security review; `P07-gate.md`. | Capacity per node recorded and turned into a sizing table; the prompt's gate, item by item. |

Order: M1 is independent of the server. M2 needs nothing from M1 but the identity rule. M3 builds
on M2. M4 needs M1 to M3. M5 needs everything.

## Threat-model rows this plan will propose (each with its milestone)

- A live 1:1 call: the room ID, the caller's and callee's **accounts**, its creation time
  (`valkey-hot`, for the call's life, at most 24 h; never in SurrealDB or logs).
- A live group call: a keyed hash of the group ID, the room ID, the time (for the call's life).
- Call links: `SHA-256` of the link ID, the admin token's hash, the room ID, expiry and lobby flag;
  waiting joiners' lobby handles and encrypted cards (minutes); no account.
- LiveKit's own state (on the calls hosts, memory and its Valkey): room IDs, pseudonymous
  identities, IP addresses of connected participants, track kinds and bitrates; webhooks are
  processed and dropped.
- The call signing key (`api` and `calls`): mints tokens and verifies webhooks.

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 to 6.

1. **1:1 calls name the callee, only for the call's life.** Recommended: the server checks the
   contact proof (the callee's access key) or that the callee is open, keeps the two accounts in
   `valkey-hot` until the room closes (at most 24 h), and wakes the callee. The alternative is a
   capability: the caller gets a join secret and sends it in the offer, so the server never learns
   the callee, but cannot keep anyone else out, and cannot send a wake-up.
2. **Call-link keys.** Recommended: Signal's design. Link holders exchange identities over the
   link's encrypted channel, then per-sender keys over Signal sessions, rotated on every join and
   leave; joining needs a Songbird account. The alternative is one key derived from the link: any
   past link holder can decrypt, and removal relies on the SFU.
3. **Participant caps.** Recommended: **32** in a video call, **128** audio-only (WhatsApp allows
   32; Signal 75). Configurable; M5's numbers may move them.
4. **LiveKit's store and TURN.** Recommended: a **dedicated Valkey** for LiveKit on the calls
   hosts, and **a second public IPv4** per calls host for TURN/TLS on 443 (`turn.` name under
   `songbird.chat`, still the owner's to choose). The alternatives: share `valkey-hot` under an
   ACL; an L4 SNI router in front of 443.
5. **Agent decisions, recorded unless you object:** `livekit-api` for tokens and webhooks only,
   with our own Twirp client on aws-lc-rs (finding 1); the harness outside the workspace
   (finding 10); LiveKit's `lk` CLI as the load tester (a pinned binary, test-only); tokens valid
   2 minutes.
