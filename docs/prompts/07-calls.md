# Prompt 7 — Voice and video calls with LiveKit

*File: `docs/prompts/07-calls.md` · Skills: WebRTC and media infrastructure, applied cryptography review, load testing.*

**Goal:** end-to-end encrypted 1:1 and group voice and video calls, screen sharing and call links, on self-hosted LiveKit, with the servers unable to see or hear anything.

**Build:**

- **LiveKit cluster** from `deploy/`: self-hosted (Apache-2.0), multi-node through its Redis-protocol store (verify Valkey compatibility on the pinned version; otherwise run a dedicated instance), built-in TURN over TLS on port 443 for restrictive networks. Recording and Egress stay disabled.
- **`services/calls`** (Rust, using LiveKit's `livekit-api` crate): creates rooms with random IDs and mints short-lived, single-room tokens with the minimum grants. Participant identities are per-call pseudonyms, not account IDs, so LiveKit's own state reveals as little as possible. Authorization: a 1:1 call admits only the caller and the invited account's devices; a group call admits only current roster members whose role may start or join calls (Prompt 5). Rooms close when empty; participant caps configurable (larger for audio-only).
- **Signalling:** ring, accept, decline, busy and hang-up are encrypted content messages (Prompt 4). Live ringing uses the ephemeral lane; a missed-call record goes through the mailbox. Wake-ups use VoIP push on iOS and high-priority FCM on Android (Prompt 8). Calls from non-contacts go through message requests and do not ring.
- **End-to-end encryption:** LiveKit E2EE with a custom key provider, covering media and data channels. Keys come from Songbird's own crypto: for 1:1, from the Signal session through encrypted signalling; for groups, from the MLS exporter secret per epoch, rotated on every membership change. Specify the key schedule in `docs/PROTOCOL.md` with test vectors. No server component ever receives a media key.
- **IP privacy:** all calls go through the SFU, never peer-to-peer, so participants never learn each other's IP addresses.
- **Call links:** random secrets stored as hashes, with expiry and an optional lobby where an admin admits people.
- **LiveKit webhooks** are signature-verified and used only for cleanup and capacity metrics, with short retention.

**Also build (WhatsApp parity):** a low-data call mode ("Use less data for calls"): audio and video bitrate caps and simulcast layers chosen by the client, with server-side LiveKit configuration supporting them; measure bandwidth per mode in the load tests.

**Tests and benchmarks:** an automated harness using LiveKit's Rust SDK with E2EE enabled that proves calls connect, that a participant with the wrong key cannot decode media, and that keys rotate on membership change. LiveKit's load tester for rooms × participants; CPU and bandwidth per participant; behaviour under packet loss and latency (`tc netem`).

**Gate:** authorization negative tests pass (non-members, expired tokens, removed members mid-call); E2EE verified by the harness; capacity numbers per node recorded and turned into a sizing table.
