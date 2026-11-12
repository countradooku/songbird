# Prompt 2 — Realtime delivery core

*File: `docs/prompts/02-realtime.md` · Skills: Rust async and networking, concurrency testing, benchmarking, security review.*

**Goal:** the WebSocket server (`services/delivery`, its own binary and process) and everything it needs to deliver envelopes in order, fast, without loss, across many nodes.

**Detailed specification:** follow [Songbird Realtime Backend — Master Build Prompt](02a-realtime-master.md), milestones M1 to M4 and M7. Where it and the constitution disagree, the constitution wins. Summary of what it requires:

- `crates/proto`: hand-encoded hot-path frames, protobuf control frames, close-code ranges, challenge-signature device auth, `store_generation` in `Hello`.
- `sockudo-ws` server on per-core runtimes with `SO_REUSEPORT`; session algorithm (subscribe, then drain, then live, dedupe by `seq`, gap triggers drain, slow safety sweep); bounded queues with disconnect on overflow; graceful drain.
- `crates/mailbox` on SurrealDB with group commit, per-device `seq`, batched ACK deletes, 30-day expiry.
- `crates/registry` and `crates/router`: **Valkey pub/sub with one channel per device is the default** (the Sockudo model, targeted per device instead of broadcast). Each core subscribes to `device:<id>` for the devices it holds; a send publishes there, and zero receivers means offline, so a push job is queued. On attach, publish a `close` control message before subscribing, so any older connection elsewhere drops. Re-subscribe automatically after a Valkey restart. Plain `PUBLISH`/`SUBSCRIBE` on the single beta Valkey; sharded `SPUBLISH`/`SSUBSCRIBE` through redis-rs's cluster connection once Valkey is clustered. Direct node-to-node links and Iggy stay behind features as alternatives to benchmark later.
- `crates/client` and `tools/loadgen` with the delivery checker (no loss, no duplicates, strict order).

**Add beyond that document:**

- **Shared bodies for group fan-out.** A group or channel message is one ciphertext for many devices. Store the body once, keyed by a random message ID, and give each recipient device a small mailbox entry `(seq, body_id)`. Delete the body when the last device ACKs it or after 30 days. Prove with a benchmark that a 1,000-member send writes one body plus compact index entries.
- **Ephemeral lane.** Typing indicators, presence pings and call signals that are only useful live go through a separate, never-stored lane with its own rate limits, dropped first under pressure.
- **Sending from other services and clients without a socket.** No internal network Send API: the `send` crate (validate, store in SurrealDB, publish on the device's Valkey channel) is a library that `delivery`, `api`, `calls` and `worker` all link directly, so every send takes the same tested path with no extra hop. Server-originated notices (for example 'your device list changed') are server-signed system frames, never user messages. For clients with no open WebSocket (notification quick-reply, share extension, failed socket), `api` exposes one HTTP endpoint (PUT /v1/messages) that accepts the same encrypted envelopes as the WebSocket Send frame and calls the same crate. *(Amended 2026-11-13, D-0037; the store is the mailbox, Apache Iggy since D-0029.)*

**Gate:** Autobahn passes; every invariant has a named passing test; the checker passes in load, chaos (killed nodes, Valkey restart, SurrealDB pause) and a reconnect storm; throughput scales across cores and nodes with numbers against Sockudo on the same hardware.
