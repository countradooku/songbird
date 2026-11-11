# Prompt 4 — Messaging content and conversation features

*File: `docs/prompts/04-messaging.md` · Skills: protocol and schema design, Rust testing, security review.*

**Goal:** every chat feature WhatsApp and Signal have (except stories and live location), specified so future apps interoperate exactly, plus the few server-side controls those features need.

Most of these features live **inside** the encrypted payload, so the server cannot see them. Your job is twofold: define the encrypted content precisely, and build the server parts that cannot live on the client.

**Build `crates/content`** (protobuf, versioned, tolerant of unknown fields, never decoded by the server):

- Text with formatting spans and mentions; replies (quoted reference); reactions (add, replace, remove); edits (with an edit window and history); delete for everyone (with a time limit); forwarded marker with a forward counter (for forwarding limits).
- Voice notes; attachment pointers (Prompt 6); contact cards; static location pins.
- Polls (create, vote, change vote, close; single or multiple choice) and events with RSVPs. Define tallying so every device reaches the same result regardless of arrival order (last vote per voter wins, by a per-voter counter); prove it with property tests.
- Pinned messages (with duration), disappearing-timer changes, view-once media, nudge (Prompt 9), sticker references, group and channel system messages, call events (Prompt 7).
- Delivery and read receipts (batched), typing indicators (ephemeral lane).
- Sync messages to the user's own devices: sent transcripts, read state, starred messages, archived and muted chats, settings changes.
- Publish test vectors (byte-exact encodings) and a compatibility suite: every version decodes every older version's vectors.

**Build on the server:**

- **Message requests.** With sealed sender (Prompt 3), only senders holding the recipient's access key may send without restriction; others go through a request path the recipient controls (accept, block, report), rate-limited.
- **Blocking.** Server-side drop of envelopes from blocked identified senders, plus the client-side rule for sealed senders. Block lists are stored encrypted where the server does not need them in plaintext; document exactly what the server must see.
- **Reporting with message franking.** The reporter submits the plaintext and the franking opening; the server verifies the commitment it stamped at send time, then queues a minimal report for moderation with short retention. Nothing else about the conversation is revealed.
- **Disappearing and view-once hints.** An envelope flag tells the server to expire an undelivered envelope early (the disappearing timer) and to exclude it from any server-side retention beyond delivery.
- **Rate limits per conversation type** (1:1, group, channel, requests), enforced in the send path.

**Also build (WhatsApp parity):**

- **Broadcast lists.** One send request carrying separately encrypted 1:1 envelopes for up to a configured number of contacts; recipients see an ordinary 1:1 message. Rate-limited as a bulk send.
- **Restricted chat** (WhatsApp's advanced chat privacy). A chat-level policy inside the encrypted chat or group settings that tells every participant's client to block chat export and automatic media saving. Clients enforce it; the server only carries it. Document honestly that a modified client can ignore it.
- **Call history sync** across the user's own devices, as encrypted sync messages.
- **Lock chat, free up storage, media and links overview, in-chat search, save to photos, export chat, groups in common:** client-only features. Confirm that nothing in the protocol prevents them, and add nothing to the server.

**Message status (sending, sent, delivered, read, played, failed):**

| Status | Meaning | Produced by |
| --- | --- | --- |
| Sending | Not yet stored on the server | Sender's app, locally |
| Sent (one tick) | Stored durably on the server | The server's `Accepted` reply to the send |
| Delivered (two ticks) | At least one recipient device decrypted and saved it | Recipient's app: encrypted delivery receipt |
| Read (blue ticks) | Recipient opened the chat | Recipient's app: encrypted read receipt, if enabled |
| Played | A voice note or video note was played | Recipient's app: encrypted played receipt |
| Failed | Could not be sent after retries | Sender's app, locally |

- Delivered, read and played receipts are end-to-end encrypted content messages, so the server can neither fake nor hide them. They travel through the **mailbox**, not the ephemeral lane, so an offline sender still gets the ticks later.
- **Batching:** one receipt carries many message IDs ("read up to here"); opening a chat with 200 unread messages sends one receipt. The recipient's app coalesces receipts per conversation over a short window.
- **Multi-device:** receipts are encrypted to every device of the sender, so all of the sender's devices show the same ticks; a sync message tells the reader's own other devices what was read.
- **Groups:** each member sends receipts only to the message's sender, never to the whole group. The sender's app builds the per-member "Message info" view and shows two ticks only when every member has at least one device that received it, blue only when every member read it.
- **Read-receipt setting:** turning it off stops sending and stops showing others' read receipts (reciprocal). Whether group read receipts follow the setting is an owner decision; record it in `docs/DECISIONS.md`.
- **Tests:** property tests that statuses only move forward (sent → delivered → read) regardless of receipt arrival order; batching and coalescing tests; group aggregation tests with members joining and leaving between send and read; a load test measuring receipt traffic as a share of all envelopes in a 1,024-member group.

**Gate:** test vectors and compatibility suite pass; poll and reaction convergence proven by property tests across random orderings; franking verification has known-answer tests and a fuzzer; message-request and block paths covered by integration tests, including abuse scenarios (request floods, report floods).
