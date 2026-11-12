# Songbird protocol

Skeleton. Each section is filled by the prompt that builds it; every encoding has published test vectors.

## 1. Transport and framing (Prompt 2)

Implemented in `crates/proto` (shared by server and clients); decisions D-0019, D-0020.

- **Transport.** TLS 1.3 only (rustls, aws-lc-rs), ALPN `http/1.1`, then an HTTP/1.1 WebSocket
  upgrade (RFC 6455) to path `/v1/ws` with subprotocol `songbird.v1`. Another path gets `404`, no
  `songbird.v1` offer gets `400`, a request over 8 KiB gets `431`, a version other than 13 gets
  `426`. No extensions are negotiated (no permessage-deflate). Plain TCP is accepted only in
  development and CI.
- **Messages.** Binary messages only; a text message closes the connection (4003). Each message is
  one frame: a one-byte type, then big-endian fixed-width fields, then (for frames that carry one)
  a payload that runs to the end of the message.
- **Heartbeat.** The server pings after 25 s of inbound silence and closes after 60 s of silence.
  Clients answer pings and do not need to ping.

### 1.2 Frames

| Type | Direction | Frame | Body |
| --- | --- | --- | --- |
| `0x01` | C→S | `Send` | `req_id u32`, `idempotency_key [16]`, `flags u8`, [if flag `0x01`: `group [16]`, `epoch u64`], `count u16` (≥ 1), then per device (no flag `0x02`) `count ×` (`device_id [16]`, `len u32` (≥ 1), `envelope [len]`), or shared (flag `0x02`) `count × device_id [16]`, `len u32` (≥ 1), `body [len]` |
| `0x02` | C→S | `Ack` | `up_to_seq u64` |
| `0x03` | C→S | `Ephemeral` | `to [16]`, `payload` (≥ 1 byte) |
| `0x10` | C→S | `Auth` | protobuf `Auth` (§2) |
| `0x81` | S→C | `Deliver` | `seq u64`, `envelope` (≥ 1 byte) |
| `0x82` | S→C | `SendResult` | `req_id u32`, `status u8`; status 0 accepted; 1 rejected: `reason u16`, `retry_after_ms u32`; 2 device mismatch: protobuf `DeviceMismatch` |
| `0x83` | S→C | `Ephemeral` | `payload` |
| `0x90` | S→C | `Hello` | protobuf `Hello` (§2) |
| `0x91` | S→C | `AuthOk` | protobuf `AuthOk` |
| `0x92` | S→C | `Error` | protobuf `Error` (`code u32`, `retry_after_ms u32`), sent before a close when needed |

`Send` flags: `0x01` MLS commit, `0x02` shared body; other bits must be zero.

Rejection reasons: 1 rate limited, 2 too large, 3 too many recipients, 4 unknown recipient
(unused since milestone 2: unknown devices are reported in a device mismatch), 5 duplicate
recipient, 6 store unavailable, 7 idempotency key already used for other recipients (detected
when the earlier send shares a mailbox partition with this one; a reuse that cannot be detected is
stored as a new send, never dropped), 8 stale
MLS epoch (the group moved on; process the winning commit, then retry from the new epoch).
1 and 6 are retryable after `retry_after_ms`, with the
same idempotency key. Unknown reason codes are kept (forward compatibility).

Decoders reject trailing bytes, so every frame has exactly one encoding.

### 1.3 Limits

Configured on the server (`[delivery.limits]`) and checked before any allocation proportional to
input. Defaults: envelope 64 KiB, 1,024 recipients per `Send`, `Send` frame 1 MiB, ephemeral
payload 4 KiB, control-frame body 4 KiB. The WebSocket layer refuses any message larger than the
largest legal frame (1 MiB by default) from its header, before buffering it, and fails the
connection. Per connection: 50 sends/s (burst 200; excess rejected with reason 1), 400 frames/s
(burst 800; excess closes with 4103), 20 ephemeral events/s (burst 40; excess dropped). Per
listener: 2,000 new connections/s (burst 4,000) and 100,000 open connections; beyond either the
connection is closed with 4101 and a retry hint.

### 1.1 Reaching Songbird through a proxy (Prompt 1)

Clients that cannot reach Songbird directly may connect through a `songbird-proxy`
(`services/proxy`, operator guide `deploy/proxy/README.md`).

**Connection.** The client opens TCP to the proxy host and port, then TLS with SNI set to the proxy
host, validating the proxy's certificate against the system roots. Inside that TLS session it
opens its normal TLS session to the Songbird endpoint, with SNI set to that endpoint's name,
exactly as it would directly. The proxy routes by the inner SNI to an allowlist of Songbird
endpoints and refuses anything else by closing the connection without a response. Everything after
the inner `ClientHello` is opaque to the proxy. The inner `ClientHello` must fit in
`max_client_hello_bytes` (default 16 KiB) and arrive within the handshake timeout (default 10 s).

**Proxy links.** UTF-8, at most 300 bytes, one of:

```
songbird://proxy#<host>[:<port>]
https://<web-domain>/proxy#<host>[:<port>]
```

- The address is in the fragment so web servers never receive it.
- `<host>`: DNS name, 1–253 bytes, labels 1–63 bytes of `[A-Za-z0-9-]`, no leading or trailing
  `-`, no trailing dot; compared case-insensitively and stored lower-case. IP literals are not
  accepted.
- `<port>`: decimal 1–65535, default 443.
- `<web-domain>`: from a fixed list compiled into the app (owner decision open, D-0011).
- Anything else (other schemes, paths, user info, query strings, extra characters) is rejected.

Test vectors (from `services/proxy/src/link.rs`):

| Input | Result |
| --- | --- |
| `songbird://proxy#Proxy.Example.org` | host `proxy.example.org`, port 443 |
| `https://songbird.example/proxy#proxy.example.org:8443` (web domain `songbird.example`) | host `proxy.example.org`, port 8443 |
| `songbird://proxy#p.example:0` | rejected (port) |
| `songbird://proxy#user@p.example` | rejected (host) |
| `https://evil.example/proxy#p.example` | rejected (domain not allowed) |

## 2. Device authentication and sessions (Prompts 2, 3)

Decision D-0018.

### 2.1 Handshake

1. After the upgrade the server sends `Hello`:
   `nonce` (bytes, 32, fresh per connection), `server_time_ms` (uint64),
   `protocol_versions` (repeated uint32, currently `[1]`), `store_generation` (uint64, §3.6),
   `server_name` (string, informational).
2. Within 5 s the device sends `Auth`: `device_id` (bytes, 16), `signature` (bytes, 64),
   `last_acked_seq` (uint64), `client_version` (string, ≤ 64 printable ASCII bytes),
   `protocol_version` (uint32, one of the offered versions). Otherwise the server closes with 4102.
3. The server verifies the Ed25519 signature with the device's registered authentication key over
   the transcript below. An unknown device and a bad signature both close with 4000.
4. The server treats `last_acked_seq` as an `Ack`, claims the device (closing any older
   connection with 4001), replies `AuthOk` (`store_generation`, `resume_after_seq`) and starts
   delivery after `last_acked_seq`.

### 2.2 Signed transcript

```
"songbird.v1/device-auth\0" || u8 len(server_name) || server_name || nonce[32]
  || device_id[16] || protocol_version u32 (big-endian) || channel_binding[32]
```

The client uses the server name from its own configuration, never the one in `Hello`, so a
signature for one endpoint is useless at another. `channel_binding` is the TLS exporter of the
connection (RFC 9266 `tls-exporter`: 32 bytes, label `EXPORTER-Channel-Binding`, no context), so
a signature obtained by relaying the nonce over another TLS session does not verify (D-0024); TLS
must end at the delivery server. Without TLS (development only) it is 32 zero bytes. The server
name is the only variable-length field and is length-prefixed. Test vector: §13.

### 2.3 One connection per device

A newer authenticated connection for the same device closes the older one with 4001 (invariant 4).
A client closed with 4001 does not reconnect by itself.

### 2.4 Close codes and reconnecting

| Code | Meaning | Client action |
| --- | --- | --- |
| 4000 | authentication failed | stop |
| 4001 | replaced by a newer connection | stop |
| 4002 | device removed | stop |
| 4003 | protocol violation | stop |
| 4004 | unsupported protocol version | stop |
| 4100 | slow consumer | back off, then reconnect and catch up |
| 4101 | overloaded | back off (honour the hint) |
| 4102 | authentication timeout | back off |
| 4103 | rate limited | back off (honour the hint) |
| 4104 | store unavailable | back off |
| 4200 | server draining for a deploy | reconnect now (any node) |
| other | standard or unknown codes, transport errors | back off |

The reason may carry a hint `retry_ms=<decimal>`: wait at least that long. Backoff is exponential
with full jitter (initial 250 ms, cap 30 s, never below the hint); "reconnect now" waits a random
0–500 ms. On a deploy the server closes every connection with 4200 at random times within its
drain window (default 2 s) so clients do not return all at once.

## 3. Envelopes, mailbox and delivery (Prompt 2)

Decisions D-0020, D-0021.

### 3.1 Sending

A `Send` carries either one opaque, client-encrypted envelope per recipient device (pairwise
sessions) or, with flag `0x02`, one ciphertext for every listed device (an MLS group or channel
message), which the server stores once with a small entry per device. The server checks limits,
rate limits and recipients, stores every envelope in the recipients' mailboxes with each device's
next `seq` (fsynced), and only then answers `SendResult` accepted (invariant 1) and routes the
envelopes to connected recipients. A send rejected for a reason other than 6 stored nothing. After
reason 6 (store unavailable) the send may already be recorded, and if so the server stores it for
every recipient by itself; retrying with the same idempotency key returns the original result and
stores nothing twice.

**Device lists.** Every addressed device must exist, and a send that addresses an account must
address all of that account's devices except the sending device. Otherwise the answer is
`SendResult` status 2 with a `DeviceMismatch`: `missing` (devices to add), `extra` (devices that do
not exist), `stale` (devices whose keys changed; filled from Prompt 3). The client updates its view,
re-encrypts and retries with the same idempotency key.

**MLS commits.** A `Send` with flag `0x01` names the group and the epoch the commit was made
from. The server stores it only if the group is at that epoch and advances the group to `epoch +
1` in the same transaction, so of several concurrent commits exactly one is accepted; the others
are rejected with reason 8 and stored nothing. The group ID is 16 opaque bytes chosen by the
clients.

### 3.2 Idempotency

`idempotency_key` is 16 random bytes per logical message. A retry with the same key and the same
recipient devices (after a timeout, a disconnect or a retryable rejection) within 6 hours is
stored at most once: the server answers it from a record of the send (a keyed fingerprint of the
recipient set and where the send is stored), kept under a keyed hash of the key (never the key
itself) and not linked to the sender; envelopes already acknowledged are not stored or routed
again. The same key for other recipients is refused with reason 7. A retry after 6 hours may be stored again;
recipients drop it by the message ID inside the envelope.

### 3.3 Delivery and ordering

Each device has a sequence `seq` starting at 1, strictly increasing with no gaps at allocation.
After `AuthOk` the server sends every stored envelope after `last_acked_seq` in `seq` order, then
streams new ones. A device can receive a `seq` again after a reconnect if its `Ack` had not reached
the server; clients drop any `seq` at or below the last one they handed to the app, so the app
sees each envelope exactly once and in order. A `seq` may be skipped only where an envelope expired
(30 days, §3.5). `seq`s are allocated in the same durable transaction as the envelope, so they are
never reused, even across restarts or several server nodes.

### 3.4 Acknowledgement

`Ack{up_to_seq}` is cumulative: everything up to and including `up_to_seq` is stored on the device
and is deleted from the server (invariant 3). Clients acknowledge only what the app stored
durably, coalescing ACKs for a few milliseconds and flushing them before a clean close. An `Ack`
beyond the last `seq` sent on the connection closes it with 4003.

At most 256 envelopes (server setting `max_unacked`) are sent on a connection and not yet
acknowledged; the server pauses delivery at that limit and resumes on the next `Ack`. A socket
that accepts no data for 30 s is closed with 4100; the device catches up after reconnecting.

### 3.5 Retention

Undelivered envelopes are deleted after 30 days. Mailboxes hold at most 10,000 unacknowledged
envelopes per device by default; sends to a full mailbox are rejected with reason 6 (retryable).

### 3.6 Store generation

`Hello.store_generation` grows by one at every restore from backup. A client that sees it grow
resends every message from the last 30 days that has no end-to-end delivery receipt yet, and
re-asserts its device registration and keys; recipients drop duplicates by the message ID inside
the encrypted payload (milestone 6 implements the resend; the Rust client already reports the
change as `StoreGenerationChanged`).

### 3.7 Ephemeral events

Typing indicators, presence pings and call signals that are only useful live use `Ephemeral`.
They are never stored, only delivered if the recipient is connected, rate limited per connection,
and dropped first under pressure. The recipient learns the sender only from inside the encrypted
payload.

## 4. Identity, devices and key directory (Prompt 3)

## 5. Encrypted content schemas (Prompt 4)

## 6. Groups, roles and channels (MLS) (Prompt 5)

## 7. Attachments and packs (Prompt 6)

## 8. Calls and the call key schedule (Prompt 7)

## 9. Push (Prompt 8)

## 10. Settings sync and presence (Prompt 9)

## 11. Backup format and vault access (Prompt 10)

## 12. Versioning and compatibility rules

## 13. Test vectors

Frames (hex; from `crates/proto` tests and the fuzz seeds in `fuzz/corpus/proto_*`):

| Frame | Encoding |
| --- | --- |
| `Ack{up_to_seq: 42}` | `02 000000000000002a` |
| `Deliver{seq: 1, envelope: "envelope"}` | `81 0000000000000001 656e76656c6f7065` |
| `SendResult{req_id: 7, accepted}` | `82 00000007 00` |
| `SendResult{req_id: 7, rejected: rate limited, retry 500 ms}` | `82 00000007 01 0001 000001f4` |
| `Ephemeral{to: 44…44, "typing"}` | `03 44444444444444444444444444444444 747970696e67` |
| `Send{req_id 7, key 11…11, [(22…22, "abc"), (33…33, "z")]}` | `01 00000007 11111111111111111111111111111111 00 0002 22222222222222222222222222222222 00000003 616263 33333333333333333333333333333333 00000001 7a` |
| `Send{req_id 8, key 11…11, MLS commit (group 44…44, epoch 3), shared "grp" to 22…22, 33…33}` | `01 00000008 11111111111111111111111111111111 03 44444444444444444444444444444444 0000000000000003 0002 22222222222222222222222222222222 33333333333333333333333333333333 00000003 677270` |

Authentication transcript for server name `chat.example`, nonce 32 × `11`, device 16 × `22`,
version 1, channel binding 32 × `33`:

```
736f6e67626972642e76312f6465766963652d6175746800 0c 636861742e6578616d706c65
1111111111111111111111111111111111111111111111111111111111111111
22222222222222222222222222222222 00000001
3333333333333333333333333333333333333333333333333333333333333333
```
