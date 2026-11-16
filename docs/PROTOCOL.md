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
| `0x01` | C→S | `Send` | `req_id u32`, `idempotency_key [16]`, `flags u8`, [if flag `0x01`: `group [16]`, `epoch u64`], [if `0x04`: `access_key [16]`], [if `0x10`: `commitment [32]`], [if `0x20`: `expire_after_s u32`], `count u16` (≥ 1), then per device (no flag `0x02`) `count ×` (`device_id [16]`, `len u32` (≥ 1), `envelope [len]`), or shared (flag `0x02`) `count × device_id [16]`, `len u32` (≥ 1), `body [len]` |
| `0x02` | C→S | `Ack` | `up_to_seq u64` |
| `0x03` | C→S | `Ephemeral` | `to [16]`, `payload` (≥ 1 byte) |
| `0x10` | C→S | `Auth` | protobuf `Auth` (§2) |
| `0x81` | S→C | `Deliver` | `seq u64`, `envelope` (≥ 1 byte) |
| `0x82` | S→C | `SendResult` | `req_id u32`, `status u8`; status 0 accepted; 1 rejected: `reason u16`, `retry_after_ms u32`; 2 device mismatch: protobuf `DeviceMismatch` |
| `0x83` | S→C | `Ephemeral` | `payload` |
| `0x90` | S→C | `Hello` | protobuf `Hello` (§2) |
| `0x91` | S→C | `AuthOk` | protobuf `AuthOk` |
| `0x92` | S→C | `Error` | protobuf `Error` (`code u32`, `retry_after_ms u32`), sent before a close when needed |

`Send` flags (other bits must be zero; each optional block appears only with its flag, in the order
above, so every frame has one encoding):

| Flag | Meaning | Rules |
| --- | --- | --- |
| `0x01` | MLS commit (§3.1) | |
| `0x02` | One shared body for every device | |
| `0x04` | `ACCESS`: the XOR of the access keys of every addressed account that is not open (§5.10), per device or with a shared body | Not with `0x08` |
| `0x08` | `REQUEST`: a message request (§5.10) | Not with `0x04`, `0x02` or `0x01` |
| `0x10` | `FRANKED`: the sender's franking commitment (§5.3), stamped by the server (§5.13) | |
| `0x20` | `EXPIRES`: the disappearing hint, 1 s to 30 days (§5.13) | Zero or more than 30 days refused |

Rejection reasons: 1 rate limited, 2 too large, 3 too many recipients, 4 unknown recipient
(unused since milestone 2: unknown devices are reported in a device mismatch), 5 duplicate
recipient, 6 store unavailable, 7 idempotency key already used for other recipients (detected
when the earlier send shares a mailbox partition with this one; a reuse that cannot be detected is
stored as a new send, never dropped), 8 stale
MLS epoch (the group moved on; process the winning commit, then retry from the new epoch), 9 an
envelope begins with `F5 53 42`, the prefix reserved for what the server writes (system frames
§3.9, franking stamps §5.13; never retryable), 10 access required (a send to another account with
neither its access key, nor the right one, nor `REQUEST`: fetch the profile key again or send a
request, §5.10), 11 an invalid request (not franked, or for more than one other account, §5.10).
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

`Hello.store_generation` grows at every restore from backup and at every loss of the mailbox
(D-0040: it jumps to at least the restore time in milliseconds, so it always exceeds every value
clients have seen, even when the registry itself was restored from an older backup). A client
that sees it grow:

1. resets its delivery cursor to 0 (the mailbox's `seq` counters may restart);
2. resends every message from its send log, in the order first sent, with each message's original
   idempotency key. A mailbox that survived the restore recognises the key and stores nothing
   twice; a lost one stores the message again. The log holds every accepted send until the
   message's end-to-end delivery receipt arrives (`Client::confirm_delivered`) or 30 days pass;
3. re-asserts its device registration and keys (Prompt 3).

Recipients drop repeats by the message ID inside the encrypted payload. A resend the server
refuses for a reason that needs the app (a changed device list, an MLS epoch that moved on) leaves
the log and is reported (`ResendRefused`), so the app re-encrypts it. The mailbox itself is never
backed up (D-0040). Tests: `tests/e2e/tests/restore.rs`.

### 3.7 Ephemeral events

Typing indicators, presence pings and call signals that are only useful live use `Ephemeral`.
They are never stored, only delivered if the recipient is connected, rate limited per connection,
and dropped first under pressure. The recipient learns the sender only from inside the encrypted
payload.

### 3.8 Sending without a WebSocket: `PUT /v1/messages`

Decisions D-0037, D-0044. For a client with no open WebSocket (a notification quick-reply, a
share extension, a socket that failed), `api` accepts the same send over HTTPS:

- **Request:** `PUT /v1/messages`, body = one `Send` frame (§1.2), byte for byte as it would go
  over the WebSocket, `Content-Length` required (at most `max_send_bytes`; otherwise 411 or 413),
  signed like every `api` request (`authorization` over method, path, server name, time, nonce
  and body digest; `x-songbird-content-sha256` required). The server verifies the signature from
  the headers before it reads the body, then checks the body against the digest (401 otherwise).
- **Response:** `200` with body = the `SendResult` frame (§1.2) the WebSocket would have sent
  (`application/octet-stream`): accepted, rejected with a reason and retry hint, or a device
  mismatch. Other statuses come only from before the send path: 400 (not a `Send` frame, or over
  a limit), 401, 411, 413, 503 (no send path configured).
- **Same rules:** the same limits, the same device-list check, the same idempotency (a retry with
  the same key over HTTP or the WebSocket, in either order, is stored once), the same rate limit
  per device (50 sends/s, burst 200, counted across every `api` node; reason 1 with a hint),
  the same routing and push wake-ups. The request ID in the frame is echoed.

### 3.9 System frames

Decisions D-0037, D-0044. A notice from the server itself (`Kind` 1: an account's device list
changed; body: the account ID) arrives as an ordinary stored envelope (`Deliver`, with a `seq`,
acknowledged like any other), in a format no user can send:

```
magic F5 53 42 53 59 53 00 01 | version u8 (1) | key_id [8] | device [16] | issued_at_ms u64
  | notice_id [16] | kind u16 | body_len u16 (<= 1024) | body | signature [64]
```

- The signature is Ed25519 by the server's system key over `songbird-system-frame-v1\0`
  followed by every byte before the signature. Apps pin the system public key; `key_id` is the
  first 8 bytes of its SHA-256 (rotation). A frame that does not verify, names another device, or
  repeats a `notice_id` already seen is dropped and never shown. Unknown kinds are verified, then
  ignored.
- The send path refuses any user envelope that begins with the magic (reason 9), over the
  WebSocket and HTTP alike, so a client never has to consider a forged notice.
- Format and test vector: `crates/proto/src/system.rs`; signer: `crates/send/src/system.rs`.

## 4. Identity, devices and key directory (Prompt 3)

Decisions D-0047 (the owner's Prompt 3 choices) and D-0048 (registration).

### 4.1 Registration: `POST /v1/registration`

Accounts have no phone number or e-mail. An account is a random ID, an **account identity key**
(Ed25519; it signs the device list from M4 and is what people verify) and its devices. Each
device has its own **authentication key** (Ed25519, §2), never used for end-to-end encryption.
The server chooses both IDs (16 random bytes, D-0003).

1. `POST /v1/registration/challenge` (no body) returns a 51-byte proof-of-work challenge
   (`application/octet-stream`):

   ```
   version u8 (1) | issued_ms u64 | memory_kib u32 | iterations u32 | bits u8 | solutions u8
     | nonce [16] | tag [16]
   ```

   The tag is the first 16 bytes of `HMAC-SHA256(key, "songbird.v1/pow-challenge\0" || the 35
   bytes before it)`, with a key every `api` node derives from the registration secret: no state
   is kept until a solution arrives. A challenge is valid for 10 minutes and for one attempt.
2. The client finds `solutions` strictly increasing `u32` counters `c`, each such that

   ```
   Argon2id(v1.3, m = memory_kib KiB, t = iterations, p = 1, 32-byte output)(
       password = "songbird.v1/pow\0" || challenge[0..35] || c (u32 big-endian),
       salt = nonce)
   ```

   begins with `bits` zero bits (on average `solutions × 2^bits` evaluations). A client refuses
   parameters outside: memory 8–262,144 KiB, iterations 1–16, bits 0–24, solutions 1–64.
   Defaults: 16 MiB, 1, 4, 8 (128 evaluations; 0.48 s median on an Apple M5 Pro core).
3. `POST /v1/registration` with `Content-Length` and the body:

   ```
   version u8 (1) | challenge [51] | k u8 | k × solution u32 | flags u8
     | [invite [15] if flags & 1] | identity_key [32] | auth_key [32]
     | identity_sig [64] | auth_sig [64]
   ```

   Unknown flags, trailing bytes and `k` outside 1–64 are refused. Each key signs, with Ed25519:

   ```
   context || u8 len(server_name) || server_name || challenge [51] || identity_key [32]
     || auth_key [32]
   ```

   with context `"songbird.v1/register-identity\0"` for the identity key and
   `"songbird.v1/register-device\0"` for the authentication key. The two keys must differ, and
   each must be the canonical encoding of a point of prime order (small-order and mixed-order
   keys are refused: under the identity point, `R = sB` verifies for any message).

Answers:

| Status | Body | Meaning |
| --- | --- | --- |
| 201 | `{"account": hex, "device": hex}` | Registered |
| 400 | `{"error": "request" \| "keys" \| "server name"}` | Does not decode; keys or signatures refused (the challenge is not spent) |
| 403 | `{"error": "challenge"}` | Forged, expired, already used or wrongly solved: get a new challenge |
| 403 | `{"error": "invite"}` | Invite-only mode: the code is missing, unknown, used up, expired or revoked (one answer for all) |
| 411, 413 | none | No `Content-Length`, or longer than 518 bytes |
| 429 | none, `Retry-After` | Throttled (per IP range or deployment-wide) |
| 503 | none | Registration is not configured, or a store is unavailable |

The server checks, cheapest first: length and decoding; throttles; the challenge's tag and age;
both keys and signatures; then spends the challenge (single use); then verifies the work; then
consumes the invite and creates the account in one transaction.

**Right after registering**, delivery nodes may not know the new device yet: they reload the
directory from the registry within `directory_poll_ms` (1 s by default). A client that connects
in that window gets 4000 like any unknown device. Apps therefore treat 4000 as retryable, with
backoff, for 10 seconds after registering (`ClientConfig::new_device_grace` in the Rust client).
The server never looks a device up on behalf of an unauthenticated connection.

### 4.2 Invites

Invite-only mode is a server setting (`[api.registration] invite_only`, the launch default);
switching it off needs no migration, and codes are then ignored.

- **Codes:** 15 random bytes (120 bits), shown as 24 Crockford base32 symbols in six groups of
  four (`0123-4567-89AB-CDEF-GHJK-MNPQ`). Parsing ignores case, hyphens and spaces and reads `O`
  as `0`, `I` and `L` as `1`. The server stores `SHA-256("songbird.v1/invite\0" || code)` with
  the uses left and the expiry, nothing else: **not who created the code** (D-0038, D-0047). The
  row goes at its last use.
- **Guessing:** a guess costs a solved challenge, and refused codes spend a per-range budget
  (10 an hour, burst 5) and a deployment-wide one (600 an hour); once spent, registrations from
  that range wait (429) before their challenge is even checked.
- **Users' invites**, signed like every device request (§2 of `api`, D-0036):
  - `POST /v1/invites`, optional body `{"ttl_days": n}` (capped at 7 by default): `201
    {"code": "...", "expires_in_secs": n}`, single use, one taken from the account's allowance (5
    per new account by default); `403 {"error": "allowance"}` when none is left.
  - `GET /v1/invites`: `{"allowance": n, "invite_only": bool}`.
  - `DELETE /v1/invites`, body `{"code": "..."}`: revokes it; `204` whether or not it existed.
    Whoever holds a code may revoke it (nothing records who created it).
- **Operators:** `songbird-admin invites create --count N --uses U --days D` prints codes once
  (audit-logged without them); `songbird-admin invites grant --account <hex> --add N`.

### 4.3 Usernames, the username key and links

Decision D-0049 (unique handles, the owner's choice). Every request is signed by a device.

- **A username** is 3 to 32 characters: ASCII letters, digits, `_` and `.`; it starts with a
  letter, has no `..` and does not end with `.`. Unique in lower case (`Radu` and `radu` are one
  username); shown as typed. Found only by exact match: there is no search, prefix or listing.
- **The server never sees it.** It stores and is asked about only
  `hash = s·G` on Ristretto255, with `s = SHA-512("songbird.v1/username\0" || lower-cased
  username)` reduced mod l and `G` the point `Sho("songbird.v1/username-generator")` squeezes
  (64 bytes, `from_uniform_bytes`). The SHO is libsignal's poksho `ShoHmacSha256`.
- **Claiming** needs a proof: a poksho proof (label `POKSHO_Ristretto_SHOHMACSHA256`, statement
  `hash = s·G`, encoded `01 01 01 00 02`, points base, hash, `G`, message the hash) that the
  client knows `s`: `challenge || response`, two canonical scalars, 64 bytes. libsignal's own
  verifier accepts these proofs (`tools/libsignal-vectors`).

| Request | Body | Answers |
| --- | --- | --- |
| `PUT /v1/username` | `hash [32] \|\| proof [64]` | 204; 409 `{"error":"taken"}` (another account's, held, or reserved); 400 `{"error":"proof"}`; 429 |
| `DELETE /v1/username` | none | 204 |
| `POST /v1/username/lookup` | `{"hash": hex, "key"?: digits}` | 200 `{"account": hex}`; 404; 400 for a malformed hash or key; 429 |
| `PUT /v1/username/key` | `{"key": "4 to 10 digits"}` | 204 |
| `DELETE /v1/username/key` | none | 204 |
| `PUT /v1/username/link` | the link's ciphertext, 1 to 256 bytes | 200 `{"handle": 32 hex}`; 409 `{"error":"no username"}` |
| `DELETE /v1/username/link` | none | 204 |
| `GET /v1/username/link/<handle>` | none | 200 the ciphertext; 404 |

- **Changing or releasing** a username holds the old one for 30 days: nobody can claim or find
  it, so nobody can pose as its previous owner by grabbing it. The held row names no account.
  Account deletion releases the username the same way.
- **Reserved names** (`admin`, `support`, `songbird`, … plus `[api.usernames] reserved`) answer
  `taken`; the server compares hashes.
- **The username key** (optional): with one set, a lookup finds the account only with the right
  key. A missing key, a wrong key and a username whose guessing budget is spent all answer 404,
  exactly like an unknown or held username (the owner's decision, D-0049). A lookup that
  carries a key always costs one Argon2id verification, and one without never does, so time
  does not tell them apart either. The key is stored as `salt [16] || Argon2id(m = 19 MiB, t = 2,
  p = 1, secret = a pepper from the secrets store)(key, salt)`.
- **Throttles:** lookups and link reads 120 an hour per account (burst 30) and 600 per IP range
  (burst 100); claims 2 an hour per account (burst 5), counting every attempt; key guesses that
  find nothing, 1 an hour per username across all requesters (burst 10).
- **Links** let someone share a username without typing it, and reset the link without changing
  the username: the client encrypts the username under a key that stays in the link (the
  server never sees it) and uploads the ciphertext; the server keeps it under a new random
  16-byte handle each time (the old handle stops working). A username change deletes the link.
  The client's encryption follows Signal's username links; the server only stores bytes.

### 4.4 The key directory (PQXDH prekeys)

Decision D-0050. Every device has its own **device identity key** (X25519, used by PQXDH;
D-0048) and publishes prekeys for others to start sessions with it. Keys are libsignal's
serializations: an X25519 key is `0x05 || u [32]`; a post-quantum key is ML-KEM-1024 only,
`0x0A || encapsulation key [1568]` (libsignal's pre-standard Kyber1024, type `0x08`, is refused;
the owner's decision). Signatures are XEdDSA (libsignal's variant: the signer's Edwards sign bit in
the top bit of `s`) by the device identity key over the key's serialization.

| Request | Body | Answers |
| --- | --- | --- |
| `PUT /v1/keys` | the upload below (at most 169,177 bytes; signed over its digest, authenticated before the body is read) | 204; 400 `{"error": "request" \| "keys" \| "signature" \| "incomplete" \| "duplicate"}`; 409 `{"error": "identity" \| "full" \| "duplicate"}` |
| `GET /v1/keys` | none | 200 `{"ec": n, "kem": n}` (one-time prekeys left) |
| `POST /v1/keys/fetch` | `{"account": hex, "device"?: hex}` | 200 the bundles below; 404 (no device of the account holds keys, the requester's own excepted); 429 |

Upload (integers big-endian):

```
version u8 (1) | flags u8 (1 identity, 2 signed prekey, 4 last-resort KEM prekey)
  | [identity [33]] | [id u32 | key [33] | sig [64]] | [id u32 | key [1569] | sig [64]]
  | n u16 | n × (id u32 | key [33])                      one-time X25519, n <= 100
  | m u16 | m × (id u32 | key [1569] | sig [64])         one-time ML-KEM-1024, m <= 100
```

- The first upload must carry the identity key, a signed prekey and a last-resort ML-KEM prekey.
  The identity key is **set once and never replaced** (another one: 409 `identity`; a new
  identity is a new device, M4). Signed and last-resort prekeys replace the current ones.
- The server checks every key and signature before storing anything: X25519 keys must be honest
  (canonical `u`, on the curve, of prime order); ML-KEM keys must pass FIPS 203's modulus check
  (every coefficient below 3329); XEdDSA signatures must verify with a canonical `s` (stricter than
  libsignal, which reduces a larger one). A device holds at most 200 one-time keys of each kind.

Fetch answer: `version u8 (1) | n u8 | n × bundle`, one per device of the account that holds
keys (not the requester's own device):

```
device [16] | identity [33] | signed: id u32 | key [33] | sig [64]
  | flags u8 (1 a one-time X25519 key follows, 2 the KEM key is one-time, not last-resort)
  | [id u32 | key [33]] | kem: id u32 | key [1569] | sig [64]
```

- Each one-time key goes to **exactly one fetch** and leaves the store with it (the prompt's gate:
  `no_one_time_prekey_is_ever_served_twice_under_parallel_claims`).
- **Exhaustion:** fetches are limited per requesting account (240 an hour, burst 60) and per IP
  range; one-time keys per target account are limited across all requesters (60 an hour, burst
  30). Past that budget a fetch still answers, with the last-resort ML-KEM key and no one-time
  X25519 key, and the one-time keys stay for later.
- **Refill:** when a fetch leaves a device below 10 one-time keys of either kind, the server sends
  it a system notice (§3.9) of kind 2, `PrekeysLow`, body `ec u16 | kem u16`, at most once an hour.
  Clients also see their counts with `GET /v1/keys`.
- A client verifies both signatures with the identity key before PQXDH, as libsignal does.

### 4.5 MLS KeyPackages

Decision D-0051. Groups (Prompt 5) add a device with one of its KeyPackages (RFC 9420 §10). The
server checks each package before publishing it, with its own focused parser (the owner's choice
over running OpenMLS on the server), and **binds it to the uploading device**:

- RFC 9420's encoding, strictly (minimal variable-length integers, no trailing bytes, at most
  2,048 bytes, no duplicate extension types); version mls10; ciphersuite `0x0001` or `0x0003`
  (X25519 HPKE, Ed25519 signatures);
- `init_key` and the leaf's `encryption_key` honest X25519 keys, different from each other; the
  `signature_key` an honest Ed25519 key;
- a **basic credential whose identity is the uploading device's 16-byte ID**;
- capabilities listing mls10, the package's ciphersuite and basic credentials; leaf source
  `key_package`; a lifetime that has begun (an hour of skew allowed), has not ended and is at most
  100 days;
- both `SignWithLabel` signatures (`LeafNodeTBS`, `KeyPackageTBS`) by the signature key.

A package carrying the `last_resort` extension (type 10, as OpenMLS writes it) replaces the
device's last-resort package; the others are single use. Packages are stored under their
`KeyPackageRef` (RFC 9420 §5.2).

| Request | Body | Answers |
| --- | --- | --- |
| `PUT /v1/keypackages` | `version u8 (1) \| n u8 \| n × (len u16 \| KeyPackage)`, 1 to 100 packages | 204; 400 `{"error": "request" \| "unsupported" \| "keys" \| "identity" \| "lifetime" \| "signature" \| "duplicate" \| "last resort"}`; 409 `{"error": "full" \| "duplicate"}` |
| `GET /v1/keypackages` | none | 200 `{"single_use": n, "last_resort": bool}` (unexpired) |
| `POST /v1/keypackages/fetch` | `{"account": hex, "device"?: hex}` | 200 `version u8 \| n u8 \| n × (device [16] \| flags u8 (1 single use) \| len u16 \| KeyPackage)`; 404; 429 |

- Each single-use package goes to exactly one fetch (`no_key_package_is_ever_served_twice_under_parallel_claims`);
  an expired one is never served; beyond the single-use ones, the unexpired last-resort one.
- The same throttles as prekey fetches (§4.4), counted separately, with the same per-target
  budget and last-resort fall-back; a device left below 10 single-use packages gets a system
  notice of kind 3, `KeyPackagesLow`, body `n u16`, at most once an hour. At most 200 stored per
  device.
- Clients still validate every package fully before use (RFC 9420 §10.1).

### 4.6 Devices: QR provisioning, linking and the signed device list

Decision D-0052 (M4). An account has one **primary** device (the one holding the account identity
key, which registered it) and at most five linked devices (owner, D-0047; `max_devices`, until
Prompt 11's plans). Integers are big-endian.

**Linking a device.**

1. The new device draws an X25519 provisioning key and opens a channel
   (`POST /v1/provisioning`, unsigned, throttled per IP range). Its QR code shows the channel ID
   and the provisioning public key.
2. The primary asks for a link token (`POST /v1/devices/link-token`): 32 random bytes, stored
   only as `SHA-256("songbird.v1/link-token\0" || token)`, single use, ten minutes. It reserves
   a server-chosen device ID and counts toward the limit until it is used or expires.
3. The primary seals the provisioning message to the QR key and puts it in the channel
   (`PUT /v1/provisioning/<channel>`, signed). Seal: X25519 with a fresh ephemeral key;
   HKDF-SHA256 (salt `"songbird.v1/provisioning"`, info `ephemeral || recipient`) to an
   AES-256-GCM key; nonce zero (one key, one message); AAD `version || ephemeral || recipient`.
   Envelope: `version u8 (1) | ephemeral [32] | ciphertext || tag [16]`, at most 4,096 bytes. A
   channel holds one message, written once and read once, and lives ten minutes. The server sees
   only the envelope. Plaintext:
   `version u8 (1) | account [16] | account_identity [32] | token [32] | device [16] | confirm_key [32] | u8 len | server_name`.
4. The new device reads it (`GET /v1/provisioning/<channel>`, unsigned; waits up to 25 s, 204
   when nothing came, 404 once it has been read or the channel is gone) and opens it.
5. The new device links (`POST /v1/devices/link`, unsigned, throttled per IP range):
   `version u8 (1) | token [32] | device [16] | auth_key [32] | identity_key [33] | auth_sig [64] | identity_sig [64] | confirm [32]`.
   The transcript is
   `context || u8 len(server_name) || server_name || token || device || auth_key || identity_key`.
   `auth_sig` is Ed25519 by the authentication key with context
   `"songbird.v1/link-device-auth\0"`; `identity_sig` is XEdDSA by the identity key with context
   `"songbird.v1/link-device-identity\0"`. `confirm` is
   `HMAC-SHA256(confirm_key, "songbird.v1/link-confirm\0" || transcript)` over the identity
   transcript. The server checks both keys are honest and both signatures verify, then consumes
   the token for exactly that device ID. The device is created **pending**, with its identity key
   fixed (a later `PUT /v1/keys` cannot change it).
6. The primary lists the account's devices (`GET /v1/devices`). It checks the pending device's
   `confirm` tag with the `confirm_key` it sent. The server saw the token but never the
   confirmation key, so it cannot link keys of its own unnoticed. The primary then signs a list
   that names the new device.

While pending, a device authenticates but is outside the send check: a send to its account need
not address it, and a send that does is refused as extra (§3.1). Its keys are not served
(§4.4, §4.5). Once a list names it, a send that leaves it out is refused as missing, and the
sender fetches the list again.

**The device list.**

```text
version u8 (1) | account [16] | list_version u64 | issued_ms u64 | n u8 (1..=16)
  | n × (device [16] | auth_key [32] | identity_key [33] | flags u8 (1 primary)) | signature [64]
```

The signature is Ed25519 by the account identity key over `"songbird.v1/device-list\0"` followed
by every byte before it. Exactly one entry is the primary; no device appears twice.

`PUT /v1/devices/list` accepts a list only if all of these hold:

- it verifies under the account identity key;
- it names the requester's account;
- it has at most `max_devices` entries;
- its version is higher than the stored one (no rollback);
- every entry is an enabled device of the account with exactly its stored keys, and the primary
  entry is the account's primary.

On acceptance, devices it names stop being pending. Enabled devices it leaves out are removed:
they are disabled at once and a `DeleteDevices` job (outbox) deletes them from every store, as
account deletion does. Clients keep the highest `list_version` they have seen for each account
and refuse an older one, so a server cannot roll a list back to a device it removed.

A linked device may remove itself (`DELETE /v1/devices/self`); the primary cannot (it deletes the
account instead). **Only the primary deletes the account** (`DELETE /v1/account` from any other
device: 403 `{"error": "primary"}`, checked inside the deletion's transaction). **A pending device
changes nothing account-wide**: claiming, changing or releasing a username, the username key and
link, and invites answer 403 `{"error": "pending"}` (lookups and reading links are allowed). Linking, a new list and a removal send a `DeviceListChanged` system notice
(kind 1, §3.9) to the account's other devices.

| Request | Body | Answers |
| --- | --- | --- |
| `POST /v1/provisioning` | none (unsigned) | 200 `{"channel": hex, "expires_in": s}`; 429 |
| `PUT /v1/provisioning/<channel>` | envelope (signed) | 204; 400 `{"error": "size"}`; 404 (unknown, expired or written); 413; 429 |
| `GET /v1/provisioning/<channel>` | none (unsigned) | 200 envelope; 204 (ask again); 404; 429 |
| `POST /v1/devices/link-token` | none (the primary) | 200 `{"token": hex, "device": hex, "expires_in": s}`; 409 `{"error": "primary" \| "limit"}`; 429 |
| `POST /v1/devices/link` | link request (unsigned) | 200 `{"account": hex, "device": hex}`; 400 `{"error": "request" \| "keys" \| "signature"}`; 409 `{"error": "token" \| "limit"}`; 429 |
| `GET /v1/devices` | none | 200 `{"devices": [{"device", "auth_key", "identity_key", "primary", "pending", "confirm"}], "list_version"}` |
| `PUT /v1/devices/list` | list | 204; 400 `{"error": "list" \| "account" \| "limit" \| "signature"}`; 409 `{"error": "version" \| "devices" \| "identity"}` |
| `POST /v1/devices/list/fetch` | `{"account": hex}` | 200 list; 404 (none stored); 429 |
| `DELETE /v1/devices/self` | none | 204; 409 `{"error": "primary"}` |

Throttles (defaults), all as GCRA records in `valkey-hot` under keyed hashes:

- per IP range: 60 channels an hour, 1,200 channel reads an hour and 30 link attempts an hour;
- per account: 20 link tokens and provisioning messages an hour;
- per requesting account: 240 list fetches an hour.

### 4.7 Second factors and multiple accounts

Decision D-0053 (M4b). An account may set a two-step PIN and passkeys. Once it has either, linking
a device needs one of them, and so will account recovery (Prompt 10). Only the primary sets,
replaces or removes them.

**The link request's factor.** These bytes follow `confirm` (§4.6). They are not covered by the
link signatures; each factor binds itself:

```text
factor u8: 0 none
         | 1 PIN:     len u8 | 6 to 12 ASCII digits
         | 2 passkey: len u16 | credential_id | len u16 | authenticatorData | len u16 | clientDataJSON
                      | len u8 | signature
```

- **PIN.** Stored as `salt [16] || Argon2id(m, t, p = 1, secret = pepper)(pin, salt)`. The pepper
  is derived from `[api.keys] secret` (the secrets store, never the database or its backups).
  Each attempt is counted before it is checked, so parallel guesses cannot exceed the limit:
  - the first 5 attempts are free;
  - each further attempt locks the next for `60 s · 2^(k-1)`, at most a week;
  - after 20 attempts the PIN is unusable until the primary sets a new one;
  - a correct PIN resets the count.
  Refusals: 403 `{"error": "factor"}` for a missing or wrong factor, 403
  `{"error": "locked", "retry_after": s}` while locked.
- **Passkey.** WebAuthn with Songbird's own minimal verifier (`songbird_keys::webauthn`):
  - ES256 or EdDSA (Ed25519) credentials;
  - no attestation is trusted;
  - user presence always, user verification required by default;
  - the RP ID and allowed origins come from `[api.keys.devices]`;
  - the signature counter must grow unless it is always zero.
  The assertion's challenge is `SHA-256("songbird.v1/link-passkey\0" || identity-context
  transcript)`, so it approves exactly this token, device ID, pair of keys and server, and needs
  no server state.

| Request | Body | Answers |
| --- | --- | --- |
| `PUT /v1/account/pin` | `{"pin": "6 to 12 digits"}` (primary) | 204; 400 `{"error": "pin"}`; 403 `{"error": "primary"}` |
| `DELETE /v1/account/pin` | none (primary) | 204; 403 |
| `POST /v1/account/passkeys/challenge` | none (primary) | 200 `{"challenge": hex, "rp_id"}`, single use, five minutes; 503 without an RP ID |
| `PUT /v1/account/passkeys` | `{"client_data_json": hex, "attestation_object": hex}` (primary) | 200 `{"id": hex}`; 400 `{"error": "passkey"}`; 409 `{"error": "challenge" \| "limit" \| "duplicate"}` |
| `DELETE /v1/account/passkeys` | `{"id": hex}` (primary) | 204 |
| `GET /v1/account/factors` | none | 200 `{"pin", "pin_locked_secs", "pin_unusable", "passkeys": [hex]}` |

**Multiple accounts on one installation.** Each account is a separate account on the server:
its own device ID and authentication key, identity keys, mailbox and push registration. The app
holds one device per account and signs each request as that account's device. One push token
registered for several accounts is sealed and stored under a separate keyed index per device.
The push service still opens each registration to deliver, so it can see that one token belongs
to several devices: it links them. Where the platform allows several tokens per installation
(FCM instance IDs, Web Push subscriptions), the app registers one per account. APNs gives one
token per app installation, so on iOS the link remains (threat model §6).

### 4.8 Encrypted profiles and sealed sender

Decision D-0054 (M5).

**Profiles.** A profile is one blob, encrypted by the client under its 32-byte profile key, which
it shares only with contacts. The blob holds the name, avatar pointer, about, status line and
profile links; the server never sees inside it.

```text
PUT /v1/profile:
version u8 (1) | profile_version u64 | access_key [16] | flags u8 (1 anyone may send sealed)
  | len u16 | blob (1..=8192)
```

- The version must exceed the stored one (409 `{"error": "version"}`).
- A pending device may not change it (403 `pending`).
- `POST /v1/profile/fetch` `{"account": hex}` answers `{"version", "profile": hex}` and is
  throttled per requesting account.
- Avatars are encrypted by the client and uploaded with `PUT /v1/profile/avatar` (a signed body,
  at most 512 KiB). They are stored in RustFS under a fresh random 32-byte ID (`p/<hex>`), which
  is answered as `{"avatar": hex}` and goes inside the profile blob.
- `GET /v1/profile/avatar/<id>` serves only an account's current avatar. Replaced ones are
  deleted by the worker after an hour; all of them go when the account is deleted.

**Sealed sender** (behind `[api.profiles] sealed_sender`, off by default; Prompt 12 verifies it):

- **Access key.** `access_key = HKDF-SHA256(salt = "songbird.v1", ikm = profile_key,
  info = "unidentified-access")[..16]` (`songbird_keys::sealed::access_key`). Contacts derive it
  from the profile key. The server stores only it, plus the "anyone may send" flag.
- **Sender certificate.** `GET /v1/certificate`, from a listed device that has uploaded its
  identity key:
  `version u8 (1) | key_id [8] | account [16] | device [16] | identity_key [33] | expires_ms u64 | signature [64]`.
  - The signature is Ed25519 by the certificate key over `"songbird.v1/sender-certificate\0"`
    followed by every byte before it.
  - `key_id` is the first 8 bytes of SHA-256 of the key; lifetime 24 hours (configurable, at
    most a week).
  - The sender puts the certificate inside the end-to-end encrypted envelope. The recipient
    checks the signature against the pinned key, the expiry, and the identity key against the
    sender's.
- **Sealed send.** `PUT /v1/messages/sealed` carries an ordinary `Send` frame (no MLS commit),
  with no device signature, and the header `Unidentified-Access-Key: hex(16)`. The header holds
  the XOR of the access keys of every addressed account that is not open
  (`songbird_keys::sealed::combine`).
  - The server recomputes it from what it stores and compares in constant time.
  - An account with no access key that is not open cannot be reached sealed (401).
  - The device-list check applies as for any send.
  - Throttles: per IP range and per recipient account.
  - The server learns who receives, never who sent.

### 4.9 Key transparency and security notifications

Decisions D-0055 and D-0057. Key transparency runs on Meta's `akd` 0.13 (the owner's decision of
2026-11-16), a verifiable key directory with the WhatsApp v1 configuration:

- labels hidden behind a VRF;
- lookup proofs of a label's current value (and of non-membership);
- key-history proofs;
- append-only (audit) proofs between epochs.

What the directory records about each account:

- **Label** = `kind u8 (1 identity, 2 device list, 3 username) || account [16]`. Labels are
  deterministic, so each account has one label per kind. akd shows everyone the one value of a
  label, and its VRF keeps labels out of the tree.
- **Value** = `HMAC-SHA256(salt, "songbird.v1/kt-value\0" || kind || raw)`.
  - `raw` is SHA-256 of the identity key or of the signed device list, or the username hash (32
    zero bytes once released).
  - `salt` is a random per-account salt that whoever asks receives. A server that hands someone
    another salt cannot make the published value match another key.
  - The salt is deleted with the account, which leaves its values unlinkable (`akd` 0.13 cannot
    tombstone them). The labels keep the account ID and the epochs of its changes.
- **Publishing**: a registration, a new device list, or a username claimed or released bumps the
  account's generation in its own transaction. The worker publishes one epoch per sweep with the
  values that changed. There is one writer, enforced by the store: an epoch commits only from the
  epoch before it (a compare and swap in the same transaction). Nothing is missed, and a crash only delays it.
- **Signed head**: `version u8 (1) | epoch u64 | root [32] | time_ms u64 | signature [64]`. The
  signature is Ed25519 by the log key over `"songbird.v1/kt-head\0"` followed by the bytes
  before it. Apps pin the log key and the VRF key.
- **Proofs** travel in akd's own protobuf encoding (`akd::proto`), hex in JSON.

| Request | Body | Answers |
| --- | --- | --- |
| `GET /v1/kt/keys` | none | 200 `{"vrf": hex, "log": hex}` |
| `GET /v1/kt/head` | none | 200 signed head |
| `POST /v1/kt/lookup` | `{"account": hex, "kind": "identity" \| "device_list" \| "username"}` | 200 `{"salt", "head", "proof"}`; 404 (nothing published); 400; 429 |
| `POST /v1/kt/history` | the same | 200 `{"salt", "head", "most_recent": 64, "proof"}`; 404; 400; 429 |
| `POST /v1/kt/audit` | `{"from", "to"}` (at most 1,000 epochs apart) | 200 `{"proof"}`; 400 for epochs out of order or beyond the directory; 429 |

**What clients do** (with `akd_core`'s verifiers, `lookup_verify`, `key_history_verify` and
`audit_verify`):

- Check every head's signature; keep the newest verified head.
- Before trusting a contact's identity key or device list, verify a lookup proof for the
  contact's label (`kind || account`) against a verified head. The proven value must equal
  `HMAC(salt, context || kind || SHA-256(key or list in hand))`.
- Verify an audit proof between the last head seen and a newer one. Two signed heads that no audit
  proof joins are evidence of a fork: show it and stop trusting the server.
- Owners check their own key history regularly. A version they did not publish is the warning.

**Security notifications.** An account identity key is never replaced (a new one is a new
account), and a device's identity key is fixed when it is linked. What changes is the device
list, and changes reach clients by three paths:

- the account's own devices get a signed `DeviceListChanged` notice (§3.9);
- a contact's next send is refused as stale by the device check (§3.1), and the contact fetches
  the signed list;
- the change appears in the directory with a new version.

In each case the app compares the new list with the last one it accepted and warns the user
about new devices.

### 4.10 GDPR: export, deletion and inactivity

Decision D-0056 (M7).

- **Export** (`GET /v1/account/export`, the primary, signed): JSON of everything the registry
  holds about the account:
  - the account row: creation, invites left, identity key, username hash, whether a username key
    is set, the signed device list, the profile, the access key, the PIN's state, the
    transparency salt, last use and the inactivity period;
  - username links, passkeys and avatars;
  - every device: keys, flags, prekey and KeyPackage counts, whether a sealed push registration
    exists, pending uploads.
  Secrets derived from what the user knows (the PIN and username-key verifiers) are reported as
  present, not handed out. What cannot be attributed to the account (mailbox ciphertext, sent
  attachments, keyed throttle records, transparency leaves once the salt is gone, encrypted
  backups) is listed with its retention.
- **Deletion** (`DELETE /v1/account`, the primary): the outbox job deletes every Prompt 2 and 3
  store, then verifies it:
  - mailbox and push registrations;
  - upload grants and objects, and avatar objects;
  - devices, prekeys, KeyPackages and passkeys;
  - username (held 30 days, unlinked) and links;
  - link tokens;
  - the profile, device list, PIN and transparency salt on the account row.
  Encrypted backups keep the data until they expire (at most 93 days); a restore deletes it
  again through the journal (D-0041).
- **Inactivity** (owner, D-0047): each account chooses 6, 12 or 24 months
  (`PUT /v1/account/inactivity {"months"}`, the primary; default 12; a month is 30 days).
  - Any signed `api` request counts as use, recorded at most once a day.
  - A month and a week before the period ends, the worker sends every device a wake-up push. The
    app wakes, makes a request, and the clock restarts.
  - At the end, the account is deleted exactly as if it had asked.

## 5. Encrypted content schemas (Prompt 4)

Decision D-0059 (M1). Specification: `crates/content/proto/content.proto`; Rust types, padding,
franking and validation: `crates/content`. **No service links that crate** (a test checks every
manifest): the server never decodes content. What the server must act on travels in fixed fields
of the `Send` frame (§1.2), never inside the ciphertext.

### 5.1 Layers

```
Send frame (§1.2): per-device envelopes or one shared body, plus the server's fields (M3, M4)
  └─ envelope: the session layer's ciphertext (pairwise PQXDH and Double Ratchet, §4.4;
     MLS for groups, Prompt 5; sealed sender wraps it with the sender certificate, §4.8)
       └─ padded plaintext: encode(Plaintext) || 0x80 || 0x00*, to a multiple of 160 bytes
            └─ Plaintext { content: encode(Content), franking_key, profile_key }
                 └─ Content { version, required_version, message_id, sent_at_ms,
                              body: data | receipt | typing | sync | request_response }
```

- **Padding.** Exactly `0x80` then zeros up to the next multiple of 160 bytes (1 to 160 bytes of
  padding; one encoding per length). Readers refuse anything else. Padding hides lengths within a
  bucket from the server, which sees envelope sizes (threat model §1).
- **Bounds.** A padded plaintext is at most 64 KiB and its `Content` at most 61,440 bytes, both
  checked before decoding; after decoding every list, string and ID is held to the bound written
  next to it in `content.proto` (`songbird_content::validate`).
- **IDs.** Accounts, messages, groups, calls and sticker packs are 16 bytes; keys and digests 32.
  A message is named by (author account, `message_id`): `message_id` is 16 random bytes chosen
  by the sender, and a repeat of the same pair is dropped (this is how resends after a restore,
  §3.6, and retries beyond the 6-hour idempotency window are made harmless).
- **Text.** UTF-8. Formatting spans and mentions count UTF-8 bytes (not UTF-16 units as Signal
  does) and must start and end on character boundaries; a mention's span covers the placeholder
  U+FFFC, and names the account. Styles: bold, italic, strikethrough, monospace, spoiler.
- **Times** are the sender's clock (`sent_at_ms`), except where §5.3 gives the server's.

### 5.2 Versions

- `version` is the writer's schema version (1). `required_version` is the lowest version that can
  show the message; an older reader shows "update to see this message".
- Readers ignore unknown fields, unknown `oneof` members and unknown enum values (a newer writer
  added them) instead of refusing the message. Field numbers are never reused or retyped.
- The compatibility suite (`crates/content/tests/compat.rs`) decodes every published version's
  vectors with the current reader, and a simulated newer writer's fields at three depths.

### 5.3 Franking

A message to another account is franked: the sender draws a 32-byte `franking_key`, puts it in
the `Plaintext`, and sends the commitment

```
commitment = HMAC-SHA256(franking_key, "songbird.v1/franking\0" || content)
```

(`content` = the encoded `Content` bytes, exactly as carried) in the `Send` frame's `FRANKED`
block (§1.2). The server stamps it (§5.13); the recipient checks that the stamped commitment
opens to the content it decrypted, and **drops a franked message whose commitment does not
open**, so every message it shows can be reported (§5.14). Visible messages (`DataMessage`) to
another account must be franked; receipts, typing and sync messages need not be.

### 5.4 Chat messages (`DataMessage`)

`group_id` (16 bytes) marks a group or channel message; empty is a 1:1 chat. `expire_timer_s` is
the chat's disappearing timer the sender applied. Exactly one kind:

| Kind | Rules |
| --- | --- |
| `Message` | Text with spans; up to 32 attachments (voice notes and video notes are attachments with a flag; voice notes carry a waveform); a quote (`MessageRef`, a 2 KiB preview, a thumbnail); a forward counter; up to 8 contact cards; a location pin (degrees × 10⁷); a sticker reference (pack ID, pack key, sticker ID); a poll; an event; `view_once`; up to 4 link previews. At least one visible part. |
| `Reaction` | One per reactor and message; add, replace (a new emoji) or remove. The reactor's highest `counter` wins (§5.5). |
| `Edit` | The sender's own message, within **24 hours** (D-0058); the highest `revision` is shown and every revision is kept as history. |
| `Delete` | Delete for everyone, the sender's own message, within **24 hours** (D-0058); group admins delete others' (Prompt 5). |
| `PollVote`, `PollClose`, `Rsvp` | §5.5 |
| `Pin` | Pin for 24 hours, 7 days or 30 days, or unpin; at most 3 pinned per chat, the newest winning (§5.5). |
| `TimerChange` | The chat's disappearing timer: off, or 5 s to 4 weeks. |
| `Nudge` | A nudge (Prompt 9). |
| `CallEvent` | A call's outcome in the chat (Prompt 7). |
| `GroupUpdate` | A group or channel system message written by a client from what changed (Prompt 5 orders the changes themselves). |
| `ChatPolicy` | Restricted chat (§5.9). |

**Forwarding.** Forwarding a message sets `forward_count` to the original's plus one (a message
first forwarded has 1). From 5 the app shows "forwarded many times" and lets it be forwarded to
one chat at a time; otherwise to at most 5 chats at once. Apps enforce this; the server sees
nothing of it.

**Edit and delete windows** use the server's stamp time (§5.13) of both messages when both carry
one, otherwise the sender's `sent_at_ms`. The rule looks only at the two messages, never at when
they arrived, so every device agrees. A modified app can still ignore the window on its own
device, as in Signal and WhatsApp.

### 5.5 Order-independent state

Decision D-0060 (M2). Reference implementation: `songbird_content::state`; every app computes
the same. Every state is a function of the **set** of operations received, never of their
order or repeats (property tests: `crates/content/tests/convergence.rs`).

- **Last write per author, by the author's counter.** Reactions, poll votes and RSVPs keep, per
  (target, author), the write with the greatest `(counter, value)`. Each author numbers its own
  writes (any strictly increasing counter), so no clock is trusted, and a reused counter still
  breaks ties on the value's bytes.
- **A total order for state many people write.** Pins, the disappearing timer and the
  restricted-chat policy are decided by the greatest `(time, author, message ID)`. The time is the
  server's stamp (§5.13) when the message has one, else `sent_at_ms`.
- **Reactions:** one per reactor and message; a new emoji replaces, `remove` clears.
- **Polls:**
  - while open, each voter's vote with the highest counter counts. A vote for an option the poll
    lacks, or for several options in a single-choice poll, counts as none; no options retracts;
  - only the poll's author can close it, and a close names the poll (author and message ID).
    `heads` lists each voter's counter as the author saw it. From then on exactly those votes
    count, and nobody else's, so late votes cannot change a closed result on any device. Of two
    closes, the greater `(time, author, message ID)` wins;
  - votes may arrive before the poll and are judged once it is known;
  - a device keeps at most 64 votes per voter (the highest counters), which bounds what one
    voter can make it store.
- **Events:** RSVPs as votes (going, maybe, declined), the responder's highest counter winning.
- **Edits:**
  - the shown text is the author's valid edit with the highest revision; every valid revision is
    the history;
  - an edit is valid when its editor is the original's author and it falls within 24 hours of
    the original (§5.4);
  - at most 64 revisions are kept.
- **Delete for everyone:** by the author (or a group admin, Prompt 5) within 24 hours.
- **Pins:** per message, the greatest pin operation wins. A pin lasts its duration from its time,
  and at most 3 are shown, the newest pins first.

### 5.6 Receipts and message status

Decision D-0060 (M2).

| Status | Meaning | Produced by |
| --- | --- | --- |
| Sending | Not yet stored on the server | The sender's app |
| Sent (one tick) | Stored durably | The server's `Accepted` (§3.1) |
| Delivered (two ticks) | At least one device of the recipient (of every member) decrypted and saved it | Encrypted delivered receipts |
| Read (blue) | The recipient (every member) opened the chat | Encrypted read receipts, if enabled |
| Played | A voice or video note was played | Encrypted played receipts |
| Failed | Could not be sent after retries | The sender's app |

- **Receipts are content** (`ReceiptMessage`), end-to-end encrypted, so the server can neither
  fake nor hide them. They travel through the mailbox (never the ephemeral lane), so an offline
  sender gets its ticks later. Every device that saves a message sends a delivered receipt.
- **Only to the author.** A receipt goes to every device of the message's author, never to the
  rest of a group.
- **Forward only.** The status is computed from each recipient's greatest receipt (delivered <
  read < played), so it never moves back, whatever order receipts arrive in. A receipt also lifts
  a message the app had marked failed, since it proves the server stored it.
- **Groups ("Message info").** The audience is the members when the message was sent:
  - members who left since are no longer waited for, and members who joined later are not
    counted;
  - two ticks when every remaining audience member has a device that received it, and read when
    every one of them read it.
- **Batching.** The recipient's app gathers receipts per (chat, author, kind) for 1 second, or 10
  seconds in groups above 32 members, then sends one receipt:
  - delivered and played receipts list message IDs, at most 512 per receipt;
  - a read receipt says "up to here" (`up_to`), so opening a chat with 200 unread messages from
    one author sends one receipt;
  - the reader's own other devices get one `ReadSync` of what was read.
- **The read-receipt setting** is reciprocal and **applies to groups too** (D-0058): off means
  no read or played receipts sent, and none shown (at most two ticks). Delivered receipts are
  always sent.
- **Load** (the M2 report): in a 1,024-member group where members chat in bursts, receipts are
  47 % of all envelopes with the 10-second window (66 % with 1 second).

### 5.7 Typing

`TypingMessage` (started or stopped, optional group) travels only on the ephemeral lane (§3.7):
never stored, dropped first under pressure. Apps stop showing "typing" 15 seconds after the last
"started".

### 5.8 Sync messages

Sent only to the sender's own other devices (a send that addresses only the sender's account,
§5.10):

| Kind | Carries |
| --- | --- |
| `sent` | A transcript of what this device sent: the chat (or a broadcast list's accounts), the exact `Content` bytes the recipients got, its franking key, and when the server accepted it. The content must be a `DataMessage` (nesting stops at one level). |
| `read`, `viewed` | Messages read, or view-once media and voice notes played, with when. |
| `starred` | Messages starred and unstarred. |
| `chat_state` | Archived, muted until, pinned, marked unread. |
| `settings` | Read receipts, typing indicators, link previews, the default disappearing timer (Prompt 9 adds the rest); unset fields are unchanged. |
| `blocked` | The whole block list (accounts and groups), replacing the previous one. The server keeps only what it must to drop blocked senders (§5.11). |
| `call_history` | Call log entries (Prompt 7's calls), so every device shows the same history. |
| `request_response` | What the user did with a message request (§5.10). |

### 5.9 Restricted chat

`ChatPolicy` (in a 1:1 chat, or in a group's settings from Prompt 5) tells every participant's
app to refuse exporting the chat and saving its media automatically. Apps enforce it; **the
server only carries it, and a modified app can ignore it.** It is a courtesy between honest apps,
not a protection against a participant: anyone can photograph a screen.

### 5.10 Message requests, contacts and lanes

Decisions D-0058 (the owner's rules) and D-0062 (M4).

**Contacts are proven by the access key.** An account's access key is derived from its profile key
(§4.8), and the profile key goes only to contacts:

- when a request is accepted (`RequestResponse{ACCEPT}` with `Plaintext.profile_key`: beside
  the content, never inside what franking commits to, so a report never reveals it);
- or when users meet by username, link or QR code;
- or with every message to an existing contact after a rotation.

The server keeps no contact list: a send carries the proof.

**Every send to another account** (identified, over the WebSocket or `PUT /v1/messages`) falls
in one lane, decided from the directory snapshot alone, so the hot path makes no store round
trip:

| Lane | What the server sees | Rule |
| --- | --- | --- |
| Sync | Only the sender's own other devices | Always allowed |
| Direct | One other account, a contact | The send carries `ACCESS` with its access key |
| Open | One other account that is open ("anyone may send") | No key needed; its blocks apply (dropped silently) |
| Broadcast | Several other accounts (per-device envelopes) | Every closed one has an access key, and `ACCESS` carries their XOR; at most 256 accounts by default; a budget of accounts per hour |
| Request | One other closed account, `REQUEST` set | Must be `FRANKED`; budgets per sender, per (sender, recipient) and per recipient; dropped silently if blocked or refused |
| Group | A shared body (MLS) | Until Prompt 5 authorizes membership: every closed account it reaches is a contact (`ACCESS` carries their XOR; groups share their members' profile keys) or the body is refused. No budget beyond the group-send rate |
| Sealed | `PUT /v1/messages/sealed` | The sealed endpoint checks the access keys (§4.8); `ACCESS` and `REQUEST` are refused there |

- A send to a closed account with neither a valid key nor `REQUEST` is refused with reason 10
  ("access required"). The app then fetches the profile key again (if it had one) or sends a
  request.
- An account with no profile (no access key) is reachable by requests only. **Every app
  publishes a profile, with its access key, at registration.**
- A request addressed to more than one other account, or not franked, is refused with reason
  11.
- A request is never sealed, so it can be blocked and reported with a sender the server can
  attest.

**Answering a request** (all inside encrypted content, §5.8):

- **accept**: share the profile key with the requester; from then on it sends as a contact;
- **delete**: nothing reaches the requester;
- **block**: §5.11;
- **report**: §5.14.

Every response is synced to the user's own devices.

**The request policy** (`GET`/`PUT /v1/account/requests`, `{"from": "everyone" | "nobody"}`):
with "nobody", requests are accepted and dropped silently; contacts are unaffected. Refusing
requests may be done from any listed device, accepting them again only from the primary (D-0058).

**Budgets** (`[api.requests]` and `[delivery.requests] limits`, kept in `valkey-hot` under keyed
names, shared by every node and transport):

| Budget | Default |
| --- | --- |
| Requests per sender account | 20 an hour, burst 10 |
| Requests per (sender, recipient) | 10 an hour, burst 5 |
| Requests per recipient account | 100 an hour, burst 30 |
| Broadcast accounts per sender | 1,024 an hour, burst 256; at most 256 a send |

Over budget: reason 1 with a retry hint. The budgets are spent **before** the block and policy
checks, so a blocked sender gets exactly the answers an unblocked one gets.

**A dropped send leaves the same traces as a delivered one** (D-0064):

- the whole send is stored under its idempotency key with a deadline already passed, so it is
  never fetched or routed and the next sweep deletes it;
- its idempotency record names the same devices, and a reused key gets the same answers (reason
  7, a replay);
- the sender's own envelopes (its sync transcript) are stored live under a key derived from the
  send's.

**Who may loosen:** opening the account ("anyone may send" in the profile, false to true) is the
primary's, like unblocking and accepting requests again; a linked device may keep it open or
close it. A send from a device not yet in the snapshot is refused as unavailable (never treated as
sealed).

**Rate limits per conversation type** (the prompt's requirement), counted per device unless said:

| Lane | Limit |
| --- | --- |
| Every send | 50 a second, burst 200 (per connection, and across `api` nodes for HTTP) |
| Group sends (shared bodies) | Also 10 a second, burst 40 |
| Requests and broadcasts | The budgets above, per account across the cluster |
| Channels | Prompt 5, once the server can tell a channel from a group |

What is not gated, stated plainly:

- **Ephemeral frames** (typing) to a stranger's device are not checked. They are end-to-end
  encrypted, so a client without a session with the sender drops them; per-connection limits
  bound them.
- **Group invitations from strangers** go as a message request first (a Welcome to a
  non-contact needs that member's key, like any shared body).

### 5.11 Blocking

- **`PUT /v1/blocks`** `{"account": hex}` (any listed device) and **`DELETE /v1/blocks`** (the
  primary only, D-0058).
- **What the server keeps:** one row named by `HMAC(k_pair, blocker ‖ blocked)[..16]`, a keyed
  tag of the owner `HMAC(k_owner, blocker)[..16]`, the time, and a per-owner counter (at most
  1,000). No account ID is stored. The keys derive from the requests secret every node holds,
  so the server (with its key) can test whether one account blocked another; a database or
  backup thief cannot.
- **What it does:** a request from a blocked account, or any send to an open account that blocked
  the sender, is accepted and never delivered. A blocked
  contact still holding the access key is cut off by a client rule: **blocking rotates the
  profile key**, sharing the new one with every remaining contact (as Signal does), so the old
  access key fails (reason 10) and only the request lane, where the block applies, is left.
- **Sealed senders** are blocked by the client: it drops sealed messages whose certificate names
  a blocked account. Rotating the profile key also ends their sealed access.
- **The full block list** (accounts and groups) syncs between the user's own devices as an
  encrypted `blocked` sync message (§5.8).
- **Deletion:** an account's block rows are deleted with it (found by its owner tag) and
  verified. A blocked account's deletion leaves the rows naming it as keyed hashes until the
  blocker unblocks or is deleted.

### 5.12 Client-only features

Lock chat, free up storage, the media and links overview, in-chat search, save to photos, export
chat and groups in common live entirely on the device: they read the app's own database. Nothing
in the protocol prevents them, and the server gains nothing for them:

- export and save to photos are refused only by a restricted chat's policy (§5.9);
- groups in common are computed from groups the device belongs to (Prompt 5), with no server
  query.

### 5.13 Franking stamps and disappearing envelopes (server)

Decision D-0061 (M3).

**Franking stamps.** For a `FRANKED` send, the server stores every envelope addressed to another
account behind a stamp; the sender's own devices get their envelopes as sent:

```
magic F5 53 42 46 52 4B 00 01 | version u8 (1) | key_id [8] | commitment [32]
  | stamped_at_ms u64 | tag [32] | the client's envelope
tag = HMAC-SHA256(franking key, "songbird.v1/franking-stamp\0" || key_id || commitment
                  || stamped_at_ms || sender account [16] || recipient account [16])
```

- The sender account is all zeros for a sealed send (the server does not know it). The recipient
  is all zeros for a shared body, which is stamped once.
- `key_id` names the franking key: `HKDF-SHA256(salt "songbird.v1", secret, info "franking")`,
  identified by the first 8 bytes of `SHA-256("songbird.v1/franking-key-id\0" || key)`. Every
  node that sends holds the current key (secrets store); `api` also keeps earlier keys for
  reports.
- The tag is a MAC only the server can check. It names neither account in the clear; whoever
  holds the key could test candidate senders for an envelope still undelivered (threat model
  §1).
- A recipient app splits off the stamp (`songbird_proto::envelope::Stamp::split`), decrypts, and
  **drops the message unless the stamped commitment opens to the content** (§5.3). It keeps the
  stamp with the message: a report needs it (§5.14). `stamped_at_ms` is the server's time, used
  for the edit and delete windows (§5.4).
- User envelopes beginning with `F5 53 42` are refused (reason 9), so no client can forge a stamp
  or a system frame.

**Disappearing envelopes.** An `EXPIRES` send gives each of its envelopes a deadline,
`expire_after_s` after the store:

- every mailbox (in memory, SurrealDB, Iggy) **never delivers it after the deadline**, and its
  `seq` is skipped, as §3.3 allows for expired envelopes;
- the mailbox **deletes it at the next sweep** even if no device ever connected. In Iggy its key is
  punctured, so it cannot be read again, nor come back on a restart;
- apps set it to the chat's disappearing timer for messages in a chat with one, and for view-once
  media. Nothing about such an envelope is kept beyond delivery: the server keeps no copy of any
  delivered envelope, and backups never hold the mailbox (D-0040). View-once attachments are
  deleted after one fetch by Prompt 6's upload grants;
- a resend after a restore (§3.6) carries the time left, and apps do not resend what has already
  disappeared.

### 5.14 Reporting

Decision D-0063 (M5). A recipient shows the server one message it received; nothing else about
the conversation is revealed.

```
POST /v1/reports (a listed device, signed body, at most 61,602 bytes):
version u8 (1) | reason u8 (1 spam, 2 harassment, 3 illegal, 4 impersonation, 5 other)
  | key_id [8] | commitment [32] | stamped_at_ms u64 | tag [32]     (the stamp, §5.13)
  | sender [16] | franking_key [32] | content_len u32 | content       (1 to 61,440 bytes)
```

The app keeps each franked message's stamp and franking key, and its encoded `Content` exactly
as received. To report, it sends them with the sender it decrypted. The server then checks, in
order:

1. **The reporter's budget:** 20 reports an hour, burst 10, keyed in `valkey-hot`. It is spent
   before anything else, so reports cannot probe stamps. Over it: 429.
2. **The franking key:** the current key or one still accepted (`[api.send]
   previous_franking_keys`). Otherwise 403 `key`.
3. **The window:** the stamp is at most 30 days old (`window_days`) and not from the future.
   Otherwise 403 `expired`.
4. **The stamp,** which binds the sender and the recipient. The MAC must verify for the named
   sender (attested), else for no sender (a sealed send: the sender is only the reporter's claim);
   and for the reporter's account, else for no recipient (a group's shared body, which any member
   may report). Otherwise 403 `stamp`. So a message can be reported only by a recipient, and
   only against the sender who sent it.
5. **The commitment:** it must open to the content under the franking key (constant time).
   Otherwise 403 `commitment`.

Then the server seals a **minimal report** to the moderation key and queues it (204):

```json
{"version": 1, "reason": "harassment", "sender": hex, "sender_attested": true,
 "conversation": "direct" | "group", "stamped_at_ms": …, "reported_at_ms": …, "content": hex}
```

- **Sealing:** X25519 with a fresh ephemeral key, HKDF-SHA256 under the domain
  `songbird.v1/report`, AES-256-GCM
  (`songbird_keys::provisioning::seal_with(Domain::Report, …)`), to
  `[api.reports] moderation_key`. The private half stays offline with the moderators
  (`songbird-admin reports keygen`).
- **What the report leaves out:** the reporter, any other message, the conversation's members.
- **Storage:** the row is named by a keyed hash of the stamp's tag, so the same message is
  reported once (409 `duplicate`). Rows are kept `retention_days` (30 by default, at most 90),
  then swept by the worker.
- **Moderators** list, open (decrypt, and decode the content with `songbird-content`) and
  delete reports with `songbird-admin reports`.
- **In memory only:** `api` holds the content in memory while it verifies a report; it never
  decodes it, and never stores it unsealed.
- **A report does not block:** an app that reports usually also blocks the sender (§5.11).

## 6. Groups, roles and channels (MLS) (Prompt 5)

## 7. Attachments and packs (Prompt 6)

## 8. Calls and the call key schedule (Prompt 7)

## 9. Push (Prompt 8)

## 10. Settings sync and presence (Prompt 9)

## 11. Backup format and vault access (Prompt 10)

## 12. Versioning and compatibility rules

- **Wire frames** (§1.2): one encoding per frame, unknown flag bits refused; new optional blocks
  come behind new flag bits, in a fixed order (D-0061). `protocol_versions` changes only for an
  incompatible frame.
- **Encrypted content** (§5.2): protobuf, unknown fields, kinds and enum values ignored,
  `required_version` for what an older app must not misread; every published version's vectors
  decode with every later reader (`crates/content/tests/compat.rs`).

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

Registration (Prompt 3, D-0048), from `crates/pow` and `crates/proto` tests:

- Proof-of-work challenge for registration secret 32 × `42`, issued at 1,763,164,800,000 ms,
  memory 64 KiB, 1 iteration, 4 bits, 2 solutions, nonce 16 × `11`:

  ```
  01 0000019a84cfc400 00000040 00000001 04 02 11111111111111111111111111111111
  0062f574373fcffeceeac3d8e2446d66
  ```

  Its solutions are `[7, 31]`; the Argon2id output for counter 7 is
  `039ed8433f9111cfc95132559389a12a974d312b0f22e013cacb546aff63fd56`, which the reference
  `argon2` command (phc-winner-argon2) reproduces.
- Invite code bytes `00 01 02 … 0e` (15 bytes counting up) display as
  `000G-40R4-0M30-E209-185G-R38E` (checked independently against a Python implementation of
  Crockford base32).
- Registration request with challenge 51 × `11`, solutions `[7, 31]`, that invite code, identity
  key 32 × `22`, authentication key 32 × `33`, signatures 64 × `44` and 64 × `55` (269 bytes):

  ```
  01 | 51 × 11 | 02 | 00000007 0000001f | 01 | 000102030405060708090a0b0c0d0e
    | 32 × 22 | 32 × 33 | 64 × 44 | 64 × 55
  ```
- The identity key's transcript for server name `chat.example` and the same challenge and keys:

  ```
  736f6e67626972642e76312f72656769737465722d6964656e7469747900 0c 636861742e6578616d706c65
    | 51 × 11 | 32 × 22 | 32 × 33
  ```

  The authentication key's differs only in its context, `"songbird.v1/register-device\0"`.
- Username (Prompt 3, M2, D-0049), from `crates/keys/tests/username_vectors.rs`: the
  generator `G` is `9c921379c3fdb3bf5dc4810f37d8fb50ea2e9392fa28b908ca6fdd849f0c627c`; the username `Radu` hashes to `b0aff097b1eb85225fbb895965cb81ff2757a8e39f458e731743270b1fb5ad09`; its proof with randomness 32 ×
  `11` is

  ```
  77c74bbf972c93f70681b1b75869c7538915a43910e79341499dc4428559710d
  0bd820c1436c8e463b66283e3b805440c59905fc025c964fa709c7be6a031f04
  ```

  libsignal's poksho (commit `8be00c2`) produces the same proof for the same statement and
  randomness, and verifies it.
- XEdDSA (Prompt 3, M3, D-0050), from `crates/keys/tests/xeddsa_vectors.rs`: private key 32 ×
  `31`, message `songbird.v1/xeddsa-vector`, signing randomness 64 × `42`. libsignal (commit
  `8be00c2`) and Songbird both give the public key
  `0504f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f3a` and the signature

  ```
  5bdccfa0250b116ef988e11c678a3562f8b37884cbc3c2ee720d87760a0e8cf0
  68aba378d09d70b2ad14b47a44709b3b72400c10bd2bdffbe84ee24b29373e82
  ```

  and each verifies the other's signature.

Sender certificate (Prompt 3, D-0054), from `services/api` `certificate_vector`, cross-checked
with OpenSSL 4.1. The inputs are: Ed25519 seed 32 × `42`; account 16 × `01`; device 16 × `02`;
identity key `05` || 32 × `03`; expiry 1,800,000,000,000 ms. The certificate:

```
01 3097e2dee2cb4a34 01010101010101010101010101010101 02020202020202020202020202020202
05 0303030303030303030303030303030303030303030303030303030303030303 000001a3185c5000
e2ba85e62f8006c7ff540bbed16ff64f1636cb28133f05da28b9604b0d4d32596d486dd773916abf4a674b75813703d273e747b840ed8288da465c69f4c98804
```

WebAuthn (Prompt 3, D-0053): `crates/keys/tests/webauthn_vectors.rs` carries the W3C WebAuthn
Level 3 test vectors (§16.2, §16.11) verbatim.

Key transparency (Prompt 3, D-0057): `akd` 0.13's proofs and their protobuf encoding are akd's
own. `crates/akd/tests/akd_live.rs` checks Songbird's storage with akd's client verifiers. The
proofs are accepted, and refused under another label, another root, another VRF key or a
rewritten history.

Encrypted content (Prompt 4, D-0059): `crates/content/vectors/v1/vectors.json` holds 33 vectors,
one or more per kind of content, each as hand-written protobuf JSON and the hex the Rust types
produce. `tools/content-vectors` checks with an independent compiler (protox) that
`content.proto` encodes each JSON to exactly that hex. Two of them:

- `reaction` (a 👍 from the author of message 16 × `33` by 16 × `22`, counter 7; message ID 16 ×
  `01`, sent at 1,800,000,000,000 ms):

  ```
  0801 1a10 01010101010101010101010101010101 2080a0f1c2b134
  5230 5a2e 0a24 0a10 22222222222222222222222222222222 1210 33333333333333333333333333333333
  1204 f09f918d 2007
  ```
- `plaintext_franked`: that content under franking key 32 × `42`, padded to 160 bytes; its
  commitment is `4cc19e38508a8cdbcbac905629cee83e217741cf3cc0878bd00fee0bb9fb2c50`
  (recomputed with Python's `hmac`).

Send frames with hints (Prompt 4, D-0061), from `crates/proto/tests/vectors.rs`:

| Frame | Encoding |
| --- | --- |
| A franked message request that disappears after an hour: `Send{req_id 9, key 11…11, REQUEST, commitment 55…55, expires 3600, to 22…22 "abc"}` | `01 00000009 11111111111111111111111111111111 38 5555555555555555555555555555555555555555555555555555555555555555 00000e10 0001 22222222222222222222222222222222 00000003 616263` |
| A contact's send: `Send{req_id 10, key 11…11, ACCESS 66…66, to 22…22 "z"}` | `01 0000000a 11111111111111111111111111111111 04 66666666666666666666666666666666 0001 22222222222222222222222222222222 00000001 7a` |

Franking stamp (D-0061), from `crates/send/src/franking.rs` `stamp_known_answer`, recomputed
independently with Python's `hmac` and `hashlib`: secret 32 × `46`, commitment 32 × `01`, time
1,800,000,000,000 ms, sender 16 × `0a`, recipient 16 × `0b`. The key ID is
`3df2c8855889e63b` and the tag is
`114c33cc2b8f1a5e0ad8943b34ebb738c10f3397504e858b44b8e06e45a8b3b6`.
