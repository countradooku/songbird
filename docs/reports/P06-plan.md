# P06 — Media, attachments, stickers and packs: plan, milestones and gates

- Date: 2026-11-17
- Prompt: [06-media.md](../prompts/06-media.md)
- Status: **proposed**, waiting for the owner (D-0079)
- Base: `main` at `ae76726` (Prompt 5 and its follow-ups done, PR #60).
- Way of working (the owner, 2026-11-17: "all the milestones in the same PR"): one branch and one PR
  (`claude/p06-media`). Each milestone gets its own commit, tests, report `docs/reports/P06-Mn.md`,
  decision record (D-0080 onward), PROTOCOL §7 text and threat-model rows marked "awaiting the
  owner's approval". Then a final gate report, an independent security review of the whole diff,
  and `cargo xtask ci fast` plus the live suites, one heavy job at a time. Nothing is merged
  without the owner.
- Skills: the environment offers general skills only (`security-review`, `code-review`,
  `simplify`); none covers storage systems, applied cryptography or HTTP performance, and the
  repository has no project skills. `security-review` runs as an independent read-only reviewer
  over the whole diff before the gate. Proposed again, not part of the plan unless asked: a
  `songbird-invariants` checklist skill under `.claude/skills/`.

## What Prompt 6 starts from

Prompt 2 (M5, D-0036) built a minimal attachment path in `services/api`, and it already holds
the prompt's core invariants:

- `POST /v1/attachments` issues a **single-use grant** for an exact size (at most 100 MiB) and a
  number of recipient fetches (at most 1,024), bound to the requesting device, valid 1 hour.
- `PUT /v1/attachments/<id>` streams exactly the granted length to RustFS (`a/<64 hex>`); a short
  or long body is refused, and the grant becomes an **attachment record with no link to the
  uploader** (approved threat-model row).
- `GET /v1/attachments/<id>` needs a signed device request, streams the whole object, counts a
  fetch when the last byte goes out, and deletes at the last fetch or after 30 days (worker sweep).
- `crates/content` (Prompt 4) has `AttachmentPointer { object_id, key, digest, size, … }` and
  `StickerRef { pack_id, pack_key, sticker_id, … }`, but no encryption format: the key and digest
  are opaque fields.
- `crates/s3` is our own minimal S3 client (SigV4, streaming PUT, ranged GET, list, versions). It
  has **no multipart upload**.
- RustFS listens on loopback only, behind a mutual-TLS tunnel (D-0035, threat model). **Clients
  can never reach it directly**, so every byte flows through a Songbird service, and "signed URLs"
  have to be Songbird URLs, not S3 presigned ones.

## Findings that shape the plan

1. **Downloads today tell the server who fetched what.** Every `GET` is signed by a device, so
   for 30 days the server could join "this device fetched this object" with "that device uploaded
   it" (the grant names the uploader for up to an hour). Nothing stores that join today, but the
   requests carry it. The object ID is already a 256-bit capability that travels only inside
   end-to-end encrypted messages, which is what Signal's CDN relies on. Downloads can drop device
   authentication and lose nothing (question 1).
2. **Range requests need signed URLs for speed, not only for safety.** A video player streaming a
   1 GiB file sends dozens of range requests. Today each would hit SurrealDB for the record. A
   short-lived URL signed by `api` (HMAC over object, expiry and size) lets the serving path check
   a MAC instead, and makes the bytes cacheable by a reverse proxy if the benchmark asks for one.
3. **"Fetched" has to become explicit.** With range requests, "the last byte went out" no longer
   means "the recipient has the file": players fetch the MP4 index at the end first. The client
   confirms after it has verified every chunk (`POST …/fetched`), and an unconfirmed attachment
   still goes at 30 days. A malicious recipient could confirm several times and delete early; it
   can already do the same today by downloading several times, so nothing gets weaker.
4. **Resumable uploads: S3 multipart and tus differ in where the bytes wait.** S3 parts must be at
   least 5 MiB (except the last). tus appends at any offset, so `api` would have to buffer up to a
   part per upload or write and later compose small objects. Fixed-size parts uploaded with
   `PUT …/parts/<n>` map one-to-one to S3 `UploadPart`, need no buffering, and can run in
   parallel. Both get built behind one trait and measured (constitution rule 3); the plan expects
   parts to win, and the numbers decide.
5. **A storage quota per account would link objects to accounts.** The attachment record
   deliberately has no uploader. A rolling **upload volume** budget per account (keyed records in
   `valkey-hot`, as P03/P04 throttles) bounds storage just as well: at most budget × 30 days per
   account, and no record says which objects are whose. Plans (Prompt 11) only change the numbers.
6. **The server never needs the pack kind.** Sticker packs, chat scenes (IMVironments), sound
   stickers and emoticon packs differ only inside the encrypted manifest. The server sees a pack
   ID, the number and padded sizes of its objects, and fetch times. One service covers all four.
7. **Tenor's API shut down on 30 June 2026.** WhatsApp moved to GIPHY; Discord tested GIPHY and
   Klipy. The provider is a contract and terms question for the owner (question 4). The code goes
   behind a provider trait, with a mock in tests, so nothing waits for an API key.
8. **The GIF proxy has to proxy the images too.** Proxying only the search hides the user from the
   provider until the app loads the results, then every image request from the provider's CDN
   reveals the user's IP. `api` proxies both, which is also where caching pays off: popular GIFs
   are the same bytes for everyone.

## Architecture

- **Attachment format** (`crates/content`, new module `attachment`): client-side, never linked
  by a service (D-0059).
  - **STREAM construction** (Hoang, Reyhanitabar, Rogaway and Vizár, "online authenticated
    encryption", as in `age`): a 64 KiB plaintext chunk size, a per-attachment key derived with
    HKDF-SHA256 from the pointer's key and a random 32-byte header salt, a nonce that encodes
    the chunk counter and a last-chunk flag. Each chunk verifies on its own, and reordering,
    truncation and extension are detected. Resuming a download starts at any chunk boundary.
  - **AEAD: AES-256-GCM versus ChaCha20-Poly1305**, both from aws-lc-rs, behind a version byte;
    decided by measurement (x86 here; the ARM numbers come with the apps). Signal uses AES; `age`
    and our MLS suite use ChaCha20-Poly1305.
  - **Padding: Padmé** (Nikitin et al., PURBs, 2019): at most 12 % overhead and O(log log n) bits
    leaked about the size. The padding is encrypted inside the last chunks, and the real length
    stays in the encrypted pointer. The server only checks that a granted size is a legal
    Padmé ciphertext size, which rules out arbitrary sizes.
  - **Thumbnails** are ordinary attachments with their own key and object.
  - **Test vectors** published in PROTOCOL §13, cross-checked against an independent
    implementation (Python `cryptography`) outside the workspace, plus proptests (round trip,
    any tampered byte is refused at its chunk) and a fuzz target for the decryptor.
  - `crates/client` gets streaming encrypt and decrypt, resumable upload and range download, and
    a forwarding helper that always re-encrypts under a fresh key and new object ID.
- **Uploads** (`api`):
  - **Grants v2:** the size is a Padmé size within the plan limit (question 2); the per-account
    grant rate and 24-hour volume are budgets in `valkey-hot`; single use and device-bound as
    today. Small attachments keep the single `PUT`.
  - **Resumable:** `POST /v1/attachments/<id>/parts` opens an S3 multipart upload; `PUT …/parts/<n>`
    streams one fixed-size part; `GET …/parts` lists what arrived; the last part completes it.
    tus 1.0 (core, creation, termination) is built behind the same trait for the benchmark.
    The worker aborts multipart uploads whose grant expired.
  - `crates/s3` gains Create/UploadPart/ListParts/Complete/Abort multipart, with fuzzed XML.
- **Downloads** (`api`):
  - `GET /v1/attachments/<id>`, **unauthenticated** (question 1): checks the record, throttles per
    IP range, and redirects (303) to `GET /v1/media/<id>?e=<expiry>&s=<mac>` valid 10 minutes.
  - The media path checks only the MAC and serves `Range` (single ranges; 206/416), straight
    from RustFS. No database access per request.
  - `POST /v1/attachments/<id>/fetched` counts one fetch; the last one deletes.
  - **A caching reverse proxy** in front of RustFS only if the benchmark shows RustFS limits p99
    or throughput; otherwise recorded as not justified.
- **Packs** (`api`, generic):
  - A pack is an encrypted manifest plus encrypted assets, each an object in the attachment
    format, under one random pack ID.
  - The share link is `https://<web domain>/pack#<pack id>.<pack key>`: the key lives in the
    fragment and never reaches the server.
  - Created with one grant for every object (count and sizes bounded), charged to the creator's
    volume budget. No link to the creator's account: the creator's devices hold a random
    management token whose hash the server keeps, for deletion. Lifetime in question 3.
  - Fetches are unauthenticated by pack ID, like attachments, and cacheable.
- **GIF proxy** (`api`): `GET /v1/gifs/search?q=…` and `/v1/gifs/trending`, authenticated for the
  rate limit only. The proxy forwards queries without IPs, headers, cookies or identifiers, and
  rewrites media URLs to `GET /v1/gifs/media/<token>` so images also come through `api`. It keeps
  an in-memory cache keyed by a keyed hash of the query (TTL minutes), a per-account rate limit
  and a global provider budget with a circuit breaker. Queries are never logged or written to disk.
  The provider sits behind a trait, with a mock server in tests (question 4).
- **Logs:** object and pack IDs never appear in logs or metrics. A test asserts that the telemetry
  redaction refuses them, as for device IDs.

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **The attachment format.**<br>• STREAM over 64 KiB chunks, HKDF-derived per-attachment keys, Padmé padding, version byte.<br>• AES-256-GCM versus ChaCha20-Poly1305, measured.<br>• `crates/client` streaming encrypt and decrypt; forwarding re-encrypts. | Published test vectors, cross-checked by an independent implementation; proptests (round trip, tamper, truncate, reorder, extend refused at the right chunk); fuzz target `attachment_decrypt`; AEAD benchmark recorded. |
| **M2** | **Uploads.**<br>• Grants v2 (Padmé size, plan limit, rate and 24-hour volume budgets).<br>• Multipart in `crates/s3`.<br>• Resumable parts and tus behind one trait; the winner kept, the loser removed.<br>• Abandoned multipart uploads aborted by the worker. | Live (RustFS) integration tests: an upload interrupted at every part boundary and mid-part resumes and matches byte for byte. A grant cannot be reused, enlarged or used by another device. Budgets stop storage exhaustion. Fuzz targets `upload_grant`, `s3_multipart_xml`. Parts-versus-tus benchmark recorded. |
| **M3** | **Downloads and lifecycle.**<br>• Unauthenticated capability download with a 303 to a signed media URL.<br>• Range requests.<br>• Explicit fetch confirmation.<br>• The reverse-proxy decision.<br>• Upload and download **benchmarks**. | Range downloads integration tested (first, middle, last chunk, suffix ranges, 416); signed URLs expire and cannot be altered; **lifecycle tests** prove deletion after the last confirmed fetch and at 30 days (time-shifted record), and after an expired grant. Throughput, latency (p50/p99) and concurrency benchmarks recorded with hardware and configuration. Fuzz target `media_url`. |
| **M4** | **Packs and the GIF proxy.**<br>• The generic pack service and the encrypted manifest schema (`crates/content`) for the four kinds.<br>• The GIF proxy with the provider trait, the adapter for the owner's provider, and a mock. | Pack create, share, fetch and delete live tests; the manifest decoder fuzzed (`pack_manifest`); the GIF proxy forwards no IP, header or identifier (asserted on the mock's received requests); cache and rate-limit tests; the provider outage path tested, with a runbook. |
| **M5** | **The gate.** GDPR export and deletion for every new store (budgets, packs, multipart state), the security review, `P06-gate.md`. | The prompt's gate, item by item. |

Order: M1 is independent of the server and goes first. M2 needs nothing from M1 beyond Padmé.
M3 builds on M2's records. M4 reuses M2 and M3.

## Threat-model rows this plan will propose (each with its milestone)

- Per-account upload budgets (keyed records: grant count and bytes in a rolling window; no object IDs).
- Multipart upload state (the S3 upload ID and parts already received, under the grant's object ID;
  at most the grant's hour).
- The media URL signing key (`api` only; rotating it invalidates outstanding URLs within 10 minutes).
- Pack records: pack ID, object IDs and padded sizes, the hash of the management token, the last
  fetch time; no account.
- GIF queries: seen by `api` in memory while proxied and cached (minutes), never written or logged,
  sent to the provider from Songbird's addresses.
- The changed attachment row: downloads no longer authenticated (if question 1 is approved).

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 and 5.

1. **Downloads without device authentication.** Recommended. The 256-bit object ID inside the
   encrypted message is the capability. `api` checks the record, throttles per IP range, and
   hands out a 10-minute signed URL for range requests. The server no longer learns which device
   fetched which attachment. Signal's CDN works the same way. The alternative keeps today's
   signed downloads: simpler, but every fetch names a device next to an object ID.
2. **Size limit and budgets.** Recommended:
   - **2 GiB** per attachment (padded), for WhatsApp parity, since people switching send long
     videos and documents. Today's limit is 100 MiB.
   - Per account: **10 GiB uploaded per 24 hours** and **300 grants per hour**.
   - These are the defaults until Prompt 11's plans change them.

   The alternative keeps 100 MiB (Signal's limit) and costs less storage and egress.
3. **Pack lifetime.** Recommended:
   - A pack has no link to an account. The creator's devices hold a management token.
   - A pack is deleted by that token, or **one year after its last fetch**.
   - Limits: **200 assets** and **300 MiB** per pack.
   - Consequence for GDPR: deleting an account cannot find its packs. They are anonymous
     ciphertext and go one year after last use. The export lists none.

   The alternative links packs to the creator's account: deletion with the account, but the
   server learns who published which pack.
4. **GIF provider and design.** Recommended: **GIPHY**, through the prompt's design. `api` proxies
   search and images, caches, rate-limits, and never logs or stores queries.
   - The provider choice is a contract and terms decision. Please check GIPHY's terms on
     proxying and caching. Klipy is the other option (Tenor's API closed on 30 June 2026). The
     code supports either behind one trait.
   - The alternative is Signal's design: a CONNECT tunnel with an allowlist of domains. The
     server then sees neither queries nor images, but there is no shared cache and the provider
     key ships in the apps.
5. **Benchmarks decide** three choices without further questions, and the numbers get recorded:
   - AES-256-GCM or ChaCha20-Poly1305;
   - resumable parts or tus;
   - whether to put a caching proxy in front of RustFS.

   Please say if you want any of these decided differently.
