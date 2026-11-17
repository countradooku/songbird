# P06 — Media, attachments, stickers and packs: the final gate

- Date: 2026-11-17
- Prompt: [06-media.md](../prompts/06-media.md).
- Status: **waiting for the owner.**
- Reports: `P06-plan.md` (agreed, D-0079), `P06-M1.md` to `P06-M4.md`, and this report.
- Decisions: D-0079 to D-0084 (D-0084: the security review's fixes).
- Branch: `claude/p06-media` (PR #61), one PR at the owner's request (2026-11-17: "all the milestones in the
  same PR").
- Machine: Windows 11 Pro 10.0.26300, AMD Ryzen 9 7950X, 31 GiB. Live stack under podman 5 (WSL 2
  VM, 4 vCPU, 6 GiB): SurrealDB v4.0.1, Valkey 9.1.3 (×2), RustFS 1.0.5.

## The gate, item by item

| Gate item | Met by | Evidence |
| --- | --- | --- |
| **Upload and download throughput, latency and concurrency benchmarks recorded** | M2, M3 | **Uploads, 256 MiB:** parallel parts 288 to 731 MB/s; single `PUT` 255 to 376; tus 83 to 223. `media_live::upload_protocols`, D-0081.<br>**1 MiB:** latency p50 / p99 at concurrency 1, 16 and 64: downloads 5.0 / 9.1, 9.2 / 13.9 and 44 / 56 ms; uploads 64 / 75, 44 / 125 and 136 / 187 ms; up to 684 MB/s each way.<br>**64 MiB:** 277 MB/s up, 775 MB/s down.<br>**Seeks:** 128 KiB ranges 4.0 / 5.6 ms.<br>Source: `gate_p06::media_load`, D-0082 |
| **Resumed uploads and range downloads pass integration tests** | M2, M3 | **Resumed:** `media_live::resumable_parts_survive_interruptions_and_complete_exactly`, `rustfs_live::multipart_uploads_resume_and_complete_exactly`, and `gate_p06` (a real encrypted file in parallel parts).<br>**Ranges:** `media_live::downloads_need_no_account_and_serve_ranges` (five kinds, 416, ignored ranges) and `gate_p06` (a seek decrypted chunk by chunk) |
| **Lifecycle tests prove deletion after the last fetch and at 30 days** | M3 | `gate_p06::an_encrypted_file_goes_up_in_parts_comes_back_by_range_and_goes_after_the_last_fetch`: two devices confirm, the worker deletes the object, and the URL then serves nothing.<br>`gate_p06::attachments_nobody_fetches_go_at_30_days_and_abandoned_uploads_are_aborted`: the 30-day sweep, and abandoned multipart uploads aborted.<br>Packs: `gate_p06::a_pack_opens_from_its_link_and_expires_when_unused` (a year unused; unfinished after a day) |
| **Fuzzed manifest and grant decoders** | M1–M4 | Fuzz targets `pack_manifest` (manifests), `upload_grant` (grants), `attachment_decrypt`, `s3_multipart_xml`, `media_url` and `gif_proxy`. Local runs below; all six are in the nightly CI matrix |

## The rest of the prompt

| Prompt item | Where |
| --- | --- |
| Attachment format in `crates/content` with test vectors: fixed-size chunks, a streaming AEAD, stream, resume and verify chunk by chunk; sizes padded into buckets; thumbnails separate objects | M1 (D-0080; PROTOCOL §7.1, §13). STREAM over 64 KiB chunks, key-committing, Padmé. Vectors reproduced by Node.js and OpenSSL |
| Grants bound to an exact padded size and a per-plan limit; resumable chunked uploads (S3 multipart or tus, benchmark both); per-account upload rate and storage quotas | M2 (D-0081; §7.2). Both built and measured; parts kept; budgets per account (D-0079 §2) |
| Unguessable object IDs, short-lived signed URLs, range requests, a caching proxy if benchmarks justify it | M3 (D-0082; §7.3). Downloads by capability with no account (D-0079 §1). The proxy is not justified |
| Recipient-device counting; deletion at the last fetch or 30 days; forwarding re-uploads with fresh keys | M3 (explicit confirmation); M1 (the forwarding rule, §7.1) |
| Packs: one service for sticker packs, chat scenes, sound stickers and emoticon packs; an encrypted manifest and assets; the key only in the link | M4 (D-0083; §7.4) |
| A GIF search proxy that strips addresses and identifiers, with caching and rate limits; no server-side link previews | M4 (D-0083; §7.5). GIPHY (D-0079 §4) |
| The server never parses media; grants cannot be reused or enlarged; quotas stop storage exhaustion; object IDs never next to account IDs in logs | §3.23 of the threat model, with a test per row. No object or pack ID reaches a log line, an error or a metric (every `Debug` of a record hides it) |
| GDPR for every new store | M5: `gate_p06::the_export_lists_uploads_and_packs_in_progress_and_deletion_removes_them`; the export's statements on what cannot be attributed |

## Runs

All runs were on the machine above, at `66d79f2` plus this report.

| Run | Result |
| --- | --- |
| `cargo fmt --check`; `cargo clippy --workspace --all-targets --locked -D warnings`; workflow policy | Clean (`cargo xtask ci fast`'s first three steps) |
| `cargo nextest run --workspace --locked --profile ci`, with SurrealDB and Valkey live (as CI's fast tier; tests needing the whole stack skip) | **703 of 705 passed**, 7 skipped. The two failures, `usernames_live::keyed_lookups_take_the_same_time…` (a timing comparison) and `devices_live::a_pin_gates_linking…` (503s from `valkey-hot` under load), pass alone, twice each, and in the serial run below. Prompt 6 does not touch their code; the only change to their files is the `media: None` field. They fail when the whole workspace loads the WSL VM that hosts the stores |
| The stack suites, one crate at a time with `-j 1` against SurrealDB, both Valkeys and RustFS (as CI runs them) | `songbird-api` **71 of 71**; `songbird-jobs` 12 of 12; `songbird-e2e` **55 of 55** (including `gate_p06` 4 of 4, `gate_m5`, `gate_p03`); accounts, s3, content, proto and worker **172 of 172** |
| `gate_p06`, live, `SONGBIRD_REQUIRE_STACK=1` | **4 of 4**: an encrypted file in parallel parts, a ranged seek decrypted, and deletion after the last confirmation; 30 days and abandoned uploads; a pack opened from its link and expired; the GDPR export and deletion |
| Fuzzing, nightly toolchain, ASan, 120 s each | `upload_grant` 4,449,800 runs; `s3_multipart_xml` 3,986,796; `media_url` 13,949,443; `pack_manifest` 10,735,174; `gif_proxy` 954,520: nothing found.<br>`attachment_decrypt`: its first run stopped on the **target's own oracle**, which wrongly required an equal length claim. A longer length in the same padding bucket correctly returns the authenticated zero padding, as specified in §7.1 and tested by `padding_must_be_zeros_and_the_real_length_is_the_pointers`. With the oracle fixed: 98,066 runs, nothing found.<br>All six targets are in the nightly CI matrix (10 minutes each) |
| Independent vectors | `node tools/attachment-vectors/check.mjs`: 6 attachment vectors and the pack keys match |
| Benchmarks (release) | `attachment_bench` (D-0080), `media_live::upload_protocols` (D-0081), `gate_p06::media_load` (D-0082) |

The full CI run on Linux is the PR's checks.

## Security review

An independent, read-only review of the whole Prompt 6 diff. A separate agent was given the code
and the documents, not this report's conclusions. It found no high-severity issue. Its findings,
and what was done about each (D-0084):

| # | Finding | Severity | Done |
| --- | --- | --- | --- |
| 1 | Confirmations need no account: one recipient could confirm N times and delete a group's file before the others fetched it | Medium | **Fixed:** each source (IPv4 address, IPv6 /64) counts once per object. Live: three confirmations from one source count once, and a second source deletes |
| 2 | `finish` deleted the object whenever completion failed, including a retried completion of a finished attachment; an expired grant could still complete | Medium | **Fixed:** `finish_upload` has three outcomes, and only "no live grant" deletes; grants must be unexpired. Registry test |
| 3 | The abandoned-upload sweep read only the first 1,000 uploads | Medium | **Fixed:** paged listing (`NextKeyMarker`, `NextUploadIdMarker`), up to 100,000 |
| 4 | Unauthenticated GIF file failures (a removed GIF) could open the breaker for everyone's searches and spend the provider budget | Low–medium | **Fixed:** files never move the breaker, have their own budget and run at most 32 in flight; searches count only transport errors, 5xx and 429. Live: eight failing file fetches, then a search succeeds |
| 5 | Parts and pack objects could be rewritten without limit while a grant lived | Low | **Fixed:** at most 2 × parts + 8 writes (409 after). Live tests for both |
| 6 | A pack upload racing deletion or expiry left an orphaned object | Low | **Fixed:** checked after writing, and deleted if the pack is gone |
| 6b | The `digest` commits to the key, not to the ciphertext | Low (design) | **Recorded, not changed:** objects are immutable once complete, and only the uploader can write before that. A ciphertext hash would cost every app a second pass over every file |
| 7 | A signed URL could be replayed without limit for its 10 minutes | Low | **Fixed:** a per-IP-range budget on the media path (36,000 an hour, burst 3,600) |
| 8 | `[api.media]` not required when deployed (no budgets without it) | Low | **Fixed:** required in staging and production |
| 9 | The GIF base URL check accepted `http://127.0.0.1.evil…`; `part_size` allowed more parts than the server reads | Info | **Fixed:** the host is parsed and compared; at most 1,000 parts |

The reviewer checked and found sound:

- the size arithmetic (overflow-safe, only format lengths granted);
- the attachment format (unique nonces, the suite in the key derivation, the commitment checked
  first, truncation and padding caught, buffers wiped);
- the manifest decoder;
- grant authorization (another device gets 404, exact lengths, single use) and the upload-ID
  compare-and-set;
- the media URL MAC and query parser;
- range parsing;
- the GIF proxy's allowlist against userinfo, ports, case, trailing dots and IPv6 literals, with
  no redirects followed, TLS verified and bodies capped;
- logs and metrics (no IDs or queries);
- GDPR.

## For the owner

1. **The gate:** M1 to M5, the benchmarks (above; D-0081, D-0082) and the decisions they drove:
   - parallel parts with tus removed;
   - 16 MiB parts;
   - AES-256-GCM by default;
   - no caching proxy.
2. **Five threat-model §1 rows** awaiting approval:
   - resumable grants up to 24 h;
   - per-account upload budgets;
   - downloads by capability (replacing device-signed downloads);
   - packs;
   - GIF queries.

   The third also changes the approved attachment row: downloads no longer name a device.
3. **Before production** (not blocking the merge):
   - GIPHY's API key into SOPS, and acceptance of GIPHY's terms (caching and proxying files;
     attribution in the apps);
   - `[api.media]` with its secret on every `api` node. Without it, downloads, packs and GIFs
     answer 503.
