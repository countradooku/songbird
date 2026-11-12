# Prompt 6 — Media, attachments, stickers and packs

*File: `docs/prompts/06-media.md` · Skills: storage systems, applied cryptography review, HTTP performance, testing.*

**Goal:** fast, private transfer of photos, videos, voice notes, documents, stickers and other asset packs, with the server only ever holding ciphertext.

**Build:**

- **Attachment format** (in `crates/content`, with test vectors): files are encrypted on the device in fixed-size chunks with a streaming AEAD construction, so large files can be streamed, resumed and verified chunk by chunk; sizes are padded into buckets so the server does not learn exact sizes. Thumbnails are separate encrypted objects made by the client.
- **Uploads:** `api` issues short-lived upload grants bound to an exact padded size and a per-plan size limit; resumable chunked uploads to RustFS (S3 multipart or the tus protocol, benchmark both); per-account upload rate and storage quotas (Prompt 11).
- **Downloads:** unguessable object IDs with short-lived signed URLs; HTTP range requests for streaming video and voice notes; a caching reverse proxy in front of RustFS if benchmarks justify it.
- **Lifecycle:** each attachment records how many recipient devices still need it. Delete when every recipient device has fetched it, or after 30 days, whichever comes first. Forwarding re-uploads with fresh keys, so two messages cannot be linked by object ID.
- **Packs:** one generic service for sticker packs, chat scenes (Yahoo IMVironments), sound stickers and emoticon packs: an encrypted manifest plus encrypted assets in RustFS, shared by a link containing the pack key (the server never holds the key).
- **GIF search proxy:** `api` proxies queries to a GIF provider, stripping IP addresses and identifiers, with caching and rate limits, so the provider sees queries but not who sent them. No server-side link previews; clients build those.

**Security:** the server never parses media; upload grants cannot be reused or enlarged; quotas stop storage exhaustion; object IDs never appear next to account IDs in logs.

**Gate:** upload and download throughput, latency and concurrency benchmarks recorded; resumed uploads and range downloads pass integration tests; lifecycle tests prove deletion after the last fetch and at 30 days; fuzzed manifest and grant decoders.
