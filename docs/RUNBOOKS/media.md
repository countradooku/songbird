# Media: attachments, packs and the GIF proxy (Prompt 6)

PROTOCOL §7; D-0079 to D-0083. Covers the object store, abandoned uploads, budgets, and the GIF
provider.

## The GIF provider is down or failing

- **Detection:**
  - `api_gif_searches` stops growing while searches keep arriving;
  - the warning "gif provider failing: circuit open" appears in `api`'s log;
  - apps see 503 with `Retry-After: 30` on `POST /v1/gifs/search`.
- **Impact:** GIF search and trending stop, and GIF files not in a node's cache fail. Nothing else
  is affected: messages, attachments and packs do not depend on the provider. No query or user
  data is at risk. Queries are never stored, and the circuit stops traffic to the provider.
- **Immediate actions:**
  1. Nothing is needed for a short outage. After five consecutive failures, each node opens its
     circuit for 30 s and answers 503 without calling the provider. It closes on the first
     success.
  2. Check the provider's status page. Check that the key still works:
     `curl -s "https://api.giphy.com/v1/gifs/trending?api_key=$KEY&limit=1" -o /dev/null -w '%{http_code}'`,
     run from an admin host, never from a production node with a user's query.
  3. If the key was revoked or exceeded its quota, rotate it (below).
- **Recovery:**
  - **Key rotation:** put the new key in SOPS (`[api.media.gifs] api_key`), deploy `api`
    (minutes), and confirm a search answers 200.
  - **A provider that stays down:** set `[api.media.gifs]` aside, which removes the section, and
    deploy. The endpoints answer 503 and apps hide the GIF button.
  - **Moving to Klipy:** write a `Provider` adapter (`services/api/src/gifs.rs`), set
    `base_url` and `cdn_hosts`, and deploy. The proxy, cache and privacy rules do not change.
    Clear the switch with the owner first: it is a contract (D-0079 §4).
- **Verification:**
  - `api_gif_searches` and `api_gif_files` grow again;
  - a search from a test account returns results whose file URLs are all `/v1/gifs/media/…`.
- **Follow-up:** record the outage, and whether the provider budget (`provider_per_sec`) needs
  changing.

## Uploads failing or slow (RustFS)

- **Detection:**
  - `api_errors` rises;
  - grants succeed but `PUT …/parts/<n>` or `PUT /v1/attachments/<id>` answer 503;
  - `api_upload_parts` stalls.
- **Impact:** new attachments and packs cannot be sent. Messages still flow: an app retries the
  attachment and sends its message when the upload completes. Nothing already uploaded is lost.
- **Immediate actions:** follow [jobs-push-api-worker.md](jobs-push-api-worker.md) for RustFS
  being unreachable. Resumable uploads keep their parts for as long as their grants live (1 h
  idle, at most 24 h), so apps resume where they stopped once RustFS returns.
- **Verification:** the live tests' upload paths (`media_live`) against the environment, and
  `api_upload_parts` growing.

## Storage growing unexpectedly

- **Detection:** RustFS disk use grows faster than the uploads (`api_uploads`) explain, or
  `worker_objects_deleted`, `worker_uploads_aborted` and `worker_packs_deleted` stop.
- **Checks:**
  1. The worker's sweep is running (its counters move).
  2. No account escapes its budget: `api_media_throttled` moves when expected, and
     `[api.media]` is configured. Without it there are no budgets, which is development only.
  3. Abandoned multipart uploads (`rustfs` listing with `?uploads`) are older than 24 h only if
     the sweep is failing.
- **Recovery:** fix the sweep, then let it catch up (500 per run per kind). Nothing needs
  deleting by hand. Attachments go at 30 days, abandoned uploads with their grant, unused packs
  after a year.

## Download abuse (unauthenticated endpoints)

- **Detection:** `api_media_throttled` rises sharply, or egress rises without
  `api_media_redirects` rising.
- **Impact:** throttled IP ranges get 429 on redirects and confirmations. A signed URL works for
  10 minutes.
- **Actions:**
  - If one range drives egress through valid URLs, block it at the edge (nftables, D-0014).
  - Shorten `url_ttl_secs` (minimum 60) if URLs are being shared.
  - Prompt 11's abuse limits are the long-term answer (P06-M3 open risk).
