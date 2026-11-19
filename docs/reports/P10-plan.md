# P10 — Backups: cloud-agnostic format and vault service: plan, milestones and gates

- Date: 2026-11-19
- Prompt: [10-backups.md](../prompts/10-backups.md)
- Status: **approved by the owner on 2026-11-19** ("Approve all"), every recommendation (D-0119).
- Base: `main` at `f6b0444` (Prompt 9 merged, PR #67). The camera module (PR #68) is merged too.
- Way of working (as Prompts 7 to 9): one branch and one PR (`claude/p10-backups-40584b`). Each
  milestone gets its own commit, tests, report `docs/reports/P10-Mn.md`, decision record
  (D-0120 onward) and threat-model rows marked "awaiting the owner's approval". Then
  `cargo xtask ci fast`, the live suites (one heavy job at a time, `-j 1` for crates that share
  job streams, the environment of `ci.yml`'s compose job, without Iggy locally), an independent
  read-only security review of the whole diff by a separate agent given the code and not my
  conclusions, and `docs/reports/P10-gate.md`. Nothing is merged without the owner.
- Skills: `nsh` and `nsh-design-guides` before the app milestone (M5); `security-review` for the
  independent review (M6). No skill covers backup formats, content-defined chunking, OAuth for
  native apps (RFC 8252) or the cloud providers' APIs; I read the specifications and the exact
  pinned crate sources instead. A `songbird-invariants` checklist (constitution) is still only
  proposed.

## What Prompt 10 starts from

| The prompt asks for | Already there | Missing |
| --- | --- | --- |
| A versioned, chunked, encrypted backup format with a recovery key | PROTOCOL §11 is an empty heading. The app has a 32-character mock key (`SB4K-…`, 8 groups of 4) shown at account creation. Padmé padding (D-0080) and protobuf content with forward-compatible readers (`crates/content`, §5.2) | Everything: no crate, no key schedule, no chunker, no manifest |
| XChaCha20-Poly1305 | aws-lc-rs 1.19 has ChaCha20-Poly1305 (IETF, 12-byte nonce), HKDF, HMAC and SHA-256, but **no XChaCha20** (read in `aws-lc-rs-1.19.0/src`). RustCrypto `chacha20poly1305` 0.10.1 is already in `Cargo.lock` (through OpenMLS's test harness) and has a cargo-vet exemption | A recorded reason to use it in a shipped crate |
| `BackupStore` with adapters | `crates/s3`: our own SigV4 S3 client on hyper (put, get, head, delete, list, multipart), used by `api` and `worker` against RustFS | The trait, every adapter, a transport the app can use (the app talks HTTP through NSH's `HttpRequest`, not hyper) |
| The Songbird vault in `api` on RustFS | RustFS in compose, a bucket per service, streamed uploads into S3 (`media.rs`), GCRA throttles in `valkey-hot`, the account deletion job (`worker` deletes the account's objects), GDPR export | The vault endpoints, tables, quota, throttles, the deletion and export of vaults |
| A brand-new device restores with only the recovery key | Accounts have no phone number or e-mail; the **account identity key** (Ed25519) lives on the primary only and signs the device list (§4.6). PROTOCOL §4.7 says linking "needs the PIN or a passkey once set, **and so will account recovery (Prompt 10)**" | **Account recovery does not exist.** Without it, a restored identity key cannot become a working account again |
| Device-to-device transfer | A mocked flow (`apps/ui/src/features/backups/transfer.rs`): roles, QR, pairing, progress. Real QR codes and the camera (D-0110) | Protocol, channel, discovery, the primary's role passing to the new phone |
| Local export | Mock "Encrypted file" destination | Everything |
| Conformance suite, emulators | RustFS in compose; CI's compose job | A WebDAV server in compose; mock Drive, OneDrive and Dropbox servers |

## Findings that shape the plan

1. **Restoring the identity key is not enough: the account must be recoverable.** A new phone
   with only the recovery key can read the backup, but the account's devices are all gone and
   the server only lets the primary link new ones. The prompt's goal (a restore on a brand-new
   device, safety numbers kept) therefore needs **account recovery**, which Prompt 3 already
   assigned to Prompt 10:
   `POST /v1/account/recover` (unsigned, throttled per IP range and per account) with the
   account ID, the new device's keys, a fresh server challenge signed by the **account identity
   key** from the backup, and the PIN or a passkey **when the account has one** (§4.7's rules
   and lockouts, unchanged). The new device becomes the primary; every other device is
   disabled and deleted through the outbox as a removal is; contacts see a device change but
   the same safety number. The transfer to a new phone uses the same call with a **handover
   token** from the old primary in place of the factor (question 4).

2. **The recovery key is the whole account.** Whoever holds it can read the backup and, through
   recovery, take the account unless a PIN or passkey is set. This is the same trade Signal makes
   with its account entropy pool and Proton with its recovery phrase. So the key must be strong
   and typed correctly: 64 characters of Crockford base32 (no I, L, O, U; case, spaces and
   dashes ignored; `I`/`L` read as `1`, `O` as `0`) carry **320 bits: a 256-bit secret and a
   64-bit check**, shown as 16 groups of 4. A typo is caught on the device before any network
   request ("check the key"), instead of looking like "no backup found" (question 2). The set-up
   wizard asks the user to set a PIN if none is set.

3. **Every key comes from the recovery key, nothing else.** HKDF-SHA256 (aws-lc-rs) over the
   256-bit secret, salt `"songbird.v1/backup"`, one label per key:
   - `vault-id` (32 bytes): where the vault is, on any store;
   - `vault-access` (32): the vault's bearer secret; the Songbird vault keeps only
     `SHA-256("songbird.v1/vault-access\0" || secret)`, so its database cannot open a vault;
   - `manifest` (32), `chunk` (32): XChaCha20-Poly1305 keys;
   - `chunk-name` (32): the HMAC key that names chunks;
   - `chunker` (32): the seed of the chunker's gear table (finding 5).
   A new recovery key is a new vault: full upload, then the old vault is deleted.

4. **Format: a small encrypted manifest and opaque, padded chunks.**
   - Chunk object: `magic "SBC" | version u8 | nonce [24] | XChaCha20-Poly1305(padded
     plaintext)`, the AAD binding the version and the chunk's name, so no chunk can be served
     under another name. Plaintext is padded with Padmé (as attachments, D-0080) and carries
     its true length inside.
   - Chunk name: `HMAC-SHA256(chunk-name key, plaintext)`, 32 bytes, base32 in object names.
     Equal content gets the same name, which is what makes backups incremental and media
     deduplicated, and reveals nothing about content to anyone without the key.
   - Manifest: `magic "SBM" | version u8 | generation u64 | nonce [24] |
     XChaCha20-Poly1305(protobuf)`, AAD = the header and the vault ID. The `generation` is in
     the clear because the store's compare-and-swap needs it; it says how many backups were
     made, nothing else. Inside: the format version that wrote it and the oldest that may read
     it, the writing app's version and platform (informational only), and the sections, each a
     list of chunk references (name, padded length, plaintext length, SHA-256 of the
     plaintext).
   - Contents, as protobuf sections (prost, as `crates/content`): the account (account ID,
     account identity private key, profile key, storage key of the record store (§10.1),
     access key, username key if any), profile, contacts, settings (a snapshot of the records
     and the device-only settings), chats, messages (per chat, in order), media (one stream per
     file, so a photo is stored once however often it was forwarded), the group list (group
     ID, name, the group's metadata key and member list, enough to rejoin). **Excluded**:
     ratchet sessions, prekeys, device identity keys, MLS epoch secrets and pending
     KeyPackages. A restored device starts fresh sessions; groups are rejoined by re-add or
     external commit (§6).
   - Readers: every later version reads every earlier one; unknown fields are ignored; a
     manifest whose "oldest reader" is newer than the app is refused with "update Songbird",
     never half-read. The vectors of each published version stay in the repository and are
     read by every later reader (as `crates/content/tests/compat.rs`).

5. **Incremental needs chunk boundaries that survive edits.** Fixed-size chunks would re-upload
   everything after the first changed byte. Content-defined chunking (a FastCDC-style rolling
   gear hash) cuts where the content says, so a new day of messages changes the chunks at the
   end of each touched chat and an old deleted message changes one chunk. The gear table is
   **keyed** by the `chunker` key (as Borg and restic do), so boundaries reveal nothing about
   content. Sizes: minimum 1 MiB, average 2 MiB, maximum 8 MiB ("a few MB each"), tuned by the
   M1 benchmark. Messages are cut per chat, media per file; small sections (account, profile,
   settings) share one chunk.

6. **"Verified before anything is written" means two phases.** Restore first fetches every
   chunk the manifest names, checks each one's tag, name (HMAC of the plaintext), length and
   SHA-256, and only then applies the backup to an empty store in one transaction. Chunks are
   kept encrypted in a staging folder while they are checked, so a large backup does not need
   its size in memory. Any failure (a missing chunk, a bad tag, a truncated object, a renamed
   chunk, a manifest from another vault) stops with a named error and leaves the device exactly
   as it was. Fuzzing and the corruption tests check this.

7. **The store can roll a backup back; a new device cannot tell.** A device keeps the highest
   generation it has seen and refuses an older manifest. A brand-new device has nothing to
   compare with, so a malicious store could serve an older backup (never a forged one). Each
   manifest also carries the SHA-256 of the previous one, so a device that has seen any later
   manifest detects a fork. Stated in the threat model, as Prompt 9 stated it for records.

8. **The Songbird vault can be found and opened by the recovery key alone, and still be owned by
   an account.** Reads need only the vault ID and the access secret (a new device has no account
   yet). Writes need both the access secret and a signature by the primary device of the account
   that owns the vault, because quotas (Prompt 11) and deletion with the account need an owner.
   So the server learns **which account has a vault, its byte count, its chunk count and its
   generation**, and never a write time (none is stored). Signal unlinks backups from accounts
   with zero-knowledge backup credentials; Prompt 11 evaluates exactly that library for
   payments. Recommended now: linked, stated in the threat model, with unlinking re-decided in
   Prompt 11 on the same credential work; the vault's API keeps the owner in a separate table so
   that change needs no format change (question 3).
   - Tables in the registry: `vault` (`HMAC(server key, vault ID)`, access hash, generation,
     manifest object, bytes, chunks) and `vault_owner` (vault, account). Objects in a dedicated
     RustFS bucket under `HMAC(server key, vault ID)/` (the bucket's operator sees neither the
     vault ID nor the account).
   - `GET`/`PUT /v1/vault/manifest` (compare-and-swap on the generation, one transaction),
     `PUT`/`GET /v1/vault/chunks/<name>` (streamed straight into RustFS, as attachments),
     `POST /v1/vault/chunks/list` (paged), `POST /v1/vault/chunks/delete` (up to 1,000),
     `POST`/`DELETE /v1/vault`. An unknown vault and a wrong access secret get the same 404,
     timing and throttle.
   - Quota per vault (bytes and chunks) from configuration until Prompt 11's entitlements
     (question 5); clients delete unreferenced chunks after each manifest, and the quota bounds
     what a careless client leaves.
   - Throttles (GCRA in `valkey-hot`, keyed hashes): failed opens per IP range, reads per
     vault, writes and bytes per account per day. Defaults measured in M2.
   - Deleting the account deletes its vault (the `worker`'s deletion job, with the objects);
     GDPR export reports the vault's existence, bytes, chunks and generation.

9. **Third-party adapters must run on the device and speak only what the app can speak.**
   OAuth tokens never reach Songbird. `crates/backup-storage` is therefore transport-agnostic:
   adapters build requests and parse responses over a small `Http` trait; the app plugs in NSH's
   `HttpRequest`, tests and the reference CLI plug in hyper with rustls. Each provider's
   compare-and-swap is different, and one is weak:
   - S3: conditional writes (`If-Match` / `If-None-Match: *` on `PutObject`); support in
     RustFS 1.0.5 checked in M3, MinIO as the fallback emulator if it lacks them;
   - WebDAV: `If-Match` on the ETag, `If-None-Match: *` to create (RFC 4918 / RFC 9110);
   - OneDrive: `If-Match` on the eTag (Microsoft Graph), app folder `special/approot`;
   - Dropbox: `files/upload` with `mode = update(rev)`, an atomic compare-and-swap, in the App
     Folder;
   - Google Drive (`appDataFolder`, scope `drive.appdata`): v3 has **no conditional update**.
     The adapter writes each manifest as a new file named by its generation and reads the
     highest; two writers racing on one generation are resolved by a fixed rule (lowest file
     ID wins, the loser retries). Backups come from the primary only, so a race needs two
     primaries, which the account model rules out except during recovery. The weaker guarantee
     is stated in the adapter and the threat model.
   - iCloud Drive: the interface only (`NSFileCoordinator` and `NSFileVersion` give a
     compare-and-swap); the conformance suite is written so a native adapter can run it later.
   The app's sign-in to Google, Microsoft and Dropbox needs OAuth clients the owner registers
   (client IDs are public; PKCE, RFC 8252). Desktop can use a loopback redirect now; iOS and
   Android need `ASWebAuthenticationSession` and Custom Tabs from the host projects deferred
   with push (question 6).

10. **Device-to-device transfer reuses the format, not a second one.** The new phone listens on
    the local network and shows a QR code with its addresses, port, a one-time X25519 public key
    and a 16-byte secret. The old phone scans it and connects over TCP. The channel is Noise
    `NNpsk0` built on aws-lc-rs (X25519, HKDF-SHA256, ChaCha20-Poly1305): only a phone that
    scanned the code can complete the handshake, and both show a 6-digit code derived from the
    handshake to compare. The old phone then streams a backup made with a one-time recovery key
    sent inside the channel (the same manifest and chunk encoding, so restore code and its
    checks are shared), plus a handover token, and the new phone recovers the account as the new
    primary (finding 1). Nothing passes through Songbird's servers except the handover. iOS
    needs the local-network usage string in the host project (noted for the app phase).

11. **The app has no real chats yet.** app-core (A2) does not exist; chats, messages and media
    are the in-memory mock (`apps/ui/src/store`). The account, profile, settings records,
    contacts and supervision are real since Prompt 9. So the app backs up what is real from the
    real stores and the chats and messages from the mock, through the same format. app-core
    later fills the same sections, with no format change.

12. **Only the primary can make a backup.** A linked device has no account identity key
    (§4.6), so it cannot make a backup that restores an account. Linked desktops show the
    primary's backup status read from the settings records and offer only export and restore.

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **`crates/backup-format`** (`#![forbid(unsafe_code)]`): the recovery key (parse, check, display), the key schedule, the keyed chunker, chunk and manifest encodings, the content sections (protobuf), the writer (plans which chunks are new against the previous manifest) and the two-phase reader; PROTOCOL §11.1–11.4. | Byte-exact vectors (fixed key and nonces) for the key schedule, a chunk, a manifest and a whole small backup; a **cross-platform determinism test** (the same history gives the same chunk names and bytes on Linux x86_64, Linux i686 (32-bit `usize`) and macOS arm64; the vectors in CI); corruption and truncation tests (a flipped bit, a missing chunk, a truncated object, a swapped name, another vault's manifest, a rollback: each fails loudly and writes nothing); proptests for round trips and incremental reuse; fuzz targets for the manifest, chunk, section and key decoders; chunker throughput recorded with the hardware. |
| **M2** | **`crates/backup-storage` core and the Songbird vault:** the `BackupStore` trait, the conformance suite, in-memory and local-file adapters (an export is a folder or one `.songbird-backup` file); the vault service in `api` (tables, RustFS bucket, endpoints, quota, throttles, deletion with the account, GDPR export) and its adapter. | The conformance suite passes on memory, local file and the **live vault** (compose RustFS, SurrealDB, Valkey): put, get, list, delete, compare-and-swap races (N writers, one winner per generation), quota refusals, same 404 for an unknown vault and a wrong secret; account deletion leaves no vault row and no object; p99 of chunk put and get and of the manifest swap recorded with the hardware. |
| **M3** | **Third-party adapters:** S3, WebDAV, Google Drive, OneDrive, Dropbox over the `Http` trait; OAuth helpers (PKCE, token refresh, tokens only in the caller's hands); the iCloud interface; a WebDAV server in compose; mock Drive, OneDrive and Dropbox servers written from the providers' documentation, including their conflict and error behaviour. | The same conformance suite passes on RustFS (S3), the WebDAV container and the three mocks; each adapter's compare-and-swap race test; a token or a vault secret never appears in `Debug` or a log (tests). |
| **M4** | **Account recovery and transfer:** `POST /v1/account/recover` (identity signature, factor or handover token), the handover token, removal of the old devices; the transfer protocol and its reference implementation (listener, QR payload, `NNpsk0` channel, streamed backup); **restore across simulated platforms**; the **incremental cost** measurement. | Live tests: recovery with the right key and PIN works and removes old devices, a wrong PIN is counted and locks as linking does, no factor when one is set is refused, a replayed challenge is refused; transfer between two processes over loopback, a wrong QR secret or a man in the middle fails the handshake; backups written as iOS, Android, Windows and macOS restore on every other; incremental cost on a large simulated history (1,000,000 messages in 2,000 chats, 20,000 media files) for the first backup, a day of new messages, and deletions of old ones: bytes and chunks uploaded, time, on the vault and in memory, with the hardware. |
| **M5** | **The app (`apps/ui`):** the 64-character recovery key at account creation; Settings → Backups real for the Songbird vault, an encrypted file, S3 and WebDAV; Google Drive, OneDrive and Dropbox on desktop once their client IDs exist (question 6); restore (from the vault or a file) with account recovery in onboarding; transfer to a new phone between two app instances; backup status on linked devices. | Headless NSH tests of each flow; two live instances: back up, wipe, restore with only the key, the safety number unchanged; a damaged backup shows "can't be restored" and changes nothing; transfer between two instances; screenshots of every changed screen, light and dark. |
| **M6** | **The gate:** the security review of the whole diff; fixes; `P10-gate.md`. | The prompt's gate item by item: every adapter passes the conformance suite; cross-platform restore and corruption tests pass; incremental cost measured. |

Order: M1 first. M2 needs M1's encodings for the vault adapter's tests only. M3 needs M2's trait
and suite. M4 needs M1 and M2. M5 needs M1 to M4. M6 needs everything.

## Threat-model rows this plan will propose

- §1 (new rows): per vault, the keyed hash of its ID, the hash of its access secret, its
  generation, byte and chunk counts, and its owning account (question 3); its chunks as opaque
  padded objects under keyed names; no write time. Recovery attempts (counts, in `valkey-hot`
  throttles only). Handover tokens (hashed, single use, ten minutes).
- §3.27 (new STRIDE table): a stolen recovery key; recovery without the factor; vault probing;
  rollback and forking of manifests; swapped, truncated or replayed chunks; quota exhaustion;
  a malicious store returning crafted objects (decoder bugs); a man in the middle of the
  transfer; a token leak from an adapter; a provider correlating backups with an account
  (timing, sizes).
- §6: what third-party clouds see (that an app folder exists, object count, padded sizes,
  times); the Google Drive compare-and-swap weakness; rollback on a brand-new device.

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 to 9.

1. **Scope.** Recommended: the milestones above, **account recovery included** (finding 1),
   because a restore on a brand-new phone cannot work without it and PROTOCOL §4.7 already
   assigned it to this prompt.
2. **The recovery key.** Recommended: 64 Crockford base32 characters, a 256-bit secret and a
   64-bit check, 16 groups of 4, created with the account (as the app's onboarding already
   shows) and kept on the primary, encrypted at rest (finding 2). The alternative: 64 random
   characters without a check (320 bits), where a typo looks like "no backup found".
3. **Vault and account.** Recommended: the vault is owned by an account (quota, deletion with
   the account); the server learns that the account has a vault, its size, chunk count and
   generation, never a time; unlinking with anonymous credentials re-decided in Prompt 11
   (finding 8). The alternative: unlinkable now, which pulls Prompt 11's credential work
   forward and needs another way to bound abuse and delete vaults.
4. **Account recovery.** Recommended: the account identity key's signature plus the PIN or a
   passkey when the account has one (§4.7's attempts and lockouts); the old devices are removed
   and notified; the transfer uses the old primary's handover token instead of the factor
   (finding 1). The stricter alternative: when any device of the account was online in the last
   7 days, the recovery waits 7 days and that device can cancel it (protects against a stolen
   key, delays a real loss by a week).
5. **Vault quota until Prompt 11.** Recommended: 5 GiB and 100,000 chunks per vault, from
   configuration (about €0.03 a month for a full vault, at roughly €5 per TB a month of object storage);
   Prompt 11's entitlements replace it. Or name another figure.
6. **Google Drive, OneDrive and Dropbox in the app.** Recommended: adapters and mock-server
   tests now; the app's sign-in on desktop (loopback redirect with PKCE) as soon as you register
   the three OAuth apps (Google Cloud with the `drive.appdata` scope, Microsoft Entra with
   `Files.ReadWrite.AppFolder`, a Dropbox App Folder app; the client IDs are public). On iOS and
   Android, with the host projects after the whole app is built, as for push. Until the IDs
   exist, those rows say "coming soon". The alternative: hide them until then.
7. **WebDAV in CI.** Recommended: Apache httpd with `mod_dav` in compose (small, the reference
   WebDAV server, ETags and conditional requests), pinned by digest, plus one manual run against
   a Nextcloud container recorded in M3. The alternative: Nextcloud itself in CI (a database and
   about 1 GB of image).
8. **Agent decisions, recorded unless you object:**
   - `chacha20poly1305` 0.10.1 (RustCrypto, already in the lock and exempted in cargo-vet) for
     XChaCha20-Poly1305, which aws-lc-rs lacks; everything else on aws-lc-rs;
   - a keyed FastCDC-style chunker (1, 2 and 8 MiB), media chunked per file, Padmé padding;
   - chunk names by HMAC of the plaintext; the manifest's generation in the clear, its previous
     hash inside;
   - protobuf (prost) for the manifest and sections; a "minimum reader version" field;
   - two-phase restore through an encrypted staging folder;
   - backups made by the primary only;
   - the `Http` trait in `crates/backup-storage`; the S3 adapter reuses `songbird_s3::sigv4`;
   - vault chunks streamed through `api` into a dedicated RustFS bucket; the same 404 for an
     unknown vault and a wrong secret;
   - the transfer channel as Noise `NNpsk0` on aws-lc-rs (no Noise library), a 6-digit
     comparison code, addresses in the QR (no mDNS);
   - a new recovery key means a new vault and a full upload;
   - the determinism test on Linux x86_64, Linux i686 and macOS arm64;
   - one branch and one PR for every milestone.
