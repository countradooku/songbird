# Prompt 10 — Backups: cloud-agnostic format and vault service

*File: `docs/prompts/10-backups.md` · Skills: applied cryptography review, storage APIs, Rust testing.*

**Goal:** user backups that restore on any operating system (Android to iPhone, Windows to Mac) and can live in any storage the user chooses, unreadable by every storage provider, Songbird included. (Disaster recovery for Songbird's own servers is Prompt 13.)

**Build `crates/backup-format`** (a shared library the future apps will use; the format is defined here, never by iOS or Android):

- Versioned manifest plus content chunks of a few MB each. Chunks encrypted with XChaCha20-Poly1305 under keys derived (HKDF) from a random 64-character recovery key; chunk names are keyed hashes so names reveal nothing.
- Contents: account identity key (so safety numbers survive a restore), profile, contacts, chats, messages, media, settings, group list. Excluded: ratchet session state (restored devices start fresh sessions; groups rejoin through re-add or external commit).
- Incremental (only new chunks upload), verified (every chunk checked before anything is written), newer versions always read older ones.
- Byte-exact test vectors and a cross-platform determinism test.

**Build `crates/backup-storage`:** one small `BackupStore` interface (put, get, list, delete, and a compare-and-swap for the manifest) with adapters:

- Songbird vault (below), any S3-compatible bucket, WebDAV (Nextcloud), Google Drive app folder, OneDrive app folder, Dropbox app folder.
- OAuth tokens for third-party clouds stay on the device; these adapters run in the client, never on Songbird servers.
- iCloud Drive has no server-side API, so it is a native iOS adapter for the app phase; define the interface it must satisfy now.
- Local file export and a device-to-device transfer protocol over the local network (QR pairing, encrypted channel), specified with a reference implementation.

**Build the Songbird vault service** (in `api`, storage in RustFS):

- Vault location and access credentials are derived from the recovery key, so a brand-new device holding only the recovery key can find and open its vault; the server stores only a hash of the access secret.
- Atomic manifest replacement by version; per-plan quotas (Prompt 11); rate limits; vault deletion on account deletion. The server cannot read manifests, so clients remove unreferenced chunks, and quotas bound what they leave behind.

**Tests:** one conformance suite run against every adapter, using local emulators (RustFS or MinIO for S3, a WebDAV container, mock servers for Drive, OneDrive and Dropbox); restore across simulated platforms; corruption and truncation tests (a damaged chunk must fail loudly, never restore silently wrong data); fuzzing of manifest and chunk decoders.

**Gate:** all adapters pass the conformance suite; cross-platform restore and corruption tests pass; incremental backup cost measured for a large simulated history.
