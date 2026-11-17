# Threat model

Skeleton. Completed in Prompt 12; every prompt adds the threats for what it builds.

## 1. What the server may see

The exhaustive list of data the server may hold in plaintext. Anything not listed must not reach the
server in plaintext. Adding to this list requires the owner's approval.

| Data | Why the server needs it | Retention | Introduced by |
| --- | --- | --- | --- |
| Device ID | Authenticate the connection, address mailboxes | Life of the device | Prompt 2 (M1) |
| Device authentication public key (Ed25519) | Verify the connection challenge | Life of the device | Prompt 2 (M1) |
| Connection times and source IP | Accepting the TCP connection; rate limits | Memory only, for the connection's life; never logged or exported | Prompt 2 (M1) |
| Recipient device ID, `seq`, envelope size and store time per stored envelope | Store, order and deliver | Index: until acknowledged, at most 30 days. Iggy log: sealed under a per-message key destroyed at acknowledgement (unopenable within about 1 s, `key_interval`); the sealed bytes are deleted with their segment, about 25 minutes after delivery plus the time to fill a 16 MiB segment (D-0031). Iggy's own message headers (record size, time, partition) stay readable until then | Prompt 2 (M1, M2) |
| Envelope ciphertext | Store and relay (opaque, never decrypted) | As the row above | Prompt 2 (M1, M2) |
| Keyed hash (HMAC-SHA256, server secret) of a send's idempotency key, with a keyed fingerprint of its recipient set and the log offset of the send; **not** the sender, the devices or the content, never the key itself | Store a retried send once | 6 hours in the index; 7 hours in the idempotency topic (D-0031) | Prompt 2 (M1), D-0021, D-0024 (owner delegated) |
| Mailbox key store (per partition: window keys, punctured key trees, the keys of pending messages), sealed with the node's master key | Decrypt pending messages; destroy acknowledged ones | Until the window's records are below the low-water offset; a key of an acknowledged message leaves it within about 1 s; never backed up (D-0031) | Prompt 2 (M2) |
| Sender device at send time | Authorization and rate limits | Memory only, for the request; never stored with the envelope | Prompt 2 (M1) |
| Device-to-account mapping (the device list of each account) | Device-list check on every send | Life of the device | Prompt 2 (M2); owned by Prompt 3 |
| Per-device counters: last `seq` allocated, last `seq` acknowledged | Ordering, delete on ACK, mailbox capacity | Life of the device | Prompt 2 (M2) |
| Shared group/channel bodies (ciphertext) | Store a group message once per partition | As envelope ciphertext | Prompt 2 (M2) |
| Snapshots of every device's last and acknowledged `seq` and every MLS group's epoch, in the Iggy log (sealed with the window's metadata key) | Never reuse a `seq` after old records are deleted | Rewritten by every compaction; old copies unopenable once their window is destroyed and deleted with their segments | Prompt 2 (M2), D-0029, D-0031 |
| MLS group ID (16 opaque client-chosen bytes) and its current epoch | Order commits (one winner per epoch) | Life of the group | Prompt 2 (M2); group membership is Prompt 5 |
| Per MLS group (`grp`): its epoch; its roster (the member devices; their accounts follow from the device lists); OpenMLS's public group state (the ratchet tree: each leaf's device ID, public HPKE and signature keys, capabilities and signatures; the group context; transcript hashes); the current epoch's `GroupInfo`; the hash of the commit that made the epoch. **No group secret, name, avatar, setting or message.** Anyone with the registry can tell which devices share a group | Validate and order handshakes; authorize and fan out group messages; let a device join (D-0065 §2, D-0066, D-0067) | The life of the group (deletion with M2's roles and GDPR) | Prompt 5 (M1); **approved by the owner 2026-11-16** |
| A commit's pending fan-out (`grp_fanout`): the commit and Welcome as uploaded (MLS handshakes: public proposals and keys, and secrets encrypted to the members that the server cannot open) and the recipient device IDs | Deliver an accepted commit even if `api` crashes before the mailboxes stored it | Until every recipient's mailbox stored it: normally milliseconds, at most until a re-drive (seconds) | Prompt 5 (M1), D-0067; **approved by the owner 2026-11-16** |
| Per MLS group, in its context (part of the group state above): the roles extension (the policy, and the accounts whose role is not the default, with their roles: **who the owners, admins and moderators are**) and each roster device's role; a queued `SelfRemove` (who is leaving) until the next commit; a revision counter | Authorize commits, sends, metadata writes and links by role (D-0070); let a member leave | As the group state; a queued proposal until the next commit | Prompt 5 (M2), D-0070; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Per MLS group: the encrypted metadata (name, description, avatar pointer, settings: ciphertext under a key the members share) and its version | Serve it to members and joiners; let permitted roles replace it | Until replaced, or with the group | Prompt 5 (M2), D-0070; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Per MLS group: change-log entries (`grp_log`): ciphertext (≤ 2 KiB) and the committer's signature, keyed by the commit's epoch; the newest 1,000 | Show "View member changes" on devices that join later; the signature lets the server refuse forgeries | The newest 1,000 entries, or with the group | Prompt 5 (M2), D-0070; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Per MLS group, its invite links (`grp_link`): a random handle, `SHA-256(auth)` (never the link's secret, nor the key to the group's info), whether joins need approval, a use count, a limit and an expiry; at most 16 | Let a person holding a link open and join the group, while the link is usable (D-0071) | Until revoked or expired (swept hourly); used-up ones until the group's next link is made; or with the group | Prompt 5 (M3), D-0071; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Per MLS group, its pending join requests (`grp_req`): **the account asking to join**, and when it asked; at most 256 | Let members with the `add` role approve (add) or decline | Until approved, declined, or 7 days | Prompt 5 (M3), D-0071; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Per MLS group, in its context (part of the group state): the delivery service's external-sender public key (one key for every group) with its credential `songbird.v1/ds`; and, until the next commit, the service's queued `Remove` proposals, each naming the leaf of a device that left the directory | Propose removing departed devices' leaves, so they do not outlive the account or the device in group state (D-0075) | As the group state; a proposal until the next commit | Prompt 5 follow-up 1, D-0075; **awaiting the owner's approval** |
| Per MLS group, in its roles extension (part of the group state): each published invite link's handle and its proof public key (Ed25519; the private key comes from the link's secret, which the server never sees); in a join's commit, the proof (the handle and a signature) | Let members check that a joiner held a link they made, and the server apply the same rule (D-0076) | Until the links role withdraws the key, or with the group; the proof with the commit (fan-out) | Prompt 5 follow-up 2, D-0076; the handles were already in `grp_link`; **awaiting the owner's approval** |
| Keyed hash (HMAC-SHA256, key from the requests secret) of a private channel's group ID, with its next allowed post time, in `valkey-hot`; no group or device ID | Hold a channel to one post budget across every node and transport (D-0077) | At most the burst window (about 10 s at the defaults), then expired | Prompt 5 follow-up 3, D-0077; keyed form of the group ID; **awaiting the owner's approval** |
| Prune marks (`grp_prune`): per group holding a device that left the directory, the group ID, **the IDs of its devices that left**, a counter and the time | Let any `api` node propose their removal within seconds (D-0075) | Until proposed (seconds); the device IDs are stripped at the account's or device's final deletion | Prompt 5 follow-up 1, D-0075; **awaiting the owner's approval** |
| Per community (`cmty`, `cmty_grp`): its ID, **which group is its announcement group and which groups belong to it** (opaque IDs; at most 100), and its encrypted info (name, description, picture: ciphertext under a key the members share) with its version | Let the announcement group's admins run the community; show its members the community's groups | Until a group is unlinked or the community deleted | Prompt 5 (M4), D-0072; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Push registration (APNs, FCM or Web Push token / endpoint), **sealed to the push service's X25519 key** and stored under a keyed hash (HMAC-SHA256, push-index secret) of the device ID; `api` and `worker` hold only the public key | Wake an offline device | Until replaced, reported unregistered by the provider, or the device is deleted | Prompt 2 (M5), D-0036; **approved by the owner 2026-11-12** |
| Attachment record: random 32-byte object ID, padded size, expiry, fetches still due; **no link to the uploading account** once uploaded. Before upload, a grant names the uploading device (at most 1 h) | Accept exactly the granted upload; delete after the last fetch or 30 days | Until the last fetch or 30 days; grant at most 1 h | Prompt 2 (M5), D-0036; **approved by the owner 2026-11-12** |
| Attachment ciphertext in RustFS (client-encrypted, opaque), named by the object ID | Relay to recipients | As the attachment record | Prompt 2 (M5); the ciphertext the approved attachment row describes |
| Jobs in `valkey-jobs` (push wake-ups, deletions, cleanups): IDs only, **sealed** (AES-256-GCM-SIV, bound to their stream); the outbox row (account ID) in SurrealDB until relayed | Run background work exactly when needed | Until done (deleted at once); dead letters capped at 100,000 | Prompt 2 (M5), D-0036; sealed form of rows above, **approved by the owner 2026-11-15** |
| Hash of a request's (device, nonce) in `valkey-hot` | Refuse replayed `api` requests | 2 minutes | Prompt 2 (M5), D-0036; hashed form of the device ID, **approved by the owner 2026-11-15** |
| Registry backups off-site (Hetzner Object Storage, Helsinki; a project of its own, D-0042): every registry row above as it was at the export (accounts, devices and their public keys, sealed push registrations, attachment records, grants, outbox, store generation), **age-encrypted** to the owner's offline identity and the verification identity; never the mailbox, its keys or the jobs | Recover accounts after losing the database (RPO 5 minutes) | Write-once: 25 hours (5-minute exports), 8 days (daily), 29 days (weekly), 93 days (monthly). **A deleted account stays in older backups until they expire, at most 93 days**; a restore deletes it again (deletion journal) | Prompt 2 (M6), D-0040; **approved 2026-11-13 under the owner's delegation (D-0041)** |
| Keyed hash (HMAC-SHA256, key derived from the router's cluster secret) of a device that sent through `PUT /v1/messages`, with its next allowed send time, in `valkey-hot`; no device ID | Hold HTTP sends to the WebSocket's rate limit across every `api` node | At most the burst window (4 s at the defaults), then expired | Prompt 2 (send, D-0044); keyed form of the device ID, **approved by the owner 2026-11-14** |
| Server-signed system notices (recipient device, kind, the account whose device list changed, issue time, random notice ID, signature), stored and delivered as mailbox envelopes | Tell a device something only the server knows it must hear (D-0037) | As envelope rows (sealed, deleted at acknowledgement) | Prompt 2 (send, D-0044); data the server already holds (device lists), **approved by the owner 2026-11-14** |
| Account identity public key (Ed25519), with the account's creation time and the number of invites it may still create | Verify the device list (M4) and publish it (key transparency, M6); invite quotas | Life of the account | Prompt 3 (M1), D-0047, D-0048; public key and a count, **approved by the owner 2026-11-15** |
| Invite code: SHA-256 of the code, uses left and expiry; **not who created it, nor who used it** (D-0038: per-user counts only) | Admit registrations in invite-only mode | Until its last use (deleted at once), revocation, or expiry (swept) | Prompt 3 (M1), D-0038, D-0047; **approved by the owner 2026-11-15** |
| Keyed hash (HMAC-SHA256, key from the registration secret) of a client's IP range (IPv4 `/24`, IPv6 `/48`), with the range's next allowed time for challenges, registrations and refused invite codes, in `valkey-hot`; no address | Throttle registration and invite guessing per range | At most the throttle window (about an hour at the defaults), then expired | Prompt 3 (M1), D-0048; keyed form of "connection IPs", **approved by the owner 2026-11-15** |
| A used proof-of-work challenge's random nonce in `valkey-hot` | Single use of each challenge | 10 minutes 10 seconds | Prompt 3 (M1), D-0048; random, identifies nobody, **approved by the owner 2026-11-15** |
| Username hash (Ristretto, D-0049) and the account it names; while held after a release, the hash alone, naming no account. **Anyone who guesses a username can compute its hash**: the hash keeps usernames out of the database in plain text, it does not hide a guessable one | Exact-match lookup; uniqueness | Until changed or released, then held 30 days and swept | Prompt 3 (M2), D-0049; the constitution's "username", in hashed form, **approved by the owner 2026-11-15** |
| Username key verifier: random salt and Argon2id output under a pepper from the secrets store (not in the database or backups) | Answer a lookup only to someone who has the key | Until removed or changed, or with the account | Prompt 3 (M2), D-0049; **approved by the owner 2026-11-15** |
| Username link: a random 16-byte handle, the account, and the link's ciphertext (the key that opens it stays in the link, never sent to the server) | Let a shared link resolve to a username, resettably | Until reset, deleted, the username changes, or with the account | Prompt 3 (M2), D-0049; **approved by the owner 2026-11-15** |
| Keyed hashes (HMAC-SHA256, key from the usernames secret) of an account, an IP range or a username hash, with the next allowed time for lookups, claims and key guesses, in `valkey-hot`; no identifier | Throttle lookups, claims and username-key guessing | At most the throttle window (minutes to about ten hours at the defaults), then expired | Prompt 3 (M2), D-0049; keyed forms of data above, **approved by the owner 2026-11-15** |
| Per device: its identity key (X25519), signed prekey and last-resort ML-KEM-1024 prekey with their signatures, and its one-time X25519 and ML-KEM-1024 prekeys (public keys only) | Let others start sessions with the device (PQXDH) | Identity key for the device's life; signed and last-resort prekeys until replaced; a one-time prekey until one fetch claims it; all with the device | Prompt 3 (M3), D-0050; the constitution's "public keys", **approved by the owner 2026-11-15** |
| Keyed hashes (HMAC-SHA256, key from the key directory's secret) of a requesting account, an IP range, a target account and a device, with the next allowed time for fetches and one-time claims, and a one-hour "notice sent" mark, in `valkey-hot`; no identifier | Limit fetches; stop one-time prekeys being drained; send at most one "prekeys low" notice an hour | At most the throttle window (about an hour at the defaults), then expired | Prompt 3 (M3), D-0050; keyed forms of data above, **approved by the owner 2026-11-15** |
| Per device: its MLS KeyPackages (public HPKE and signature keys, a basic credential holding the device ID, capabilities, lifetime, signatures) and their `KeyPackageRef`s; its last-resort KeyPackage | Let others add the device to MLS groups (Prompt 5) | A single-use package until one fetch claims it or it expires (swept); the last-resort one until replaced; all with the device | Prompt 3 (M3b), D-0051; public keys and the device ID, already listed, **approved by the owner 2026-11-15** |
| Per device, the references (`KeyPackageRef`) of its single-use KeyPackages that were claimed, and the reference of its last-resort one (`mlskp_used`, `device.mlslr_ref`); not who claimed them | Accept in a group commit only KeyPackages their device published (D-0074) | Until the package expires (swept), or with the device | Prompt 5, D-0074; approved by the owner on 2026-11-17 (the Prompt 5 gate) |
| Per account: the signed device list (each device's ID, authentication and identity public keys, which is the primary) with its version; per device: the primary flag, whether it is still pending, and until a list names it a 32-byte link confirmation tag (a MAC under a key the server never sees) | Refuse lists that do not verify or roll back; keep senders to the devices the account vouches for; let the primary check a new device | The list until replaced or with the account; the tag until the device is listed or removed | Prompt 3 (M4), D-0052; public keys and the device list, already listed; **approved by the owner on 2026-11-15** |
| Link token: SHA-256 of a random 32-byte token, the account and the device ID it reserves | Link exactly one new device, once | Until used, or ten minutes (expired ones swept); with the account | Prompt 3 (M4), D-0052; **approved by the owner on 2026-11-15** |
| Provisioning channel in `valkey-hot`: a keyed hash (HMAC-SHA256, key derived from the key directory's secret) of a random channel ID, holding at most one sealed provisioning message (at most 4 KiB, sealed to the new device's key; the server cannot open it); no account or device ID | Carry the QR provisioning message from the primary to the new device | Until read (deleted on read) or ten minutes | Prompt 3 (M4), D-0052; **approved by the owner on 2026-11-15** |
| Keyed hashes (same key) of an IP range or an account, with the next allowed time for channels, channel reads, link attempts, link tokens and list fetches, in `valkey-hot`; no identifier | Throttle provisioning and linking | At most the throttle window (about an hour at the defaults), then expired | Prompt 3 (M4), D-0052; keyed forms of data above; **approved by the owner on 2026-11-15** |
| Two-step PIN verifier: random salt and Argon2id output under a pepper from the secrets store (not in the database or backups); attempts since the last correct PIN and the lock's end | Require the PIN to link a device (and to recover, Prompt 10) without it being guessable from the database | Until removed or replaced, or with the account | Prompt 3 (M4b), D-0053; **approved by the owner on 2026-11-16** |
| Passkeys: credential ID, public key (ES256 or Ed25519), signature counter, registration time | Require a passkey to link a device (and to recover) | Until removed, or with the account | Prompt 3 (M4b), D-0053; **approved by the owner on 2026-11-16** |
| Per account: the encrypted profile and its version, the unidentified-access key (16 bytes derived from the profile key; reveals nothing of it) and whether anyone may send to it sealed; encrypted avatar objects in RustFS with their random IDs and upload times | Serve profiles and avatars to contacts who hold the key; authorize sealed sends | Until replaced (avatars: an hour after replacement) or with the account | Prompt 3 (M5), D-0054; ciphertext and a derived key; **approved by the owner on 2026-11-16** |
| Keyed hashes (HMAC-SHA256, key from the profiles secret) of a requesting account, an IP range or a recipient account, with the next allowed time for profile and avatar fetches and sealed sends, in `valkey-hot`; no identifier | Throttle fetches and sealed sends | At most the throttle window (about an hour), then expired | Prompt 3 (M5), D-0054; keyed forms; **approved by the owner on 2026-11-16** |
| Key transparency directory (`akd`, D-0057): per change, a label (the kind and the account ID, hidden from the tree by the VRF), a value salted per account (HMAC of the identity key's or device list's hash or the username hash; the salt deleted with the account), its version and epoch; akd's tree nodes; per account the salt, the last published values and generations | Let anyone verify what the server vouches for, and detect a server that shows different keys to different people | The directory is append-only and kept for the service's life; a deleted account's salt goes with it, which leaves its entries unlinkable | Prompt 3 (M6), D-0055, D-0057; **approved by the owner on 2026-11-16** (as the log; the move to `akd` stores the same data in akd's form) |
| Per account: last use (a day's precision), the chosen inactivity period and which warnings were sent; a keyed daily "seen" mark in `valkey-hot` (no identifier) | Delete accounts after the inactivity period the user chose, warning twice first | Last use until the next use or the account's deletion; the mark 24 hours | Prompt 3 (M7), D-0056; **approved by the owner on 2026-11-16** |
| Per stored envelope of a send with the disappearing hint: its deadline (store time plus the client's `expire_after_s`) | Never deliver it after the deadline; delete it then even if no device connected | As the envelope row (deleted at the deadline at the latest) | Prompt 4 (M3), D-0061; **approved by the owner 2026-11-16** |
| Franking stamp in front of each franked envelope for another account: the franking key's ID, the sender's commitment (an HMAC of the content under a key the server never sees), the server's stamp time, and a MAC binding them to the sender's and recipient's accounts; **neither account in the clear**. Whoever holds the franking key could test candidate senders against an envelope still undelivered | Let a recipient prove to the server, in a report, who sent what and when (§5.14) | As the envelope row: gone from the server at acknowledgement or expiry; the recipient keeps it | Prompt 4 (M3), D-0061; **approved by the owner 2026-11-16** |
| Block rows: per (blocker, blocked) pair a keyed hash (HMAC-SHA256 under a key derived from the requests secret), a keyed tag of the blocker, the time; per blocker a counter; **no account ID** | Drop message requests from blocked senders (D-0062) | Until unblocked, or the blocker's account is deleted (rows found by its tag, verified gone) | Prompt 4 (M4), D-0062; **approved by the owner 2026-11-16** |
| Per account: whether it refuses message requests (`requests_off`); with its access key and "anyone may send" flag, held in every delivery and `api` node's directory snapshot (memory) | Classify every send without a store round trip; drop requests the account refuses | With the account (snapshot: until the next reload) | Prompt 4 (M4), D-0062; the access key and flag were approved with profiles (D-0054), their use in the send path is new; **approved by the owner 2026-11-16** |
| Keyed hashes (HMAC-SHA256, key from the requests secret) of a sender account, a (sender, recipient) pair or a recipient account, with the next allowed time for requests and broadcasts, in `valkey-hot`; no identifier | Hold message requests and broadcasts to their budgets across every node | At most the budget window (hours at the defaults), then expired | Prompt 4 (M4), D-0062; keyed forms; **approved by the owner 2026-11-16** |
| A report's minimal content, **sealed to the offline moderation key** (X25519, AES-256-GCM): the reason, the reported sender and whether the server attests it, direct or group, the stamp's time, the report's time, and the reported message's content (plaintext the reporter chose to reveal); the row named by a keyed hash of the stamp; **no reporter**. `api` sees the content in memory while verifying | Moderate abuse a recipient reports (D-0063) | 30 days (configurable up to 90), or until a moderator deletes it; in registry backups (sealed) until they expire | Prompt 4 (M5), D-0063; **approved by the owner 2026-11-16** |
| Keyed hashes (HMAC-SHA256, key from the requests secret) of a reporting account, with its next allowed report time, in `valkey-hot`; no identifier | Hold reporting to its budget | At most the budget window (hours), then expired | Prompt 4 (M5), D-0063; keyed form; **approved by the owner 2026-11-16** |
| Deletion journal: per deleted account, an empty tombstone in the backup bucket named by the deletion time and HMAC-SHA256(journal key, account ID); no account ID | A restore must not bring a deleted account back | Write-once, 93 days (the longest backup retention) | Prompt 2 (M6), D-0041; **approved under the owner's delegation** |

Prompt 1 adds two operational views, neither of which is user data on the server:

- **Aggregate metrics** on the private admin endpoint: counts and build information only. Metric
  and label names are checked against the redaction rules (D-0005); no per-device or
  per-connection labels.
- **Proxy operators** (third parties running `songbird-proxy`) see the IP addresses of people who
  connect to their proxy and when, but no content and no Songbird identifiers. This is outside
  Songbird's servers and is stated plainly in `deploy/proxy/README.md`.

## 2. Attackers

- Network attacker
- Malicious client
- Malicious group member
- Compromised server or operator
- Legally compelled provider
- Insider
- Supply-chain attacker

## 3. Components (STRIDE)

One subsection per component. Each threat names its mitigation and the test or proof that covers it.

### 3.1 Build, CI and supply chain (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Malicious or compromised crate | T, E | Supply chain | `Cargo.lock` + `--locked`; cargo-deny (advisories, licences, crates.io only, no OpenSSL), cargo-audit, cargo-vet (imported audits; exemptions listed) | `cargo xtask ci fast`; D-0004 |
| Retagged action or image | T | Supply chain | Actions pinned by commit SHA; images by digest; tool downloads checksum-verified | `cargo xtask workflows` (fails on an unpinned action or an undigested docker action); `.github/workflows/*`, `deploy/bin/install-tools`; D-0007, D-0008, D-0045 |
| Tampered release artifact | T, S | Supply chain, insider | Reproducible build checked twice; cosign keyless signature on `SHA256SUMS`; SLSA provenance and SBOM attestations; signed images; deploy verifies before rollout | `cargo xtask release --verify`; `deploy/bin/verify-release`; D-0013 |
| Workflow token abuse | E | Malicious PR | Default `contents: read`; write scopes only on release/deploy jobs; `persist-credentials: false`; no `pull_request_target` or `workflow_run`; secrets only in `release.yml` and `deploy.yml`, which run only on a pushed tag or by hand; deploy needs environment approval | `cargo xtask workflows` (top-level permissions exactly `contents: read`; forbidden triggers; `secrets.` only in the two privileged workflows); CodeQL `actions` analysis |
| Outside code from a pull request runs on our infrastructure (the repository is public; a fork's pull request runs its own copy of the workflows) | E, T, I | Anyone opening a PR | GitHub-hosted runners only: a fresh VM per job, nothing of ours on it; no self-hosted runner registered for the repository (D-0039 superseded); fork PRs get a read-only token and no secrets; workflow approval for external contributors (repository setting, owner) | `cargo xtask workflows` (rejects self-hosted runners, label lists, expressions, `-latest` and larger runners); D-0045 |
| CI stops or bills because minutes or storage ran out | D | Self-inflicted, PR spam | Standard hosted runners are free for a public repository; larger runners rejected; caches saved on `main` only, artifacts only on failure or 14 days; concurrency cancels superseded PR runs; `cargo xtask ci fast` runs the same checks locally; organization budget $0 with stop usage (owner) | `cargo xtask workflows`; D-0045 |
| Secret committed to the repo | I | Insider (accident) | SOPS-only secrets; config files reject literal secrets; `.gitignore`; Semgrep `p/secrets` | `crates/types/src/secret.rs` tests; CI semgrep job |

### 3.2 Secrets and infrastructure (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Stolen OpenTofu state reveals infrastructure secrets | I | Provider, network | Client-side state and plan encryption; state stored at the other provider | `envs/*/main.tf` `encryption` block (enforced) |
| Exposed internal service | I, T, E | Network | Two firewall layers (provider + nftables default drop); internal ports only from the private range; host networking keeps nftables authoritative | `modules/topology/tests/topology.tftest.hcl`; `nft -c` validation at deploy |
| SSH brute force or key theft | S, E | Network | SSH only on the bastion, only from admin ranges (never 0.0.0.0/0, enforced by validation); keys only, no passwords | topology tests; cloud-init `sshd_config` |
| Lateral movement between services | S, E | Compromised host or component | Mutual TLS with per-component leaves from a name-constrained intermediate; Valkey requires client certificates; RustFS behind an mTLS tunnel (D-0035); containers non-root, read-only, no capabilities | `tools/admin/tests/mtls.rs`; D-0012 |
| Authorization flaw in the object store (RustFS has had 43 published advisories, several in IAM, bucket policy and presigned uploads) | I, T, E | Anyone who reaches the S3 API | Objects are client-side ciphertext; the S3 API listens on loopback only, behind a mutual-TLS tunnel; console, FTP, FTPS, SFTP, WebDAV and the update check disabled; image pinned; advisories tracked and patched | D-0035; `deploy/ansible/roles/data/tasks/main.yml` |
| CA key theft | S | Insider, compromised CI | Root key owner-only and offline; intermediate in deploy secrets, decrypted only into a temporary directory during rotation; leaves ≤ 30 days | `deploy/ansible/rotate-certs.yml`; runbook `mtls-rotation.md` |

### 3.3 Service runtime common to every service (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Personal data in logs (invariant 6) | I | Insider, compromised log store | Redaction layer refuses sensitive field names per callsite; IDs and secrets redact themselves in `Debug`; Semgrep rules; smoke test and rollout fail if any callsite was refused | `crates/telemetry/tests/redaction.rs`; `id.rs`, `secret.rs` tests; `cargo xtask smoke` |
| Logging stalls request handling | D | Load | Non-blocking, lossy writer; drops counted | `songbird_telemetry_log_lines_dropped_total` |
| Admin endpoint abuse | I, D | Network (private) | Private address enforced in staging/production; header timeout, 8 KiB buffer, 32 headers, 64 connections, GET/HEAD only | `admin.rs` tests; `config.rs` tests |
| Malformed configuration or overrides | T, D | Operator error, compromised env | Size bounds before reading; unknown fields rejected; validation of every field; single-line overrides | `config.rs` tests; `config_toml` fuzz target |

### 3.4 Censorship-resistant proxy (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Proxy reads or alters traffic | I, T | Malicious proxy operator | Inner TLS is end to end between app and Songbird server; the proxy only sees ciphertext and the inner SNI | `services/proxy/tests/relay.rs` (nested TLS) |
| Proxy used as an open relay | E | Abuser | Inner-SNI allowlist of Songbird upstreams; anything else closed silently | `refuses_unknown_sni` test |
| Malformed ClientHello crashes or exhausts the proxy | D | Network | Bounded, allocation-free parser; scratch sized by configuration; handshake timeout; connection cap; idle timeout | `sni.rs` property tests; `client_hello` fuzz target; relay tests |
| Proxy identified by probing | I | Censor | Looks like an HTTPS server on the operator's domain (real certificate, ALPN h2/http1.1); non-TLS probes get nothing | `non_tls_probes_get_nothing` test. Residual risk: traffic analysis |
| Users' IPs logged by operator | I | Proxy operator | No logging code; operator compose disables Docker logs; documented honestly | `deploy/proxy/README.md` |
| Malicious proxy link | S, T | Phisher | Strict, bounded link parser; host in the URL fragment; app shows the proxy host before use (Prompt 9 UI requirement) | `link.rs` tests; `proxy_link` fuzz target |

### 3.5 Delivery service (Prompt 2, milestone 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Impersonating a device | S | Network, malicious client | Ed25519 signature over a transcript binding a fresh 32-byte nonce, the server name, the device ID, the protocol version and the TLS session (RFC 9266 exporter); TLS 1.3 | `inv9_server_side_authorization` (unknown device, other server name, replayed signature, wrong key); `tls_connection_works` (signature without this session's binding refused); `vectors.rs` |
| Relaying a device's login through a TLS-terminating man in the middle | S | Network with a misissued certificate, interception proxy | Channel binding: the device signs its own TLS session's exporter, which differs from the attacker's session to the server (D-0024) | `tls_connection_works` |
| Probing which device IDs exist | I | Malicious client | Unknown device and bad signature: same close code, same work (dummy-key verification) | `directory.rs` tests; `inv9_server_side_authorization` |
| Reading or deleting another device's mailbox | I, T, E | Malicious client | Every mailbox operation uses the authenticated device only; ACKs beyond what was sent close the connection | `inv3_delete_on_ack_and_expiry`; session code review |
| Sending to devices that do not exist, or one device twice | T | Malicious client | Recipients checked against the directory; duplicates refused; nothing stored on rejection | `inv9_server_side_authorization` |
| Memory exhaustion by large or malformed input | D | Malicious client | Limits checked before allocation; WebSocket layer refuses oversize frames from the header; upgrade request ≤ 8 KiB; fuzzed decoders | `inv7_bounded_and_validated_input`; `frame.rs` property tests; `proto_*` fuzz targets; Autobahn |
| Connection or reconnect floods | D | Botnet, reconnect storm | Accept-rate token bucket and connection cap (close 4101 with retry hint); handshake and auth timeouts; jittered client backoff | `accept_rate_limit_closes_with_retry_hint`; reconnect storm in the load generator |
| Frame or send floods from one connection | D | Malicious client | Per-connection token buckets: frames (close 4103), sends (rejected), ephemeral (dropped) | `bucket.rs` tests; session code |
| A slow or stalled reader holding others back, or server memory | D | Malicious or broken client | Bounded inboxes, non-blocking routing with lag flag and mailbox drain; at most 256 envelopes in flight per connection; write-progress timeout closes 4100 | `inv5_slow_client_never_slows_anyone_else`; `unacked_window_bounds_in_flight`; D-0020, D-0024 |
| Suppressing another send by reusing its idempotency key | T | Party that learned a key | Keys are 128 random bits seen only by sender and server (TLS); records are scoped to the recipient set by a fingerprint (reuse for others is refused, reason 7, where the sends share a partition; elsewhere it is stored as a new send, never suppressed) and kept 6 h under a keyed hash | `retried_send_is_stored_once` |
| Losing, duplicating or reordering messages | T | Faults, races | Store before acknowledge; per-device `seq`; attach before drain; cursor rule; idempotency keys; client dedupe by `seq` | `ordering.rs` property test; `inv1`, `inv2`, `inv8`; load-generator checker (steady and reconnect storm) |
| Identifiers or content in logs and metrics | I | Insider, log store | No per-device log fields; IDs and frames redact themselves in `Debug`; aggregate counters only | `inv6_no_identifiers_in_logs_or_metrics`; `frame.rs` `debug_output_hides_identifiers` |
| Bugs in the WebSocket library | T, D | Supply chain, malicious client | Pinned version; Autobahn in CI; our own upgrade and limits; vet exemption recorded for audit | `cargo xtask autobahn`; D-0017, D-0023 |
| Losing an acknowledged send (crash, power loss) | T | Faults | Iggy topic `durability = persisted` (fsync before it confirms); `SendResult` only after that; a send's remote parts recorded in its home record and completed by the re-driver | D-0029; `inv1_store_before_acknowledge` on Iggy; `redriver_completes_remote_parts_in_process_and_after_restart` |
| Reused or skipped `seq` with several writers | T | Faults, races, a second node | One writer per partition; Iggy fences older producer epochs; uncertain appends resent with the same producer sequence; counter snapshots before old records are deleted | `restart_rebuilds_state_and_fences_the_old_writer`; `compaction_relocates_and_keeps_counters_across_restart`; `concurrent_senders_get_gap_free_unique_seqs`; D-0029 |
| Racing MLS commits forking a group | T | Malicious or racing members | Epoch check on the group's home partition writer, recorded with the commit; one winner | `mls_commits_are_ordered_by_epoch` (Iggy and SurrealDB); `send_path_device_lists_shared_bodies_and_mls_ordering` |
| Malformed mailbox records read back from Iggy | T, D | Compromised data host, bugs | Bounded record decoder (counts checked against remaining bytes), fuzzed; every record authenticated (AES-GCM, bound to partition, window and slot); an unreadable record stops the start rather than reuse `seq`s | `record.rs`, `sealed.rs` tests; `iggy_record` fuzz target; `start_up_refuses_an_unreadable_log` |
| Reading delivered messages from the server's disk (seized or stolen server, backups, insider, later compromise) | I | Insider, attacker on the data host, legal seizure | Every entry sealed under its own puncturable key; the key destroyed at acknowledgement and the key store rewritten within about 1 s; segments deleted within minutes; key store never backed up; master key from the secrets store (D-0031) | `acknowledged_messages_cannot_be_decrypted_even_with_every_key` (opens every record with every key on disk); `compaction_destroys_old_windows` |
| A lost or rolled-back key-store page making pending messages look acknowledged | T | Faults, operator error, tampering | Copy-on-write key store; the head lists every page with its generation and key count; a missing, misplaced or altered page stops the start (runbook) | `start_up_refuses_a_lost_key_page`; key-store unit tests |
| An older writer overwriting the key store | T | A second delivery process, a stale node | The new writer writes the key store with its epoch before appending; older epochs are refused; writes serialised | `an_older_writer_cannot_overwrite_a_newer_one`; `restart_rebuilds_state_and_fences_the_old_writer` |
| Two messages sealed under one key (AES-GCM nonce reuse; one ACK destroying another message) | T, I | Faults (crash, restart, takeover) | Each slot used once: replay marks every replayed record's slots used; a new writer seals in a fresh random window | `a_restart_never_reuses_key_slots`; `replayed_records_move_the_next_slot` |
| Valkey (routing) learning who talks to whom, or reading routed envelopes | I | Insider, attacker on the Valkey host, a Valkey bug | Channel names are keyed hashes of device IDs (HMAC, cluster secret); every routed payload sealed (AES-256-GCM-SIV) and bound to its channel and kind; TLS with client certificates in deployments (D-0034) | `valkey_sees_neither_device_ids_nor_content`; `sealed_payloads_open_only_on_their_channel_kind_and_key` |
| Disconnecting devices by replaying captured `close` messages | D | Attacker who recorded Valkey traffic | A `close` older than 30 s is ignored; payloads authenticated | router unit tests; D-0034 |
| Another internal service (API, push) reading or writing mailboxes over node links | I, T, E | Compromised internal service holding an internal-CA certificate | Node links need mutual TLS from the internal CA and a peer name its certificate is valid for; each admitted prefix has its own handler: `delivery.` every operation, `api.` (only when listed in `[delivery.cluster] senders`, D-0044) the store of a send and nothing else; any other prefix is refused at the handshake | `other_components_and_other_cas_are_refused`; `each_admitted_kind_of_peer_gets_only_its_own_handler`; `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else`; `the_client_refuses_a_server_with_another_name` |
| Two nodes writing one partition (seq reuse, key-store clobbering) | T | Network partition, Valkey loss, a slow node | Leases in Valkey with compare-and-set renewal; Iggy producer epochs fence a stale writer; key stores fenced by epoch; a lost lease is taken back without a restart, a lease taken by another node stops the writer | `leases_lost_with_valkey_are_taken_back_without_restarting`; `the_standby_takes_over_without_losing_anything`; `restart_rebuilds_state_and_fences_the_old_writer` |
| A node's death losing its pending messages | T | Host failure, two at once, a zone | Each partition's key store copied to two standby nodes, the second in another zone (full copy when a standby changes, then every write); a key window seals records only once a standby holds its keys; the first live standby takes the lease when it expires | `the_standby_takes_over_without_losing_anything`; `two_nodes_can_die_at_once`; `a_window_seals_nothing_before_a_standby_holds_its_keys`; chaos run in report P02-M4 |
| Deleted keys lingering on a node that no longer needs them | I | Placement changes, a standby that missed punctures | A full copy deletes the page files it does not list; a node that stops being a standby deletes its copy after three lease periods; a stopped node serves no link requests | `a_standby_follows_its_owner_and_drops_what_a_full_copy_no_longer_lists`; `a_stopped_server_serves_nothing_more_even_on_open_connections` |
| Third-party client logs leaking addresses | I | Log store | Iggy SDK log targets forced off in every filter | `inv6_no_identifiers_in_logs_or_metrics` (TRACE through the production filter); D-0030 |
| A container escape through io_uring | E | Attacker who compromised Iggy | Iggy's seccomp profile adds only the three io_uring syscalls to Docker's default; `no-new-privileges`, all capabilities dropped; private address only | `deploy/compose/iggy-seccomp.json`; D-0029 |
| Malformed SurrealDB responses | T, D | Compromised database, network | Bounded CBOR decoder (depth, lengths before allocation), fuzzed; TLS with the internal CA outside development | `cbor.rs` tests; `surreal_cbor` fuzz target |
| A compromised database reads metadata | I | Insider, attacker on the data host | Holds only ciphertext and the metadata listed in §1; idempotency keys only as keyed hashes; no sender stored with envelopes | §1; D-0024 |

### 3.5.1 Delivery at scale (Prompt 2, milestone 7)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Exhausting memory with many idle connections | D | Botnet, a client opening sockets and never sending | About 33 KiB per idle TLS connection (measured); connection cap (100,000: about 3.3 GB) and accept-rate limit per core; handshake and authentication deadlines (5 s each) drop unauthenticated sockets | `loadgen --scenario idle` (32.5 KiB per connection at 30,000, P02-M7); `bench/m7/suite.sh` |
| A reconnect storm after an outage melting the node | D | Every client at once (an outage, a network flap) | Per-core accept-rate token buckets with retry hints in the close; clients back off with jitter; sessions resume their mailbox position, so nothing is lost or re-sent | `loadgen --scenario storm` at the beta's size: checker PASS, recovery time in P02-M7 |
| Linking a device's sessions through TLS resumption | I | Network observer | TLS 1.3 resumption tickets are encrypted by the server and change with each issue; the device authenticates again inside every session (channel binding, D-0018), so a resumed session proves nothing by itself | rustls defaults (aws-lc-rs ticketer, rotating keys); `services/delivery/src/server.rs` |
| A benchmark build reaching production | T | Operator error | The system-allocator switch is a cargo feature off by default; release builds and images never enable it | `services/delivery/Cargo.toml`; `cargo xtask release` builds default features |

### 3.5.2 The send path shared by `delivery` and `api` (Prompt 2, D-0037, D-0044)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| A compromised `api` reading, acknowledging or forgetting messages, or touching key stores, over node links | I, T, E | Attacker on an `api` host (internet-facing, holds an `api.` certificate) | Owners admit `api.` peers to a store-only handler: fetch, ACK, count, expire, forget, known, part-done and key-store copies are refused and counted; `api` runs no Iggy client, holds no key store or master key, takes no lease | `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else`; `each_admitted_kind_of_peer_gets_only_its_own_handler` |
| A compromised `api` marking another send's remote part stored before it is (losing that part) | T | Attacker on an `api` host | `PartDone` refused from senders; the home partition's re-driver completes a sender's multi-partition bookkeeping (finds the part stored, punctures its slot) | `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else`; `redriver_completes_remote_parts_in_process_and_after_restart` |
| A compromised `api` injecting envelopes into mailboxes | T, D | Attacker on an `api` host | Envelopes are end-to-end ciphertext: recipients drop what they cannot authenticate; system notices need the system key, which `api` does not hold; per-device mailbox capacity bounds the damage; refused requests alert (runbook) | Residual risk, stated in §6; same capability a compromised delivery node has |
| A user forging a system notice ("your device list changed") | S, T | Malicious client | Reserved format: user envelopes beginning with the system-frame magic are refused (reason 9) over WebSocket and HTTP; notices are signed (Ed25519, domain-separated) and apps pin the key | `user_envelopes_in_the_system_frame_format_are_refused`; `a_system_notice_reaches_the_device_signed_and_a_forged_one_never_does` |
| Replaying a captured notice to another device, or again | S, T | Network, malicious client, insider | The recipient device, issue time and a random notice ID are inside the signed bytes; apps drop a notice for another device or a repeated ID; the notice ID is the send's idempotency key (stored once) | `system_notices_are_signed_per_device_stored_once_and_verify`; `system_frames_round_trip_and_sign_everything_but_the_signature` |
| Malformed system frames crashing a client | D | Malicious server-side insider, bugs | Bounded decoder (body ≤ 1024 bytes, lengths checked before slicing, trailing bytes refused), property-tested; nothing trusted before the signature verifies | `malformed_system_frames_are_refused`; `decoder_never_panics` |
| Making `api` buffer large bodies without authenticating | D | Anyone on the internet | `Content-Length` required and at most `max_send_bytes` before anything; the signature (over the declared digest) verified from the headers before the body is read; the body then held to the declared length and digest | `put_messages_is_signed_and_authenticated_before_the_body_is_read` |
| Forged or replayed HTTP sends | S, T | Network, malicious client | Same signing as every `api` request (device key, time ±60 s, single-use nonce, path, body digest); a disabled or unknown device fails alike | `put_messages_is_signed_and_authenticated_before_the_body_is_read` |
| Flooding sends through HTTP to escape the WebSocket's limits | D | Malicious client | Same frame limits (one `LimitsConfig`) and the same per-device rate, counted in `valkey-hot` across every `api` node on Valkey's clock (GCRA); the limiter fails closed | `put_messages_holds_the_send_frame_to_the_websocket_limits_and_rate`; runbook "`PUT /v1/messages` refusing sends" |
| A retry over the other transport stored twice | T | Faults (a socket dies after the HTTP attempt, or the reverse) | One idempotency tag: `api` uses the delivery nodes' secret and the owners' own store routine; a retry in either order is a replay | `a_send_retried_over_the_websocket_after_http_is_stored_once`; `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else` |
| The extraction changing the hot path's behaviour or cost | T, D | Regression | `delivery` calls the same library in the same order (store, `SendResult`, route, one flush); borrows only (no shared reference count per send); the M3 allocation gate (5.20 per message, budget 5.5) and every invariant test unchanged | `server_allocations_per_message_stay_within_budget`; `tests/e2e/tests/invariants.rs`; M7 suite against its VM baseline (report P02-send) |

### 3.6 Jobs, push, api, worker (Prompt 2, milestone 5)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| The persistent job queue records who was messaged when | I | Insider, attacker on the Valkey host, its AOF or backups | Jobs carry IDs only and are sealed (AES-256-GCM-SIV under the jobs secret, bound to the stream); done jobs are `XDEL`eted | `sealed_jobs_reveal_no_ids_and_open_only_on_their_stream_and_key`; `jobs_are_sealed_delivered_once_and_deleted_when_done`; gate `account_deletion_is_verified_across_every_store` (raw dump of both Valkeys) |
| Forged or moved jobs | T | Attacker with Valkey access | AEAD: a tampered job, or one moved to another stream, does not open and is dead-lettered unrun | `garbage_in_a_stream_is_dead_lettered_not_run` |
| A poison job crashing every consumer | D | Bug, malformed data | Delivery count from `XPENDING`; dead-lettered after `max_deliveries`; capped dead-letter stream counted for alerting | `a_dead_consumers_jobs_are_reclaimed_and_poison_jobs_dead_lettered` |
| Push tokens leaking from the database, `api` or `worker` | I | Insider, database theft, compromised `api` | Sealed to the push service's X25519 key (`api`, `worker` hold only the public key); keyed-hash row IDs; a token sealed for one row does not open on another | `only_the_push_key_opens_and_only_on_its_row`; `push_registration_is_sealed_and_requests_are_authenticated` |
| Apple, Google or a distributor learning who talks to whom | I | Push provider, legal compulsion of a provider | Every push identical: constant alert text (APNs `mutable-content`), empty FCM data, constant encrypted Web Push body; constant collapse IDs; no identifiers, counts or content; one wake-up per burst | `an_offline_device_receives_a_push_end_to_end` (no ID in path, headers or body); push-providers tests |
| SSRF through a Web Push endpoint | E, I | Malicious client | https, port 443, no private, loopback, link-local or embedded-IPv4 addresses (checked after resolution), no redirects | push-providers `webpush` tests |
| Push credentials outside the push service | I | Compromise of another service | APNs, FCM and VAPID keys exist only in `push`'s configuration and process | config structs (`api`, `worker`, `delivery` have no such fields); D-0036 |
| Replaying or forging `api` requests | S, T | Network, malicious client, log reader | No bearer tokens: each request signed (Ed25519, device key) over server name, method, path, time, nonce and body digest; ±60 s; nonces single-use; unknown, disabled and forged requests fail alike | `signatures_bind_every_field`; `push_registration_is_sealed_and_requests_are_authenticated` (replay, wrong path, swapped body, stranger) |
| Storage exhaustion or overwrite through uploads | D, T | Malicious client | Grants fix an exact size (bounded) and are single-use and device-bound; the upload must match the length exactly; object names random | `attachments_upload_exactly_and_go_after_the_last_fetch` |
| An attachment outliving its purpose | I | Insider, later compromise | Deleted after the last recipient fetch (counted when the last byte is sent) or 30 days; expired grants and their partial objects swept | `attachments_upload_exactly_and_go_after_the_last_fetch`; worker sweep |
| A deleted account surviving in some store | I | Insider, legal request, the user's own GDPR right | Outbox job written with the deletion; worker forgets mailboxes (keys punctured, counters dropped, `Forget` record replayed on restart), closes sessions everywhere, deletes push tokens, grants and objects, repeats after directory propagation, then verifies mailbox, object store and registry before finishing (else retried, then dead-lettered) | gate `account_deletion_is_verified_across_every_store`; `forgotten_devices_leave_nothing_readable_and_no_counters` (Iggy) |
| A compromised internal service deleting other users' data | E | Compromised `api`, `push` | The device link accepts only `worker.` certificates and only Forget/Known; `api` deletes only the authenticated device's own account | `songbird_link` identity tests; `services/delivery/src/internal.rs` |

### 3.7 Backups and restore (Prompt 2, milestone 6)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| The backup provider, a thief of its disks or a legal request reads the registry | I | Storage provider, legal compulsion of the provider | age encryption before upload (the plaintext export is piped into `age` and never touches disk); the two identities that decrypt are offline (owner) or on a host outside production (verification) | `bench/m6/backup-cycle.sh` (no plaintext marker in stored files; a third identity cannot decrypt) |
| A compromised production server reads old backups (deleted accounts) | I | Attacker on the data host | Its key lives in a project with no buckets and the bucket policy grants it only `PutObject`/`PutObjectRetention` under `registry/`; it holds no identity that decrypts | `backups-policy selftest` (a widened writer fails it); `backups-up <env> check` proves Hetzner enforces it with each key before the bucket is used |
| Ransomware or a compromised server destroys the backups | D, T | Attacker on any production host, a rogue operator | Object Lock in compliance mode (nobody can shorten a retention, the owner included), versioned bucket, writer cannot delete; bucket administration only with the backups project's admin key, held by the owner, not the deploy pipeline; console Protection on | `locked_objects_cannot_be_deleted_and_checksums_are_checked` (RustFS); `backups-up <env> check` (even the admin key cannot delete a locked version) |
| A forged backup restored: an attacker with the put-only key writes a backup of their own (the recipients are public keys) over an older name, adding devices to impersonate users | S, T | Attacker on the data host | Restores read the **first** stored version of each name, chosen by the server's `LastModified`; a name written twice or a misdated backup counts as tampering: verification fails, restore warns and audit-logs; `--before` restores from before a compromise | `an_overwritten_backup_is_never_restored_and_verify_reports_it` (RustFS, SurrealDB, age); `restores_read_the_earliest_version_and_skip_forgeries` |
| A corrupted or truncated backup goes unnoticed until it is needed | T, D | Bug, storage fault | SHA-256 checked by the server at upload (`x-amz-checksum-sha256`); age's authenticated encryption; daily restore into a throwaway database with consistency checks; a backup older than 1 hour fails verification | `bench/m6/backup-cycle.sh` (an orphaned device fails verification); `songbird-backup-verify` |
| An operator restores over a live registry, or the wrong one | T, D | Operator error | `--confirm <namespace>/<database>`; restore only into an empty database; append-only audit log written before and after (fails closed) | `a_missing_or_wrong_confirmation_is_refused_and_logs_nothing`; `an_unwritable_log_stops_the_action`; `bench/m6/backup-cycle.sh` |
| Messages lost with the mailbox (never backed up) | D | Disaster, operator error | Store generation bumped by every restore; clients resend everything without an end-to-end delivery receipt with the original idempotency keys; recipients drop repeats | `a_lost_mailbox_is_refilled_by_senders`, `a_surviving_mailbox_stores_nothing_twice` (Iggy in CI); `bench/m6/restore-drill.sh` (checker PASS; without resend 11,581 lost) |
| A restore brings back accounts deleted after the backup (erasure undone) | I | Disaster, operator error | Deletion journal: the worker writes a write-once tombstone before deleting anything (required in staging and production); a restore refuses to start without the journal key and re-deletes, through the outbox, every restored account with a tombstone | `a_deletion_after_the_backup_survives_the_restore`; `account_deletion_is_verified_across_every_store` (tombstone present, no identifier in it) |
| Forged tombstones delete accounts at the next restore | T, D | Attacker holding the worker's journal key | Its credential can only put under `deletions/`; after a compromise the restore uses `--before`, which applies to tombstones too; a deletion goes through the outbox and the audit log records how many | `backups-policy selftest`; `backups-up <env> check`; D-0041 |
| The backup timer's database user writes to the registry | E | Attacker on the data host using the backup credential | A database user with the `VIEWER` role (export and read only) | Checked by hand against SurrealDB 4.0.1 (a `CREATE` as that user is refused); `deploy/ansible/roles/backup` |

### 3.8 Registration and invites (Prompt 3, milestone 1)

Account takeover, enumeration and key substitution are the Prompt 3 gate's three threat classes;
this milestone adds the registration-time rows of each. Later milestones add device linking (M4),
the key directory (M3) and key transparency (M6).

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **Takeover by squatting an ID**: registering with an account or device ID chosen to collide with someone's | S | Malicious client | The server draws both IDs (16 random bytes); the request carries none | `registration_creates_the_account_its_device_and_bumps_the_directory` (taken IDs refused, server redraws) |
| **Takeover by a key that verifies anything**: an identity or authentication key of small order (under the identity point, `R = sB` verifies every message), or with a torsion component; aws-lc-rs alone accepts such a forgery | S, E | Malicious client, then anyone | Every registered key must be the canonical encoding of a prime-order point (`songbird-keys`), before any signature is checked; the admin link refuses them too | `every_small_order_point_is_refused` (asserts aws-lc-rs alone accepts the forgery), `mixed_order_and_non_canonical_encodings_are_refused`, `keys_must_be_distinct_honest_and_signed_for_this_server`; fuzz `ed25519_key` |
| **Key substitution at registration**: a relay swaps the identity or authentication key, or replays signatures into another registration | T, S | Network attacker, malicious relay | Both keys sign one transcript naming the server, the single-use challenge and both keys, under different contexts; TLS | `keys_must_be_distinct_honest_and_signed_for_this_server` (swapped signatures, another server's name refused); `transcripts_differ_by_context_and_refuse_bad_names`; vector in PROTOCOL.md §13 |
| Mass registration (spam accounts, Sybil) | D, E | Botnet | Invite-only mode (launch); Argon2id proof of work per registration (memory-hard, 16 MiB); per-range and deployment-wide throttles; per-account invite quotas | `challenges_and_registrations_are_throttled_per_range`; `user_invites_spend_a_quota_and_can_be_revoked`; D-0048 timing |
| **Invite code guessing** | E | Anyone | 120-bit codes; a guess costs a solved challenge; refused codes spend a per-range (10/h, burst 5) and a deployment-wide (600/h) budget, after which the range waits before any work is checked | `guessing_codes_is_throttled_before_any_work`; `invite_codes_valid_expired_reused_and_guessed` |
| A code used more often than allowed (race) | T, E | Malicious client | One transaction consumes the use and creates the account; concurrent redemptions write the same row, so SurrealDB commits one and the others retry and find it used | `racing_registrations_never_exceed_a_codes_uses` (24 racing registrations for 1 and 5 uses) |
| **Enumeration through invite answers**: telling unknown, expired, used-up and revoked codes apart | I | Anyone | One answer (`403 invite`) for all; revocation answers `204` whether or not the code existed | `invite_codes_valid_expired_reused_and_guessed`; `user_invites_spend_a_quota_and_can_be_revoked` |
| The invite system records the social graph | I | Compromised server, legal compulsion | Nothing links a code to its creator or its user: rows hold uses and expiry only and go at the last use; allowances are counts (owner's decision, D-0047) | `user_invites_spend_the_allowance_and_record_no_issuer` (the row's fields are exactly `expires`, `id`, `uses`) |
| Challenge replay or forgery; work skipped | S, E | Malicious client | Stateless MAC'd challenges with a 10-minute life; the nonce is burnt before the work is verified; strictly increasing solutions | `challenges_are_authenticated_single_use_and_must_be_solved`; `forged_expired_and_malformed_challenges_are_refused`; fuzz `pow_challenge` |
| Verification as a denial-of-service lever | D | Botnet | Throttles first; tag, age, keys and signatures before any Argon2id; the nonce burnt first, so a forged solution costs at most one evaluation per issued challenge; verifications off the runtime and bounded (half the cores) | `challenges_are_authenticated_single_use_and_must_be_solved` (a wrong solution spends the challenge) |
| Unauthenticated connections turned into database queries (looking a just-registered device up on demand) | D | Anyone | Delivery never queries the registry for an unauthenticated connection; new clients retry 4000 for 10 s instead (§4.1) | `registered_accounts_connect_and_talk_without_an_operator` (client grace, and a stranger still stops) |
| A malformed request crashes or exhausts `api` | D | Anyone | `Content-Length` required and at most 518 bytes before reading; strict decoder with fixed fields; fuzzed | `requests_round_trip_and_decode_strictly`, `decoding_never_panics`; fuzz `registration_request` |

### 3.9 Usernames, the username key and links (Prompt 3, milestone 2)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **Enumeration by lookup**: confirming who is on Songbird by trying names | I | Anyone with an account | Exact match only (no search, prefix, listing); lookups signed (an account, scarce while invite-only) and throttled per account and per IP range; the optional username key | `lookups_and_claims_are_throttled`; `unique_claims_reserved_names_proofs_and_holds` (a prefix is not found) |
| **Enumeration through answers or timing** when a username key is set | I | Anyone with an account | One answer (404) for unknown, held, key missing, key wrong, budget spent; the registry reads the same rows either way; a keyed lookup always runs one Argon2id check and touches the guessing budget, an unkeyed one never does | `the_username_key_answers_not_found_to_strangers_without_it` (identical answers; key checks counted: unchanged without a key, one per keyed lookup whatever the case); `keyed_lookups_take_the_same_time_whether_or_not_the_username_exists` (ratio 0.995 on the Mac) |
| **Guessing a username key** | I, E | Anyone, with many accounts | 4 to 10 digits; key guesses that find nothing limited per username across all requesters (more accounts give no more guesses), 1 an hour, burst 10, checked and spent in one atomic step | `the_username_key_answers_not_found_to_strangers_without_it` (the right key refused once the budget is spent) |
| Offline key search from a stolen database or backup | I | Database or backup thief | Argon2id with a salt and a pepper held only in the secrets store; a compromised `api` can search (accepted: the key gates finding someone by username, nothing else) | `Usernames::new` (pepper by HKDF from the secret); D-0049 |
| **Impersonation by a recycled username**: grabbing a name right after its owner changes it | S | Anyone | A released username is held 30 days, claimable and findable by nobody; key transparency (M6) and the key-change notice show a new identity behind a known name | `usernames_are_unique_held_after_release_and_swept`; `unique_claims_reserved_names_proofs_and_holds` |
| Impersonation of the service | S | Anyone | Reserved names (built in and configured), compared by hash | `unique_claims_reserved_names_proofs_and_holds` (`admin`, `Support`, a configured name: taken) |
| Look-alike usernames from other scripts | S | Anyone | ASCII only; unique in lower case | `rules` (a Cyrillic `а` is refused); `case_does_not_change_the_hash_but_display_keeps_it` |
| **Key substitution at claim**: registering someone else's hash, or a point that is no username's | T, S | Malicious client | A poksho proof of knowledge of the scalar behind the hash, checked on every claim; canonical encodings only, the identity point refused | `proofs_verify_and_tampering_does_not`; `unique_claims_reserved_names_proofs_and_holds` (forged proof: 400); fuzz `username` |
| Two accounts holding one username (race) | T | Malicious client | One transaction checks and writes the username row; concurrent claims conflict and retry | `racing_claims_for_one_username_give_it_to_one_account` (16 racing accounts, one winner) |
| Squatting names | D | Botnet | Invite-only registration; claims throttled per account, every attempt counted; held names expire | `lookups_and_claims_are_throttled` |
| A dictionary attack on the stored hashes | I | Database thief, compromised server | Inherent: clients must compute hashes from names alone, so they cannot be salted. Recorded, not mitigated: a guessable username is found by guessing (D-0049) | D-0049 |
| A link reveals the username to the server or a link host | I | Compromised server | The server stores ciphertext under a random handle; the key stays in the link; a reset gives a new handle | `links_reset_and_need_a_username` |
| Spending someone's guessing budget so their username stops resolving with the key | D | Anyone with an account | Accepted: for at most about ten hours; links and QR codes still work | D-0049 |

### 3.10 The key directory (Prompt 3, milestone 3)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **One one-time prekey served to two senders** (both sessions' first messages then share it) | T, I | Concurrent requesters, a race | Each claim deletes one record and returns what it deleted; concurrent claims on one record conflict and retry; random choice among candidates keeps collisions rare | **The gate**: `no_one_time_prekey_is_ever_served_twice_under_parallel_claims` (400 claims, 8 connections, 3 rounds: 200 distinct of each kind served, none twice, none lost); a deliberately non-atomic claim makes it fail at once |
| **Key substitution by a malicious uploader or relay**: prekeys not made by the device's identity key | S, T | Malicious client, network attacker | Every signed prekey and every ML-KEM prekey verified with XEdDSA against the device identity key before storing; canonical `s` only (no malleable second encoding); clients verify again before PQXDH | `honest_uploads_pass_and_every_kind_of_tampering_is_refused`; `bad_keys_signatures_identity_changes_and_overflow_are_refused`; XEdDSA cross-checked with libsignal both ways (`xeddsa_vectors.rs`) |
| **Identity key replaced** under an existing device, so senders encrypt to an attacker's key | S | Compromised device credential, malicious client | The identity key is set once per device and never replaced (409); a new identity is a new device (signed device list, M4; key transparency, M6) | `uploads_keep_the_identity_bound_the_store_and_refuse_duplicates`; `bad_keys_signatures_identity_changes_and_overflow_are_refused` |
| Dishonest public keys (small or mixed order, non-canonical, on the twist) that weaken or break the X25519 agreement | T | Malicious client | Every X25519 key checked: canonical `u`, on the curve, prime order | `dishonest_public_keys_are_refused`; fuzz `prekeys` |
| Malformed ML-KEM keys (coefficients ≥ q) that FIPS 203 says must be rejected; aws-lc-rs 1.19 alone accepts them | T | Malicious client | Explicit modulus check on every ML-KEM key; type `0x0A` only | `a_coefficient_at_or_above_q_is_refused` (asserts aws-lc-rs alone accepts it) |
| **Prekey exhaustion**: draining a target's one-time keys so its sessions start without them | D | Anyone with an account | Fetches limited per requesting account and per IP range; one-time claims limited per target across all requesters, after which fetches get last-resort keys only and the one-time keys remain; refill notices | `a_targets_one_time_keys_cannot_be_drained_and_fetchers_are_throttled`; `a_device_low_on_prekeys_is_told_once` |
| A forged "prekeys low" notice | S | Malicious client | System notices are signed by the system key in a reserved format a user envelope may not take (D-0044) | `a_device_low_on_prekeys_is_told_once` (signature verified); `a_system_notice_reaches_the_device_signed_and_a_forged_one_never_does` |
| Storage exhaustion by uploads | D | Malicious client | At most 100 keys of each kind per upload and 200 stored per device; body length bounded and authenticated before it is read | `uploads_round_trip_and_decode_strictly`; `bad_keys_signatures_identity_changes_and_overflow_are_refused` |
| A deleted account's prekeys outlive it | I | Compromised server later | Deletion removes every one-time prekey row of the account's devices; the worker's verification counts them | `bundles_claim_one_time_keys_skip_the_requester_and_fall_back_to_last_resort` (remnants empty) |

### 3.11 MLS KeyPackages (Prompt 3, milestone 3b)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **A device publishes KeyPackages claiming to be another device**, so a group adds an attacker under that device's name | S | Malicious client | The credential's identity must be the uploading (authenticated) device's ID; both signatures verified with the package's own signature key | `tampering_is_refused_with_its_reason` (another device: identity); `key_packages_for_another_device_or_out_of_date_are_refused` |
| A single-use KeyPackage handed to two adders (two groups share one init key) | T, I | Concurrent requesters | Claims delete exactly one record each, as for prekeys | `no_key_package_is_ever_served_twice_under_parallel_claims` (400 claims, 8 connections, 2 rounds) |
| Malformed, weak or stale packages published (parser differentials, weak keys, a ciphersuite clients refuse, expired packages) | T | Malicious client | Strict RFC 9420 parse; allow-listed ciphersuites; honest X25519 and Ed25519 keys, init key ≠ encryption key; lifetime current and bounded; expired packages never served | `openmls_packages_pass_with_openmls_references` (OpenMLS's own packages pass with OpenMLS's references; P-256 refused); `tampering_is_refused_with_its_reason` (every flipped byte refused); fuzz `keypackages` |
| KeyPackage exhaustion | D | Anyone with an account | The prekey throttles and per-target budget, counted separately; last-resort fall-back; refill notices | `key_packages_are_bound_to_their_device_and_served_once` |
| The server parser and clients disagree on what a package is | T | Malicious client | Clients validate fully (RFC 9420 §10.1); the server's checks are a strict subset proven against OpenMLS's encodings | `tools/openmls-vectors`; D-0051 |

### 3.12 Devices: linking and the signed device list (Prompt 3, milestone 4)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **The server (or anyone who sees a link request) links keys of its own** as the user's new device | S | Malicious or compromised server, network | The new device proves its keys with a MAC under a confirmation key that travelled only inside the sealed provisioning message; the primary checks it before signing a list; until listed, the device gets no messages and its keys are not served | `the_confirmation_tag_verifies_with_the_real_transcript` (another identity key fails); `pending_devices_get_no_key_fetches`; `a_linked_device_is_announced_and_joins_the_send_check_only_once_listed` |
| **Account takeover by linking**: an attacker links a device without the primary | S, E | Anyone, a malicious client | A link needs a single-use token only the account's primary can obtain (hash stored; ten minutes; bound to a server-chosen device ID); both new keys proven over a transcript binding token, device and server; per-range throttle; the primary is told by a signed notice | `link_tokens_are_single_use_bound_to_their_device_and_only_for_the_primary`; `bad_link_proofs_limits_and_self_removal`; `link_requests_need_both_proofs_over_this_server`; `channels_and_links_are_throttled_per_range` |
| **A forged or rolled-back device list** adds a device or brings back a removed one | S, T | Malicious server, malicious client | Lists signed by the account identity key, checked by the server (and by clients, which keep the highest version seen); versions only grow; every entry must match an enabled device's stored keys; removed devices are disabled and deleted, so they can never be named again | `a_device_links_through_the_qr_flow_and_joins_only_through_a_signed_list` (another key, another account, the same version, a removed device: refused); `lists_only_grow_name_exact_keys_and_remove_what_they_leave_out`; `lists_need_the_account_identity_key_and_the_limit` |
| Reading the provisioning message (the account, its identity key, the token) | I | Server, network, someone who sees the QR code later | Sealed to a key that never leaves the new device (X25519, HKDF, AES-256-GCM); the channel holds one message, read once, ten minutes; the channel ID is a 128-bit bearer secret stored under a keyed hash | `sealed_messages_open_only_for_their_key_and_unchanged` (wrong recipient, every flipped byte, every truncation); the HTTP flow in `devices_live`; fuzz `devices` |
| **Exceeding the device limit by racing** token requests or links | E | Malicious client | Every change to an account's devices writes its account row in the same transaction, so concurrent changes conflict and retry; outstanding tokens count toward the limit | `racing_token_requests_never_exceed_the_device_limit` (40 concurrent requests, 8 connections, limit 6: exactly 5; without the account-row write all 40 succeeded); `the_device_limit_counts_outstanding_tokens` |
| A removed device keeps reading, or its data outlives it | I | Lost or stolen device, compromised server later | Disabled in the same transaction that removes it (authentication refused at once; delivery drops it at its next directory reload and closes its session); the worker deletes its mailbox, push registration, upload grants and objects, rows, prekeys and KeyPackages, and verifies, leaving the account's other devices untouched | `device_removal_is_verified_across_every_store_and_spares_the_rest` |
| **A linked device, or one linked by phishing a QR scan and still pending, deletes the account or changes its username or invites** before the primary removes it | E, T | Phisher, thief of a linked device | Only the primary deletes the account, checked inside the deletion transaction; pending devices are refused every account-wide change (usernames, username key and link, invites) | `a_pending_device_changes_nothing_account_wide_and_only_the_primary_deletes` |
| Flooding provisioning channels or link attempts | D | Anyone | Per-IP-range throttles on opening and reading channels and on linking; bounded message size and lifetime | `channels_and_links_are_throttled_per_range` |

### 3.13 Second factors and multiple accounts (Prompt 3, milestone 4b)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **Linking by phishing a QR scan**: the victim's primary approves an attacker's device | S, E | Phisher | With a PIN or passkey set, the new device must present one; the passkey assertion is bound to this link's transcript (it cannot be replayed onto another link) | `a_pin_gates_linking_with_attempt_limits_and_lockout`; `a_passkey_registers_and_approves_a_link_bound_to_its_transcript` |
| **Guessing the PIN online**, also in parallel | S | Anyone holding a link token | Every attempt counted before it is checked (account-row transaction); 5 free, then doubling locks, unusable after 20 until the primary sets a new PIN | `racing_pin_guesses_never_exceed_the_free_attempts` (40 parallel guesses: exactly 4 checked); `a_pin_gates_linking_with_attempt_limits_and_lockout` |
| **Guessing the PIN offline** from a stolen database or backup | I | Database or backup thief | Argon2id with a pepper held only in the secrets store; without it the verifier cannot be searched | D-0053; the pepper's derivation in `devices.rs` |
| A forged, replayed or cloned passkey assertion | S | Attacker with a copied credential or a recorded assertion | Signature over authenticator data and client data checked with the stored key; RP ID hash, origin, type and challenge checked; the counter must grow (compare and swap, so one assertion counts once) | W3C WebAuthn test vectors (`webauthn_vectors.rs`: other challenge, origin, RP ID, flipped signature or data, counter); live test (cloned counter refused) |
| Malformed WebAuthn data (parser differentials) | T | Malicious client | A strict CBOR subset (minimal encodings, no tags or floats, no duplicate keys, bounded depth); fuzzed | `cbor_refuses_non_minimal_indefinite_tags_and_duplicates`; fuzz `devices` |
| A linked or pending device changing the account's factors | E | Thief of a linked device | Only the primary sets or removes a PIN or passkey | `a_pin_gates_linking…` (403 `primary`) |
| One account's actions reaching another account on the same installation | E, I | Malicious app state, bug | Accounts share nothing on the server; every request is the authenticated device's own account | `accounts_sharing_an_installation_stay_apart` |

### 3.14 Profiles and sealed sender (Prompt 3, milestone 5)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Reading profiles or avatars on the server | I | Insider, seized server, backups | Encrypted by the client under a profile key the server never holds; stored opaque; avatars under random IDs | `profiles_certificates_and_sealed_sends` (the server stores and returns only ciphertext) |
| Rolling a profile back to an older one | T | Malicious client, replay | Versions only grow | `profiles_only_grow_and_access_keys_follow_devices`; the e2e test (409) |
| **Sending sealed without being a contact** (spam, harassment) | S, E | Anyone | A sealed send needs every closed recipient account's access key (derived from the profile key, compared in constant time); accounts without one are unreachable sealed unless open; throttles per IP range and per recipient account | `profiles_certificates_and_sealed_sends` (wrong key, no key, no profile: 401; combined keys) |
| **Impersonating a sender** inside a sealed message | S | Malicious client | Certificates signed by the server's certificate key, bound to the account, device and identity key, valid 24 hours; the recipient checks them | `certificate_vector` (OpenSSL cross-check; another device, expiry); the e2e test |
| Learning who sent a sealed message | I | Server, insider | The sealed endpoint takes no device signature; the sender's IP range is used only for a keyed throttle record; the envelope (with the certificate) is end-to-end encrypted | D-0054; the code path (`SEALED_SENDER`) |
| Sealed sender running before it is verified | E | Configuration error | Off by default; on needs a certificate key; off answers 404 | the e2e test (flag off) |
| Malformed certificate or profile bytes | T | Malicious client | Strict, bounded decoders; fuzzed | `uploads_and_certificates_round_trip_and_decode_strictly`; fuzz `profile` |

### 3.15 Key transparency on `akd` (Prompt 3, milestone 6; D-0057)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| **Key substitution by the server**: a contact is given a different identity key or device list, or a different view than the owner | S, T | Malicious or compelled server | Every key and list is published to `akd` under a deterministic label (one per account and kind), so everyone is shown the same value; clients verify a lookup proof against a signed head and that the value equals the salted hash of the key in hand; another salt cannot match it; owners verify their key history | `clients_verify_the_transparency_log`; `another_salt_never_matches_the_published_value`; `published_epochs_verify_with_akds_own_client_checks` |
| **A forked or rewritten directory** | T | Malicious server | Signed heads, with clients requiring akd's append-only (audit) proofs between heads; two heads no proof joins are evidence | `published_epochs_verify…` (a rewritten epoch root fails the audit); `clients_verify…` (a forked root fails) |
| Proofs forged under another VRF key | S | Malicious server | Apps pin the VRF key; lookup verification fails under another key | `published_epochs_verify…` |
| Storage corrupting akd's state (partial epochs, an epoch overwritten by a second writer) | T | Faults, concurrency, a second worker | Each epoch written in one transaction with the Azks record last; **an epoch commits only from the epoch before it** (compare and swap); the store matches akd's retrieval rules | `epochs_cannot_be_rewritten_and_racing_writers_never_both_commit`; `the_store_keeps_akds_semantics` |
| A change never published | T | Crash, bug | The change bumps a generation in its own transaction; the worker publishes until the published generation catches up | `each_change_is_reported_once_under_a_stored_salt_and_deletion_unlinks` |
| The directory identifying people forever (GDPR) | I | Anyone reading the directory, the database or backups | Values are salted per account (including the computable username hash); the salt is deleted with the account; labels keep only the account ID and the epochs of its changes | `each_change_is_reported_once…` (no salt after deletion); `another_salt_never_matches…` |
| Malformed proofs or heads | T | Malicious server | akd's protobuf decoding and verifiers; bounded input; fuzzed | fuzz `kt` |

### 3.16 GDPR (Prompt 3, milestone 7)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Data outliving an account's deletion | I | Compromised server later, insider | The outbox job deletes every Prompt 2 and 3 store and verifies it; the transparency salt goes with the row (its leaves unlinkable); backups expire within 93 days and a restore deletes again | `an_account_is_exported_then_deleted_from_every_prompt_3_store`; `account_deletion_is_verified_across_every_store` |
| Exporting someone else's data, or a thief exporting with a linked device | I, E | Thief of a linked device | Export only by the account's primary, signed; it carries public keys and ciphertext, never the PIN or username-key verifiers | the same test (the PIN verifier absent from the export); `a_pending_device_changes_nothing_account_wide…` |
| An active user's account deleted for inactivity | D | Bug, a user who only uses the WebSocket | Any signed `api` request counts as use (apps call `api` at least daily); two wake-up warnings first; the user chooses the period | `inactivity_warns_a_month_and_a_week_before_then_deletes` |
| Inactivity deletion as an attack (keeping someone's devices from reaching `api`) | D | Network attacker | Months-long periods, two warnings, any single request resets; censorship resistance is the proxy's (Prompt 1) | D-0056 |

### 3.17 Encrypted content (Prompt 4, milestone 1; D-0059)

Content is end-to-end encrypted and never decoded by the server; these threats are the apps'
and the specification's. Nothing new reaches the server (no §1 row).

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Content reaching the server in plaintext, or a service starting to parse it | I | Developer error, insider | No service or server crate may depend on `songbird-content`; what the server must act on is a fixed `Send` field, never the ciphertext | `no_service_or_server_crate_depends_on_content` |
| Malformed content crashing or exhausting an app | D | Malicious contact, compromised device | Size checked before decoding; every list, string and ID bounded after; nesting stops at one level (a sent transcript holds a chat message only) | `bounds_are_refused_with_their_field`; `open_never_panics`; fuzz `content` |
| Message lengths revealing content to the server | I | Server, network | Plaintexts padded to 160-byte buckets, one encoding per length | `padding_is_canonical` |
| Replayed or resent messages shown twice | T | Faults, restores, malicious server | Recipients drop a repeat of (author, message ID) | PROTOCOL §5.1; M2's state tests |
| An old app misreading a newer message | T | Version skew | Unknown fields, kinds and enums ignored; `required_version` shows "update to see this" | `a_newer_writers_*`, `this_reader_decodes_every_versions_vectors` |
| Apps logging message content or keys | I | App bugs, log collection | `Debug` of every content type prints its name only | `debug_prints_no_content` |
| Two implementations disagreeing on the encoding | T | Interoperability bugs | The `.proto` is the specification; 33 vectors encoded by the Rust types and by an independent compiler from hand-written JSON | `every_vector_matches_the_rust_types_byte_for_byte`; `tools/content-vectors` |

### 3.18 Chat state and receipts (Prompt 4, milestone 2; D-0060)

These run in apps, over end-to-end encrypted content. The server sees receipts only as envelopes
(their count and timing, §1).

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Devices disagreeing on a poll, reaction, pin or timer (or an attacker making them disagree by reordering or replaying) | T | Malicious server (reorders, delays, replays), network faults | Every state is a function of the set of operations: per-author counters, or a total order on (time, author, message ID) | `crates/content/tests/convergence.rs` |
| Changing someone else's vote or reaction | T, S | Malicious member | Slots are per author; the author comes from the session layer, not the content | `Lww`, `Poll` (votes keyed by the authenticated voter) |
| Closing someone else's poll, or rewriting a closed result with late votes | T | Malicious member | Only the poll's author's close counts; a close fixes each listed voter's counted vote | `a_closed_poll_counts_exactly_the_votes_its_author_saw` |
| Editing or deleting another person's message, or after the window | T | Malicious member | Only the author (group admins from Prompt 5), within 24 hours of the messages' own times | `edits_and_deletes_converge…` (only the author's in-window edits shown) |
| Faking ticks | S | Server, insider | Receipts are end-to-end encrypted content from the audience only; the server's `Accepted` gives one tick only | `group_ticks_wait…`; PROTOCOL §5.6 |
| Flooding a device with operations it must store | D | Malicious member | Validation bounds every message; per-voter (64) and per-message (64 revisions, 16 deletes) caps | `crates/content/src/state` |
| Read receipts revealing reading habits against the user's wish | I | Contacts, group members | Reciprocal setting, applied to groups (D-0058); receipts go to the author only, never the group | `with_read_receipts_off_only_the_own_devices_learn_what_was_read` |
| Receipt traffic overloading the server in large groups | D | Large groups (load) | Batching per author, 10 s above 32 members; measured | `receipt_share_in_a_1024_member_group` (47 %) |

### 3.19 Franking stamps and disappearing envelopes (Prompt 4, milestone 3; D-0061)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| A client forging a franking stamp (to frame someone, or to make a report verify) | S, T | Malicious client | The stamp is a MAC under a key only the server holds; user envelopes beginning with the server's prefix `F5 53 42` are refused (reason 9) | `franking_without_a_key_is_refused_and_forged_stamps_are_reserved`; `stamps_verify_only_for_their_key_sender_and_recipient` |
| A stamp moved to another sender, recipient, time or content | T | Malicious client, insider | The MAC covers the key ID, commitment, time, sender and recipient accounts | `stamps_verify_only_for_their_key_sender_and_recipient`; `stamp_known_answer` |
| A sender committing to other content than it sent (so reports fail) | R | Malicious client | Recipients drop a franked message whose commitment does not open to the decrypted content | `sealed_plaintexts_open_and_franking_verifies` (M1); PROTOCOL §5.3 |
| Stamps linking senders to undelivered envelopes for someone holding the database and the franking key | I | Insider with the key, seized server | The MAC names no account in the clear; the envelope (and stamp) is sealed in Iggy under a per-message key destroyed at acknowledgement; testing needs the key, which is in the secrets store only | Threat model §1 row; D-0061 |
| Sealed senders unattributable in reports | R | Malicious contact sending sealed | Stated: a sealed send's stamp has no sender; requests (strangers) are never sealed (M4) | `a_sealed_franked_send_is_stamped_without_a_sender` |
| A disappearing message delivered after its timer, or kept for a device that never returns | I | Server retention, a lost device | The deadline is stored with each envelope in every mailbox; never fetched after it; swept (Iggy: key punctured, absent after a restart) | `an_envelope_past_its_deadline_is_skipped_then_deleted`; `the_disappearing_hint_skips_then_deletes` (SurrealDB); `the_disappearing_hint_skips_drops_and_survives_a_restart` (Iggy, CI); `entries_past_their_deadline_are_dropped_wherever_they_are` |
| Malformed hints or stamps | T, D | Malicious client, insider | Strict frame decoder (flag rules, bounds, one encoding); fuzzed | `send_hint_flags_are_exclusive_and_bounded`; fuzz `proto_client_frame`, `franking` |

### 3.20 Message requests, blocking and lanes (Prompt 4, milestone 4; D-0062)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| A stranger messaging anyone at will (spam, harassment) | S, E, D | Anyone with an account | A send to a closed account needs its access key (only contacts hold it) or goes as a request: franked, identified, budgeted per sender, pair and recipient, blockable | `a_send_to_another_account_needs_its_access_key_or_a_request`; `contacts_requests_blocks_and_the_request_policy_end_to_end` |
| Request floods: one sender to many, many to one, one pair | D | Spammer, sybil accounts | Three budgets in `valkey-hot`, shared by every node and both transports (fail closed) | `request_floods_are_held_to_their_budgets…` (unit); `request_floods_are_held_across_the_cluster…` (live) |
| Detecting a block (or the request policy) from the answers | I | A blocked sender | Blocked and refused requests are accepted and dropped; budgets are spent before the check, so the answers and rate limits are identical | `…_dropped_silently`; `…a_block_does_not_show` |
| A blocked contact keeps writing with the access key | E | Blocked contact | Blocking rotates the profile key (client rule), so the old key fails (reason 10) and only the request lane is left | PROTOCOL §5.11; `a_send_to_another_account…` (a wrong key refused) |
| A stolen linked device unblocking a stalker or reopening requests | E | Thief of a linked device | Loosening (unblock, accept requests) only from the primary; pending devices change nothing (D-0058) | `contacts_requests_blocks…` (403 from the linked device) |
| Block rows revealing who blocked whom | I | Database or backup thief | Rows named by keyed hashes; no account ID; a key holder can still test pairs (stated) | `blocks_are_keyed_pairs_bounded…`; `records_and_tags_are_keyed…` |
| Filling the block table | D | Malicious client | 1,000 per owner, enforced by a per-owner counter row written in each change's transaction (concurrent adds conflict) | `blocks_are_keyed_pairs_bounded_per_owner…` (1,020 racing adds) |
| A broadcast to non-contacts | E | Spammer | Every closed account's key must be in the combined key; accounts without a profile can never be in a broadcast; budget per sender | `broadcasts_need_every_contacts_key…` (unit and live) |
| Guessing an access key | S | Anyone | 128-bit keys compared in constant time; a wrong key is refused like a missing one | `ct_eq` in the send path; `a_send_to_another_account…` |
| Bypassing the gate with a shared body (found by the review, D-0064) | E | Spammer, blocked sender | A shared body reaching a closed account needs its key in the combined key, as a broadcast does, until Prompt 5's membership checks | `groups_and_sealed_sends_are_not_classified_as_strangers`; `contacts_requests_blocks…` (live) |
| Detecting a block through idempotency-key reuse (found by the review, D-0064) | I | A blocked sender | A dropped send is stored whole, already expired, under its key, so the record and the answers match a delivered send's | `requests_from_a_blocked_sender…` (reuse for other devices and a subset: reason 7) |
| A linked device opening the account, or blocked senders reaching an open account (found by the review, D-0064) | E | Thief of a linked device, blocked sender | Opening is the primary's (checked in the profile's transaction); the open lane applies blocks | `only_the_primary_opens_an_account_to_anyone`; `an_open_account_takes_anyone_but_its_blocks_still_apply` |
| Ephemeral frames from strangers | E | Spammer | Encrypted and dropped without a session; per-connection limits | PROTOCOL §5.10 |
| A request's timing revealing a block | I | A blocked sender measuring latency | A dropped send is stored durably too (expired, D-0064), so both take a durable store; a request to a blocking account adds one registry lookup either way | D-0064 |

### 3.21 Reporting with message franking (Prompt 4, milestone 5; D-0063)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Framing someone with words they never sent | S, R | Malicious reporter | The server's stamp binds the commitment and time to the sender; the commitment must open to the reported content under the franking key | `tampering_keys_and_windows_are_refused`; `a_recipient_reports_a_message…` (other words, another sender refused) |
| Reporting a message one never received (a forwarded opening) | S | Malicious third party | The stamp binds the recipient's account (zero only for a group's shared body) | `a_recipients_report_of_an_identified_send_attests_the_sender`; the live test (403 for Dave) |
| A sender escaping a report by committing to other words | R | Malicious sender | Recipients drop franked messages whose commitment does not open (§5.3) | M1 `sealed_plaintexts_open_and_franking_verifies` |
| Sealed senders blamed on a claim | R | Malicious reporter | A sealed send's stamp has no sender; the report says `sender_attested: false` | `sealed_and_group_messages_verify_with_what_the_stamp_names` |
| Report floods, repeated reports, probing stamps | D, I | Malicious client | A per-account budget spent before verification; one report per message (keyed stamp ID) | `report_floods_are_throttled_per_reporter` |
| The moderation queue read by an insider, a seized database or a backup | I | Insider, seized server | Reports sealed to an offline key the servers never hold; rows named by keyed hashes; no reporter | the live test (another key cannot open; content not in the clear) |
| Reporters exposed to the reported or to moderators | I | Reported sender, moderator | The report holds no reporter identifier | the live test (the plaintext has eight fields, none the reporter) |
| Stale stamps or a retired key | T | Anyone | A 30-day window; old franking keys verify only while listed | `tampering_keys_and_windows_are_refused` |
| Oversized or malformed reports | D | Anyone | Signed request, length checked before the body is read; strict decoder; fuzzed | `reports_round_trip_and_decode_strictly`; fuzz `franking` |

### 3.22 Prompt 5 follow-ups (D-0075 to D-0077)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| The server removing a member who is still listed, through its external-sender power | T, E | Compromised server or operator; a node with a stale directory | Apps keep and commit a server removal only for a device no longer in its account's signed device list; a commit carrying one for a listed device is refused by clients and the server, whoever commits it; the server confirms candidates in the registry, and a stale node answers 503 | `a_server_removal_of_a_listed_device_is_refused_by_members_and_the_server`; `server_removals_are_only_for_devices_that_left`; live `departed_devices_are_removed_through_server_proposals` |
| The server admitting someone, or reshaping a group, by external proposal | E | Compromised server | Apps and the server take only `Remove` from the external sender; `NewMemberProposal` is refused | `the_service_may_only_propose_removals` |
| A member dropping the service (to keep departed leaves) or adding an external sender of its own (to propose) | T, E | Malicious member | The context must name exactly the service's key, at creation and after every commit | `groups_name_exactly_the_service` |
| Theft of the external-sender key | S | Insider, host compromise | It can only propose removals of departed devices (apps refuse the rest); it is derived from the cluster secret, which is not rotated while groups exist until key rotation is built (`docs/RUNBOOKS/secrets-rotation.md`) | the trust-rule tests above |
| The server admitting someone who never held a link | S, E | Compromised server or operator | Members follow an external commit from a new account only with a proof signed by a link key the links role published; the server cannot sign (it holds `SHA-256(auth)` only) and applies the same rule (403 `proof`) | `joins_without_a_valid_proof_are_refused_by_the_server_and_members`; live `invite_links_and_join_requests` |
| A link holder proving for links it never held, or reusing a proof | S | Holder of another link, a past joiner | One key per link, from its own secret; the proof binds group, epoch, handle, device and leaf key | `proofs_bind_the_link_group_epoch_device_and_leaf` |
| A member publishing a link key to let someone in | E | Malicious member below the links role | Publishing or withdrawing keys is the links role's (`roles::authorize`) | `only_the_links_role_publishes_link_keys`; `link_keys_have_one_encoding_and_are_the_links_roles` |
| A channel's admins multiplying its post budget by posting through several nodes, or both transports | D | Malicious or careless channel admin | One GCRA record per channel in `valkey-hot`, shared by every node and transport; the per-node budget in front and as the fallback | `the_channel_class_is_shared_by_every_send_path`; live `a_channels_rate_class_is_shared_by_the_websocket_and_http` |
| `valkey-hot` down or slow stalling channel posts | D | Outage, network fault | Each post waits at most 250 ms, then the per-node budget decides (counted, runbook) | `without_valkey_the_per_node_budget_decides_alone` |
| Departed devices' leaves outliving the account | I | Anyone reading group state later | Marks in the transactions that disable devices; proposals within seconds; again after each commit; the IDs stripped from marks at deletion | `departing_devices_mark_the_groups_that_hold_them`; live `departed_devices_are_removed_through_server_proposals` |

## 4. Server-enforced settings

| Setting | Who changes it | Enforced where |
| --- | --- | --- |
| Message requests from everyone or nobody (Prompt 4, D-0062) | Refusing: any listed device; accepting again: the primary | The send path (requests dropped silently) |
| Blocks (Prompt 4, D-0062) | Blocking: any listed device; unblocking: the primary | The send path (requests from blocked senders dropped) |
| "Anyone may send" (Prompt 3, D-0054; widened by D-0062) | Any listed device, with the profile | The send path and the sealed endpoint |

## 5. Compliance notes (GDPR, age of digital consent per EU country)

## 6. Open risks

- The nightly TSan run suppresses one report inside tokio's I/O driver: `ScheduledIo::set_readiness`
  and `ScheduledIo::wake` from `dispatch_event`, touching state that `TcpStream::new` allocated on
  another thread and handed over through epoll (`xtask/tsan-suppressions.txt`). No Songbird frame is involved, but if it is a
  real tokio bug the suppression hides it. Re-check on every tokio upgrade and drop it once tokio
  or the TSan runtime models the hand-off.
- No certificate revocation for internal leaves yet; mitigated by 30-day lifetimes and intermediate
  rotation (runbook `mtls-rotation.md`).
- SurrealDB and Iggy have server TLS and password authentication but no client-certificate
  authentication.
- Deleted key-store files and overwritten Iggy segments can survive in SSD flash until garbage
  collection: with the raw flash and the master key an attacker might recover keys that ACKs
  destroyed. Data volumes need full-disk encryption with a key kept off the disk (Prompt 13,
  D-0031). On a quiet node a delivered message's sealed bytes (unopenable) stay until its
  16 MiB segment fills.
- Losing a node's key store (`key_dir`) or master key loses its pending messages (D-0031), unless
  a standby holds a copy (cluster mode, D-0034). A partition's key store exists on three nodes;
  deleted keys can survive in any of their flash (full-disk encryption, #28). With fewer live
  nodes than copies, writes continue on the copies that exist.
- A compromised `api` host can store envelopes into any device's mailbox over node links
  (D-0044), as a compromised delivery node could: recipients drop what they cannot authenticate
  (end to end), but it costs mailbox capacity until acknowledged or expired. It cannot read,
  acknowledge or forget anything, nor forge system notices.
- A device sending over both its WebSocket and `PUT /v1/messages` has each path's rate budget
  (the WebSocket's per connection, HTTP's across `api` nodes): at most twice the per-device rate.
- The system key that signs notices is not deployed yet; `api` issues "prekeys low",
  "KeyPackages low" and "device list changed" notices (Prompt 3) once it is configured. It will
  live in the secrets store of the issuing service only; rotation by `key_id` (apps pin the
  current and next key).
- Valkey holds leases and routing without persistence: losing it costs re-subscribing and re-taking
  leases (seconds), not messages; Iggy's epochs remain the guard against two writers.
- Iggy is pre-1.0; the Iggy SDK added 153 exempted crates to the audit backlog (D-0030).
- cargo-vet: 57 of 167 crates are exempted rather than vetted; accepted by the owner (report P01, D-0016).
- Root SSH through the bastion (owner decision open, D-0014).
- The proxy is identifiable by traffic analysis; it is a reachability tool, not an anonymity tool.
- Delivery reads devices from the account registry in SurrealDB (M5, reloaded within a second of a
  change); accounts are created by registration (Prompt 3, M1) or by operators through `api`'s
  admin link.
  A deleted device can authenticate for up to the registry poll interval (1 s) if SurrealDB is
  unreachable during that window (its sessions are closed by the deletion itself).
- Attachments already sent stay (opaque, unlinked to the account) until fetched or 30 days after
  their sender's account is deleted.
- Backups (D-0040, D-0041): a deleted account stays in older encrypted backups for up to 93
  days (a restore deletes it again through the journal). A deletion whose job never reached the
  worker before the registry was lost (the outbox relay's sub-second window) has no tombstone
  and is lost with the registry. Whoever holds the
  verification identity and the verifier key (the verification host, the owner-only SOPS file)
  can read every retained backup. Backups stored after a data host is compromised are
  untrusted (restore with `--before`). Backups, state and servers are all at Hetzner (owner
  decision, D-0042): different projects and locations, but losing the Hetzner account itself
  would lose all three; the owner's optional monthly offline copy covers that. Until the
  observability work adds alerting, a failed
  backup timer is noticed by the daily verification (newest older than 1 hour), so the RPO
  can silently grow to a day.
- Every service uses one RustFS credential in development; per-service least-privilege users
  and bucket policies are configured at deployment (Prompt 13), not yet automated.
- The delivery service connects to Iggy as the root user; a least-privilege user is Prompt 12's.
- One delivery node per Iggy topic until M4 (a second one is fenced and goes unready).
- sockudo-ws (parses every client byte, contains `unsafe` SIMD code) and quanta are exempted in
  cargo-vet, not audited (D-0017).
- Registration (Prompt 3, M1): per-range throttles treat everyone behind one IPv4 `/24` (carrier
  NAT, a censorship proxy relaying TCP) as one client; the numbers are generous and the
  deployment-wide caps are the backstop. The proof of work's phone timing is an estimate from
  the Mac measurement until the apps exist (D-0048). A registry restore brings back invite codes
  used after the backup, valid again until they expire.
- Devices (Prompt 3, M4, D-0052): only the account's own devices get a "device list changed"
  notice. The server keeps no social graph, so contacts learn of a change when the send
  path's device check refuses a stale send, or when they next fetch the list. The account
  identity key vouches for lists, but until key transparency (M6) a server could still answer a
  first-time contact with a different account identity key. A registry restore brings back
  devices removed after the backup: the restored list is the old one, and clients refuse it as
  a rollback (they keep the highest version they have seen), so the primary must sign a new list.
  The deletion journal covers accounts, not single devices. Losing the primary means deleting
  the account until M4b's recovery (two-step PIN, passkeys) and a primary transfer exist.
- Second factors (M4b, D-0053): the PIN stops a database or backup thief, not a fully
  compromised `api` (which holds the pepper and sees PINs in requests). Hardware guess-limiting
  is issue #26 (Prompt 10). Passkeys sync through Apple or Google accounts, so whoever controls
  that account can use the passkey; the PIN and the signed device list remain. No authenticator
  attestation is checked: any authenticator the user picks is accepted. APNs gives one token per
  app installation, so on iOS several accounts on one phone are linked by their shared push token
  at the push service (the app documents this; FCM and Web Push register one per account).
- Sealed sender (M5, D-0054): the server still sees the sender's IP address (as for any
  request) and the time, so traffic analysis can link a sealed send to a connection. Users who
  need that hidden use the proxy or Tor. The access key is shared with every contact who has the
  profile key, so revoking a contact means rotating the profile key. Spam from one contact is
  bounded by the per-recipient throttle, not by identity. The certificate key is not deployed yet
  (it goes in the secrets store at deployment; rotation by `key_id`).
- Key transparency (D-0057): `akd` 0.13 brings 27 newly exempted crates into cargo-vet, among
  them a second Ed25519 and curve25519 stack (`ed25519-dalek`, `curve25519-dalek` 4) and
  protobuf code generation at build time. `akd` cannot tombstone values in 0.13, which is why
  values are salted and deletion removes the salt. A deleted account's ID and the epochs of its
  changes stay in the directory's labels, which are needed for its integrity. Records are stored as serde JSON (larger than
  needed). There is no external auditor yet; the log and VRF keys are not deployed (secrets store;
  apps pin both).
- GDPR (M7, D-0056): the export does not include what the mailbox holds (ciphertext the user's
  devices receive anyway); `api` has no read path into it. A device that only holds a WebSocket
  and never calls `api` would not count as use; the apps call `api` at least daily (prekey and
  KeyPackage counts). Inactivity warnings are wake-up pushes: a device without push gets none.
- Message requests (Prompt 4, D-0062, D-0064): a dropped send is stored durably like a delivered
  one (expired), so answers, budgets and store latency match; the
  recipient budget lets a set of sybil accounts use up an account's requests for an hour
  (contacts are unaffected). Every node's directory snapshot now holds every account's access
  key (memory only), and reloads on profile changes as on device changes (an incremental reload
  is Prompt 13's). Ephemeral frames are not gated. A dropped send waits, expired and
  unreadable, in the recipient's mailbox until the next sweep (minutes). Until Prompt 5, group
  members prove they are contacts with their access keys (groups share profile keys); a group
  report's single stamp lets the first reporter take the message's report slot.
- Reporting (Prompt 4, D-0063): `api` sees a reported message's content in memory while it
  verifies the report (never decoded, never stored unsealed). A sealed sender cannot be attested,
  only claimed. The moderation key's private half must stay offline: whoever holds it can read
  every queued report; rotating it is a configuration change, and reports sealed to the old key
  need the old key.
- Groups (Prompt 5, M1; D-0067): delivery nodes cache rosters for up to a second, so a device
  removed by a commit can still post at its last epoch for that long on a node that has not
  refreshed. Members that processed the removal see who sent it. The registry holds every
  group's roster and public ratchet tree: whoever reads it learns which devices (and, through
  the device lists, which accounts) share a group, the constitution's "group membership
  changes it must order" (D-0065 §2). GDPR (D-0073): the export lists the account's groups,
  roles and requests; deletion removes its requests, and group messages skip its devices, but
  its devices' leaves (and an account ID in the roles, if it held one) stay in each group's MLS
  state until a member commits their removal: the server cannot edit a group without forking it.
  Since D-0075 the server proposes that removal within seconds, and the next commit by any
  member includes it. Still open:
  - a group none of whose members comes back keeps the leaves;
  - a member can fill the 64-proposal queue so the service's proposals wait for the next
    commit;
  - rotating the service's key needs a context change in every group, which is not built
    (it follows the cluster secret).

  A member whose view of a device list is stale refuses a valid server removal until it
  refreshes (apps refresh before refusing).
- Invite links (Prompt 5, M3; D-0071): the server decides whether a joiner may use a link.
  Since D-0076 members check for themselves that a joiner held a link they made (a proof under
  the key the links role published); a malicious server can no longer admit an account apps
  accept without one. A server that admits one anyway forks itself from the members, who refuse
  the join. It cannot hide a join from the members: every member sees the new leaf, its account
  and its default role, and can remove it. A link leaked from a chat is usable by whoever holds
  it until it is revoked, used up or expired (the proof shows a link was held, not by whom);
  opening it shows the members' devices (the ratchet tree an external commit needs) before any
  join, unless joins need approval.
  A join request tells the server which account wants which group before it is a member.
- Communities and channels (Prompt 5, M4; D-0072): the server knows which groups form a
  community, so with the rosters it knows who shares a community. A private channel is an MLS
  group: subscribers see each other's devices. A full-path commit right after many adds
  encrypts to nearly every leaf (1.2 MiB at 1,024 X-Wing leaves): a member who adds many
  people and then commits makes every member download that much. The channel rate class is
  cluster-wide since D-0077; while `valkey-hot` is unreachable it falls back to each node's own
  budget, so a channel posting through several nodes then gets each one's.
- Review leftovers (D-0074): role checks for metadata, links, requests and communities read the
  roster before the write, so one in-flight action by a just-demoted admin can land. There is
  no per-account cap on creating groups, and groups are not deleted yet. A client whose view
  of the directory differs from the server's may judge a commit differently and stay behind
  until it refreshes. A member can fill the 64-proposal queue until the next commit, which
  removes them.
