# P09 — Settings, presence, statuses and Yahoo-style features: plan, milestones and gates

- Date: 2026-11-18
- Prompt: [09-settings-presence.md](../prompts/09-settings-presence.md)
- Status: **proposed, awaiting the owner's approval** (D-0101). Nothing is built until then.
- Base: `main` at `8271b89` (Prompt 8 merged, PR #65; the Floating redesign, PR #66).
- Scope set by the owner on 2026-11-18, while this plan was being written: "implement every
  single setting implemented on settings except those handled in later Prompts". So the plan
  covers the prompt **and** every row of the app's Settings screens (`apps/ui`), made real:
  stored, synced or enforced, and applied. The inventory below lists each row. The only
  exclusions are rows that later prompts own, each named with its prompt.
- Way of working (as Prompts 7 and 8): one branch and one PR (`claude/p09-settings-presence-44c936`).
  Each milestone gets its own commit, tests, report `docs/reports/P09-Mn.md`, decision record
  (D-0102 onward) and threat-model rows marked "awaiting the owner's approval". Then
  `cargo xtask ci fast`, the live suites (one heavy job at a time, `-j 1` for crates that share
  job streams), an independent read-only security review of the whole diff by a separate agent
  given the code and not my conclusions, and `docs/reports/P09-gate.md`. Nothing is merged
  without the owner.
- Skills: `nsh` and `nsh-design-guides` before the app milestones (M5, M6); `security-review`
  for the independent review. No skill covers CRDTs, hybrid logical clocks or GDPR Article 8;
  the repository has no project skills for them. A `songbird-invariants` review checklist
  (constitution) would help the review in M7; proposed, not built.

## What Prompt 9 starts from

| The prompt asks for | Already there | Missing |
| --- | --- | --- |
| Encrypted settings records, LWW on a hybrid logical clock, partial updates, server stores opaque versioned records | A `settings` sync message with four fields (`SettingsSync`, PROTOCOL §5.8) sent to one's own devices; per-author LWW and a `(time, author, id)` order in `crates/content/src/state` | No account-level record store on the server; no HLC anywhere; nothing in the app is saved or synced (the `Store` is in memory) |
| Server-enforced settings | Message requests everyone or nobody (`account.requests_off`, D-0062); inactivity period 6/12/24 months (D-0047, worker sweep) | Username discoverability (none; only the optional username key); plan (Prompt 11); threat model §4 is three rows |
| Encrypted presence and last seen through the ephemeral lane, debounced, rate limited; invisible sends nothing; a batched fan-out | `Ephemeral` frame: one device per frame, never stored, online only, 20/s per connection, sender identified by its connection, no answer to the sender | No batch, no class, no contact gate (PROTOCOL §5.10 "not gated"), no Valkey budget; no presence content type |
| Custom statuses and "about" in the encrypted profile; a "profile changed" signal | Profiles are one encrypted blob (≤ 8 KiB) under the profile key, versions only grow (D-0054) | No profile-changed signal (system notices are only device-list, prekeys and KeyPackages); no expiry field |
| Nudge in an "attention" class, rate-limited per pair | `Nudge {}` exists as a `DataMessage` kind: a stored, franked, visible message | No attention class, no pair budget |
| Scenes, sound stickers, emoticons through the pack service | Pack kinds Stickers, Scene, Sounds, Emoticons in the encrypted manifest (D-0083); `StickerRef` | Nothing references a scene or emoticon; the manifest allows 64 MiB items while the server caps objects at 16 MiB |
| Ignore list = blocking | Done in Prompt 4 (D-0062) | — |
| More synced settings, contacts sync | — | Everything; the app has no contacts screen, no "Save to contacts", no buddy groups |
| Parental controls | A mocked app flow (link by QR, rules, child's view) | Everything on the server and in cryptography |

## Findings that shape the plan

1. **The app has nothing behind its settings.** Almost every Settings screen is drawn and works
   against the in-memory mock (`apps/ui/src/store`), but nothing is saved to disk, synced or
   sent. app-core (A2) does not exist; `crates/client` is the delivery client only. So the
   record logic goes into a **new shared crate, `crates/sync`** (records, HLC, merge,
   encryption, the store client), which the app uses now and app-core reuses later. Settings
   whose effect lands on features that are still mocked (chats, calls) are stored, synced and
   applied to the mock; their real effect comes with A2 and A8, with no further settings work.

2. **A record store needs integrity, not only secrecy.** The server holds every device's view
   of the account's settings. With per-record LWW alone, a malicious server can withhold a
   record, replay an older one to a fresh device, or keep two devices apart. Signal's storage
   service answers this with an encrypted manifest that only moves forward. Plan (question 2):
   - every write gives the changed record a **fresh random 16-byte ID** (the old ID is
     deleted), so the set of IDs names the account's whole state;
   - a small encrypted **manifest** (a version and SHA-256 over the sorted ID set, about
     100 bytes) is written in the same atomic compare-and-swap as the records;
   - a device refuses a manifest older than one it has seen, or an ID set that does not match;
   - a new device trusts the first manifest it gets (stated in the threat model).
   Partial updates stay partial: a change uploads one record and the small manifest.

3. **Conflicts are per logical key, inside the ciphertext.** A record's plaintext carries its
   logical key (`setting:theme`, `chat:<id>:mute`, `contact:<uuid>`), its value and an HLC
   `(wall ms, counter, device)`. A writer that loses the compare-and-swap fetches the changed
   IDs, merges by HLC per key, and retries. Deletions are tombstone records (key and HLC), so a
   delete and an offline edit converge. Tombstones are dropped after 90 days; a device away
   longer resynchronises from the full state and drops its own edits older than the horizon.
   A remote HLC more than 24 hours ahead of local time is clamped, so one bad clock cannot pin
   a key forever. Proptest: N devices, random edits offline, random sync orders and server
   interleavings, clock skew; every device converges to the same state, and each key holds the
   value with the greatest HLC.

4. **Record sizes and counts leak, unless padded.** The server sees how many records an account
   has and when they change. Contents are padded to buckets (Padmé, as attachments are,
   D-0080), so a contact with a long note and a theme toggle look alike within a bucket. Count
   and write times are stated in the threat model; write times are kept in memory only, the
   server stores a write counter, not a time.

5. **The storage key must reach every device.** Records are encrypted under a 32-byte storage
   key held only by the account's devices (per-record keys by HKDF over the record ID; AES-256-
   GCM-SIV, as the job seal). It goes to a linked device in the provisioning message
   (PROTOCOL §4.6), which needs a version 2 with one more field. When a device is removed, the
   remaining primary rotates the key and re-encrypts every record in one write.

6. **Presence fan-out shows the server your contact list.** Typing goes to one chat at a time.
   Presence goes to every allowed contact at every change, so an identified fan-out would hand
   the server, in memory, the whole contact graph several times a day. Signal has no presence
   for this reason. Plan (question 3): presence goes **sealed**, through a batched call that
   reuses the sealed-send checks: no device signature, `Unidentified-Access-Key` = XOR of the
   recipients' access keys (so "my contacts only" is enforced cryptographically and strangers
   cannot be probed), throttled per IP range and per recipient account, at most 1,024 devices
   per batch, never stored, delivered to online devices only, no answer that reveals who is
   online. The server learns who receives and when, not who sent, except by IP and timing
   correlation with the sender's own connection (the known limit of sealed sender, stated).
   Invisible sends nothing at all: tested by counting frames.

7. **Last seen cannot reach a contact who is offline, through an ephemeral lane.** Options
   (question 4):
   - recommended: ephemeral only. Going online sends "online" to allowed contacts; online
     contacts answer once with their own state; going background sends "last seen <minute>".
     A contact who was offline the whole time sees the last value it cached, or "last seen
     recently". No new server state.
   - alternative: an encrypted last-seen blob per account, overwritten, readable by contacts.
     WhatsApp's behaviour, but the server then holds a persistent "this account was active
     recently" signal and sees who fetches whose last seen.

8. **"Everyone" cannot see an encrypted profile.** The profile opens only with the profile
   key, which goes only to contacts (PROTOCOL §5.10). So "who sees my photo, about and status:
   Everyone" means the same as "My contacts". Plan (question 7): offer **My contacts** and
   **Nobody** for photo, about and status (fields set to Nobody are left out of the blob).
   Narrowing rotates the profile key, as blocking does. For last seen and online the three
   choices stay meaningful (sealed presence to contacts, or to nobody), with WhatsApp's
   reciprocity: if you share nothing, you see nothing.

9. **Nudges need a sender; presence must not have one.** A per-pair budget needs the server to
   know the pair. So nudges go **identified** on the WebSocket, in an `attention` class of the
   ephemeral frame: budgets per (sender account, recipient account) and per sender in
   `valkey-hot` (keyed records `q:n:<hmac>`, fail closed, as requests). The server learns that
   a nudge happened between two accounts, not its content. The existing `Nudge` `DataMessage`
   kind (stored, franked) is replaced: a nudge to an offline contact is simply lost, as Yahoo's
   buzz was. The receiving app shakes the window (desktop) or vibrates, unless nudges are off,
   globally or for that contact.

10. **"Who can add me to groups" can be enforced by the server.** A commit's Welcome goes
    straight into the added devices' mailboxes (`services/api/src/groups.rs`). The server
    already maps added devices to accounts there. A per-account bit, "contacts only", lets it
    refuse a commit that adds that account unless the commit carries that account's access key
    (XOR, as broadcasts do). "Nobody" becomes an invite the user accepts in the app. Question 6.

11. **Username discoverability is new, and small.** Off: `POST /v1/username/lookup` answers the
    same single 404 as any miss, for everyone. Username links and QR codes keep working, because
    the user handed them out on purpose. Existing contacts are not affected.

12. **Parental controls create a relation the server must not learn more of than it needs.**
    The server must enforce the rules it can see (requests, discoverability, group adds), so it
    must know a child account is supervised and by which rules. It does not need to know **who**
    the parent is. Plan (question 8):
    - at linking (in person, QR on both devices, both confirm, a short code compared), the
      parent's device creates a fresh Ed25519 **policy key** for this child;
    - the child's account row stores only: that public key, the enforced rule bits, a policy
      version, and the **unlink date** (computed on the child's device from the age the child
      enters and the country's age of consent; the birth date never leaves the device);
    - policy changes and unlinking need the parent's signature over the child account, the
      version and the rules; the child's own devices cannot loosen any supervised rule;
    - on the unlink date the worker removes the supervision row;
    - group adds that need approval carry a parent-signed approval (group, child, expiry);
    - the parent never gets message content, call content or the contact list: the policy is
      the only thing the parent writes, and the child's app shows every rule in force.
    GDPR Article 8 ages (13 to 16 by country) go into the threat model's compliance notes,
    each checked against the national law in M4.

13. **Some settings need the native host projects the owner deferred in Prompt 8.** NSH 0.6
    has no biometric prompt, no screenshot blocking and no app-switcher privacy screen (read in
    `nsh-core-0.6.0/src`); passkeys need the platform's WebAuthn APIs. Plan (question 5):
    app lock by an in-app passcode now, on every platform (Argon2id, kept on the device); Face
    ID, fingerprint, screenshot blocking, hiding in the app switcher and passkeys with the
    host projects, after the whole app is built (as the owner chose for push).

14. **Scenes and sound stickers are references, not new services.** A chat scene is chat state
    (both sides see it, as an IMVironment): a `SceneChange` `DataMessage`, ordered like the
    timer change, naming a `Scene` pack item. A sound sticker is a `StickerRef` to a `Sounds`
    item. Emoticons are shortcodes the sender's installed packs resolve, with `EmoticonRef`s so
    the recipient can fetch the pack. The manifest's item limit drops to 16 MiB to match the
    server (a fix).

15. **Custom wallpapers need lasting storage.** Attachments expire after 30 days, so a custom
    wallpaper photo cannot live there. It is stored as a storage object beside the records,
    encrypted under the storage key, at most 2 MiB each and 16 per account, deleted with the
    account (like avatars).

16. **`SettingsSync` is superseded.** No released client uses it. The sync message becomes a
    "storage changed, fetch" signal for one's own online devices; the records hold the values.

## Every setting, and where it lands

"Record" = an encrypted synced record (M1, used by M5/M6). "Device" = kept on this device only,
encrypted at rest, not synced (as WhatsApp and Signal do for these). "Server" = a server-enforced
setting (threat model §4). "Profile" = inside the encrypted profile.

| Screen | Setting | Where | Milestone |
| --- | --- | --- | --- |
| You | Name, about, photo, status line with emoji and expiry | Profile, "profile changed" signal to contacts | M2, M6 |
| You | Presence: online, away, busy, invisible | Record (own choice) + sealed presence | M3, M6 |
| Account | Security notifications | Record | M5 |
| Account | Two-step PIN | Server (Prompt 3, live) | M5 |
| Account | Passkeys | Needs host projects (finding 13) | after the app |
| Account | Linked devices: list, link by QR, remove | Server (Prompt 3, live); storage key in provisioning v2 | M1, M5 |
| Account | Invites | Server (live already) | — |
| Account | Request account info, delete account | Server (Prompt 3, live); export covers the new stores | M1, M5 |
| Account | Inactivity period (6/12/24 months) | Server (Prompt 3); shown in Settings | M5 |
| Account | Username discoverability | Server (new) | M2, M5 |
| Privacy | Last seen, online ("same as last seen") | Record; sealed presence audience | M3, M6 |
| Privacy | Profile photo, about, status visibility | Record; profile fields and key rotation (finding 8) | M2, M6 |
| Privacy | Read receipts | Record | M5 |
| Privacy | Typing indicators (missing today, added) | Record | M5 |
| Privacy | Who can add me to groups | Server bit + record (Q6) | M2, M5 |
| Privacy | Message requests from everyone or nobody | Server (Prompt 4, live) | M5 |
| Privacy | Blocked contacts | Server (Prompt 4, live) + record | M5 |
| Privacy | Default message timer | Record | M5 |
| Privacy | App lock and its delay | Device; passcode now, biometrics later (Q5) | M5 |
| Privacy | Block screenshots, hide in app switcher | Device; needs host projects (Q5) | after the app |
| Privacy | Link previews | Record | M5 |
| Privacy | Protect IP address in calls | Record (relay-only, Prompt 7) | M5 |
| Privacy | Crash reports | Device | M5 |
| Chats | Default chat theme and wallpaper (built-in and custom) | Record; custom images as storage objects | M1, M5 |
| Chats | Animations, default reactions, keep chats archived | Record | M5 |
| Chats | Enter sends, save to photos | Device | M5 |
| Chats | Chat scenes and sound stickers autoplay; Stickers and packs | Record; packs list as records | M5, M6 |
| Chats | Chat backup, transfer | **Prompt 10** | — |
| Chats | Export chat, clear chat | Device (chat data is A2's) | M5 (on the mock) |
| Per chat | Mute until, archive, pin, favourite, lists, custom notification sound, reaction notifications, wallpaper, scene | Record keyed by a hashed chat ID; scene as chat state | M5, M6 |
| Appearance | Theme (system, light, dark, high contrast) | Record | M5 |
| Appearance | App icon | Record; Plus entitlement checked by the client, entitlements are **Prompt 11** (reads "not Plus" until then) | M5 |
| Notifications | Messages, groups, calls, reactions, sound, hide content, ringtone, message tone | Record | M5 |
| Storage and data | Auto-download per type on Wi-Fi and mobile, upload quality | Record | M5 |
| Storage and data | Low-data calls | Device | M5 |
| Storage and data / Proxy | Proxy from a link, on and off | Device; `crates/client` dials through the proxy (PROTOCOL §1.1, not built in the client yet) | M5 |
| Lists | Custom chat lists and favourites | Record | M5 |
| Broadcast lists | Lists and their members | Record | M5 |
| Starred messages | Starred set | Record (replaces the `starred` sync message) | M5 |
| Presence and nudges | Nudges on and off, per-contact off | Record | M3, M6 |
| Contacts (new screen) | Saved contacts: name, notes, buddy-list groups; "Save to contacts" | Record per contact | M1, M6 |
| Parental controls | Parent and child flows, rules, unlink | Server bits + signed policy | M4, M6 |
| Launch at login | Device (Prompt 8) | — |
| WhatsApp chats | **Prompt 14** | — |
| Subscription, plan | **Prompt 11** | — |
| Help and feedback, Invite a friend, Keyboard shortcuts, Server connection | No setting (pages and actions); unchanged | — |
| What Songbird can see | Copy updated to Prompt 9's facts | M6 |

## Architecture changes

- **`crates/sync`** (new, `#![forbid(unsafe_code)]`): record and manifest encodings (protobuf
  inside, padded), the HLC, per-key LWW merge with tombstones, storage-key derivation and
  AEAD, the compare-and-swap client loop. Pure and property-tested; decoders fuzzed.
- **Storage service in `api`** (SurrealDB, registry database):
  - `GET /v1/storage` (manifest, version and the ID list, optionally since a version);
  - `POST /v1/storage/read` (up to 1,024 IDs);
  - `PUT /v1/storage` (expected version, new manifest, inserts, deletes; one transaction;
    409 with the current version);
  - `PUT/GET /v1/storage/object/<id>` for wallpapers.
  Listed, non-pending devices only; caps per account (proposed: 10,000 records, 4 KiB each
  before padding, 16 MiB in all; M1 measures and sets them); a write budget per account in
  `valkey-hot`. In GDPR export (counts and sizes) and deletion (rows and objects).
- **Server-enforced bits** on the account row: `discoverable`, `groups_contacts_only`, and the
  supervision row (finding 12). Each changes `directory:v` so delivery and the send path
  reload. Loosening is the primary's (as for requests); a supervised account cannot loosen
  what its policy sets.
- **Ephemeral lane:** a `class` byte in a new `Ephemeral2` client frame (`typing`, `call`,
  `attention`); attention is budgeted per pair and per sender. `PUT /v1/ephemeral/sealed`
  (or its WebSocket twin, measured in M3) for batched sealed presence.
- **Content:** `Presence` (state, last seen minute, nonce), `ProfileChanged` (version; sent
  sealed, stored, `SILENT` so it wakes nobody), `SceneChange`, `EmoticonRef`, `StorageChanged`;
  `Nudge` moves to the attention class; the status expiry goes inside the profile blob.
- **Provisioning v2:** the plaintext gains the storage key.
- **Protocol:** PROTOCOL §10 written (records, manifest, presence, nudges, parental policy).

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **The record store:** `crates/sync`; the storage endpoints and tables; caps and the write budget; storage objects; provisioning v2; key rotation on device removal; GDPR export and deletion. | Convergence proptests (devices, offline edits, reordering, clock skew, tombstones past the horizon); the manifest catches withheld, replayed and rolled-back records (tests with a malicious server double); live tests on the compose stores: concurrent writers through compare-and-swap, caps, deletion leaves nothing; p99 of read and write recorded with the hardware; fuzzed decoders. |
| **M2** | **Server-enforced settings and profiles:** discoverability; "who can add me to groups" (Q6); the "profile changed" signal; status expiry and audience fields in the profile; threat model §4 completed (plan reserved for Prompt 11). | Live tests: a hidden username gives the same 404, budgets and timing as a miss; a commit adding a contacts-only account without its key is refused; a linked device cannot loosen either; each setting's server view matches the threat model row by row. |
| **M3** | **Presence and nudges:** sealed batched presence with debounce and limits; the attention class with pair and sender budgets; `Presence` and `Nudge` content. | Integration tests with real clients over the compose stack: **presence reaches only contacts holding a valid access key**, never strangers, never more than allowed; **invisible sends no frame at all** (counted at the server); the sender gets no signal of who is online; nudge budgets per pair and per sender hold across the cluster and fail closed; fan-out throughput and p99 for 1,024-device batches recorded. |
| **M4** | **Parental controls:** linking in person, the policy key, signed policies, server enforcement (requests, discoverability, group adds with approvals), automatic unlink on the date; GDPR Article 8 notes per country. | Tests: the child's devices cannot loosen a rule; an unsigned or replayed policy is refused; adds without approval are refused; the worker unlinks on the date; the server holds no parent account ID or birth date (schema test); compliance table checked against each country's law. |
| **M5** | **The app's settings, real:** local encrypted settings store, sync through `crates/sync` when registered, every "Record" and "Device" row above, the live server rows (PIN, requests, blocks, inactivity, discoverability, groups, export, linking, removal), typing toggle, passcode app lock, proxy dialing in `crates/client`. | Headless NSH tests: each setting survives a restart and reaches a second app instance through the live stack; two instances editing offline converge; app lock blocks the UI until the passcode; screenshots of every changed screen, light and dark. |
| **M6** | **The app's presence and extras:** presence dots in the chat list, statuses with expiry, last seen, nudges (shake, vibrate, per-contact off), contacts screen with notes and buddy groups and "Save to contacts", scenes in chats, sound stickers, emoticons, parental flows on both sides, the privacy page's copy. | Headless tests of each flow; two live instances: presence and nudges appear, invisible shows nothing, a status disappears at its expiry; the child's view lists every rule. |
| **M7** | **The gate:** the security review of the whole diff; fixes; `P09-gate.md`. | The prompt's gate item by item: convergence proptests pass; presence only to allowed contacts and nothing when invisible; nudge limits tested; the server's view of every setting matches the threat model. |

Order: M1 first (everything syncs through it). M2 and M3 need M1's crate only for the
profile and presence types and can run beside each other. M4 needs M2's server bits. M5 needs
M1 and M2; M6 needs M3 and M4. M7 needs everything.

## Threat-model rows this plan will propose

- §1: storage records: opaque bytes under random IDs, padded sizes, the count per account, a
  write counter; write times in memory only. The storage manifest (opaque, about 100 bytes) and
  its version. Storage objects (wallpapers): opaque, at most 16 per account.
- §1: the `discoverable` bit; the `groups_contacts_only` bit (if Q6).
- §1: supervision of a child account: the parent's policy public key (not linked to the
  parent's account by the server), the enforced rule bits, the policy version, the unlink date.
- §1: nudge budget records in `valkey-hot` (keyed hashes, an hour); the fact that a nudge
  happened between two accounts, in memory only.
- §1 (restated): sealed presence batches: recipients and timing in memory, never stored or
  logged; no sender.
- §3.26 (new STRIDE table): rollback and withholding of records, clock attacks on the HLC,
  record floods, presence probing, presence as a contact-graph leak, nudge harassment, a child
  loosening rules, a parent overreaching, forged policies.
- §4: discoverability, groups, the child's rules, inactivity (restated), plan (reserved for
  Prompt 11).
- §5: GDPR Article 8, the age of digital consent per EU country, and how the unlink date uses it.

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 to 8.

1. **Scope.** Recommended: the inventory above as written: every Settings row made real except
   backups (Prompt 10), subscription and plan (Prompt 11) and WhatsApp chats (Prompt 14); app
   lock by passcode now, biometrics, screenshot blocking, the app-switcher screen and passkeys
   with the host projects after the whole app is built. Tell me if any row should move.
2. **Record integrity.** Recommended: fresh IDs per write and an encrypted manifest written in
   the same compare-and-swap, as Signal's storage service (finding 2). The alternative, per
   record LWW without a manifest, is simpler but lets the server withhold or roll back records
   unseen.
3. **Presence transport.** Recommended: sealed, batched, gated by the recipients' access keys
   (finding 6). The server learns who receives presence, not who sends it, beyond IP and timing
   correlation. The alternative: identified batches on the WebSocket, simpler, but the server
   sees each user's contact list in memory at every presence change.
4. **Last seen for contacts who were offline.** Recommended: ephemeral only, with the last
   cached value or "last seen recently" (finding 7); no new server state. The alternative: an
   encrypted last-seen blob on the server, as WhatsApp behaves.
5. **App lock and the host-only settings.** Recommended: passcode lock now on every platform;
   biometrics, screenshot blocking, the app-switcher screen and passkeys with the host projects
   (finding 13). The alternative: hide those rows until then.
6. **Who can add me to groups.** Recommended: a server-enforced "contacts only" bit, proved by
   the access key on the commit; "Nobody" as an invite to accept (finding 10). The server learns
   one more bit per account. The alternative: client-only, where a stranger's add still lands
   and the app leaves the group.
7. **Profile visibility choices.** Recommended: "My contacts" and "Nobody" for photo, about and
   status, because "Everyone" cannot decrypt the profile anyway (finding 8). The alternative: a
   second, wider profile key for "Everyone", shared with message requests.
8. **Parental controls.** Recommended: the design in finding 12: the server stores a policy key
   unlinked to the parent's account, the rule bits, a version and the unlink date, never the
   parent's identity or the child's birth date. Please also confirm: **may a supervised child
   delete their own account?** Recommended yes (GDPR Article 17 is the child's right; the
   parent is not told); the alternative needs the parent's signature.
9. **Defaults.** Recommended, as WhatsApp: last seen, online, photo, about and status visible
   to "My contacts"; read receipts and typing on; discoverability on; groups "contacts only";
   nudges on but never sent by surprise (a confirm the first time). The Proton-strict
   alternative: last seen and online "Nobody" by default.
10. **Agent decisions, recorded unless you object:**
    - the new crate `crates/sync`, used by the app now and by app-core later;
    - HLC with a 24-hour clamp; tombstones kept 90 days;
    - Padmé padding of records; write counters, not times;
    - AES-256-GCM-SIV under per-record keys from the storage key; the key in provisioning v2;
      rotation on device removal;
    - caps measured in M1 (10,000 records, 16 MiB proposed);
    - custom wallpapers as storage objects (2 MiB, 16 per account);
    - nudges identified in an attention class, lost when the contact is offline; the stored
      `Nudge` kind removed;
    - discoverability off keeps links and QR codes working;
    - `SettingsSync` and the `starred` sync message replaced by records and a "storage
      changed" signal;
    - the pack manifest's item limit lowered to 16 MiB;
    - `crates/client` learns to dial through a Songbird proxy;
    - one branch and one PR for every milestone.
