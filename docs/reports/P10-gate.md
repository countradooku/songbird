# P10 gate — Cloud-agnostic user backups

- Date: 2026-11-19
- Plan: [P10-plan.md](P10-plan.md) (D-0119, approved by the owner on 2026-11-19, "Approve all")
- Milestones:
  - [M1](P10-M1.md) the format: keys, chunks, the chunker, the manifest, vectors (D-0120);
  - [M2](P10-M2.md) one store interface, the conformance suite, the Songbird vault (D-0121);
  - [M3](P10-M3.md) S3, `WebDAV`, Google Drive, OneDrive, Dropbox and the iCloud interface (D-0122);
  - [M4](P10-M4.md) account recovery, the transfer to a new phone, restore across platforms, the
    incremental cost (D-0123);
  - [M5](P10-M5.md) the app's recovery key, backups, restore and transfer (D-0124).
- The security review's fixes: D-0125.
- Branch `claude/p10-backups-40584b`.
- Status: **waiting for the owner**, with the threat-model rows (THREAT_MODEL §1, §3.27, §6).

## The gate, item by item

| Gate item | Result | Evidence |
| --- | --- | --- |
| All adapters pass the conformance suite | **Pass** | One suite (`songbird_backup_storage::conformance`): open, put/get/list/delete, the manifest's compare-and-swap with eight racing writers, a full backup and restore, an interrupted run, rollback and fork, destroy. Passed by memory, folder and archive (`memory_conforms`, `a_folder_conforms`, `an_archive_file_restores_and_refuses_damage`); the Songbird vault on the compose stack (`gate_p10::the_vault_passes_the_conformance_suite`); S3 on RustFS 1.0.5 and `WebDAV` on Apache 2.4.66 `mod_dav` (`adapters_live`); Google Drive, OneDrive and Dropbox against emulators of their documented APIs (`clouds.rs`); the iCloud interface with its reference bridge. `WebDAV` was also run once against a real Nextcloud 31.0.14 (213 s). `WebDAV` and Drive have no atomic swap: the suite checks the weaker rule they meet (a lost race is always reported, never silent; D-0122) |
| Cross-platform restore passes | **Pass** | `platforms::a_backup_from_any_platform_restores_on_every_other`: iOS, Android, Windows, macOS and Linux each write what that platform tends to produce (CRLF, decomposed Unicode, backslashes, emoji, right-to-left text, non-UTF-8 bytes, a 1.3 MB video); every one restores byte for byte on every other, through a folder and through an exported single file, and the same history makes the same chunks whatever writes it. The byte-exact vectors are re-derived by Python on x86_64 and i686 in CI (`backup-determinism`). The app restores its own backup through the real screens (`Screens_backups.test.tsx`) |
| Corruption tests pass | **Pass** | `damaged_chunks_fail_loudly`, `damaged_manifests_fail_loudly`, `staging_changed_after_verification_fails_on_read` (M1): a flipped bit, truncation, extension, a swapped or foreign chunk, a missing chunk, a damaged manifest and a too-new one all fail loudly, and nothing is written before everything is verified. Rollback and fork: `a_store_cannot_roll_back_or_fork_a_device_that_has_seen_a_backup`, `a_store_that_lost_a_seen_backup_is_reported`. Over the wire: an archive whose length doesn't match its index; an oversized object (`an_oversized_object_is_refused_before_it_is_kept`); tampering in transit during a transfer (`a_relay_with_another_code_and_tampering_in_transit_both_fail`). Fuzz target `backup_format` ran about 1.5 million inputs clean |
| Incremental backup cost measured for a large simulated history | **Pass** | M4: a million messages in 2,000 chats, 22,000 media, 1,649 MB of plaintext. On the vault: the first backup 651 chunks / 1,670 MB; nothing changed 0; a day of messages in every chat **1 chunk / 1.5 MB**; the 25 oldest messages of every chat deleted 7 chunks / 19.5 MB. The first measurement found chat-by-chat ordering cost 158 MB a day; ordering messages by time across chats fixed it (D-0123). `cost.rs` (in memory, every CI run on a smaller history) and `gate_p10::incremental_cost_on_the_vault` (ignored by default: 1.7 GB into the compose RustFS) |

## Tests and checks run (Apple M5 Pro, macOS 27.2.1; compose stores under podman; no Iggy locally)

- `cargo xtask ci fast`, after the review's fixes: **pass**.
  - workflow policy, push-credential scope, rustfmt, clippy (pedantic, `-D warnings`);
  - nextest **878 of 878** (11 skipped: live tests without their stores);
  - doctests, rustdoc (`-D warnings`), cargo deny, audit and vet;
  - smoke (every service starts, serves health and metrics, drains on SIGTERM).
- The live suites, after the review's fixes, two jobs at a time for the stores and e2e and one at
  a time for the api, with the compose job's environment (`WebDAV` on Apache included):
  - surreal, mailbox, router, s3, accounts, admin, akd, backup-storage (S3 on RustFS and
    `WebDAV` on Apache conform) and worker: **230 of 230**;
  - songbird-e2e, every gate: **78 of 79**; the P10 gate's six tests all pass;
  - songbird-api: **78 of 80**; jobs **14 of 14**; push **12 of 12**.
  - The three failures are this Mac's loopback, not Prompt 10: `gate_p06::an_encrypted_file_…`,
    `api_live::attachments_upload_exactly_…` and `media_live::fetches_are_confirmed_…` confirm a
    fetch from 127.0.0.2, which macOS's `lo0` lacks (status 0); Linux CI answers on all of
    127.0.0.0/8. Prompt 10 changed none of them.
  - Under heavier parallelism (nine packages at once) the P10 vault conformance, the vault
    latency, the M5 deletion and the P07 webhook tests timed out once; each passes alone and at
    two jobs. CI runs them as its compose job does.
- The vectors: `vectors/check.py` (the format) and `transfer_check.py` (the handshake and its
  commitment) re-derive every byte from the specifications with the Python standard library.
- The app (`apps/ui`): **201 of 201** unit tests, among them a whole transfer between two
  backends and a backup restored with its key; `Screens_backups.test.tsx` **9 of 9**
  headless and on `--target macos` (screenshots light and dark, desktop and phone, two app
  instances moving a history, each confirming the six digits).
- Fuzz target `backup_format`: about 1.5 million inputs clean locally; ten minutes nightly in
  `ci full`.
- The incremental cost on the vault (1.7 GB into the compose RustFS) was run once in M4; the
  review's fixes don't touch what it measures (a pre-swap listing is one request per 1,000
  chunks).

## Security review

An independent read-only review of the whole diff was done by a separate agent, given the code and
the specifications, not the reports. It found no critical issue: the format's cryptography, the
Noise handshake checked against revision 34, the vault's authorization, its bounds and the token
kinds held. It found 1 medium–high, 3 medium, 4 low and 5 informational issues. Each was checked in
the code and fixed with a test, except where recorded (D-0125).

| Finding | Fix | Test or check |
| --- | --- | --- |
| Medium–high: someone who saw the transfer code could grind responder keys until both phones showed the same six digits, and the new phone applied what it got without its user's word | The new phone commits to its key before the first message; the new phone asks "Does your old phone show this code?" and answers and applies nothing before | `a_reply_must_carry_the_key_committed_to_before_the_first_message`; the vector and `transfer_check.py`; `Screens_backups.test.tsx` |
| Medium: two uploads racing for one name could count a small object and store a large one; an upload landing after its chunk was forgotten stayed uncounted | A recorded name must come with its size (409 `size`); an upload rechecks its chunk after storing and deletes its object if forgotten | `a_name_keeps_its_size_and_late_uploads_leave_nothing` |
| Medium: an upload in flight when a vault was turned off could outlive it; a stale swap could land in a re-created vault | Every write checks the vault's epoch in its transaction; a turned-off vault's prefix is swept again for 15 minutes | same test; `turning_backups_off_and_deleting_the_account_leave_nothing` |
| Medium: a stranger could block a primary's hand-over and linking; the recovery endpoint told whether an account exists | Hand-overs on their own budget; only link tokens count towards the device limit; an unknown account gets a token never stored | `strangers_asking_for_recovery_tokens_block_neither_hand_over_nor_linking` |
| Low: one silent connection stalled the transfer listener | 20 s per handshake, eight at once | `a_connection_that_stalls_does_not_hold_up_the_old_phone` |
| Low: a malicious store could make a restore keep huge objects | Refused above the largest chunk before staging; archive entries bounded | `an_oversized_object_is_refused_before_it_is_kept` |
| Low: two runs on one device could leave a backup naming a collected chunk | Runs to one kind of store take turns; reused chunks checked before the swap | `runs_at_once_never_leave_a_backup_naming_missing_chunks` |
| Low: `WebDAV` sent the app password over plain `http://` | `https://` only, except to the device itself (S3 too) | `a_password_never_goes_over_plain_http_to_another_computer` |
| Info: rollback and fork judged on an unauthenticated header | Judged after the tag | the garbage case in `a_store_cannot_roll_back_or_fork…` |
| Info: the transfer's record limit was below the largest manifest | The limit is the largest chunk or manifest object | `ci fast` |
| Info: the recovery key alone takes over an account without a PIN | Said where the app shows the key and in the Settings help; PROTOCOL §4.11 | — |
| Info: OAuth `state` not checked | Nothing calls the OAuth flow yet; checked when the redirect handler is wired | recorded (D-0125) |
| Info: the recovery secret in plain app storage | Recorded: the A0 mock, the keychain with app-core | — |

## Not verified

- **The three OAuth clouds against the real services.** Google Drive, OneDrive and Dropbox pass
  the suite against emulators written from their documented APIs; the real services need the
  OAuth apps the owner registers (D-0119 §6). Until then the app says "Coming soon" for them.
- **iCloud Drive's native half.** The interface and its reference bridge pass the suite; the
  Swift side that meets it comes with the native host projects.
- **The transfer between two real phones.** Two app instances on one Mac move a history through
  the real screens; two phones on one Wi-Fi with cameras have not been tried (as for Prompt 9's
  linking).
- **A brand-new device cannot detect a rollback** of a backup it has never seen: it restores
  whatever latest manifest the store serves (stated in THREAT_MODEL §6).
- **Screens on a running app:** checked headless and in macOS screenshots, light and dark, desktop
  and phone sizes; not on a phone.

## Threat model

For the owner's approval:
- THREAT_MODEL §1: the rows for vaults, vault throttle records, `vault_gone` and recovery tokens.
- §3.27: every row, the review's rows included.
- §6: the open risk of third-party clouds and of a new device's rollback.

## For the owner

1. Approve the gate, with the threat-model rows.
2. Register the Google, Microsoft and Dropbox OAuth apps (D-0119 §6), so the desktop sign-in can
   be wired and checked against the real services.
3. The two api live tests that fail on this Mac only (they send from 127.0.0.2, which macOS's
   loopback lacks) pass on Linux CI; Prompt 10 did not change them.
4. Nothing is merged.
