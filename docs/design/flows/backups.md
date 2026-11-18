# Flow: backups and transfer (A11, Prompt 10)

**Goal:** a WhatsApp user turns on a backup in under three minutes, to the storage they already
use, understanding that only their recovery key opens it. Module: `features/backups.rs`. Data:
`Settings::backup_*`, `BackupDestination`.

## Entry points

You › Backups; one-time card in Chats after day 1 ("Don't lose your chats"); Onboarding ›
I have Songbird elsewhere › Restore; Trust copy in Privacy centre.

## Steps: turn on

| # | Screen | Content | Action |
| --- | --- | --- | --- |
| 1 | Backups (off) | "Back up your chats so you can restore them on a new phone, even an iPhone after Android." | **Turn on backups** |
| 2 | Where | Destinations: Songbird servers (included space by plan), iCloud Drive (iOS), Google Drive, OneDrive, Dropbox, Nextcloud (WebDAV), S3 bucket, Encrypted file (manual). Footnote: "Wherever you choose, only your recovery key can open it." | Pick |
| 3 | Connect (third-party) | OS/browser sign-in to the provider (app folder only); "Songbird gets access only to its own folder." | Provider sign-in |
| 4 | Options | Include photos and videos (off on mobile data), Back up daily (on) / weekly, Only on Wi-Fi (on) | **Back up now** |
| 5 | Recovery key check | If the key wasn't confirmed in onboarding: confirm two groups | Confirm |
| 6 | Progress | "Backing up… 340 MB of 1.2 GB" (can leave the screen; progress in You row) | — |
| 7 | Done | "Last backup: today, 14:02 · 1.2 GB · Google Drive" | — |

## Backups page (on)

Last backup (time, size, destination), Back up now, Destination (change), Include media, Frequency,
Only on Wi-Fi, Recovery key (view, needs device unlock), Transfer to a new device, Export to a file,
Turn off backups ("Deletes the backup from {destination}" confirm).

## Steps: restore

Welcome › "I have Songbird on another device" › **Restore from a backup** › choose where it is
(Songbird servers finds the vault from the recovery key alone; others sign in) › enter recovery key
(paste, groups) › PIN/passkey if set › "Restoring… 2,431 messages" › chats appear; system line in
each chat "Restored from backup. Messages after {date} aren't included."; key-change lines are not
shown to contacts for a restore (identity key survives, Prompt 10).

## Steps: transfer (device to device)

Old device: You › Backups › Transfer to a new device → QR. New device: Welcome › I have Songbird
elsewhere › Transfer → scan → both show the same code → transfer over local network with progress
→ old device: "Transfer finished. This phone is still signed in." (linked or primary handover per
Prompt 10).

## States

| State | Copy |
| --- | --- |
| Off | Row value "Off"; after 7 days a single reminder card |
| Backup failed (network) | "Last backup didn't finish. We'll try again on Wi-Fi." |
| Destination full / quota | "There's no room left in {destination}. Free up space or choose another place." |
| Provider signed out | "Sign in to {destination} again to keep backing up." |
| Corrupted chunk on restore | "Part of this backup is damaged, so we stopped. Nothing was changed on this device. Try another backup." (never restores silently) |
| Wrong recovery key | "That recovery key doesn't open this backup. Check it and try again." |
| Lost key | "Without your recovery key, nobody can open this backup — not even Songbird." + "Start fresh" |
| Older app reading newer backup | "Update Songbird to restore this backup." |

## Copy

| Key | String |
| --- | --- |
| bk.intro | Back up your chats so you can restore them on a new phone, even an iPhone after Android. |
| bk.where.foot | Wherever you choose, only your recovery key can open it. |
| bk.provider.scope | Songbird gets access only to its own folder. |
| bk.last | Last backup: {when} · {size} · {destination} |
| bk.restored | Restored from backup. Messages after {date} aren't included. |

## Accessibility

Progress announced at 25 % steps and completion; recovery key entry accepts paste and spaces;
destination list is a radio group.

## Motion

Progress ring/bar fills continuously (reduced: step updates); done check `BASE`.

## Open questions (owner)

1. Default destination per platform: iCloud on iOS, Google Drive on Android (WhatsApp habit) or
   Songbird servers?
2. Included Songbird vault space per plan (Prompt 11).
3. Backup reminder cadence: once after day 1 and once after day 7, then never?
