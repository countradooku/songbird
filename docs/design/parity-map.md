# WhatsApp parity map

Every WhatsApp screen and setting (iOS and Android, 2026 builds, EU) mapped to where it lives in
Songbird. Status: **Same** (same name, same place), **Renamed**, **Moved**, **New** (Songbird-only,
listed at the end), **Not in Songbird** (with the reason). Paths use `Tab › page › row`; the You
tab tree is specified in `flows/settings.md`.

Desk mapping from knowledge of the apps; WhatsApp moves items between releases and between iOS
and Android. The owner's own WhatsApp screenshots (`reference/README.md`) are the check: any row
they contradict gets fixed here.

Recurring reasons:

- **R1 No phone number.** Songbird identifies people by username (D-0049); no SIM, no address
  book upload.
- **R2 No Status/Stories.** IA decision (`ia.md` §4): the "status line" (Yahoo-style custom
  status) and presence replace it.
- **R3 No Meta services.** Meta AI, Meta avatars, payments, business tools, Meta Verified and
  ads do not exist in Songbird.
- **R4 Server cannot see it.** The feature would need plaintext on the server; outside
  `THREAT_MODEL.md` §1.

## 1. Settings root

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Settings (tab, iOS) / ⋮ › Settings (Android) | You (tab) | Renamed, Moved | A tab on every platform; profile at the top. |
| Profile header (photo, name, about) | You › profile card › Edit profile | Same | Plus @username, status line and presence. |
| Your QR code | You › profile card › QR button | Moved | Encodes the username link, not a phone number (R1). |
| Avatar | — | Not in Songbird | R3. Stickers and packs (A7) cover expression. |
| Lists | You › Chats › Lists; also Chats › filter chips › Edit | Moved | Synced as encrypted records (Prompt 9). |
| Broadcasts / Broadcast lists | Chats › New (+) › New broadcast; You › Chats › Broadcast lists | Moved | D-0062 broadcast lists. |
| Starred (iOS settings root) | Chats › ⋯ › Starred; You › Starred messages | Same | |
| Linked devices | You › Account › Linked devices; also Chats › ⋯ › Linked devices | Moved | Up to 5 (D-0052). |
| Account | You › Account | Same | |
| Privacy | You › Privacy | Same | Opens with the Privacy centre card. |
| Chats | You › Chats | Same | |
| Notifications | You › Notifications | Same | |
| Storage and data | You › Storage and data | Same | |
| Accessibility | You › Accessibility | Same | |
| App language | You › Language | Renamed | |
| Help / Help and feedback | You › Help | Same | |
| Invite a friend | You › Invite friends | Renamed | Shows invites left (invite-only beta, D-0038). |
| Meta AI / AI settings | — | Not in Songbird | R3 and R4. |
| Payments (IN/BR) | — | Not in Songbird | R3. |
| Business tools / Meta Verified | — | Not in Songbird | R3. Teams plan later (Prompt 11). |
| App updates (Android) | — | Not in Songbird | Store/OS handles updates; desktop: You › Help › About › Check for updates. |

## 2. Account

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Security notifications | You › Account › Security › Security notifications | Moved | On by default; key changes always appear in the chat (trust.md). |
| Passkeys | You › Account › Security › Passkeys | Moved | D-0053. |
| Email address | — | Not in Songbird | Recovery is the recovery key + PIN/passkey; an email would link identity (R4). Owner may revisit for Plus support. |
| Two-step verification (PIN) | You › Account › Security › Two-step PIN | Renamed | 6–12 digits (PROTOCOL §4.7). |
| Change number | You › Account › Username | Renamed | R1. Changing frees the old name after 30 days. |
| Request account info | You › Account › Request my data | Renamed | GDPR export (D-0056). |
| Add account | You › Account › Add account | Same | Multiple accounts (D-0053). |
| Delete account | You › Account › Delete account | Same | Plus "Delete if inactive for…" (D-0056). |
| Third-party chats (EU DMA) | You › WhatsApp chats | Renamed | A15; legal gate (Prompt 14). |
| Username (WhatsApp, rolling out) | You › Account › Username, Username key, Link | Same | Songbird's primary identity. |

## 3. Privacy

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Privacy checkup | You › Privacy › Privacy centre › Check my settings | Renamed | Five-step walkthrough. |
| Last seen and online | You › Privacy › Last seen; Online | Same | Plus presence (online, away, busy, invisible). |
| Profile photo | You › Privacy › Profile photo | Same | Everyone / My contacts / Nobody. |
| About | You › Privacy › About | Same | |
| Links (profile links) | — | Not in Songbird | Not planned; About can hold a link. |
| Groups (who can add me) | You › Privacy › Who can add me to groups | Same | Others send an invite instead. |
| Avatar stickers | — | Not in Songbird | R3. |
| Status (privacy) | You › Privacy › Status line | Renamed | R2: governs the status line. |
| Live location | You › Privacy › Live location | Same | Lists chats where it is being shared. |
| Calls › Silence unknown callers | You › Privacy › Calls › Silence unknown callers | Same | |
| Calls › Protect IP address in calls | You › Privacy › Calls › Relay all calls | Renamed | All group calls go through the SFU anyway (Prompt 7). |
| Contacts › Blocked contacts | You › Privacy › Blocked | Renamed | |
| Disappearing messages › Default message timer | You › Privacy › Default message timer | Same | Off, 24 h, 7 days, 90 days. |
| Read receipts | You › Privacy › Read receipts | Same | Plus Typing indicator toggle (Prompt 9). |
| App lock / Screen lock | You › Privacy › App lock | Same | Biometrics or device code. |
| Chat lock (hide locked chats, secret code) | You › Privacy › Chat lock | Same | Per chat in Chat info › Lock chat. |
| Allow camera effects | You › Privacy › Camera effects | Same | Effects run on the device. |
| Advanced › Block unknown account messages | You › Privacy › Message requests › Everyone / Nobody | Renamed | Server-enforced (Prompt 9). |
| Advanced › Disable link previews | You › Privacy › Link previews | Same | Previews fetched by the sender's device. |
| Advanced chat privacy (per chat) | Chat info › Advanced chat privacy | Same | Blocks export and auto-save for everyone in the chat. |
| — (no equivalent) | You › Privacy › Find me by username | New | Discoverability, server-enforced. |
| — | You › Privacy › Screen security | New | Block screenshots, hide in app switcher. |
| — | You › Privacy › Parental controls | New | Prompt 9 supervised accounts. |

## 4. Chats

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Theme | You › Chats › Appearance › Theme | Moved | System, Light, Dark, High contrast. |
| Default chat theme / Wallpaper | You › Chats › Appearance › Chat wallpaper | Moved | Plus chat scenes (Prompt 9). |
| Font size (Android) | You › Accessibility › Text size | Moved | Follows the OS by default. |
| Enter is send (Android) | You › Chats › Enter sends | Same | Desktop default on. |
| Media visibility (Android) / Save to Photos (iOS) | You › Chats › Save to Photos | Same | |
| Keep chats archived | You › Chats › Keep chats archived | Same | |
| Voice message transcripts | You › Chats › Voice message transcripts | Same | On-device only (R4). |
| Animations (emoji, stickers, GIFs) | You › Chats › Appearance › Animations | Same | Also follows reduced motion. |
| Chat backup | You › Backups | Moved | Top-level; any storage (Prompt 10). |
| Transfer chats (to new phone / to iOS/Android) | You › Backups › Transfer to a new device | Moved | Local network transfer (Prompt 10). |
| Export chat (all, iOS) | Chat info › Export chat | Moved | Per chat only. |
| Archive all chats | You › Chats › Archive all chats | Same | |
| Clear all chats | You › Chats › Clear all chats | Same | |
| Delete all chats | You › Chats › Delete all chats | Same | |
| App language (Android, in Chats) | You › Language | Moved | |
| — | You › Chats › Default reactions | New | WhatsApp has it only in the reaction picker. |
| — | You › Chats › Nudges; Sound stickers | New | Yahoo-style extras (Prompt 9). |

## 5. Notifications

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Conversation tones | You › Notifications › In-app sounds | Renamed | |
| Messages: show notifications, tone, vibrate, popup, light, high priority | You › Notifications › Messages (on, sound, vibrate) | Same | Popup/light/high priority are Android channel settings: "Android settings" row opens them. |
| Reaction notifications (messages) | You › Notifications › Messages › Reactions | Same | |
| Groups: same set | You › Notifications › Groups | Same | Plus "Only @mentions". |
| Reaction notifications (groups) | You › Notifications › Groups › Reactions | Same | |
| Calls: ringtone, vibrate | You › Notifications › Calls | Same | |
| Status notifications / reactions | — | Not in Songbird | R2. |
| Show preview | You › Notifications › Show message content | Renamed | Default on; push payload never contains content anyway (Prompt 8). |
| Clear badge | You › Notifications › Badge count | Renamed | |
| In-app notifications (banners, sounds, vibrate) | You › Notifications › In-app | Same | |
| Reminders | You › Notifications › Reminders | Same | Unanswered messages; off by default. |
| Reset notification settings | You › Notifications › Reset | Same | |
| — | You › Notifications › Sound style (Calm / Playful) | New | brand.md §6. |
| — | You › Notifications › Nudges | New | |

## 6. Storage and data

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Manage storage | You › Storage and data › Manage storage | Same | Largest chats, large files, forwarded many times. |
| Network usage | You › Storage and data › Network usage | Same | Counted on device. |
| Use less data for calls | You › Storage and data › Low data calls | Renamed | Prompt 7 low-data mode. |
| Proxy | You › Storage and data › Proxy | Same | `songbird://proxy#host` (D-0011). |
| Media upload quality (Standard / HD) | You › Storage and data › Upload in HD | Renamed | Toggle; per-send HD chip stays. |
| Media auto-download (mobile, Wi-Fi, roaming) | You › Storage and data › Auto-download | Same | Photos, Audio, Videos, Documents × (mobile, Wi-Fi). Roaming: off for all. |
| Reset auto-download settings | You › Storage and data › Auto-download › Reset | Same | |

## 7. Accessibility, language, help, invite

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Accessibility › Increase contrast | You › Accessibility › High contrast | Same | Same as Theme › High contrast. |
| Accessibility › Animations | You › Accessibility › Reduce motion | Renamed | Defaults to the OS. |
| App language | You › Language | Same | Romanian, English first; RTL ready. |
| Help centre | You › Help › Help centre | Same | |
| Contact us | You › Help › Contact support | Renamed | User-initiated only; logs only with consent (Prompt 11). |
| Terms and privacy policy | You › Help › Terms and privacy | Same | |
| Channel reports | You › Help › My reports | Renamed | Reports on chats and groups. |
| App info / Licences | You › Help › About (version, licences, transparency report) | Same | |
| Invite a friend | You › Invite friends | Same | Personal invite code/link; no contact upload. |

## 8. Chats tab and chat list

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Chats list | Chats | Same | |
| Search (messages, chats, media types) | Chats › search field | Same | Local only. |
| Filters: All, Unread, Favourites, Groups, custom lists | Chats › chips: All, Unread, Favourites, Groups, Channels, custom lists | Same | Channels chip is new (ia.md §3). |
| Archived | Chats › Archived row (top) | Same | |
| New chat (+): New group, New contact, New community, contacts list | Chats › New (+): New group, Find by username, Scan QR, New community, New broadcast, Invite | Renamed | "New contact" becomes Find by username (R1). |
| Message yourself | Chats › New › Note to self | Renamed | |
| Swipe: archive, more (mute, delete, lock, add to list) | Same gestures; long-press menu on desktop | Same | |
| Pin chat (3) | Pin (up to 5) | Same | |
| Mark as unread | Same | Same | |
| Camera button (iOS header) | — | Not in Songbird | Camera lives in the composer; the header keeps search and New. |
| Meta AI button / search | — | Not in Songbird | R3. |
| Message requests (unknown senders) | Chats › Message requests row | New | D-0062. |

## 9. Chat screen

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Header: name, photo, status → Chat info | Same | Same | Plus status line and verified shield. |
| Header: voice call, video call | Same | Same | |
| Menu: View contact / Group info | ⋯ › Chat info | Renamed | |
| Menu: Search | ⋯ › Search | Same | |
| Menu: Media, links and docs | ⋯ › Media, links and files | Renamed | |
| Menu: Mute notifications | ⋯ › Mute | Same | 8 h, 1 week, Always. |
| Menu: Disappearing messages | ⋯ › Disappearing messages | Same | |
| Menu: Wallpaper / Chat theme | ⋯ › Chat wallpaper | Same | |
| Menu: More › Report, Block, Clear chat, Export chat, Add shortcut, Add to list | ⋯ › Report, Block, Clear chat, Export chat, Add to home screen, Add to list | Same | |
| Encryption notice at top | Same | Same | trust.md. |
| Composer: emoji / sticker / GIF | Same (one Smile button, three tabs) | Same | GIF search through Songbird's proxy (D-0083). |
| Attach: Document, Camera, Gallery/Photos, Audio, Location, Contact, Poll, Event, New sticker | Attach sheet: Photos, Camera, File, Location, Contact, Poll, Event, Sticker pack | Same | |
| Attach: Payment | — | Not in Songbird | R3. |
| Camera button (composer) | Same | Same | |
| Voice message (hold, lock, pause, preview) | Same | Same | |
| View once (photo, video, voice) | Same | Same | |
| HD toggle in media editor | Same | Same | |
| Message actions: React, Reply, Forward, Copy, Info, Star, Pin, Edit (15 min), Delete for me / everyone, Report, Select, Keep in chat, Save | Same set; Edit window 15 min | Same | Message info shows per-member receipts (D-0060). |
| Translate (on device) | — | Not in Songbird (yet) | Candidate for later; must stay on device. |
| Swipe to reply | Same | Same | |
| Reply privately (group) | Same | Same | |
| Mentions (@), @all | Same | Same | @all for admins only by default. |
| Polls, events | Same | Same | |
| Chat scenes, nudge | Chat ⋯ › Nudge; scenes in wallpaper | New | Yahoo-style. |

## 10. Contact info (1:1)

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Photo, name, phone number | Photo, name, @username, status line | Renamed | R1. |
| Audio, Video, Search buttons | Same | Same | |
| About | Same | Same | |
| Media, links and docs | Same | Same | |
| Starred messages | Same | Same | |
| Notifications (custom tone, mute) | Same | Same | |
| Chat theme / wallpaper | Same | Same | |
| Save to Photos (per chat) | Same | Same | |
| Disappearing messages | Same | Same | |
| Chat lock | Same | Same | |
| Advanced chat privacy | Same | Same | |
| Encryption › Verify security code | Encryption › Safety number | Renamed | Signal's term; `flows/safety-number.md`. |
| Groups in common | Same | Same | Computed on device. |
| Add to Favourites / Add to list | Same | Same | |
| Share contact | Share contact | Same | Shares the username. |
| Export chat | Same | Same | |
| Clear chat | Same | Same | |
| Block | Same | Same | |
| Report | Same | Same | Franked report (D-0063). |
| Edit contact (phone book) | Edit name (local nickname) | Renamed | Encrypted contacts sync (Prompt 9). |
| — | Nudges from this person on/off | New | |

## 11. Group info

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Group name, photo, description | Same | Same | Encrypted metadata (D-0070). |
| Audio, Video, Search, Add buttons | Same | Same | |
| Members list, admins | Same; roles Owner, Admin, Member | Same | |
| Add members | Same | Same | Respects "who can add me". |
| Invite via link / QR (reset link) | Invite link (share, QR, reset, approval on/off) | Same | Server cannot read the link (D-0071). |
| Pending participants / approve new members | Join requests | Renamed | |
| Group permissions: Edit group settings, Send messages, Add other members, Approve new members | Permissions: Edit info, Send messages, Add members, Approve joins, Pin messages, Start calls, Admins delete any message | Same | `GroupPermissions`. |
| Edit group admins | Member › Make admin / Remove admin | Moved | |
| Media, Starred, Notifications, Wallpaper, Save to Photos, Disappearing, Chat lock, Encryption, Advanced chat privacy | Same | Same | Encryption shows "Messages and calls are end-to-end encrypted" and the change log. |
| Events | Group info › Events | Same | |
| Add group to community | Group info › Community › Add to community | Same | |
| Exit group | Leave group | Renamed | |
| Report group | Same | Same | |
| Group created by / date | Change log (who did what) | Renamed | Encrypted log (D-0070). |
| Phone numbers visible to members | — | Not in Songbird | R1: only usernames, and only to members. |

## 12. Communities

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Communities tab (Android) / tab on iOS | Communities (tab) | Same | |
| New community (name, description, icon) | Communities › New community | Same | |
| Announcements group | Community home › Announcements | Same | Admin-only posting (D-0072). |
| Groups in the community; add existing; create new | Same | Same | Up to 100 groups. |
| Join a group in the community / request | Same | Same | |
| Invite members | Same | Same | Joining = joining Announcements (PROTOCOL §6.9). |
| Community settings (who can add groups) | Community info › Permissions | Same | |
| Members list | Community info › Members | Same | |
| Deactivate community | Community info › Delete community | Renamed | Groups stay. |
| Exit community | Same | Same | |
| Report community | Same | Same | |
| Community events | Community home › Events | Same | |

## 13. Channels

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Updates tab › Channels | Chats › Channels chip; Communities › Channels section | Moved | ia.md §3. |
| Find channels / directory | — | Not in Songbird | Public channels not built (D-0065 §4); only private channels joined by link. |
| Follow / Unfollow | Join / Leave | Renamed | Private channels: join by link. |
| Channel info, mute, share, report | Same | Same | |
| Create channel | Communities › New channel; Chats › New › New channel | Moved | Up to 2,048 devices (D-0072). |
| Channel admins, invite admins | Same | Same | |
| Reactions allowed setting | Same | Same | |
| Polls in channels | Same | Same | |
| Forward from channel | Same | Same | |
| Channel insights / follower counts | Follower count only | Renamed | No analytics (R4). |
| Verified channels | — | Not in Songbird | R3. |

## 14. Calls tab

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Recent calls list (missed in red) | Same; missed shown with icon + label, not colour alone | Same | |
| Start call (pick people) | Calls › New call | Same | Up to 32 video / 128 audio (D-0085). |
| Create call link | Calls › Create call link | Same | Lobby on/off (D-0088). |
| Schedule call | Calls › Schedule | Same | An event in the chat with a call link. |
| Favourites row | Calls › Favourites | Same | |
| Call info (details, duration) | Same | Same | |
| Clear call log | Calls › ⋯ › Clear call log | Same | |
| Keypad / call a number | — | Not in Songbird | R1. |
| In-call: mute, speaker, camera on/off, flip, add people, screen share, raise hand, reactions, effects, background blur, low light, PiP, end | Same set | Same | Effects on device. |
| Call verification (emoji/code, 2026) | In-call › Verify (shows the call's code) | Same | A8. |

## 15. Status tab

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Updates › Status (my status, contacts' statuses) | — | Not in Songbird | R2. |
| Text / photo / video / voice status | Status line (text + emoji + expiry) on profile | Renamed | R2. |
| Status privacy (contacts, except, only share with) | You › Privacy › Status line | Renamed | |
| Status viewers, reactions, replies, mentions, music, archive | — | Not in Songbird | R2. |
| Mute status | — | Not in Songbird | R2. |

## 16. Other WhatsApp surfaces

| WhatsApp | Songbird | Status | Note |
| --- | --- | --- | --- |
| Registration by phone + SMS code | Invite code → username → recovery key | Renamed | R1, D-0038. |
| Contacts permission / sync | — (never asked) | Not in Songbird | R1. Contacts are people you chat with, synced encrypted. |
| Restore from backup at sign-up | Onboarding › I have Songbird elsewhere › Restore | Same | |
| Link a device (QR on desktop/web) | Same | Same | Plus confirmation the server cannot forge. |
| WhatsApp Web | — | Not in Songbird (beta) | Desktop apps only; a web client cannot be served without trusting the server's code. |
| Disappearing chats default | Same | Same | |
| Sticker maker | Attach › Sticker pack › New | Same | Packs via anonymous pack service (D-0083). |
| Notification quick reply | Same | Same | |
| Home-screen widgets | — | Not in Songbird (yet) | Later. |
| Apple Watch / Wear OS | — | Not in Songbird (yet) | Later. |

## 17. New in Songbird (no WhatsApp equivalent)

| Songbird | Where |
| --- | --- |
| Privacy centre "What Songbird can see" | You › Privacy › Privacy centre |
| Presence (online / away / busy / invisible) and status line | You › profile card |
| Nudge (Yahoo Buzz), chat scenes, sound stickers | Chat ⋯, wallpaper, packs |
| Username key (find me only with a code) | You › Account › Username |
| Recovery key | You › Account › Security › Recovery key |
| Backups to any storage (Songbird, file, iCloud, Drive, OneDrive, Dropbox, Nextcloud, S3) | You › Backups |
| Parental controls (supervised accounts) | You › Privacy › Parental controls |
| Plans (Free, Plus, Family) | You › Account › Plan |
| Key transparency status | Chat info › Encryption › Safety number |
| Proxy links | You › Storage and data › Proxy |
| Message requests with block/report | Chats › Message requests |
