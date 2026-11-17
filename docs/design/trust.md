# Trust design

Principle: **security is visible but never in the way.** Say what happens, in plain words, once;
put details one tap away; never use fear. The source of truth for every claim is
`docs/THREAT_MODEL.md` (what the server sees) and `docs/PROTOCOL.md`; copy may not claim more.

## 1. Encryption

| Where | What the user sees | Tap |
| --- | --- | --- |
| Top of every chat (first screen of history) | Lock glyph + "Messages and calls are end-to-end encrypted. Only people in this chat can read them." | Opens Encryption sheet |
| Chat info › Encryption row | "End-to-end encrypted" + "Safety number" | Safety number screen |
| Call screen (under the name, first 3 s) | "End-to-end encrypted" | — |
| Channel | "Posts are end-to-end encrypted. Followers can see each other's devices." | Sheet |
| WhatsApp chat (A15) | "End-to-end encrypted. This chat goes through WhatsApp: Meta sees who talks to whom and when." | Sheet listing what Meta sees |
| Encryption sheet | Three short points: who can read; what Songbird's servers see (link to Privacy centre); how to check (safety number) | — |

Never shown: protocol names in primary copy (PQXDH, MLS, X-Wing). They appear only in Help ›
"How encryption works" and the About › Security page.

## 2. Key changes

| Situation | Presentation | Copy |
| --- | --- | --- |
| Contact's safety number changed | Neutral centred system line in the chat; no colour, `muted-foreground` text, Info icon | "Ana's safety number changed. This usually means they reinstalled Songbird or got a new phone. **Verify**" |
| Changed and the user had verified them | Same line + the verified shield is removed; Info banner on the chat (dismissable) | "You verified Ana before. Their safety number changed, so check it again when you can. **Verify**" |
| Sending to a changed verified contact | No blocking dialog. The message sends. | — |
| Contact added a device | No line (normal). Key transparency checks silently; line only on a mismatch. | — |
| Key transparency mismatch (the directory and the device disagree) | Info banner on the chat and a security notification | "We couldn't confirm Ana's keys with the public key directory. Compare safety numbers in person before sharing anything sensitive. **Compare**" |
| Own new device linked | System notice in Linked devices and a notification on all devices | "A new device was linked: *MacBook*. Not you? **Remove it**" |

Rules: never red, never the word "warning", never "attack", never block sending; the only
`destructive` styling is the "Remove it" action for an unknown own device.

## 3. Verified and unverified contacts

| State | Mark | Where |
| --- | --- | --- |
| Not verified (default) | Nothing | — (unverified is normal; no badge, no "unverified" label) |
| Verified | `ShieldCheck` glyph (16 pt, `primary`) after the name; accessible name "Ana, verified" | Chat header, contact info, member list |
| Verified, then changed | Shield removed; key-change line as above | |

## 4. Server limits and honesty

| Topic | Copy (Privacy centre or Help) |
| --- | --- |
| Metadata | "Our servers need some information to deliver messages: your account, your devices and when they connect, and the size and time of messages. We delete what we no longer need." |
| Groups | "Our servers know which devices are in a group, so they can deliver to them. They never see the group's name, picture or messages." |
| Calls | "During a call our servers know who is calling whom, for up to 24 hours. They never hear or see the call." |
| Push | "Notifications wake your phone without any message content. Apple and Google see only that Songbird woke your phone." |
| Backups | "Backups are locked with your recovery key. Songbird, Google, Apple or any other storage can't open them." |
| Lost recovery key | "If you lose your recovery key and every device, we can't restore your messages. Nobody can." |
| Reports | "When you report, the messages you choose are sent to Songbird's moderators. Nothing else in the chat is." |
| Legal requests | "We can only hand over what we have. Our transparency report lists every request." |

## 5. "What Songbird can see" (Privacy centre)

Built directly from `THREAT_MODEL.md` §1; each row links to the threat model row ID so a change
there is a change here. Two columns, short rows, grouped:

| Songbird can see | Songbird never sees |
| --- | --- |
| That your account exists and when it was created | Your messages, photos, files, voice notes, polls |
| Your username as a scrambled code (someone who guesses your username can check it) | Your name, photo, About and status line |
| Your devices and their public keys | Your contacts or address book |
| When your devices connect, and from which IP address (kept in memory only, never logged) | What you say in calls, or see on video |
| The size and time of messages while they wait to be delivered (deleted on delivery, at most 30 days) | Group names, pictures, descriptions and settings |
| Which devices are in a group, and who its admins are | Your settings (except the four below) |
| Who is calling whom, during a call (at most 24 hours) | Your backups |
| Four settings it must enforce: who can find you, message requests, inactivity deletion, your plan | Who invited you |

Footer: "Full details: our threat model (link to the public repository)." and "Last checked
against the threat model: <date>". **Owner:** approve wording (it is a public commitment).

## 6. Wording: do and don't

| Don't | Do | Why |
| --- | --- | --- |
| "Warning: security code changed!" | "Ana's safety number changed. This usually means they reinstalled Songbird or got a new phone." | Calm, gives the likely reason |
| "Your messages may be intercepted" | "Compare safety numbers to be sure you're talking to Ana." | Action, not threat |
| "Military-grade encryption" | "Only people in this chat can read these messages." | Concrete, checkable |
| "Unverified contact" label | (nothing) / "Verified" when verified | Unverified is normal |
| "We can't see anything" | "Our servers can't read your messages. Here's what they do see." | Honest; metadata exists |
| "E2EE with PQXDH and ML-KEM" | "End-to-end encrypted" (details in Help) | No jargon |
| "Your account is at risk" | "Set a two-step PIN so nobody can link a device without it." | Benefit framing |
| "Are you sure?" | "Delete this chat? This removes it from all your devices." | Says the consequence |
| "Error 403 allowance" | "You've used all your invites. You'll get more soon." | Plain, no codes |
| "Hackers could…" | — | Never personify attackers in UI |
| Red banners for security states | Info tone; red only for "not sent" and destructive actions | Red means failure |
| "Secret chat" mode | Every chat is encrypted; no mode | Telegram confusion avoided |

## 7. Accessibility of trust UI

- Safety numbers read aloud in groups of five digits ("12345, 67890, …"), never as one number.
- Shields and lock glyphs always have text equivalents; nothing relies on colour.
- Key-change lines are announced politely (not assertively) by screen readers.
