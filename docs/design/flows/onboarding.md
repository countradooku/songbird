# Flow: onboarding (A4)

**Goal:** a WhatsApp user goes from install to their first chat in under three minutes, with an
invite code, a username and a saved recovery key, and no phone number or contacts permission.
Module: `features/onboarding.rs` (`flow()`, `Store::finish_onboarding`).

## Entry points

- First launch (no account on the device).
- An invite link `https://songbird.chat/i#<code>` (code prefilled; ia.md §5).
- You › Account › Add account (same flow, skips the welcome).

## Steps

| # | Screen | Content | Primary action | Secondary |
| --- | --- | --- | --- | --- |
| 1 | Welcome | Feather mark, "Songbird", "Private messages and calls, made in Europe." | **Get started** | "I have Songbird on another device" → `linking-device.md` / Restore |
| 2 | Invite code | "Songbird is invite-only for now. Enter the code a friend sent you." Field formatted `XXXX-XXXX-…` (24 symbols, 6 groups), paste button | **Continue** (enabled when 24 symbols) | "How do I get an invite?" sheet |
| 3 | Checking | Progress "Setting up your account…" (proof-of-work runs here, 2–10 s) | — | — |
| 4 | Username | "Choose a username. Friends use it to find you." Field with live check: available / taken / invalid rule hint | **Continue** | "Why no phone number?" sheet |
| 5 | Profile | Name (required, 1–64 chars), photo (optional) | **Continue** | Skip photo |
| 6 | Recovery key | "This is your recovery key. It's the only way to restore your account if you lose this phone." 64 characters in 16 groups of 4, hidden until "Show". Copy, Save to password manager, Save as file | **I've saved it** | "Remind me later" (allowed once; reminder banner in You after 24 h) |
| 7 | Confirm key | Type groups 3 and 11 (two random groups) | **Confirm** | Back to show key |
| 8 | Notifications | "Turn on notifications so you don't miss messages and calls. They never contain your messages." | **Turn on** (OS prompt) | Not now |
| 9 | Who to talk to | "Who do you want to talk to?" Three tiles: Find by username · Scan a QR code · Invite a friend (shows N invites left) | Any tile | **Skip** → Chats |

Two-step PIN and backups are not in onboarding; they are offered as one-time cards in Chats after
the first day (`backups.md`).

## States

| State | Behaviour |
| --- | --- |
| Offline | Step 2+: banner "You're offline. Connect to the internet to continue." Continue disabled. |
| Loading | Step 3 progress; step 4 username check spinner inside the field (debounced 400 ms). |
| Invalid code | "This code isn't valid. Check it, or ask your friend for a new one." |
| Expired / used code | "This invite has expired or was already used. Ask your friend for a new one." |
| Too many attempts | "Too many tries. Try again in <n> minutes." |
| Username taken | "That username is taken. Try another." with 3 suggestions (name + digits) |
| Username invalid | Rule hint stays visible: "3–32 letters, numbers, _ or . — start with a letter." |
| Server error | "Something went wrong on our side. Try again." + Retry |
| Proxy needed | Link under error: "Can't connect? Use a proxy" → proxy sheet |

## Copy

| Key | String |
| --- | --- |
| welcome.title | Songbird |
| welcome.tagline | Private messages and calls, made in Europe. |
| invite.title | Enter your invite code |
| invite.body | Songbird is invite-only for now. Enter the code a friend sent you. |
| invite.help | Ask a friend who uses Songbird. Each person can invite a few friends. |
| username.title | Choose a username |
| username.body | Friends use it to find you. You can change it later. |
| username.why | Songbird doesn't use phone numbers. Nobody can find you unless you share your username or link. |
| profile.title | Your name |
| profile.body | Shown to people you chat with. Only they can see it. |
| key.title | Save your recovery key |
| key.body | It's the only way to restore your account if you lose this phone. Keep it somewhere safe, like a password manager. |
| key.warn | Songbird can't recover it for you. |
| key.confirm | Type groups 3 and 11 to confirm you saved it. |
| notify.body | Turn on notifications so you don't miss messages and calls. They never contain your messages. |
| who.title | Who do you want to talk to? |

## Accessibility

- Each step is one screen with a heading; progress "Step 2 of 6" announced (not shown as dots
  only).
- Invite and recovery fields accept paste, ignore spaces/hyphens/case; groups read aloud
  one by one.
- Recovery key: screen capture blocked; "Show" required, announced.
- Large text: steps scroll; the primary button stays above the keyboard.

## Motion

| Change | Motion | Reduced |
| --- | --- | --- |
| Step forward / back | Native push/pop | Native (fade) |
| Username available | Check glyph fades in, `FAST` | Same |
| Recovery key reveal | Blur → clear, `BASE` | Instant |
| Finish | Chats list fades in, `SLOW` | Fade |

## Open questions (owner)

1. Invite links (`/i#code`) or codes only?
2. Allow "Remind me later" for the recovery key, or require saving before continuing?
3. Show the plan picker anywhere in onboarding? (Proposal: no.)
4. Age gate: ask for age band at sign-up for parental-controls/GDPR Art. 8, or only when
   linking a supervised account?
