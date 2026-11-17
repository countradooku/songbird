# Research teardown: WhatsApp, Signal, Proton, Threema, Telegram

**Method: desk teardown.** Written from working knowledge of each app's 2025–2026 builds (iOS,
Android, desktop), not from a usability study and not from fresh screenshots. Claims about "what
confuses people" are the common, publicly discussed pain points; they are hypotheses for
`usability-plan.md`, not findings. Reference screenshots go in `reference/` (see its README);
when they arrive, every row below gets a screenshot link and any row they contradict is fixed.

## 1. Summary: what Songbird takes

| From | Take | Leave |
| --- | --- | --- |
| WhatsApp | The layout people already know (tabs, chat list, chat screen, long-press menu, ticks), group permissions, communities, call links, chat lock, lists | Phone numbers, Status/Stories, Meta AI, the long Settings tree with near-duplicate rows |
| Signal | Safety numbers, usernames + username links, sealed sender wording, calm key-change notices, "note to self", call links with lobby | Hidden-by-default features (PIN reminders that nag), sparse group admin tools |
| Proton | Plain-language security copy, a visible "what we can see" stance, calm onboarding, one recovery story, plans that never gate security | Upsell density, product-switcher clutter |
| Threema | No phone number, ID + QR verification levels, trust shown as a level next to the name | Three-dot verification levels people misread, paid entry |
| Telegram | Speed, folders, polish of media and stickers, desktop app quality, usernames | Non-E2EE default chats, "secret chats" as a separate mode, public channel discovery |

## 2. Navigation

| App | Pattern | Best at | Confuses people | Songbird |
| --- | --- | --- | --- | --- |
| WhatsApp | iOS: bottom tabs Updates · Calls · Communities · Chats · Settings. Android: bottom tabs Chats · Updates · Communities · Calls, Settings in ⋮ | Chats one tap away; muscle memory for 2bn people | Updates mixes Status and Channels; Settings in different places on iOS vs Android; Communities feels empty to most | Chats · Calls · Communities · You on every platform (ia.md) |
| Signal | Chats · Calls · Stories (optional) tabs; settings from the avatar | Stories can be turned off and the tab disappears | Settings behind the avatar is not discoverable | Settings as a visible tab ("You") |
| Proton Mail | Drawer (folders, labels) + list + detail; settings in drawer | Desktop three-pane layout | Drawer on phones hides labels | Desktop: rail + list + detail |
| Threema | Tabs Contacts · Chats · Profile | Profile tab holds ID, QR, settings | Contacts tab first is unusual | Profile at the top of You |
| Telegram | Chats with folder tabs at top; Contacts, Calls, Settings bottom tabs | Folder chips, fast search | Too many entry points; archive and folders overlap | Filter chips (All, Unread, Favourites, Groups, Channels, lists) |

## 3. Onboarding

| App | Flow | Best at | Confuses people | Songbird |
| --- | --- | --- | --- | --- |
| WhatsApp | Terms → phone → SMS code → restore backup → name + photo | Two minutes, no password | Contacts permission is near-mandatory; restore offered once only | Under two minutes, no phone, no contacts permission |
| Signal | Phone → code → PIN → name → (username optional) | PIN set early | PIN purpose unclear; PIN reminders feel like tests | Recovery key + optional PIN later, explained in one sentence |
| Proton | Choose username → password → recovery (email/phone/phrase) | Clear recovery phrase screen with "I saved it" | Long; plans shown before value | Recovery key screen modelled on Proton's, plans never in onboarding |
| Threema | Generate ID by moving finger → nickname → optional phone/email link | Identity without a phone | Random ID is meaningless to friends | Username people choose, plus link and QR |
| Telegram | Phone → code (in app/SMS) → name | Fast | Phone visible by default to contacts | — |

## 4. Chat screen

| App | Best at | Confuses people | Songbird |
| --- | --- | --- | --- |
| WhatsApp | Ticks (grey/blue), swipe to reply, reactions bar, voice note lock, view once | Blue ticks = colour only; "Delete for everyone" time limit invisible; encryption banner tapped rarely | Ticks change shape (read = filled disc); delete window shown in the menu; encryption line once at top |
| Signal | Clean bubbles, edit history, disappearing timer icon in header | Ticks hollow/filled hard to see; "safety number changed" lines look alarming to some | Neutral key-change line with "Verify" |
| Proton (Mail) | Lock icon + tooltip explaining protection level per message | Several lock colours/states | One state per chat, stated in words |
| Threema | Agree/disagree reactions, polls | Verification dots in the header | Shield-check only for verified |
| Telegram | Fast media, stickers, message effects, scheduled messages | Too many features in long-press menu | Long-press menu capped at 8 + "More" |

## 5. Settings

| App | Best at | Confuses people | Songbird |
| --- | --- | --- | --- |
| WhatsApp | Privacy checkup; per-item audience pickers | 9 top groups, 60+ rows; similar items split (Chat backup in Chats, Storage elsewhere; Protect IP under Advanced) | Ten groups, top-10 tasks within two taps (tree test in usability-plan.md) |
| Signal | Short list; privacy first | Linked devices and Data usage hard to find | Linked devices under Account and in Chats ⋯ |
| Proton | "Security and privacy" with plain explanations under each toggle | Settings split between app and web account | Everything in the app; every toggle has a one-line footnote |
| Threema | Privacy settings per data type | Jargon (PFS, "Threema Safe") | No jargon in labels; terms in Help |
| Telegram | Search in settings | Privacy defaults are permissive | Search in You (desktop, phones from 1.1) |

## 6. Calls

| App | Best at | Confuses people | Songbird |
| --- | --- | --- | --- |
| WhatsApp | Call links, schedule, 32-person video, screen share, low-data mode | Group call ringing everyone vs joining silently | Group call: ring or "start quietly" choice |
| Signal | Call links with lobby (admin approval), raise hand | Lobby approval surprises guests | Lobby copy: "The host will let you in" |
| Proton (Meet, 2025) | E2EE stated plainly | New, small feature set | — |
| Threema | Call verification emoji | Rarely used | Optional "Verify" in-call (code), never a blocker |
| Telegram | Video messages, group voice chats | Calls not E2EE in groups by default historically | Always E2EE; said once on the call screen |

## 7. Groups and communities

| App | Best at | Confuses people | Songbird |
| --- | --- | --- | --- |
| WhatsApp | Permissions page, approval of joins, communities with announcements | Community vs group vs channel; who sees phone numbers | One sentence on each type at creation; no phone numbers |
| Signal | Group links with admin approval; MLS-like member lists | Admin tools minimal | Full WhatsApp permission set |
| Proton | — (no groups) | — | — |
| Threema | Group polls | Group creator owns forever | Owner can hand over ownership |
| Telegram | Topics, admin rights granularity | Rights screen overwhelming | Seven toggles, plain names, defaults safe |

## 8. Trust presentation

| App | Pattern | Songbird stance |
| --- | --- | --- |
| WhatsApp | Yellow notice "Messages and calls are end-to-end encrypted. No one outside of this chat…" | Same idea, shorter, neutral tone |
| Signal | "Safety number changed" line, verify screen with QR and 60 digits | Same structure; calmer copy; QR first, digits second |
| Proton | "Zero-access encryption" explainers, transparency report, Swiss jurisdiction | Privacy centre: what the server sees, in a table, from THREAT_MODEL.md; EU hosting stated |
| Threema | Red/orange/green dots for verification level | No traffic-light colours; only "verified" is marked |
| Telegram | Lock icon only in secret chats | Every chat encrypted; no mode to choose |

## 9. Open items

- Owner screenshots of their own WhatsApp (iOS or Android, Romanian and English UI) to confirm
  parity-map rows and the current Settings order.
- Proton Pass/Drive/VPN onboarding screenshots to confirm the recovery-key screen pattern.
- Usability sessions (usability-plan.md) test the hypotheses in the "Confuses people" columns.
