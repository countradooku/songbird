# Component library

Every component the A1 prompt lists, with its states and accessibility notes, mapped to
`apps/ui/src/ui` (the styled layer features must compose from). "**feature-level**" means it is
not in `src/ui` yet: it is built inside a feature module, and moves to `src/ui` once a second
feature needs it (DESIGN.md rule 1). The gallery (`features/gallery.rs`, You › Help › Design
system) shows every component in every state, light and dark.

Common states: **default**, **hover** (pointer), **pressed** (scale `PRESS_SCALE` 0.97, `FAST`),
**focus-visible** (2 pt `ring` outline, offset 2), **disabled** (40 % opacity, no hover, removed
from tab order only if the action is impossible, else kept focusable with "dimmed" in its name),
**loading** (spinner replaces the label, width kept, `aria-busy`), **error** (destructive text +
icon, message below). Touch targets ≥ 44 pt (`ui::TOUCH` 48 on mobile).

## 1. Actions

| Component | `src/ui` | States | Accessibility |
| --- | --- | --- | --- |
| Button | `btn(label, Variant, BtnSize, f)`, `btn_with_icon` — variants `Primary`, `Secondary`, `Ghost`, `Outline`, `Danger`; sizes Sm/Md/Lg | all common states; loading: label → spinner + "Loading" in name | Role button; label is the text; one Primary per screen; Danger only for irreversible |
| Icon button | `icon_btn(Icon, label, f)` | default, hover/pressed wash `accent`, focus, disabled, toggled (filled pill, `aria-pressed`) | Label required by signature; 44 pt hit area even if the glyph is 20 pt |
| Floating action button | `fab` | default, pressed, hidden while scrolling down (phones) | Label "New chat" etc.; not used on desktop |
| Chip / filter | `chip(label, selected, f)` | unselected (`secondary`), selected (`accent`), focus, disabled | Role button with selected state; group labelled "Filters" |
| Segmented control | `segmented` | selected segment `card`; disabled | Role radiogroup; arrow keys move |
| Toggle | `toggle`, `toggle_row` | off, on, disabled, pending (sync) | Role switch; the row label is its name; knob/track contrast: see brand.md FAILS #1–9 |

## 2. Lists and text

| Component | `src/ui` | States | Accessibility |
| --- | --- | --- | --- |
| Row | `Row::new(..).icon/.subtitle/.chevron/.value/.trailing/.danger/.on_press` | default, hover/pressed `accent`, focus, disabled, danger | Role button when pressable; name = title + subtitle + value; chevron decorative |
| Grouped list | `group([...])`, `section_title`, `footnote` | — | Section titles are headings |
| Chat list row | **feature-level** (`features/chats.rs`; built on `Row`) | default, unread (bold title, badge), muted (muted badge, bell-off), pinned, typing ("typing…" replaces preview), draft ("Draft: …"), selected (desktop), swipe actions revealed | Name: "Ana, 2 unread, last message: …, 10:42"; swipe actions also in the context menu and via VoiceOver actions |
| Text | `heading`, `body`, `muted`, `section_title`, `footnote` | — | Dynamic type; headings marked |
| Separator | `separator`, `separator_inset` | — | Decorative |
| Card | `card()` | — | Container only |
| Icon tile | `icon_tile(Icon)` | — | Decorative next to labelled rows |
| Search field | `search_field` | empty, typing, results, no results, clear button | Role search; "Clear" button labelled |
| Field | `field`, `labelled_field` | default, focus (`ring` border), filled, invalid (destructive hint), disabled | Label always visible (no placeholder-only labels); error text linked as description |

## 3. People and status

| Component | `src/ui` | States | Accessibility |
| --- | --- | --- | --- |
| Avatar | `avatar(name, seed, size)`, `initials` | photo, initials (hue from seed), group (stacked), loading (skeleton) | Decorative when next to the name; else name as label. Dark hues fail 4.5:1 today (brand.md #10–17) |
| Avatar with presence | `avatar_presence` | online, away, busy, invisible (no dot), last seen hidden | Presence in the label ("Ana, away"); dot never the only signal |
| Unread badge | `unread_badge(count, muted)` | count, 99+, muted (grey), mention (@ badge, **feature-level**) | "3 unread" |
| Tag | `tag(label)` | neutral | Text only ("Admin", "Plus", "WhatsApp") |
| Ticks | `ticks(|| Tick)` — Sending clock, Sent, Delivered, Read (disc), Played, Failed | all six; transitions `FAST` | Label per state ("Read"); failed adds "Not sent. Tap to retry." |
| Verified mark | **feature-level** (`Icon::ShieldCheck` after a name) | shown / hidden | ", verified" appended to the name |

## 4. Messages

All **feature-level** in `features/chat.rs` (A5) unless noted; one `bubble` frame shared by every
type.

| Component | Variants / types | States | Accessibility |
| --- | --- | --- | --- |
| Bubble frame | incoming / outgoing; first / middle / last in a run (tail on last); with reply quote; forwarded; edited; starred; pinned; selected; highlighted (search, jump-to) | default, pressed (long-press menu), selected (multi-select check), sending, failed | Each bubble one element: "Ana, 10:42, Hello, read". Swipe-to-reply also as action |
| Text | links, @mentions, emoji-only (large), code spans | read more for > 20 lines | Links are focusable children |
| Link preview | title, site, image | loading skeleton, no preview | Preview is part of the link's name |
| Photo / video | single, album grid (2–4+), HD badge, duration | downloading (progress ring, cancel), tap to download (size shown), failed (retry), expired | Alt text from sender (optional) or "Photo"; video duration in name |
| Voice note | waveform, duration, speed 1×/1.5×/2×, played state | idle, playing, paused, downloading, transcript shown | Play button labelled; transcript as text |
| File | icon by kind, name, size | download, downloading, open, failed | "PDF, Report.pdf, 2 MB" |
| Poll | question, options with bars, single/multiple, my vote | open, voted, closed | Options as radio/checkbox; result percentages read |
| Event | title, when, place, going count | going / not going / no answer, past | |
| Contact card | name, @username, Message button | | |
| Location | static map tile, label; live (time left) | live, stopped | Address as text |
| Sticker | image/animation, sound sticker | playing (respects reduced motion) | Pack name + emoji meaning as label |
| View once | photo/video | unopened, opened ("Opened") | Cannot be screenshot (where OS allows); says so |
| Nudge | centred "Ana nudged you" + shake | | Shake skipped with reduced motion |
| Call record | voice/video, missed, duration, Call back | | Missed with icon + word |
| Deleted | "This message was deleted" italic | | |
| System line | centred, `muted-foreground` on `chat-bg` | info, key change (trust.md) | Polite live announcement |
| Date chip | sticky "Today", "Yesterday", date | | Heading level 3 |
| Encryption notice | lock + copy (trust.md §1) | | Button opening the sheet |

## 5. Input

| Component | Where | States | Accessibility |
| --- | --- | --- | --- |
| Composer | **feature-level** (`features/chat.rs`) | empty (mic shown), typing (send shown), replying (quote bar with close), editing ("Editing" bar), recording (hold / locked / paused / preview), disabled (announcement group: "Only admins can send messages"), blocked ("You blocked Ana. **Unblock**"), request pending | Field labelled "Message"; send button "Send"; record button "Hold to record, or double-tap and swipe up to lock" |
| Reaction bar | **feature-level** | 6 default reactions + "+" (full picker); my reaction highlighted | Each emoji labelled by name; reaction summary under the bubble: "2 reactions: thumbs up by Ana and you" |
| Message action menu | **feature-level** | Reply, Forward, Copy, Edit, Pin, Star, Info, Delete; "More": Select, Report, Save | Context menu role; keyboard: Menu key / Shift+F10 |
| Attachment sheet | **feature-level** on `app_sheet` | grid of 8: Photos, Camera, File, Location, Contact, Poll, Event, Stickers | Each tile a labelled button |
| Emoji / sticker / GIF picker | **feature-level** | tabs, search, recents, loading GIFs | Search labelled; GIF search note "Searched through Songbird; GIPHY doesn't see who you are" |

## 6. Feedback and overlays

| Component | `src/ui` | States | Accessibility |
| --- | --- | --- | --- |
| Banner | `banner(Tone, Icon, msg)` — `Info`, `Secure`, `Warning`, `Danger` | with/without action, dismissable | Icon + text (never colour alone); role status |
| Dialog (confirm) | `confirm(title, msg, action, f)` | default, destructive action, loading | Focus trapped; Esc cancels; default focus on the safe action |
| Sheet | `app_sheet(open, title, content)` | open, dragging, closed; detents medium/large | Grabber decorative; close button labelled; focus returns to the opener |
| Toast | `toast(msg)`, `toast_layer()` | info, with Undo action | Polite announcement; ≥ 4 s, longer with an action; never the only place an error is reported |
| Empty state | `empty_state(Icon, title, msg, action)` | per screen (flows list exact copy) | Title as heading |
| Skeleton | `skeleton(w, h)`, `skeleton_row()` | shimmer off with reduced motion | Container `aria-busy`, "Loading" once |
| Offline bar | **feature-level** (on `banner`) | offline ("Waiting for network"), connecting ("Connecting…"), via proxy | Polite |

## 7. Trust and devices

| Component | Where | States | Accessibility |
| --- | --- | --- | --- |
| QR code display | **feature-level** (`features/devices.rs`, profile) | showing, expired (refresh), with text code below | The text alternative (username/link) always beside |
| QR scanner frame | **feature-level** | camera permission needed, scanning (rounded square guide, 240 pt), recognised (frame turns `primary`, haptic), invalid ("This isn't a Songbird code"), no camera (enter code instead) | Manual entry always offered |
| Safety-number view | **feature-level** (`features/devices.rs`) | QR + 12 groups of 5 digits; not verified / verified; changed; KT checked / not checked | Digits read in groups; "Mark as verified" toggle labelled |
| Recovery key view | **feature-level** (`features/onboarding.rs`) | hidden (tap to reveal), shown, copied, confirmed | Monospace groups; copy button; screen capture blocked while shown |
| Device row | `Row` | this device, other, pending confirmation, removing | "MacBook, desktop, active 2 hours ago" |

## 8. Calls

All **feature-level** in `features/calls.rs` (A8).

| Component | States | Accessibility |
| --- | --- | --- |
| Incoming call screen | ringing (voice/video), with name, avatar, "End-to-end encrypted" | Accept/Decline labelled; system CallKit/ConnectionService on phones |
| Call controls bar | mute on/off, camera on/off, flip, speaker/route, screen share, raise hand, reactions, more, end | Each a toggle with pressed state; End is `call-decline` with label "End call"; accept glyph contrast FAIL in dark (brand.md #5) |
| Participant tile | speaking ring, muted icon, camera off (avatar), poor connection, hand raised, pinned | Name + state in label; active speaker announced only on change, rate-limited |
| Call status | ringing, connecting, connected (timer), reconnecting, ended | Polite live region |
| Lobby list (host) | waiting people with Let in / Decline | |
| Mini player / PiP | | Expand labelled |
