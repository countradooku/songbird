# Brand and design system spec

> **Palette changed (2026-11-17, owner):** the brand moved from green-teal to **Dusk violet** so Songbird does not look like WhatsApp. The token values in this file's tables are the earlier palette; the source of truth is `apps/ui/theme.json` (and the high-contrast overrides in `apps/ui/src/theming.rs`). Rerun `python3 docs/design/tools/contrast.py` for current ratios (0 failing pairs at the change).

Status: **proposal, pending owner approval** (A1 gate). The tokens already live in
`apps/ui/theme.json`; this file explains them, checks them and specifies what is not yet in code
(logo, sounds, licensed type).

## 1. Logo and app icon brief

| Item | Brief |
| --- | --- |
| Concept | A single **feather** that also reads as a small songbird in flight (the quill's vane is the wing, the shaft's tip the beak). Not a padlock, shield or speech bubble: trust is shown in the product, not in the mark. |
| Tone | Calm, European, quiet confidence. Closer to a stamp or a bookplate than to a tech logo. |
| Shape | One closed silhouette, no gradients, no thin hairlines; must survive 16 px. Optical weight centred in the iOS/Android masks. |
| Colour | Mark in `primary` (#136B5B) on `background` (#FBFBF9) for the default icon; reversed (#FBFBF9 on #136B5B) for the store icon. Dark variant: `primary` dark (#4CC3A5) on #0D1113. |
| Monochrome | Single-colour version required: iOS 18 tinted icons, Android 13 themed (monochrome layer), macOS menu-bar / Windows tray template (black + alpha), notification small icon (Android: white on transparent). |
| Avoid | Green speech bubble (WhatsApp), blue paper plane (Telegram), purple (Proton), a lock (fear), a bird that looks like X/Twitter's. Run a trademark search on the final shape (EUIPO TMview). |
| Wordmark | "Songbird" in the brand face (§3), sentence case, tracking 0, never all caps. |

### Required sizes

| Platform | Sizes (px) | Notes |
| --- | --- | --- |
| iOS | 1024 (App Store), 180, 120, 167, 152, 87, 80, 60, 58, 40, 29, 20 | Square, no transparency; dark and tinted variants (iOS 18). |
| Android | 512 (Play), adaptive 108 dp foreground + background layers, monochrome layer; legacy 192, 144, 96, 72, 48 | Keep the mark inside the 66 dp safe zone. |
| macOS | 1024, 512, 256, 128, 64, 32, 16 (@1x and @2x) | Follow the macOS rounded-square grid; menu-bar template 18 pt. |
| Windows | 256, 64, 48, 40, 32, 24, 20, 16 (ICO); MSIX tiles 44, 50, 150, 310 | Tray icon 16/20/24 in light and dark. |
| Linux | SVG plus 512, 256, 128, 64, 48, 32, 16 PNG (freedesktop hicolor) | Symbolic `-symbolic.svg` for GNOME. |
| Web / links | favicon 32, 16, SVG; apple-touch-icon 180; Open Graph 1200×630 | Link previews of `songbird.chat` invites. |
| In-app | Rail logo 28 pt, onboarding hero 96 pt | Already drawn as `Icon::Feather` (Lucide) until the final mark exists. |

Deliverable from the designer: SVG master, monochrome SVG, the export set above, a one-page usage
sheet (clear space = the feather's width / 4, minimum size 16 px).

## 2. Colour

Rationale (from `apps/ui/DESIGN.md`): a deep green-teal primary, trustworthy without being
WhatsApp's green or Proton's purple; warm paper chat background; mint outgoing bubbles; status
colours only for their meaning, never colour alone (ticks have shapes, banners have icons).

### 2.1 Every token

High contrast (HC) is `theme.json` with the overrides in `apps/ui/src/theming.rs`; **bold** = a
value the HC override changes.

| Token | Light | Dark | HC light | HC dark |
| --- | --- | --- | --- | --- |
| `background` | #FBFBF9 | #0D1113 | **#FFFFFF** | **#000000** |
| `foreground` | #15191C | #E7ECEA | **#000000** | **#FFFFFF** |
| `card` | #FFFFFF | #151B1E | #FFFFFF | **#0A0A0A** |
| `card-foreground` | #15191C | #E7ECEA | #15191C | #E7ECEA |
| `popover` | #FFFFFF | #1A2125 | #FFFFFF | #1A2125 |
| `popover-foreground` | #15191C | #E7ECEA | #15191C | #E7ECEA |
| `primary` | #136B5B | #4CC3A5 | **#004A3B** | **#8AF0D4** |
| `primary-foreground` | #FFFFFF | #04201A | #FFFFFF | **#000000** |
| `secondary` | #EEF1EE | #1C2427 | #EEF1EE | #1C2427 |
| `secondary-foreground` | #1B2A26 | #DDE6E3 | #1B2A26 | #DDE6E3 |
| `muted` | #F1F2EF | #182024 | **#F0F0F0** | **#141414** |
| `muted-foreground` | #5A636B | #9AA6A2 | **#262626** | **#E0E0E0** |
| `accent` | #E7F1EE | #1C2B28 | **#D6EEE7** | **#123A31** |
| `accent-foreground` | #0E3D34 | #CFEFE6 | **#002A21** | **#FFFFFF** |
| `destructive` | #B9302A | #F06A5F | #B9302A | #F06A5F |
| `destructive-foreground` | #FFFFFF | #2A0603 | #FFFFFF | #2A0603 |
| `border` | #E2E5E1 | #252F33 | **#4A4A4A** | **#BDBDBD** |
| `input` | #CDD2CD | #334047 | **#262626** | **#E0E0E0** |
| `ring` | #136B5B | #4CC3A5 | **#000000** | **#FFFFFF** |
| `sidebar` | #F4F5F2 | #111719 | #F4F5F2 | #111719 |
| `sidebar-foreground` | #15191C | #E7ECEA | #15191C | #E7ECEA |
| `sidebar-accent` | #E3EEEA | #1C2B28 | #E3EEEA | #1C2B28 |
| `sidebar-accent-foreground` | #0E3D34 | #CFEFE6 | #0E3D34 | #CFEFE6 |
| `sidebar-border` | #E2E5E1 | #222B2F | #E2E5E1 | #222B2F |
| `chat-bg` | #F2F0EA | #0A0E10 | **#FFFFFF** | **#000000** |
| `bubble-out` | #D8EEE6 | #17443A | **#C6EADD** | **#0E3B31** |
| `bubble-out-foreground` | #0F2B24 | #E5F4EF | **#000000** | **#FFFFFF** |
| `bubble-in` | #FFFFFF | #1A2124 | **#F0F0F0** | **#161616** |
| `bubble-in-foreground` | #15191C | #E7ECEA | #15191C | #E7ECEA |
| `bubble-meta` | #56605D | #A3B1AC | **#262626** | **#E0E0E0** |
| `tick-read` | #1660C0 | #7DB9FF | **#003E9C** | **#A9D1FF** |
| `link` | #1660C0 | #7DB9FF | **#003E9C** | **#A9D1FF** |
| `success` | #1C7A4A | #5BD08F | #1C7A4A | #5BD08F |
| `success-foreground` | #FFFFFF | #04200F | #FFFFFF | #04200F |
| `warning` | #8A5A00 | #F2C35B | #8A5A00 | #F2C35B |
| `warning-bg` | #FFF4DA | #2C2410 | #FFF4DA | #2C2410 |
| `info-bg` | #E6F0FB | #132233 | #E6F0FB | #132233 |
| `online` | #1F9D55 | #4CD486 | #1F9D55 | #4CD486 |
| `call-accept` | #1C8A4E | #2FB36A | #1C8A4E | #2FB36A |
| `call-decline` | #C7342C | #E5544A | #C7342C | #E5544A |
| `call-bg` | #0F1A17 | #070B0A | #0F1A17 | #070B0A |
| `call-foreground` | #F2F6F4 | #F2F6F4 | #F2F6F4 | #F2F6F4 |
| `overlay` | #0B0F1180 | #000000A0 | #0B0F1180 | #000000A0 |
| `mention` | #136B5B | #4CC3A5 | #136B5B | #4CC3A5 |
| `whatsapp` | #1F8A4C | #4CD486 | #1F8A4C | #4CD486 |
| `highlight` | #FFE9A8 | #5A4A12 | #FFE9A8 | #5A4A12 |
| `avatar-1` | #2F6F9F | #4A8CC0 | #2F6F9F | #4A8CC0 |
| `avatar-2` | #8A4FA3 | #A574BE | #8A4FA3 | #A574BE |
| `avatar-3` | #B4532A | #CC7550 | #B4532A | #CC7550 |
| `avatar-4` | #2E7D5B | #4F9E7C | #2E7D5B | #4F9E7C |
| `avatar-5` | #A63D63 | #C2648A | #A63D63 | #C2648A |
| `avatar-6` | #5A5FB0 | #7E83CF | #5A5FB0 | #7E83CF |
| `avatar-7` | #7A6A1E | #A69544 | #7A6A1E | #A69544 |
| `avatar-8` | #2D7A86 | #4D9BA7 | #2D7A86 | #4D9BA7 |
| `avatar-foreground` | #FFFFFF | #FFFFFF | #FFFFFF | #FFFFFF |

Radii: `radius` 10, `radius-sm` 6, `radius-lg` 14, `radius-bubble` 18, `radius-sheet` 20.
`overlay` carries alpha and is not contrast-checked (it dims, it never carries text).

### 2.2 Contrast check

Run `python3 docs/design/tools/contrast.py` (exit 1 on any failure; `--fails` for failures only,
`--markdown` for the table). It reads `theme.json` and `theming.rs`, so it checks what ships.
Pairs are the real combinations used in `src/ui` (listed in the script with where each is used).
Thresholds: text 4.5:1 (WCAG 1.4.3), icons, control boundaries, focus rings and ticks 3:1
(WCAG 1.4.11). Hairlines and bubble edges are decorative and reported as `info`.

Result on 2026-11-17: **26 failing pairs** of 288 checked (262 pass).

#### FAILS to fix

| # | Theme | Pair (fg on bg) | Ratio | Needs | Used for | Proposed fix (computed to pass) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | light | `input` #CDD2CD on `card` #FFFFFF | 1.53 | 3.0 | field border | `input` → **#8A958A** (3.0 on background, 3.1 on card/popover). Or keep `input` as a fill and add an `input-border` token. |
| 2 | light | `input` on `background` #FBFBF9 | 1.48 | 3.0 | toggle track (off) | same token fix |
| 3 | light | `card` on `input` | 1.53 | 3.0 | toggle knob on off track | same token fix |
| 4 | light | `input` on `popover` | 1.53 | 3.0 | sheet grabber | same token fix |
| 5 | dark | `call-foreground` #F2F6F4 on `call-accept` #2FB36A | 2.48 | 3.0 | accept-call glyph | `call-accept` dark → **#2AA15F** (3.03 with the glyph; 5.6 on `call-bg`) |
| 6 | dark | `input` #334047 on `card` #151B1E | 1.63 | 3.0 | field border | `input` dark → **#576D79** (≥ 3.0 on card, background, popover) |
| 7 | dark | `input` on `background` #0D1113 | 1.78 | 3.0 | toggle track (off) | same token fix |
| 8 | dark | `card` on `input` | 1.63 | 3.0 | toggle knob on off track | same token fix |
| 9 | dark | `input` on `popover` #1A2125 | 1.53 | 3.0 | sheet grabber | same token fix |
| 10 | dark | `avatar-foreground` #FFFFFF on `avatar-1` #4A8CC0 | 3.62 | 4.5 | avatar initials | → **#3C7BAD** (4.54) |
| 11 | dark | … on `avatar-2` #A574BE | 3.59 | 4.5 | avatar initials | → **#985FB4** (4.53) |
| 12 | dark | … on `avatar-3` #CC7550 | 3.37 | 4.5 | avatar initials | → **#B85D36** (4.51) |
| 13 | dark | … on `avatar-4` #4F9E7C | 3.22 | 4.5 | avatar initials | → **#418266** (4.56) |
| 14 | dark | … on `avatar-5` #C2648A | 3.83 | 4.5 | avatar initials | → **#BB537D** (4.52) |
| 15 | dark | … on `avatar-6` #7E83CF | 3.48 | 4.5 | avatar initials | → **#686EC7** (4.52) |
| 16 | dark | … on `avatar-7` #A69544 | 3.00 | 4.5 | avatar initials | → **#847636** (4.54) |
| 17 | dark | … on `avatar-8` #4D9BA7 | 3.20 | 4.5 | avatar initials | → **#3F808A** (4.50) |
| 18 | HC dark | `call-foreground` on `call-accept` #2FB36A | 2.48 | 3.0 | accept-call glyph | HC inherits dark: fixed by #5, or HC override `call-accept` #1C8A4E |
| 19–26 | HC dark | `avatar-foreground` on `avatar-1`…`avatar-8` | 3.00–3.83 | 4.5 | avatar initials | HC inherits dark: fixed by #10–17 |

Notes:

- The fixed dark avatar hues are darker than today's; they still separate from `background`
  (#0D1113) because the avatar is a filled disc, not text.
- `theming.rs` says every HC pair is ≥ 7:1 (AAA). That is not true today: 19 HC text pairs are
  between 4.94 and 6.93 (destructive, mention, success, warning, avatars). Either drop the AAA
  claim from the comment or add HC overrides for `destructive`, `mention` (= HC `primary`),
  `success`, `warning` and the avatars. Owner decision; AA is met once the fixes above land.
- Near the line (pass, < 0.5 headroom): light `link` on `bubble-out` 4.99, light `online` dot
  3.37–3.49, `call-decline` on `call-bg` 3.35, dark `bubble-meta` on `bubble-out` 4.91. Re-run the
  script after any palette change.
- Bubbles barely differ from `chat-bg` (1.07–1.78). Acceptable: the text, not the bubble edge,
  carries meaning, and side (left/right) plus the sender name tell incoming from outgoing.

The full table (every pair, every theme) is in the appendix at the end.

### 2.3 Colour rules

- One `primary` action per screen. `destructive` only for irreversible actions and failures.
- Status is never colour alone: ticks change shape, banners carry an icon, presence has a label in
  the accessible name ("Ana, online").
- The `whatsapp` token marks bridged chats (badge + label "WhatsApp"), never Songbird's own UI.
- Key-change and unverified notices use neutral/info tones, never `destructive` (see `trust.md`).

## 3. Typography

| Decision | Detail |
| --- | --- |
| Default: system font | SF Pro (Apple), Roboto (Android), Segoe UI Variable (Windows), Cantarell / distro default (Linux). Native metrics, Dynamic Type and accessibility sizes for free; no font to ship, no licence, no download fingerprint. |
| Romanian | ș ț (comma below, U+0219/U+021B, **not** cedilla ş ţ U+015F/U+0163), ă â î, and capitals Ș Ț Ă Â Î. All four system families cover them. Test string in every screenshot run: "Șoseaua Țării, Brăila — îți mulțumim". Copy must use the comma-below code points (lint for U+015F/U+0163 in Romanian strings). |
| Other EU | Full Latin Extended-A (Polish ą ę ł, Czech ř ů, Hungarian ő ű, Baltic ė ų), Greek, Cyrillic (Bulgarian): covered by all system families. |
| RTL | Arabic, Hebrew, Persian (EU residents' languages): system fonts cover them; layout mirrors (NSH leading/trailing); bubbles flip sides; ticks and times stay attached to the bubble's trailing edge; numbers in safety numbers stay LTR. |
| Open-licence brand face (option) | **Inter** (SIL OFL 1.1, rsms/inter; Latin, Greek, Cyrillic; no Arabic/Hebrew) or **Noto Sans** (SIL OFL 1.1, Google; every script incl. Noto Sans Arabic/Hebrew). OFL allows bundling in an app; keep the licence text in the About screen's licences. Recommendation: system font in the app; Inter only for the wordmark and marketing. Switch: `theme.json` `font-sans`. |
| Scale (`ui::font`) | caption 12, small 13, body 14 desktop / 16 mobile, title 17, heading 20, display 28. Respect OS text size up to 200 % (WCAG 1.4.4); bubbles reflow, rows grow, nothing truncates mid-word without an accessible full label. |
| Weights | Regular 400 body, Medium 500 titles and buttons, Semibold 600 headings. No light weights (contrast). |
| Numbers | Tabular figures for times, call durations, safety numbers, invite codes. Safety numbers and recovery keys in the platform monospace. |

## 4. Icons

- **Lucide** (ISC licence, lucide.dev), shapes redrawn inline in `apps/ui/src/ui/icons.rs`, 2 pt
  stroke, round caps, `currentColor`, 24 pt grid; sizes 16 (inline), 20 (rows), 24 (bars, tabs).
- Licence text (ISC, "Copyright (c) Lucide Contributors" and the Feather MIT notice Lucide
  carries) goes into the in-app licences list.
- Filled variants only for state: read tick disc, selected tab pill (the pill is filled, the icon
  stays outline), presence dot.
- Every icon-only control has an accessible label (`icon_btn(Icon, label, f)` requires it).
- In code today: Chats, Calls, Communities, You, Search, Plus, Close, Back, Forward, chevrons,
  More, Send, Mic(Off), Camera, Video(Off), Phone (incoming, outgoing, missed, off), Paperclip,
  Smile, Image, File, MapPin, Contact, Poll, Calendar, Sticker, Lock, Unlock, Shield,
  ShieldCheck, Key, Eye(Off), Bell(Off), Pin, Archive, Star, Trash, Edit, Copy, Reply, Share,
  Link, QrCode, Scan, Users, UserPlus, User, Settings, Info, Alert, Check, Clock, Timer,
  Download, Upload, Cloud, HardDrive, Smartphone, Laptop, Globe, Palette, HelpCircle, Heart,
  Gift, Sparkles, Speaker, ScreenShare, Hand, Grid, Filter, Play, Pause, Megaphone, Flag, Ban,
  Database, Wifi(Off), Moon, Sun, Zap, Refresh, LogOut, Sliders, Volume, Minimize, Maximize,
  Keyboard, Feather, Inbox, Layers, Baby, Server.

## 5. Motion

Principles: motion explains a change (where something came from, where it went); it never
decorates, never delays input, and leaving is faster than entering. Interruptible: a new gesture
cancels a running animation from its current value.

| Token (`ui::motion`) | Value | Used for |
| --- | --- | --- |
| `INSTANT` | 120 ms | hover wash, row press |
| `FAST` | 180 ms | button press, toggles, tick change, chip select |
| `BASE` | 240 ms | tab pill, selection moving, toast in, glyph swap, reaction pop |
| `SLOW` | 360 ms | sheets, dialogs, reveals, call screen in |
| `PRESS_SCALE` / `ICON_PRESS_SCALE` | 0.97 / 0.94 | pressed controls |
| `SETTLE` | cubic-bezier(0.22, 1, 0.36, 1) | default curve (fast out, soft settle) |
| Exit | ×0.67 of enter, ease-in | dismissals |
| Spring (proposal) | stiffness 380, damping 32 | swipe-to-reply snap-back, sheet drag release |

Reduced motion (OS setting, or You › Chats › Animations off): drop every scale and translate;
keep colour and opacity fades ≤ `FAST`; no autoplaying animated stickers or chat scenes; nudge
shakes become a single highlight fade.

Signature moments (kept small): message send (bubble rises 6 pt from the composer, `BASE`); read
tick fills its disc (`FAST`); nudge (window/chat shakes 3 × 6 pt, 360 ms, once, never repeats
within 10 s); call connect (avatar ring settles into the video tile, `SLOW`).

## 6. Sound design brief

| Sound | Brief | Length | Notes |
| --- | --- | --- | --- |
| Message (in app, foreground) | Soft two-note wooden tick, rising | ≤ 150 ms | Quieter than the OS; off by default when the chat is open. |
| Notification | Short birdsong-like chirp (two syllables), warm, not shrill; peak 2–4 kHz kept low | 400–600 ms | Must stay recognisable through phone speakers and distinct from WhatsApp's/Signal's tones. |
| Group notification | Same timbre, one syllable | ≤ 300 ms | Distinguishes groups without a new sound family. |
| Ringtone (voice / video) | Calm 3-note motif, loops every 2 s, gentle fade-in over the first 3 s | 2 s loop | Never alarm-like; same melody, video one octave up. |
| Outgoing ringback | Soft low pulse | 1 s loop | |
| Call connect | Two ascending notes | ≤ 300 ms | |
| Call end | Same two notes descending | ≤ 300 ms | |
| Reconnecting | Single muted tone every 3 s | 200 ms | Stops at 30 s. |
| Nudge (Yahoo Buzz) | Playful short rattle/flutter, the one "fun" sound | ≤ 700 ms | Plays only if the receiver has nudges on; respects silent mode. |
| Fun pack (opt-in) | Retro sounds (Yahoo-style "door open", buzz) | | Off by default; You › Notifications › Sound style: Calm (default) / Playful. |

Constraints: −16 LUFS integrated, no clipping, mono-compatible, AAC/Opus plus WAV masters,
haptic pairing (iOS Core Haptics light transient for message, three soft pulses for nudge).
Every sound has an off switch; nothing plays in Do Not Disturb except what the OS allows. Licence:
commissioned work-for-hire or CC0 sources only; keep the source files in the repo.

## Appendix: full contrast table

Generated by `python3 docs/design/tools/contrast.py --markdown` on 2026-11-17.

| Theme | Foreground | Background | Ratio | Needs | Result | Used for |
| --- | --- | --- | --- | --- | --- | --- |
| light | `foreground` #15191C | `background` #FBFBF9 | 17.07 | 4.5 (text) | pass | body text on pages |
| light | `foreground` #15191C | `card` #FFFFFF | 17.68 | 4.5 (text) | pass | row titles, field text |
| light | `foreground` #15191C | `popover` #FFFFFF | 17.68 | 4.5 (text) | pass | sheet and dialog text |
| light | `card-foreground` #15191C | `card` #FFFFFF | 17.68 | 4.5 (text) | pass | card text |
| light | `popover-foreground` #15191C | `popover` #FFFFFF | 17.68 | 4.5 (text) | pass | popover text |
| light | `foreground` #15191C | `accent` #E7F1EE | 15.34 | 4.5 (text) | pass | row text while hovered/pressed |
| light | `foreground` #15191C | `sidebar-accent` #E3EEEA | 14.89 | 4.5 (text) | pass | rail item hovered |
| light | `muted-foreground` #5A636B | `background` #FBFBF9 | 5.91 | 4.5 (text) | pass | subtitles, tab labels |
| light | `muted-foreground` #5A636B | `card` #FFFFFF | 6.12 | 4.5 (text) | pass | row subtitles, values, placeholders |
| light | `muted-foreground` #5A636B | `popover` #FFFFFF | 6.12 | 4.5 (text) | pass | sheet secondary text |
| light | `muted-foreground` #5A636B | `secondary` #EEF1EE | 5.38 | 4.5 (text) | pass | search placeholder, unselected chip |
| light | `muted-foreground` #5A636B | `muted` #F1F2EF | 5.45 | 4.5 (text) | pass | muted surfaces |
| light | `muted-foreground` #5A636B | `sidebar` #F4F5F2 | 5.59 | 4.5 (text) | pass | rail labels |
| light | `muted-foreground` #5A636B | `chat-bg` #F2F0EA | 5.37 | 4.5 (text) | pass | date chips, system lines in chat |
| light | `primary-foreground` #FFFFFF | `primary` #136B5B | 6.40 | 4.5 (text) | pass | primary button, unread badge |
| light | `background` #FBFBF9 | `muted-foreground` #5A636B | 5.91 | 4.5 (text) | pass | muted chat unread badge |
| light | `secondary-foreground` #1B2A26 | `secondary` #EEF1EE | 13.13 | 4.5 (text) | pass | secondary button, tag |
| light | `accent-foreground` #0E3D34 | `accent` #E7F1EE | 10.49 | 4.5 (text) | pass | selected chip |
| light | `primary` #136B5B | `background` #FBFBF9 | 6.18 | 4.5 (text) | pass | ghost/outline button label |
| light | `primary` #136B5B | `card` #FFFFFF | 6.40 | 4.5 (text) | pass | ghost button inside a card |
| light | `primary` #136B5B | `accent` #E7F1EE | 5.55 | 3.0 (ui) | pass | selected tab icon, icon tile, empty-state glyph |
| light | `destructive` #B9302A | `background` #FBFBF9 | 5.76 | 4.5 (text) | pass | danger row label |
| light | `destructive` #B9302A | `card` #FFFFFF | 5.97 | 4.5 (text) | pass | danger row label in a group |
| light | `destructive-foreground` #FFFFFF | `destructive` #B9302A | 5.97 | 4.5 (text) | pass | danger button |
| light | `sidebar-foreground` #15191C | `sidebar` #F4F5F2 | 16.16 | 4.5 (text) | pass | rail text |
| light | `sidebar-accent-foreground` #0E3D34 | `sidebar-accent` #E3EEEA | 10.19 | 4.5 (text) | pass | rail selection |
| light | `bubble-out-foreground` #0F2B24 | `bubble-out` #D8EEE6 | 12.43 | 4.5 (text) | pass | outgoing message |
| light | `bubble-in-foreground` #15191C | `bubble-in` #FFFFFF | 17.68 | 4.5 (text) | pass | incoming message |
| light | `bubble-meta` #56605D | `bubble-out` #D8EEE6 | 5.36 | 4.5 (text) | pass | time and sent/delivered ticks, outgoing |
| light | `bubble-meta` #56605D | `bubble-in` #FFFFFF | 6.51 | 4.5 (text) | pass | time, incoming |
| light | `link` #1660C0 | `bubble-in` #FFFFFF | 6.05 | 4.5 (text) | pass | link in incoming bubble |
| light | `link` #1660C0 | `bubble-out` #D8EEE6 | 4.99 | 4.5 (text) | pass | link in outgoing bubble |
| light | `link` #1660C0 | `background` #FBFBF9 | 5.84 | 4.5 (text) | pass | link on a page |
| light | `mention` #136B5B | `bubble-in` #FFFFFF | 6.40 | 4.5 (text) | pass | @mention, incoming |
| light | `mention` #136B5B | `bubble-out` #D8EEE6 | 5.27 | 4.5 (text) | pass | @mention, outgoing |
| light | `foreground` #15191C | `highlight` #FFE9A8 | 14.71 | 4.5 (text) | pass | search match highlight |
| light | `foreground` #15191C | `warning-bg` #FFF4DA | 16.17 | 4.5 (text) | pass | warning banner text |
| light | `foreground` #15191C | `info-bg` #E6F0FB | 15.34 | 4.5 (text) | pass | info / secure banner text |
| light | `warning` #8A5A00 | `warning-bg` #FFF4DA | 5.42 | 3.0 (ui) | pass | warning banner icon |
| light | `destructive` #B9302A | `warning-bg` #FFF4DA | 5.46 | 3.0 (ui) | pass | danger banner icon |
| light | `link` #1660C0 | `info-bg` #E6F0FB | 5.25 | 3.0 (ui) | pass | info banner icon |
| light | `primary` #136B5B | `info-bg` #E6F0FB | 5.55 | 3.0 (ui) | pass | secure banner icon |
| light | `success-foreground` #FFFFFF | `success` #1C7A4A | 5.34 | 4.5 (text) | pass | success badge |
| light | `success` #1C7A4A | `background` #FBFBF9 | 5.15 | 3.0 (ui) | pass | success icon on page |
| light | `warning` #8A5A00 | `background` #FBFBF9 | 5.72 | 4.5 (text) | pass | warning text on page |
| light | `call-foreground` #F2F6F4 | `call-bg` #0F1A17 | 16.32 | 4.5 (text) | pass | call screen text |
| light | `call-foreground` #F2F6F4 | `call-accept` #1C8A4E | 4.02 | 3.0 (ui) | pass | accept glyph |
| light | `call-foreground` #F2F6F4 | `call-decline` #C7342C | 4.87 | 3.0 (ui) | pass | decline glyph |
| light | `call-accept` #1C8A4E | `call-bg` #0F1A17 | 4.06 | 3.0 (ui) | pass | accept button on call screen |
| light | `call-decline` #C7342C | `call-bg` #0F1A17 | 3.35 | 3.0 (ui) | pass | decline button on call screen |
| light | `background` #FBFBF9 | `foreground` #15191C | 17.07 | 4.5 (text) | pass | toast |
| light | `tick-read` #1660C0 | `bubble-out` #D8EEE6 | 4.99 | 3.0 (ui) | pass | read tick |
| light | `tick-read` #1660C0 | `bubble-in` #FFFFFF | 6.05 | 3.0 (ui) | pass | played mark in incoming voice note |
| light | `destructive` #B9302A | `bubble-out` #D8EEE6 | 4.91 | 3.0 (ui) | pass | failed tick |
| light | `online` #1F9D55 | `card` #FFFFFF | 3.49 | 3.0 (ui) | pass | presence dot |
| light | `online` #1F9D55 | `background` #FBFBF9 | 3.37 | 3.0 (ui) | pass | presence dot on page |
| light | `input` #CDD2CD | `card` #FFFFFF | 1.53 | 3.0 (ui) | FAIL | field border |
| light | `input` #CDD2CD | `background` #FBFBF9 | 1.48 | 3.0 (ui) | FAIL | toggle track off, on page |
| light | `card` #FFFFFF | `input` #CDD2CD | 1.53 | 3.0 (ui) | FAIL | toggle knob on off track |
| light | `card` #FFFFFF | `primary` #136B5B | 6.40 | 3.0 (ui) | pass | toggle knob on on track |
| light | `primary` #136B5B | `background` #FBFBF9 | 6.18 | 3.0 (ui) | pass | toggle on / primary button boundary |
| light | `ring` #136B5B | `background` #FBFBF9 | 6.18 | 3.0 (ui) | pass | focus ring |
| light | `ring` #136B5B | `card` #FFFFFF | 6.40 | 3.0 (ui) | pass | focus ring in a group |
| light | `input` #CDD2CD | `popover` #FFFFFF | 1.53 | 3.0 (ui) | FAIL | sheet grabber |
| light | `border` #E2E5E1 | `background` #FBFBF9 | 1.23 | — (info) | info | hairline separators (decorative) |
| light | `border` #E2E5E1 | `card` #FFFFFF | 1.27 | — (info) | info | group border (decorative) |
| light | `bubble-in` #FFFFFF | `chat-bg` #F2F0EA | 1.14 | — (info) | info | incoming bubble edge (shape is not needed to read) |
| light | `bubble-out` #D8EEE6 | `chat-bg` #F2F0EA | 1.07 | — (info) | info | outgoing bubble edge |
| light | `avatar-foreground` #FFFFFF | `avatar-1` #2F6F9F | 5.39 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-2` #8A4FA3 | 5.63 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-3` #B4532A | 4.99 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-4` #2E7D5B | 5.00 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-5` #A63D63 | 6.05 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-6` #5A5FB0 | 5.68 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-7` #7A6A1E | 5.37 | 4.5 (text) | pass | avatar initials |
| light | `avatar-foreground` #FFFFFF | `avatar-8` #2D7A86 | 4.95 | 4.5 (text) | pass | avatar initials |
| dark | `foreground` #E7ECEA | `background` #0D1113 | 15.89 | 4.5 (text) | pass | body text on pages |
| dark | `foreground` #E7ECEA | `card` #151B1E | 14.56 | 4.5 (text) | pass | row titles, field text |
| dark | `foreground` #E7ECEA | `popover` #1A2125 | 13.65 | 4.5 (text) | pass | sheet and dialog text |
| dark | `card-foreground` #E7ECEA | `card` #151B1E | 14.56 | 4.5 (text) | pass | card text |
| dark | `popover-foreground` #E7ECEA | `popover` #1A2125 | 13.65 | 4.5 (text) | pass | popover text |
| dark | `foreground` #E7ECEA | `accent` #1C2B28 | 12.33 | 4.5 (text) | pass | row text while hovered/pressed |
| dark | `foreground` #E7ECEA | `sidebar-accent` #1C2B28 | 12.33 | 4.5 (text) | pass | rail item hovered |
| dark | `muted-foreground` #9AA6A2 | `background` #0D1113 | 7.55 | 4.5 (text) | pass | subtitles, tab labels |
| dark | `muted-foreground` #9AA6A2 | `card` #151B1E | 6.92 | 4.5 (text) | pass | row subtitles, values, placeholders |
| dark | `muted-foreground` #9AA6A2 | `popover` #1A2125 | 6.48 | 4.5 (text) | pass | sheet secondary text |
| dark | `muted-foreground` #9AA6A2 | `secondary` #1C2427 | 6.27 | 4.5 (text) | pass | search placeholder, unselected chip |
| dark | `muted-foreground` #9AA6A2 | `muted` #182024 | 6.57 | 4.5 (text) | pass | muted surfaces |
| dark | `muted-foreground` #9AA6A2 | `sidebar` #111719 | 7.20 | 4.5 (text) | pass | rail labels |
| dark | `muted-foreground` #9AA6A2 | `chat-bg` #0A0E10 | 7.71 | 4.5 (text) | pass | date chips, system lines in chat |
| dark | `primary-foreground` #04201A | `primary` #4CC3A5 | 7.87 | 4.5 (text) | pass | primary button, unread badge |
| dark | `background` #0D1113 | `muted-foreground` #9AA6A2 | 7.55 | 4.5 (text) | pass | muted chat unread badge |
| dark | `secondary-foreground` #DDE6E3 | `secondary` #1C2427 | 12.40 | 4.5 (text) | pass | secondary button, tag |
| dark | `accent-foreground` #CFEFE6 | `accent` #1C2B28 | 12.02 | 4.5 (text) | pass | selected chip |
| dark | `primary` #4CC3A5 | `background` #0D1113 | 8.73 | 4.5 (text) | pass | ghost/outline button label |
| dark | `primary` #4CC3A5 | `card` #151B1E | 8.00 | 4.5 (text) | pass | ghost button inside a card |
| dark | `primary` #4CC3A5 | `accent` #1C2B28 | 6.77 | 3.0 (ui) | pass | selected tab icon, icon tile, empty-state glyph |
| dark | `destructive` #F06A5F | `background` #0D1113 | 6.26 | 4.5 (text) | pass | danger row label |
| dark | `destructive` #F06A5F | `card` #151B1E | 5.74 | 4.5 (text) | pass | danger row label in a group |
| dark | `destructive-foreground` #2A0603 | `destructive` #F06A5F | 6.16 | 4.5 (text) | pass | danger button |
| dark | `sidebar-foreground` #E7ECEA | `sidebar` #111719 | 15.15 | 4.5 (text) | pass | rail text |
| dark | `sidebar-accent-foreground` #CFEFE6 | `sidebar-accent` #1C2B28 | 12.02 | 4.5 (text) | pass | rail selection |
| dark | `bubble-out-foreground` #E5F4EF | `bubble-out` #17443A | 9.62 | 4.5 (text) | pass | outgoing message |
| dark | `bubble-in-foreground` #E7ECEA | `bubble-in` #1A2124 | 13.66 | 4.5 (text) | pass | incoming message |
| dark | `bubble-meta` #A3B1AC | `bubble-out` #17443A | 4.91 | 4.5 (text) | pass | time and sent/delivered ticks, outgoing |
| dark | `bubble-meta` #A3B1AC | `bubble-in` #1A2124 | 7.34 | 4.5 (text) | pass | time, incoming |
| dark | `link` #7DB9FF | `bubble-in` #1A2124 | 7.97 | 4.5 (text) | pass | link in incoming bubble |
| dark | `link` #7DB9FF | `bubble-out` #17443A | 5.33 | 4.5 (text) | pass | link in outgoing bubble |
| dark | `link` #7DB9FF | `background` #0D1113 | 9.27 | 4.5 (text) | pass | link on a page |
| dark | `mention` #4CC3A5 | `bubble-in` #1A2124 | 7.50 | 4.5 (text) | pass | @mention, incoming |
| dark | `mention` #4CC3A5 | `bubble-out` #17443A | 5.02 | 4.5 (text) | pass | @mention, outgoing |
| dark | `foreground` #E7ECEA | `highlight` #5A4A12 | 7.26 | 4.5 (text) | pass | search match highlight |
| dark | `foreground` #E7ECEA | `warning-bg` #2C2410 | 12.86 | 4.5 (text) | pass | warning banner text |
| dark | `foreground` #E7ECEA | `info-bg` #132233 | 13.48 | 4.5 (text) | pass | info / secure banner text |
| dark | `warning` #F2C35B | `warning-bg` #2C2410 | 9.31 | 3.0 (ui) | pass | warning banner icon |
| dark | `destructive` #F06A5F | `warning-bg` #2C2410 | 5.07 | 3.0 (ui) | pass | danger banner icon |
| dark | `link` #7DB9FF | `info-bg` #132233 | 7.86 | 3.0 (ui) | pass | info banner icon |
| dark | `primary` #4CC3A5 | `info-bg` #132233 | 7.40 | 3.0 (ui) | pass | secure banner icon |
| dark | `success-foreground` #04200F | `success` #5BD08F | 8.91 | 4.5 (text) | pass | success badge |
| dark | `success` #5BD08F | `background` #0D1113 | 9.82 | 3.0 (ui) | pass | success icon on page |
| dark | `warning` #F2C35B | `background` #0D1113 | 11.51 | 4.5 (text) | pass | warning text on page |
| dark | `call-foreground` #F2F6F4 | `call-bg` #070B0A | 18.15 | 4.5 (text) | pass | call screen text |
| dark | `call-foreground` #F2F6F4 | `call-accept` #2FB36A | 2.48 | 3.0 (ui) | FAIL | accept glyph |
| dark | `call-foreground` #F2F6F4 | `call-decline` #E5544A | 3.38 | 3.0 (ui) | pass | decline glyph |
| dark | `call-accept` #2FB36A | `call-bg` #070B0A | 7.33 | 3.0 (ui) | pass | accept button on call screen |
| dark | `call-decline` #E5544A | `call-bg` #070B0A | 5.37 | 3.0 (ui) | pass | decline button on call screen |
| dark | `background` #0D1113 | `foreground` #E7ECEA | 15.89 | 4.5 (text) | pass | toast |
| dark | `tick-read` #7DB9FF | `bubble-out` #17443A | 5.33 | 3.0 (ui) | pass | read tick |
| dark | `tick-read` #7DB9FF | `bubble-in` #1A2124 | 7.97 | 3.0 (ui) | pass | played mark in incoming voice note |
| dark | `destructive` #F06A5F | `bubble-out` #17443A | 3.60 | 3.0 (ui) | pass | failed tick |
| dark | `online` #4CD486 | `card` #151B1E | 9.17 | 3.0 (ui) | pass | presence dot |
| dark | `online` #4CD486 | `background` #0D1113 | 10.00 | 3.0 (ui) | pass | presence dot on page |
| dark | `input` #334047 | `card` #151B1E | 1.63 | 3.0 (ui) | FAIL | field border |
| dark | `input` #334047 | `background` #0D1113 | 1.78 | 3.0 (ui) | FAIL | toggle track off, on page |
| dark | `card` #151B1E | `input` #334047 | 1.63 | 3.0 (ui) | FAIL | toggle knob on off track |
| dark | `card` #151B1E | `primary` #4CC3A5 | 8.00 | 3.0 (ui) | pass | toggle knob on on track |
| dark | `primary` #4CC3A5 | `background` #0D1113 | 8.73 | 3.0 (ui) | pass | toggle on / primary button boundary |
| dark | `ring` #4CC3A5 | `background` #0D1113 | 8.73 | 3.0 (ui) | pass | focus ring |
| dark | `ring` #4CC3A5 | `card` #151B1E | 8.00 | 3.0 (ui) | pass | focus ring in a group |
| dark | `input` #334047 | `popover` #1A2125 | 1.53 | 3.0 (ui) | FAIL | sheet grabber |
| dark | `border` #252F33 | `background` #0D1113 | 1.39 | — (info) | info | hairline separators (decorative) |
| dark | `border` #252F33 | `card` #151B1E | 1.27 | — (info) | info | group border (decorative) |
| dark | `bubble-in` #1A2124 | `chat-bg` #0A0E10 | 1.19 | — (info) | info | incoming bubble edge (shape is not needed to read) |
| dark | `bubble-out` #17443A | `chat-bg` #0A0E10 | 1.78 | — (info) | info | outgoing bubble edge |
| dark | `avatar-foreground` #FFFFFF | `avatar-1` #4A8CC0 | 3.62 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-2` #A574BE | 3.59 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-3` #CC7550 | 3.37 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-4` #4F9E7C | 3.22 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-5` #C2648A | 3.83 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-6` #7E83CF | 3.48 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-7` #A69544 | 3.00 | 4.5 (text) | FAIL | avatar initials |
| dark | `avatar-foreground` #FFFFFF | `avatar-8` #4D9BA7 | 3.20 | 4.5 (text) | FAIL | avatar initials |
| hc-light | `foreground` #000000 | `background` #FFFFFF | 21.00 | 4.5 (text) | pass | body text on pages |
| hc-light | `foreground` #000000 | `card` #FFFFFF | 21.00 | 4.5 (text) | pass | row titles, field text |
| hc-light | `foreground` #000000 | `popover` #FFFFFF | 21.00 | 4.5 (text) | pass | sheet and dialog text |
| hc-light | `card-foreground` #15191C | `card` #FFFFFF | 17.68 | 4.5 (text) | pass | card text |
| hc-light | `popover-foreground` #15191C | `popover` #FFFFFF | 17.68 | 4.5 (text) | pass | popover text |
| hc-light | `foreground` #000000 | `accent` #D6EEE7 | 17.24 | 4.5 (text) | pass | row text while hovered/pressed |
| hc-light | `foreground` #000000 | `sidebar-accent` #E3EEEA | 17.68 | 4.5 (text) | pass | rail item hovered |
| hc-light | `muted-foreground` #262626 | `background` #FFFFFF | 15.13 | 4.5 (text) | pass | subtitles, tab labels |
| hc-light | `muted-foreground` #262626 | `card` #FFFFFF | 15.13 | 4.5 (text) | pass | row subtitles, values, placeholders |
| hc-light | `muted-foreground` #262626 | `popover` #FFFFFF | 15.13 | 4.5 (text) | pass | sheet secondary text |
| hc-light | `muted-foreground` #262626 | `secondary` #EEF1EE | 13.30 | 4.5 (text) | pass | search placeholder, unselected chip |
| hc-light | `muted-foreground` #262626 | `muted` #F0F0F0 | 13.28 | 4.5 (text) | pass | muted surfaces |
| hc-light | `muted-foreground` #262626 | `sidebar` #F4F5F2 | 13.83 | 4.5 (text) | pass | rail labels |
| hc-light | `muted-foreground` #262626 | `chat-bg` #FFFFFF | 15.13 | 4.5 (text) | pass | date chips, system lines in chat |
| hc-light | `primary-foreground` #FFFFFF | `primary` #004A3B | 10.28 | 4.5 (text) | pass | primary button, unread badge |
| hc-light | `background` #FFFFFF | `muted-foreground` #262626 | 15.13 | 4.5 (text) | pass | muted chat unread badge |
| hc-light | `secondary-foreground` #1B2A26 | `secondary` #EEF1EE | 13.13 | 4.5 (text) | pass | secondary button, tag |
| hc-light | `accent-foreground` #002A21 | `accent` #D6EEE7 | 12.74 | 4.5 (text) | pass | selected chip |
| hc-light | `primary` #004A3B | `background` #FFFFFF | 10.28 | 4.5 (text) | pass | ghost/outline button label |
| hc-light | `primary` #004A3B | `card` #FFFFFF | 10.28 | 4.5 (text) | pass | ghost button inside a card |
| hc-light | `primary` #004A3B | `accent` #D6EEE7 | 8.44 | 3.0 (ui) | pass | selected tab icon, icon tile, empty-state glyph |
| hc-light | `destructive` #B9302A | `background` #FFFFFF | 5.97 | 4.5 (text) | pass | danger row label |
| hc-light | `destructive` #B9302A | `card` #FFFFFF | 5.97 | 4.5 (text) | pass | danger row label in a group |
| hc-light | `destructive-foreground` #FFFFFF | `destructive` #B9302A | 5.97 | 4.5 (text) | pass | danger button |
| hc-light | `sidebar-foreground` #15191C | `sidebar` #F4F5F2 | 16.16 | 4.5 (text) | pass | rail text |
| hc-light | `sidebar-accent-foreground` #0E3D34 | `sidebar-accent` #E3EEEA | 10.19 | 4.5 (text) | pass | rail selection |
| hc-light | `bubble-out-foreground` #000000 | `bubble-out` #C6EADD | 16.21 | 4.5 (text) | pass | outgoing message |
| hc-light | `bubble-in-foreground` #15191C | `bubble-in` #F0F0F0 | 15.52 | 4.5 (text) | pass | incoming message |
| hc-light | `bubble-meta` #262626 | `bubble-out` #C6EADD | 11.68 | 4.5 (text) | pass | time and sent/delivered ticks, outgoing |
| hc-light | `bubble-meta` #262626 | `bubble-in` #F0F0F0 | 13.28 | 4.5 (text) | pass | time, incoming |
| hc-light | `link` #003E9C | `bubble-in` #F0F0F0 | 8.50 | 4.5 (text) | pass | link in incoming bubble |
| hc-light | `link` #003E9C | `bubble-out` #C6EADD | 7.48 | 4.5 (text) | pass | link in outgoing bubble |
| hc-light | `link` #003E9C | `background` #FFFFFF | 9.68 | 4.5 (text) | pass | link on a page |
| hc-light | `mention` #136B5B | `bubble-in` #F0F0F0 | 5.61 | 4.5 (text) | pass | @mention, incoming |
| hc-light | `mention` #136B5B | `bubble-out` #C6EADD | 4.94 | 4.5 (text) | pass | @mention, outgoing |
| hc-light | `foreground` #000000 | `highlight` #FFE9A8 | 17.47 | 4.5 (text) | pass | search match highlight |
| hc-light | `foreground` #000000 | `warning-bg` #FFF4DA | 19.20 | 4.5 (text) | pass | warning banner text |
| hc-light | `foreground` #000000 | `info-bg` #E6F0FB | 18.22 | 4.5 (text) | pass | info / secure banner text |
| hc-light | `warning` #8A5A00 | `warning-bg` #FFF4DA | 5.42 | 3.0 (ui) | pass | warning banner icon |
| hc-light | `destructive` #B9302A | `warning-bg` #FFF4DA | 5.46 | 3.0 (ui) | pass | danger banner icon |
| hc-light | `link` #003E9C | `info-bg` #E6F0FB | 8.40 | 3.0 (ui) | pass | info banner icon |
| hc-light | `primary` #004A3B | `info-bg` #E6F0FB | 8.92 | 3.0 (ui) | pass | secure banner icon |
| hc-light | `success-foreground` #FFFFFF | `success` #1C7A4A | 5.34 | 4.5 (text) | pass | success badge |
| hc-light | `success` #1C7A4A | `background` #FFFFFF | 5.34 | 3.0 (ui) | pass | success icon on page |
| hc-light | `warning` #8A5A00 | `background` #FFFFFF | 5.93 | 4.5 (text) | pass | warning text on page |
| hc-light | `call-foreground` #F2F6F4 | `call-bg` #0F1A17 | 16.32 | 4.5 (text) | pass | call screen text |
| hc-light | `call-foreground` #F2F6F4 | `call-accept` #1C8A4E | 4.02 | 3.0 (ui) | pass | accept glyph |
| hc-light | `call-foreground` #F2F6F4 | `call-decline` #C7342C | 4.87 | 3.0 (ui) | pass | decline glyph |
| hc-light | `call-accept` #1C8A4E | `call-bg` #0F1A17 | 4.06 | 3.0 (ui) | pass | accept button on call screen |
| hc-light | `call-decline` #C7342C | `call-bg` #0F1A17 | 3.35 | 3.0 (ui) | pass | decline button on call screen |
| hc-light | `background` #FFFFFF | `foreground` #000000 | 21.00 | 4.5 (text) | pass | toast |
| hc-light | `tick-read` #003E9C | `bubble-out` #C6EADD | 7.48 | 3.0 (ui) | pass | read tick |
| hc-light | `tick-read` #003E9C | `bubble-in` #F0F0F0 | 8.50 | 3.0 (ui) | pass | played mark in incoming voice note |
| hc-light | `destructive` #B9302A | `bubble-out` #C6EADD | 4.61 | 3.0 (ui) | pass | failed tick |
| hc-light | `online` #1F9D55 | `card` #FFFFFF | 3.49 | 3.0 (ui) | pass | presence dot |
| hc-light | `online` #1F9D55 | `background` #FFFFFF | 3.49 | 3.0 (ui) | pass | presence dot on page |
| hc-light | `input` #262626 | `card` #FFFFFF | 15.13 | 3.0 (ui) | pass | field border |
| hc-light | `input` #262626 | `background` #FFFFFF | 15.13 | 3.0 (ui) | pass | toggle track off, on page |
| hc-light | `card` #FFFFFF | `input` #262626 | 15.13 | 3.0 (ui) | pass | toggle knob on off track |
| hc-light | `card` #FFFFFF | `primary` #004A3B | 10.28 | 3.0 (ui) | pass | toggle knob on on track |
| hc-light | `primary` #004A3B | `background` #FFFFFF | 10.28 | 3.0 (ui) | pass | toggle on / primary button boundary |
| hc-light | `ring` #000000 | `background` #FFFFFF | 21.00 | 3.0 (ui) | pass | focus ring |
| hc-light | `ring` #000000 | `card` #FFFFFF | 21.00 | 3.0 (ui) | pass | focus ring in a group |
| hc-light | `input` #262626 | `popover` #FFFFFF | 15.13 | 3.0 (ui) | pass | sheet grabber |
| hc-light | `border` #4A4A4A | `background` #FFFFFF | 8.86 | — (info) | info | hairline separators (decorative) |
| hc-light | `border` #4A4A4A | `card` #FFFFFF | 8.86 | — (info) | info | group border (decorative) |
| hc-light | `bubble-in` #F0F0F0 | `chat-bg` #FFFFFF | 1.14 | — (info) | info | incoming bubble edge (shape is not needed to read) |
| hc-light | `bubble-out` #C6EADD | `chat-bg` #FFFFFF | 1.30 | — (info) | info | outgoing bubble edge |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-1` #2F6F9F | 5.39 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-2` #8A4FA3 | 5.63 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-3` #B4532A | 4.99 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-4` #2E7D5B | 5.00 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-5` #A63D63 | 6.05 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-6` #5A5FB0 | 5.68 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-7` #7A6A1E | 5.37 | 4.5 (text) | pass | avatar initials |
| hc-light | `avatar-foreground` #FFFFFF | `avatar-8` #2D7A86 | 4.95 | 4.5 (text) | pass | avatar initials |
| hc-dark | `foreground` #FFFFFF | `background` #000000 | 21.00 | 4.5 (text) | pass | body text on pages |
| hc-dark | `foreground` #FFFFFF | `card` #0A0A0A | 19.80 | 4.5 (text) | pass | row titles, field text |
| hc-dark | `foreground` #FFFFFF | `popover` #1A2125 | 16.30 | 4.5 (text) | pass | sheet and dialog text |
| hc-dark | `card-foreground` #E7ECEA | `card` #0A0A0A | 16.58 | 4.5 (text) | pass | card text |
| hc-dark | `popover-foreground` #E7ECEA | `popover` #1A2125 | 13.65 | 4.5 (text) | pass | popover text |
| hc-dark | `foreground` #FFFFFF | `accent` #123A31 | 12.54 | 4.5 (text) | pass | row text while hovered/pressed |
| hc-dark | `foreground` #FFFFFF | `sidebar-accent` #1C2B28 | 14.73 | 4.5 (text) | pass | rail item hovered |
| hc-dark | `muted-foreground` #E0E0E0 | `background` #000000 | 15.91 | 4.5 (text) | pass | subtitles, tab labels |
| hc-dark | `muted-foreground` #E0E0E0 | `card` #0A0A0A | 15.00 | 4.5 (text) | pass | row subtitles, values, placeholders |
| hc-dark | `muted-foreground` #E0E0E0 | `popover` #1A2125 | 12.35 | 4.5 (text) | pass | sheet secondary text |
| hc-dark | `muted-foreground` #E0E0E0 | `secondary` #1C2427 | 11.95 | 4.5 (text) | pass | search placeholder, unselected chip |
| hc-dark | `muted-foreground` #E0E0E0 | `muted` #141414 | 13.96 | 4.5 (text) | pass | muted surfaces |
| hc-dark | `muted-foreground` #E0E0E0 | `sidebar` #111719 | 13.71 | 4.5 (text) | pass | rail labels |
| hc-dark | `muted-foreground` #E0E0E0 | `chat-bg` #000000 | 15.91 | 4.5 (text) | pass | date chips, system lines in chat |
| hc-dark | `primary-foreground` #000000 | `primary` #8AF0D4 | 15.50 | 4.5 (text) | pass | primary button, unread badge |
| hc-dark | `background` #000000 | `muted-foreground` #E0E0E0 | 15.91 | 4.5 (text) | pass | muted chat unread badge |
| hc-dark | `secondary-foreground` #DDE6E3 | `secondary` #1C2427 | 12.40 | 4.5 (text) | pass | secondary button, tag |
| hc-dark | `accent-foreground` #FFFFFF | `accent` #123A31 | 12.54 | 4.5 (text) | pass | selected chip |
| hc-dark | `primary` #8AF0D4 | `background` #000000 | 15.50 | 4.5 (text) | pass | ghost/outline button label |
| hc-dark | `primary` #8AF0D4 | `card` #0A0A0A | 14.61 | 4.5 (text) | pass | ghost button inside a card |
| hc-dark | `primary` #8AF0D4 | `accent` #123A31 | 9.25 | 3.0 (ui) | pass | selected tab icon, icon tile, empty-state glyph |
| hc-dark | `destructive` #F06A5F | `background` #000000 | 6.93 | 4.5 (text) | pass | danger row label |
| hc-dark | `destructive` #F06A5F | `card` #0A0A0A | 6.54 | 4.5 (text) | pass | danger row label in a group |
| hc-dark | `destructive-foreground` #2A0603 | `destructive` #F06A5F | 6.16 | 4.5 (text) | pass | danger button |
| hc-dark | `sidebar-foreground` #E7ECEA | `sidebar` #111719 | 15.15 | 4.5 (text) | pass | rail text |
| hc-dark | `sidebar-accent-foreground` #CFEFE6 | `sidebar-accent` #1C2B28 | 12.02 | 4.5 (text) | pass | rail selection |
| hc-dark | `bubble-out-foreground` #FFFFFF | `bubble-out` #0E3B31 | 12.44 | 4.5 (text) | pass | outgoing message |
| hc-dark | `bubble-in-foreground` #E7ECEA | `bubble-in` #161616 | 15.15 | 4.5 (text) | pass | incoming message |
| hc-dark | `bubble-meta` #E0E0E0 | `bubble-out` #0E3B31 | 9.42 | 4.5 (text) | pass | time and sent/delivered ticks, outgoing |
| hc-dark | `bubble-meta` #E0E0E0 | `bubble-in` #161616 | 13.71 | 4.5 (text) | pass | time, incoming |
| hc-dark | `link` #A9D1FF | `bubble-in` #161616 | 11.42 | 4.5 (text) | pass | link in incoming bubble |
| hc-dark | `link` #A9D1FF | `bubble-out` #0E3B31 | 7.85 | 4.5 (text) | pass | link in outgoing bubble |
| hc-dark | `link` #A9D1FF | `background` #000000 | 13.25 | 4.5 (text) | pass | link on a page |
| hc-dark | `mention` #4CC3A5 | `bubble-in` #161616 | 8.32 | 4.5 (text) | pass | @mention, incoming |
| hc-dark | `mention` #4CC3A5 | `bubble-out` #0E3B31 | 5.72 | 4.5 (text) | pass | @mention, outgoing |
| hc-dark | `foreground` #FFFFFF | `highlight` #5A4A12 | 8.67 | 4.5 (text) | pass | search match highlight |
| hc-dark | `foreground` #FFFFFF | `warning-bg` #2C2410 | 15.36 | 4.5 (text) | pass | warning banner text |
| hc-dark | `foreground` #FFFFFF | `info-bg` #132233 | 16.10 | 4.5 (text) | pass | info / secure banner text |
| hc-dark | `warning` #F2C35B | `warning-bg` #2C2410 | 9.31 | 3.0 (ui) | pass | warning banner icon |
| hc-dark | `destructive` #F06A5F | `warning-bg` #2C2410 | 5.07 | 3.0 (ui) | pass | danger banner icon |
| hc-dark | `link` #A9D1FF | `info-bg` #132233 | 10.16 | 3.0 (ui) | pass | info banner icon |
| hc-dark | `primary` #8AF0D4 | `info-bg` #132233 | 11.88 | 3.0 (ui) | pass | secure banner icon |
| hc-dark | `success-foreground` #04200F | `success` #5BD08F | 8.91 | 4.5 (text) | pass | success badge |
| hc-dark | `success` #5BD08F | `background` #000000 | 10.86 | 3.0 (ui) | pass | success icon on page |
| hc-dark | `warning` #F2C35B | `background` #000000 | 12.73 | 4.5 (text) | pass | warning text on page |
| hc-dark | `call-foreground` #F2F6F4 | `call-bg` #070B0A | 18.15 | 4.5 (text) | pass | call screen text |
| hc-dark | `call-foreground` #F2F6F4 | `call-accept` #2FB36A | 2.48 | 3.0 (ui) | FAIL | accept glyph |
| hc-dark | `call-foreground` #F2F6F4 | `call-decline` #E5544A | 3.38 | 3.0 (ui) | pass | decline glyph |
| hc-dark | `call-accept` #2FB36A | `call-bg` #070B0A | 7.33 | 3.0 (ui) | pass | accept button on call screen |
| hc-dark | `call-decline` #E5544A | `call-bg` #070B0A | 5.37 | 3.0 (ui) | pass | decline button on call screen |
| hc-dark | `background` #000000 | `foreground` #FFFFFF | 21.00 | 4.5 (text) | pass | toast |
| hc-dark | `tick-read` #A9D1FF | `bubble-out` #0E3B31 | 7.85 | 3.0 (ui) | pass | read tick |
| hc-dark | `tick-read` #A9D1FF | `bubble-in` #161616 | 11.42 | 3.0 (ui) | pass | played mark in incoming voice note |
| hc-dark | `destructive` #F06A5F | `bubble-out` #0E3B31 | 4.11 | 3.0 (ui) | pass | failed tick |
| hc-dark | `online` #4CD486 | `card` #0A0A0A | 10.44 | 3.0 (ui) | pass | presence dot |
| hc-dark | `online` #4CD486 | `background` #000000 | 11.07 | 3.0 (ui) | pass | presence dot on page |
| hc-dark | `input` #E0E0E0 | `card` #0A0A0A | 15.00 | 3.0 (ui) | pass | field border |
| hc-dark | `input` #E0E0E0 | `background` #000000 | 15.91 | 3.0 (ui) | pass | toggle track off, on page |
| hc-dark | `card` #0A0A0A | `input` #E0E0E0 | 15.00 | 3.0 (ui) | pass | toggle knob on off track |
| hc-dark | `card` #0A0A0A | `primary` #8AF0D4 | 14.61 | 3.0 (ui) | pass | toggle knob on on track |
| hc-dark | `primary` #8AF0D4 | `background` #000000 | 15.50 | 3.0 (ui) | pass | toggle on / primary button boundary |
| hc-dark | `ring` #FFFFFF | `background` #000000 | 21.00 | 3.0 (ui) | pass | focus ring |
| hc-dark | `ring` #FFFFFF | `card` #0A0A0A | 19.80 | 3.0 (ui) | pass | focus ring in a group |
| hc-dark | `input` #E0E0E0 | `popover` #1A2125 | 12.35 | 3.0 (ui) | pass | sheet grabber |
| hc-dark | `border` #BDBDBD | `background` #000000 | 11.18 | — (info) | info | hairline separators (decorative) |
| hc-dark | `border` #BDBDBD | `card` #0A0A0A | 10.54 | — (info) | info | group border (decorative) |
| hc-dark | `bubble-in` #161616 | `chat-bg` #000000 | 1.16 | — (info) | info | incoming bubble edge (shape is not needed to read) |
| hc-dark | `bubble-out` #0E3B31 | `chat-bg` #000000 | 1.69 | — (info) | info | outgoing bubble edge |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-1` #4A8CC0 | 3.62 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-2` #A574BE | 3.59 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-3` #CC7550 | 3.37 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-4` #4F9E7C | 3.22 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-5` #C2648A | 3.83 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-6` #7E83CF | 3.48 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-7` #A69544 | 3.00 | 4.5 (text) | FAIL | avatar initials |
| hc-dark | `avatar-foreground` #FFFFFF | `avatar-8` #4D9BA7 | 3.20 | 4.5 (text) | FAIL | avatar initials |

**26 failing pair(s).**
