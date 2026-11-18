# Songbird design system (A1 foundations)

The promise: **as easy as WhatsApp, as trustworthy as Proton.** Calm, clear,
familiar; security visible but never in the way. This file is the app's
design standard (NSH Design Guides, "Establish the app's design system
first"). Every screen follows it; a look it lacks becomes a variant in
`src/ui/` first.

## Brand

- **Name and mark.** Songbird; the mark is a feather (rail logo, app icon
  draft) in the primary colour. Final logo and app icon are owner decisions
  (A1 gate).
- **Voice.** Plain words, short sentences, no jargon, no fear. Say what
  happens, not how the crypto works. "Only people in this chat can read
  these messages", never "E2EE with PQXDH". Details are one tap away.
- **Colour.** Dusk violet (owner's choice, 2026-11-17): primary `#4B3FA8` light,
  `#A99CF2` dark; lavender sent bubbles, white/near-black received bubbles,
  a cool lilac-grey chat background, read ticks in violet (filled circle).
  Chosen to be clearly *not* WhatsApp (green, mint/teal bubbles, beige
  wallpaper, blue ticks): Songbird keeps WhatsApp's familiar structure but
  has its own look. Status colours (success, warning, danger) only for
  their meanings; green is used only for "online", call accept and the
  WhatsApp-chat marker.
- **Type.** The platform's system font (SF Pro, Roboto, Segoe UI, Cantarell
  or the distro default): native manners, full Romanian diacritics and RTL
  coverage with no font to ship. Open-licence brand face (Inter or Noto
  Sans) is an owner decision; `theme.json` `font-sans` switches it.
- **Icons.** Lucide shapes (ISC licence), redrawn inline in
  `src/ui/icons.rs`, 2pt stroke, `currentColor`.

## Tokens (`theme.json`, one source)

| Group | Tokens |
| --- | --- |
| Surfaces | `background`, `card`, `popover`, `sidebar`, `muted`, `secondary`, `accent`, `chat-bg` |
| Text | `foreground`, `muted-foreground`, `*-foreground` for each surface |
| Actions | `primary`, `destructive`, `ring`, `border`, `input` |
| Chat | `bubble-out`, `bubble-out-foreground`, `bubble-in`, `bubble-in-foreground`, `bubble-meta`, `tick-read`, `link`, `mention`, `highlight` |
| Status | `success`, `warning`, `warning-bg`, `info-bg`, `online` |
| Calls | `call-bg`, `call-foreground`, `call-accept`, `call-decline` |
| Controls | `switch-thumb` (near-white knob, both themes), `switch-track` (off track, outlined in `input`), `switch-on` (on track; deeper violet than `primary` in dark so the knob keeps 3:1), `raised` (selected segment, lighter than its track in both themes), `control` (secondary button fill, distinct from `popover`) |
| Other | `overlay`, `whatsapp`, `avatar-1`…`avatar-8` (calm, violet-leaning hues, all ≥ 4.5:1 with white), `avatar-foreground` |
| Radius | `radius` 10 (controls), `radius-sm` 6 (chips, tiles), `radius-lg` 14 (cards, groups), `radius-bubble` 18, `radius-sheet` 20 — the base; each platform skin sets its own (below) |

Rust reads them only through `ui::c::*()` and `ui::radius::*()`. No hex,
`rgb()` or palette value in feature code, ever. High contrast and forced
light/dark are built from the same file (`src/theming.rs`).

**Spacing**: Tailwind's 4pt scale (`gap_1`=4 … `p_6`=24). Related items 4–8,
groups 12–16, sections 24.
**Type scale**: caption 12, small 13, body 14 desktop / 16 mobile, title 17,
heading 20, display 28 (`ui::font`).
**Sizes**: desktop controls 28/34/42pt; mobile 36/46/54pt and ≥ 44pt touch
targets (`ui::TOUCH` = 48). Rows 44pt desktop, 56pt mobile.

**Hairlines**: separators, pane borders, card and group outlines are one
device pixel (`ui::hairline()`), never a fixed 1pt.
**Separator insets** start under the row titles: 16 (plain), 58 (icon tile
30 + 12), 64 (36pt avatar + 12): `INSET_PLAIN`, `INSET_ICON`,
`INSET_AVATAR`.
**Focus ring**: 2pt `ring`, 2pt outside the control, following its radius
(buttons, icon buttons, chips, the FAB, rail items). Rows inside a clipped
group show focus as the `accent` wash instead.
**Badges and dots over another surface** carry a 2pt ring of that
surface's colour (`unread_badge_on`, `avatar_presence_on`).
**Elevation**: only what floats has a shadow (FAB: soft, primary-tinted;
toast and popups: `md`). Base regions are separated by hairlines.

## Platform skins (`ui::skin`)

Songbird follows each OS's design language and keeps its brand: Dusk
violet is the accent everywhere (Apple's tint, Material's seed, Fluent's
and Adwaita's accent), the feather mark, the copy and the layout and IA
never change. `ui::skin()` picks the skin from `os()`; a `SkinSpec` holds
its numbers and the `ui` layer and the shell read it (features don't).
`theme.json` `skins` holds each skin's surface overrides (Apple keeps the
base); `theming` layers them and the skin's radii under the user's theme
choice (high contrast always wins). Debug builds: `SONGBIRD_SKIN=apple|
material|fluent|adwaita`, ⌘⌥S / Ctrl+Alt+S cycles, and the gallery has a
switcher with the four skins' controls side by side. Every skin's light,
dark and high-contrast tokens pass WCAG AA (`contrast.py` over `skins`).

| | Apple (iOS, iPadOS, macOS) | Material 3 Expressive (Android, web) | Fluent 2 (Windows) | Adwaita (Linux) |
| --- | --- | --- | --- | --- |
| Surfaces | Base Songbird surfaces | Tonal: surface, surface-container low/–/high/highest seeded from Dusk violet | Mica-fallback window, layered cards, 1px strokes | Window, view, sidebar and header-bar roles, tinted violet |
| Radii (control / button / card / sheet / dialog / bubble) | 10 / capsule / 18 / 28 / 24 / 18 | 4 / pill / 20 / 28 / 28 / 20 | 4 / 4 / 8 / 8 / 8 / 8 | 6 / 6 (suggested action: pill) / 12 / 14 / 14 / 14 |
| Button heights desktop · phone (S/M/L) | 24/30/38 · 36/48/54 | 32/40/48 · 40/48/56 | 24/32/40 · 32/40/48 | 24/34/42 · 34/42/50 |
| Section root title | 34 bold, +0.4 (phones), under the glass toolbar; 20 bold in a Mac list pane | 32 medium headline under the top app bar (phones) | 28 semibold page title, beside the actions | 15 bold, centred in a 47pt header bar |
| Pushed page title | 17 semibold, centred on phones, chevron back on glass | 22 regular, leading, arrow back | 20 semibold, arrow back, 1px rule | 15 bold, centred, header bar with shade |
| Header controls | Grouped on a Liquid Glass capsule | Bare icon buttons, state layer | 4pt squares, subtle fill | 6pt flat buttons |
| Phone navigation | Floating Liquid Glass capsule inset 20pt, content scrolls under it; selected tab in a lighter pill, tint ink | 80dp navigation bar on surface-container, 64×32 pill indicator, labels | Bar on the layer, 16×3 accent pill under the selected label | Flat view-switcher bar, 6pt rounded selection |
| Wide navigation | Source list on the macOS sidebar material (vibrancy), tinted glyphs, plain counts | 88dp navigation rail, 56×32 pill indicator | NavigationView pane, 3×16 accent pill at the row's left, content on a layer with an 8pt rounded corner | Flat sidebar, its own header bar, rounded selection |
| New chat | Square-and-pencil in the Chats header | Expressive FAB (56, 16pt corners, primary container, elevation 6) | Header button | Header button |
| Switch | 51×31, 27pt knob | 52×32, thumb 16 → 24 when on, outlined off track | 40×20, 12pt thumb, ink thumb off | 46×26, 20pt knob inset 3, filled off track |
| Lists | Inset grouped, no outline, inset hairlines, violet-tint squircle icons | Segmented list: each row a tonal tile 2pt apart, 20/4 corners, bare icons, primary subheaders | Card with a 1px stroke, full-width 1px rules, 40pt compact rows, bare icons | Boxed list: 12pt card, 1px border, full rules, no shadow, bold group titles |
| Press | Highlight (dim); buttons settle 0.97, rows never scale | State layer 8% / 12% (Android ripple where NSH draws one) | Fill shifts a step, nothing moves | Fill shifts a step, nothing moves |
| Elevation | Glass for floating chrome; content flat | Tonal; shadow only on the FAB | Layer stroke + shadow2/xl on dialogs | Flat; borders separate |
| Sheets | Bottom sheet, 28pt top corners, grabber; centred panel on wide windows | Bottom sheet, 28pt, 32×4 drag handle, 22pt title | Always a centred dialog, 8pt, stroke and shadow | Bottom sheet on narrow, 14pt dialog on wide, no outline |
| Chips | Capsule fill | Outlined 8pt filter chip, fills and gains a check | 4pt toggle button, accent when on | Pill, soft fill |
| Toast | Capsule | Snackbar, 4pt | 8pt | Capsule |

With reduced motion every skin drops its scales and translates (the
switch thumb jumps, colours still fade).

## Motion tokens (`ui::motion`)

`INSTANT` 120ms (hover wash), `FAST` 180ms (press, control state), `BASE`
240ms (selection moving, glyph swap), `SLOW` 360ms (sheet, dialog,
reveals). Press scale 0.97 (icon buttons 0.94) on the settle curve
`(0.22, 1, 0.36, 1)`. Leaving is faster than entering. With reduced motion
every scale and translate is dropped; colour and opacity fades stay.

## The `ui` layer (src/ui)

| Component | API |
| --- | --- |
| Buttons | `btn(label, Variant, BtnSize, on_press)`, `btn_with_icon`, `icon_btn(Icon, label, f)`, `fab` |
| Variants | `Primary` (one per screen), `Secondary` (`control` fill, soft `input` edge), `Ghost`, `Outline`, `Danger`. Disabled is one look for all: `muted` fill, `border` edge, `muted-foreground` label |
| Text | `heading`, `body`, `muted`, `section_title`, `footnote` |
| Rows | `Row::new(title).icon(..).subtitle(..).chevron()/.value(..)/.trailing(..).danger().on_press(..).build()`, `group([...])` (icon rows), `group_plain` (no leading icon), `group_with_inset(rows, INSET_*)`, `Row::leading_kind().inset()`, `toggle_row`, `toggle_row_icon`, `toggle_row_with(icon, …, disabled)` |
| Inputs | `field`, `labelled_field`, `search_field`, `toggle`, `segmented`, `chip`, `chip_scroller(chips, surface)`, `edge_fade(surface)` (last child of a `w_full().overflow_hidden()` view around the scroll; content ends with `EDGE_FADE + 8` padding) |
| People | `avatar(name, seed, size)`, `avatar_presence`, `avatar_presence_on(…, surface)`, `initials` |
| Status | `ticks(|| Tick)`, `unread_badge`, `unread_badge_on(count, surface)`, `tag`, `banner(Tone, Icon, msg)` |
| Surfaces | `card()`, `separator()`, `separator_inset(left)`, `hairline()` |
| Pages | `page(title, content)`, `page_with(title, right, content)`, `app_header`, `page_scroll` |
| Overlays | `app_sheet(open, title, content)`, `confirm(title, msg, action, f)`, `toast(msg)`; toasts float above the tab bar on phones and above the composer whenever a conversation shows; a screen with its own bottom bar calls `set_toast_inset(px)` (and 0 when it goes) |
| States | `empty_state`, `skeleton`, `skeleton_row` |
| Layout | `wide()` — the desktop layout (by window width) |

### Status ticks (never colour alone)

| Status | Shape |
| --- | --- |
| Sending | clock |
| Sent | one tick |
| Delivered | two ticks |
| Read | two ticks **in a filled circle**, `tick-read` |
| Played | two ticks in a smaller filled circle with two sound waves beside it (heard; never a play control), `tick-read` |
| Failed | warning triangle, `destructive`, plus "Not sent. Tap to retry." |

## Information architecture

Chats · Calls · Communities · You (WhatsApp's layout without Status;
channels reachable from Chats via the Channels filter and from Communities).
Phones: bottom tab bar, native stack, system headers. Desktop and tablets
≥ 760pt: a rail, the section's list pane (360pt), and a detail pane with its
own stack.

## Trust design

- Encryption is stated once, calmly, at the top of every chat and in chat
  info: "Messages and calls are end-to-end encrypted." Details one tap away.
- Key changes: a neutral system line, "X's safety number changed. This
  usually means they reinstalled Songbird or got a new phone." Never red,
  never "warning", with "Verify" as the action.
- Verified contacts get a small shield-check next to their name.
- "What Songbird can see" (privacy centre) lists what the server knows and
  never sees, in plain words, straight from `docs/THREAT_MODEL.md`.

## Rules for feature code

1. Compose from `crate::ui::*`; never import controls from `nsh_base`,
   never write colours, radii or font sizes. Need a look? Add a variant.
2. Read state from `store()` (read it while building, keep the copy), change
   it only through `Store` intents. app-core is mocked; mark new intents
   `// mock:` where the real one will differ.
3. Long lists use `virtual_list` (chat list, messages, contacts, calls).
4. Every action works by keyboard, every control has a role and label.
5. Write each screen's motion inventory (below) before its code.
6. Copy: sentence case, no exclamation marks in errors, no jargon.

## Motion inventories

Each feature adds its screens' inventory here (state change → tool and
token → reduced motion).

### Shell

| Change | Motion | Reduced |
| --- | --- | --- |
| Tab selected | The skin's selection (glass pill, M3 pill, Fluent indicator, Adwaita fill) fades in, `BASE`; icon and label colour fade | Same (fade only) |
| Skin changes (debug) | The shell is rebuilt in the new skin | Same |
| Row hover / press | Muted wash on hover, accent on press, `INSTANT` | Same |
| Rail item hover / press | Sidebar-accent wash, `INSTANT` | Same |
| Button press | Scale 0.97, `FAST`, settle | Opacity only |
| Toast | Rises 8pt and fades in, `BASE`, ease-out; leaves by fading | Fade only |
| Page push / pop | Native stack transition | Native |
