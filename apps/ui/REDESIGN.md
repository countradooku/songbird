# Songbird redesign: Floating

The owner chose this on 2026-11-18. It is direction A (Floating) as the base, with C's pinned people and
per-chat themes, and B's reply-first triage and ⌘K jump-to on desktop. The aim: nothing should read as
WhatsApp, and each platform keeps its own design language (`ui/skin.rs`).

## Principles

1. **Content floats.** Panes are inset, rounded surfaces on a quiet window canvas, never edge-to-edge
   columns. The chat header and the composer float over the conversation as capsules.
2. **One accent, used sparingly.** Dusk violet (`primary`) marks your own bubbles, the selection and
   unread. Everything else is neutral.
3. **Quiet metadata.** There are no ticks on every bubble and no time inside every bubble. Status shows
   once, under your latest message; times show where the conversation pauses.
4. **People before lists.** The chats you pinned sit on top as large avatars.
5. **Each chat has its own canvas.** A per-chat theme tints the canvas and your bubbles.

## Removed WhatsApp patterns

| Was | Becomes |
|---|---|
| Filter chips (All, Unread, Favourites, Groups) | A **Lists capsule**: a segmented control of All plus the user's lists (Family, Work, Friends), with "Unread" as a toggle icon beside the search field |
| Archived row pinned at the top of the list | A quiet footer row at the end of the list: "Archived · 2" |
| Message requests row at the top | An inline notice at the top, only when there are requests: "1 message request" |
| Tab "Communities" | Tab **"Spaces"** (user-facing copy everywhere; `Tab::Spaces` in code) |
| Double ticks on every outgoing bubble | Signal-style **receipt circles** under your **latest** outgoing message only: a faint ring while sending, a ring with a check once sent, two overlapping rings once delivered, both filled in the chat theme's bubble colour once read. The words stay for screen readers ("Read by 4" in groups). A failure stays in words: "Not sent · Retry" |
| Time inside every bubble | A **time label** centred between runs when an hour or more passes ("09:24", or "Today 09:24" at a day break). Desktop: hovering a bubble shows its time as a tooltip. Phone: long-press shows message info, as now |
| Date and system pills | Plain centred 12pt muted text, no pill; system events get a 14pt leading icon |
| Coloured sender name on every group bubble | The sender's name only on the **first** bubble of a run, in their colour at reduced strength; the avatar beside the **last** bubble of the run |
| Group header listing members | A subtitle such as "5 people · 2 online" |
| Pill field next to a round mic/send button | **One capsule**: `+` (attach), the field, emoji, then mic (ghost icon) when empty or send (a filled `primary` circle) when there's text, all inside the capsule |
| Edge-to-edge rail, list and chat columns on desktop | Floating panes (below) |

## Desktop layout (wide)

- **Window canvas**: token `canvas`, a step darker than `background`. 12pt outer margin, 10pt gaps.
- **List pane**: a floating card 340pt wide (token `pane`, radius `spec().radii.pane`), holding, top to bottom:
  - a header row: the destination's title (Chats, Calls, Spaces, You) at 20pt, then its actions (compose, more);
  - the search field, with the Unread toggle beside it (Chats);
  - the Lists capsule (Chats);
  - pinned people (Chats): up to 8 pinned chats in rows of 4, 52pt avatars with the name under them (12pt,
    one line). Unread shows as a 2pt `primary` ring around the avatar, offset 2pt, plus a small count pill
    when more than 1. Muted chats get a neutral ring instead;
  - **"Needs a reply"** (desktop only): chats where the last message is someone else's, unread > 0, not
    muted, or with an unread mention. It has a section label and shows at most 5, then "Show all";
  - "Recent": the remaining chats;
  - the footer rows (Archived, as above);
  - a bottom **destination bar** inside the card: Chats, Calls, Spaces, You as 20pt icons with the unread
    badge on Chats, and the user's avatar as You. This replaces the rail.
- **Conversation pane**: a floating card filling the rest, radius `pane`, clipped; its background is the
  chat's canvas (per-chat theme). Without a chat open, it shows the calm welcome.
- **Info pane**: a third floating card (320pt) when chat info is open.
- **⌘K jump-to**: a centred floating card (560pt) over a dimmed window. It searches chats, people and
  actions ("New group", "Settings: Privacy", …). ↑/↓ move, ↵ opens, esc closes. Shortcut ⌘K / Ctrl+K.

## Phone layout

- The Chats tab: large title, search with the Unread toggle, the Lists capsule, pinned people (rows of 4,
  48pt avatars), then the rows. Unread rows: a bold name, a 8pt `primary` dot before the time, and a count
  pill only when > 1. Muted: a neutral dot.
- The tab bar: the iOS native one (keep); the other skins keep their bars. Communities is renamed Spaces.
- Conversation: the header capsule floats over the canvas (Apple: glass; others: their pane surface), and
  the composer capsule floats with a 12pt inset.

## Conversation details

- Bubbles: radius 20, no tails. Runs: 2pt between bubbles of one run, 10pt between runs; inner corners of a
  run 6pt. Gutters as now (12 phone, 20 wide). Max width 72%.
- Reactions: a small capsule overlapping the bubble's bottom edge (keep).
- Your bubbles: the theme's `bubble` colour with its `on-bubble` text. Others' bubbles: `bubble-in`.

## Per-chat themes

`ChatTheme` = Dusk (default), Rose, Sea, Moss, Sand, Slate, Night. Each defines, for light and dark, the
`canvas` (the conversation background), `bubble` (your bubbles) and `on-bubble`, all at ≥ 4.5:1 for text
(check them with `docs/design/tools/contrast.py`). Seeds: Familia = Rose, Design team = Slate, Weekend
trips = Moss; everything else Dusk. The picker is a "Theme" row in chat info that opens a sheet of
swatches, previewed live.

## Skins

Every number comes from `spec()`:

| | Apple | Material | Fluent | Adwaita |
|---|---|---|---|---|
| pane radius | 16 | 24 | 8 | 12 |
| pane surface | glass (`glass_effect(Regular)`) on the header and composer capsules; panes are `pane` | tonal surface-container | layered with a hairline border (Mica-like) | card with a 1px border |
| capsule | glass | surface-container-high | layered + hairline | card + border |

## Tokens (theme.json, every variant: light, dark, high contrast)

`canvas`, `pane`, `pane-border`, `capsule`, `capsule-border`, plus the theme palette (in code, not
theme.json, since it is per chat).
