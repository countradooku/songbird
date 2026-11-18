# Motion inventory: groups, communities, channels, media, packs (A6, A7)

> **Superseded in part by [REDESIGN.md](REDESIGN.md) (Floating, 2026-11-18).** Where the two disagree,
> REDESIGN.md wins: floating panes instead of the rail, Spaces instead of Communities, the Lists capsule
> instead of filter chips, no per-bubble ticks or times, per-chat themes, and ⌘K jump-to.

Tokens from `ui::motion` (`INSTANT` 120, `FAST` 180, `BASE` 240, `SLOW` 360,
settle curve `(0.22, 1, 0.36, 1)`). "Reduced" is what `motion::reduced()` does.
"Checked" = seen in the running app (`Screens_groups.test.tsx`, macOS) or, for
motion a still screenshot cannot show, read in the code path that runs.

## Communities tab, community home, Find channels

| Change | Motion | Reduced | Checked |
| --- | --- | --- | --- |
| Row hover / press (`Row`, `Press::Row`) | Accent wash, `INSTANT` | Same (colour) | Screenshot shows hovered row wash |
| Icon button press (New community +) | Scale 0.94, `FAST`, settle (`icon_btn`) | Wash only | Code |
| Community / group added or linked (Add group sheet, Create) | `glide()`: `animate_layout`, ease-in-out, `BASE`; new rows fade in | Jump | Code |
| Follow ↔ Following | Label swaps in place; button `selected` state; colour `FAST` | Same | Screenshot |
| Page push / pop (home, info, Find channels) | Native stack transition | Native | Running app |
| Add group sheet open / close | Native sheet (`app_sheet`) | Native | Screenshot |

## New group flow

| Change | Motion | Reduced | Checked |
| --- | --- | --- | --- |
| Contact picked / unpicked | Check circle fills (border + fill colour) and tick fades, `FAST` | Same (colour/opacity) | Screenshot 16 |
| Picked chip arrives | Fades 0→1 and grows 0.9→1, `FAST`, settle (`animated_value`) | Appears at once | Screenshot 16 |
| Chip removed | `each` drops it; the row of chips reflows | Same | Code |
| Next / Create button enabled | `disabled_style` opacity, `FAST` | Same | Screenshots 15/16 |
| Create → Share invite sheet | Native sheet rises | Native | Screenshot 18 |
| Create group → Open group label | Label swaps (button stays in place) | Same | Code |
| Contacts list (virtual) | No entrance per cell: recycled cells play nothing | — | — |

## Group / channel info, roles, invite link, join requests, member changes

| Change | Motion | Reduced | Checked |
| --- | --- | --- | --- |
| Action tile press (Audio, Video, Add, Search) | Wash + scale 0.97, `INSTANT`→settle (`Press::Tile`) | Wash only | Code |
| Switches (mute, lock, permissions) | Thumb slides 18pt, track colour, `FAST` (`ui::toggle`) | Colour only | Screenshots |
| Disabled permissions (member) | Dimmed 0.45, no hover/press | Same | Screenshot 04 |
| Disappearing timer choice | Check circle fill, `FAST` | Same | Code |
| Member made admin / dismissed | Role tag text changes in place | Same | Code |
| Member removed, people added | `glide()` layout animation, `BASE` | Jump | Code |
| Join request approved / rejected | Row leaves with `glide()`, `BASE`; toast rises 8pt, `BASE` | Row jumps; toast fades | Code |
| Segmented (expiry, max joins, shelves) | Selected fill colour, `BASE` (`ui::segmented`) | Same | Screenshot 07 |
| Reset link | QR pattern and link swap (new value) | Same | Code |
| Sheets (member, edit, add, timer, encryption) | Native sheet | Native | Screenshot 10 |
| Confirms (remove, exit, report, reset) | Native alert | Native | Code |

## Media viewer

| Change | Motion | Reduced | Checked |
| --- | --- | --- | --- |
| Open / close | Native page push / pop | Native | Screenshot 13 |
| Next / previous (arrow keys, buttons, swipe) | New picture cross-fades in, opacity 0→1, `BASE`, ease-out | Appears at once | Code |
| Swipe | Picture follows the finger 1:1 (`pan_values`); past 72pt or a fling it changes item, else springs back with the release velocity | Snaps back without a spring | Code (no touch in macOS test) |
| Zoom +/− (buttons, keys) | Scale animates, `FAST`, settle | Jumps to the level | Code |
| Pinch | Native, 1:1 (`pinch_value`); on release snaps into 100–400% | Same | Code |
| Video play / pause | Glyph swap (play ↔ pause), progress bar width per 250ms tick (no easing: a value that updates often) | Same | Code (no video in seed) |
| Star ↔ Unstar | Label swap, `selected` | Same | Code |
| Save disabled | Dimmed + explanation line under the bar | Same | Code |
| Bar buttons press | Opacity 0.7 + scale 0.94, settle (`Press::OnDark`) | Opacity only | Code |

## Storage and data, packs, upload progress

| Change | Motion | Reduced | Checked |
| --- | --- | --- | --- |
| File selected | Check circle fill, `FAST`; row `selected` | Same | Screenshot 23 |
| Files deleted | `glide()` layout animation, `BASE`; total and bar update | Jump | Code |
| Auto-download switches, HD segmented | As `ui::toggle` / `ui::segmented` | As those | Screenshot 21 |
| Pack moved up / down / removed | `glide()`, `BASE` | Jump | Code |
| Pack kind chip selected | Chip fill colour, `INSTANT` | Same | Screenshot 24 |
| Pack install progress (`progress_ring` in packs.rs) | Primary-coloured ring arc and the percentage redrawn per progress step (160ms steps); Cancel is a text button; card appears and leaves with the install | Same (no tween) | Screenshot 25 |
| Upload paused by network loss | Arc stops, glyph swaps × → ↑, caption "Paused" | Same | Unit tests (state machine) |
