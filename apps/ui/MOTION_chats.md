# Motion inventory: chat list (A5)

> **Superseded in part by [REDESIGN.md](REDESIGN.md) (Floating, 2026-11-18).** Where the two disagree,
> REDESIGN.md wins: floating panes instead of the rail, Spaces instead of Communities, the Lists capsule
> instead of filter chips, no per-bubble ticks or times, per-chat themes, and ⌘K jump-to.

Tokens from `ui::motion`. Every line checks `motion::reduced()`.

| Change | Motion | Reduced |
| --- | --- | --- |
| Row hover / press / keyboard focus | Wash (`muted` hover, `accent` press/focus), `transition_colors`, `INSTANT` | Same (colour only) |
| Open chat changes (desktop) | Selected row's `accent` fill fades in, old one fades out, `INSTANT` | Same |
| Filter chip selected | Chip fill and label colour fade, `INSTANT` (`ui::chip`) | Same |
| Manage-lists chip, header icon buttons, FAB press | Wash / scale 0.94, `FAST`, settle (`ui::icon_btn`, `ui::fab`) | Opacity only |
| Row menu opens (desktop) | Popup fades in from 0.97 scale and 4pt up, `FAST` ease-out (`popup_starting_style`); leaves by fading | Fade only |
| Row menu opens (phone, held finger) | Native bottom sheet slides up, backdrop `overlay` fades | Native |
| "Add to list" submenu | Cascades beside the menu (desktop) / replaces the items (phone) | Same |
| Pin / unpin, archive, lock, delete, accept / block request | `animate_layout` ease-in-out, `BASE`: rows glide to their new place, removed rows fade | Instant |
| Badge count, time, preview, "typing…" | Text swaps in place; typing colour is `primary` | Same. No motion by design: these tick many times a minute |
| Search results replace the list | Instant swap; the list stays mounted underneath (keeps its scroll) | Same. No motion by design: results change per keystroke |
| Archived / Requests / Locked / Lists / New chat pages | Native stack push / pop | Native |
| Broadcast recipient check | Check circle fill fades, `FAST` | Same |
| Toasts (archived, muted, list created…) | `ui::toast_layer`: rises 8pt and fades, `BASE` | Fade only |
| Confirm (delete chat, block, report, delete list) | Native alert | Native |

Verified in the running app (macOS host, screenshots): row hover/selected wash, desktop menu and
submenu, pin reorder, chips, page push. Not verifiable on screenshots: the exact entrance curve and
the phone long-press sheet (the macOS host's mouse never triggers a hold, by design of `context_menu`).

## Floating redesign (REDESIGN.md)

| Change | Motion | Reduced |
| --- | --- | --- |
| A list chosen in the Lists capsule | The indicator springs to the segment; rows glide (`animate_change`) | Indicator jumps; rows swap |
| Unread toggle | Rows that leave fade, the rest glide | Instant |
| Pin or unpin | The chat leaves the rows and appears in pinned people (glide and fade) | Instant |
| Unread ring colour | Fades over `BASE` | Kept (a colour fade) |
