# Motion inventory: settings (A10, A9)

Tokens from `ui::motion`; every scale or translate is dropped when `motion::reduced()`.

| Screen / change | Motion | Reduced motion |
| --- | --- | --- |
| You list, settings rows: hover / press | Accent wash, `INSTANT` (`Row`) | Same |
| You list on desktop: row of the open page | Steady `sidebar-accent` fill and a 3pt primary bar at the leading edge fade in, `INSTANT`; the profile card takes the fill and a primary border; cleared when the detail pane's page changes | Same (fades only) |
| Profile card press | Accent wash `INSTANT` + scale 0.99 | Wash only |
| Presence pill selected | Fill and border colour, `INSTANT`; press scale 0.97 | Colour only |
| Search: results replace the list | Instant swap (content already available; no loading state) | Same |
| "What Songbird can see" call-out press | Opacity 0.92 hover, scale 0.99 press, `FAST`, settle | Opacity only |
| Page push / pop (every settings page) | Native stack transition (desktop: detail pane stack) | Native |
| Radio row choice (audiences, timer, tones, lock after, presence) | Check circle fills `FAST`, check mark fades in `FAST` | Same (colour and opacity) |
| Toggles | Track colour + thumb slide, `FAST` (`ui::toggle`) | Colour only |
| Segmented theme selection | Selected segment fill fades `BASE`; the whole app re-themes at once (tokens swap) | Same |
| Wallpaper swatch chosen | Ring and check fade `FAST`; preview background tint cross-fades `BASE`; press scale 0.94 | Fades only |
| Reaction / emoji / app-icon tiles | Hover wash, press scale 0.97 `FAST`; selected border | Wash only |
| Sheets (status, reaction picker, block, nudges, export, rename, broadcast) | Native sheet slide up / panel on desktop; leave faster | Native |
| "Learn more" expanders (privacy centre topics; the two lists have one "Read the details" link each) | Collapsible reveal: clipped height springs open (180 ms, critically damped); chevron turns 180° `BASE` | Content shows at once; chevron swaps |
| Status set / cleared, unblock, list changes | Toast rises 8pt and fades in `BASE`; rows come and go with the keyed list (no animation) | Toast fades |
| Status expiry (mock timer) | Status line leaves the profile card with the next render | Same |
| Confirm dialogs (delete account, clear all, unlink) | Native alert | Native |
| Loading | None: settings are local; the account report is instant (mock) | — |
| Live / continuous | None | — |

Verified in the macOS screenshots run (`Screens_settings.test.tsx`): theme switching live (Light, High contrast, Dark), the status sheet opening, page pushes. Spring reveal and press scales were not frame-captured.

## Prompt 9, M6: contacts, parental controls, the privacy page

| Screen / change | Motion | Reduced motion |
| --- | --- | --- |
| Contacts: search, group chips | Chip selection fill fades `FAST` (`ui::chip`); the list's rows are replaced by the keyed virtual list (no row motion: a filter, not an arrival) | Same |
| Contacts: row hover / press | Accent wash, `INSTANT` (`Row`) | Same |
| Contacts: add / edit page | Native push; Save pops it and a toast rises 8pt and fades in `BASE` | Native; toast fades |
| Contact edit: group chips toggled, a new group added | Chip fill fades `FAST`; the new chip arrives with the wrapped row (no motion) | Same |
| Contact delete | Native destructive alert; the row leaves with the keyed list | Native |
| "Save to contacts" (shared contact, contact info) | The button's label swaps to "Saved" / the row to "In your contacts" at once; toast | Same |
| Parental link: age typed | The help line under the field updates in place (the unlink date); the code and QR stay (an unfinished link keeps its key) | Same |
| Parental link: "We both see the same code" | Native pop, then the Rules page pushes | Native |
| Parental rules: radio, toggles, quiet-hours segment | As every radio, toggle and segment above; each change signs a new policy silently (no spinner: the control is the state) | Same |
| Unlink | Native destructive alert, then pop | Native |
| Parental link, live (parent): code → scan → same code | Each step replaces the last in place, as the device link sheet's do; the camera's own states (asking, running, refused) are `camera_view`'s; "Sending…" disables the button (its own disabled fade) | Same |
| Parental link, live (child): scan → age → code and wait → rules | Steps replace each other in place; the wait is the `busy_bar`'s indeterminate sweep (still under reduced motion, as everywhere); a problem is a status line with "Start again" | Busy bar still |
| Child's view: rules load (live) | Rows swap in when the server answers; an error is a row in words, not a toast | Same |
| What Songbird can see: the new facts | Rows of the two lists, as before (expanders above) | Same |
| Loading | Child's view only, a single fetch; no skeleton (a short list, shown as soon as known) | — |
| Live / continuous | None | — |

Not frame-captured in this milestone: the lines above were checked by reading the code against the tokens, not in a running app.
