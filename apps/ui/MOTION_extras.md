# Motion inventory: extras (A12 plans/invites/help, A13 desktop, A15 WhatsApp, gallery)

Tokens from `ui::motion` (INSTANT 120, FAST 180, BASE 240, SLOW 360, settle curve). Reduced motion
(`motion::reduced()`) drops every scale and translate; colour and opacity fades stay.

| Screen | Change | Motion | Reduced |
| --- | --- | --- | --- |
| All pages | Page push / pop | Native stack transition (shell) | Native |
| All pages | Button, icon button, row hover / press | `ui` layer: hover wash INSTANT; press scale 0.97 (icon 0.94) FAST, settle; rows deepen wash | Opacity / wash only |
| Plans | Billing Monthly ↔ Yearly | Segmented fill fades BASE; prices are text swaps (no motion, a number changing in place) | Same |
| Plans | Current plan card ring | `select_card` border colour transition BASE when the plan changes | Same |
| Plans | Paywall sheet, purchase sheet open / close | `app_sheet` (native sheet: slides from the bottom, centred panel on desktop) | Native |
| Plans | Paywall → purchase | The paywall closes as the purchase sheet opens (one sheet at a time, never stacked) | Native |
| Plans | "Subscribe" → "Confirming…" | Label swap, button disabled (opacity 0.45 fade via disabled style) | Same |
| Plans / manage | Cancel / keep subscription | `confirm` native alert; result as toast (rises 8pt + fade BASE) | Toast fades only |
| Family | Member added / removed | `each` row inserted / removed (no motion: short list, instant) ; invite sheet native | Native |
| Announcement card | Dismiss | Fades out and lifts 4pt, FAST, ease-in; removed after FAST | Fade only |
| Invites | Code copied / shared | Toast; share sheet native | Toast fades only |
| Invite link | — | Static (QR, link); Copy → toast | — |
| Help | Search results change | `each` keyed by article: rows that stay keep their nodes; empty state swaps in (no motion: typing updates many times a second) | Same |
| Help article | "Was this helpful?" | Chips swap to the answer line (instant region swap) ; Yes → toast | Same |
| Contact | Logs toggle | Switch thumb slides FAST, track colour FAST; footnote text swaps | Thumb jumps, colour fades |
| Contact | Send enabled | Disabled style fades | Same |
| Logs preview | — | Static; horizontal scroll | — |
| WhatsApp opt-in | Link WhatsApp → linking panel | Region swap; segmented QR ↔ pairing code fill BASE; "Waiting for WhatsApp…" shown while pairing; linked → toast | Same, toast fades |
| WhatsApp settings | In All ↔ Separately | Segmented fill BASE; footnote swaps | Same |
| WhatsApp settings | Unlink | Native confirm; page swaps to the opt-in body; toast | Same |
| Shortcuts | Open / close (⌘/ or Esc) | Page push / pop | Native |
| Desktop settings | Toggles | Switch FAST | Thumb jumps |
| File drop overlay | Files drag over / leave | Overlay fades to 0.96 and scales 0.98 → 1, FAST, ease-out | Fade only |
| Tray | Unread count | Menu bar text updates (system) | — |
| Gallery | Motion token demos | Dot slides 88pt with each token's duration on the settle curve | Dot fades to 0.5 instead |
| Gallery | Sheet / toast / confirm triggers | As their components | As their components |

Verified in the running app (macOS, `preview/Screens_extras.test.tsx`): page pushes, the paywall
and purchase sheets, toasts, switches, segmented controls, the linking panel. Not verified on
screen: the drop overlay (needs a real drag; `dropFiles` is headless-only on Linux) and the
tray title (system menu bar, outside the window).

### Prompt 11, M7 (verified in `preview/Screens_plans_p11.test.tsx` screenshots)

| Screen | Change | Motion | Reduced |
| --- | --- | --- | --- |
| Chats | Standing banner shows / hides | None: the standing arrives from the server at start-up or on a refresh, not from a user action; it sits with the offline banner, which also appears without motion | Same |
| Chats | Limited ↔ suspended while shown | Tone and icon swap in place (`dynamic`), no motion | Same |
| Account status | Push from "What this means" | Native stack transition | Native |
| Account status | "Send appeal" | Button disabled (opacity fade via disabled style); toast rises 8pt + fades BASE | Toast fades only |
| Contact us | "About my account" toggle | `toggle_row` switch: thumb slides FAST, track colour fades | Colour fade only |
| Family | Copy a seat's link | Icon button press scale; toast | Toast fades only |
| Family | Join / leave (member) | Section swaps (`when`) after the action; leave asks with the native `confirm` | Native |
| Plans | Waiting for the browser payment | The purchase sheet stays busy ("Confirming…") until billing confirms; then the plan card ring transition BASE | Same |
