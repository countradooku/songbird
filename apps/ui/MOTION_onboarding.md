# Motion inventory: onboarding, identity and devices, backups (A4, A11)

Tokens from `ui::motion` (`INSTANT` 120, `FAST` 180, `BASE` 240, `SLOW` 360,
settle curve). Every motion goes through `motion().entering/play`, which
lands at its end at once with reduced motion, or is gated on
`motion::reduced()`.

| Screen | Change | Motion | Reduced |
| --- | --- | --- | --- |
| First run | Step forward / back | Step slides in 24pt from the side it comes from (right going forward, left going back) and fades in, `BASE`, ease-out (`Motion` on the step region) | Appears at once |
| First run | Progress segments | Segment fills with primary, colour fade `BASE`; "Step n of 6" label for screen readers | Same (colour only) |
| First run | Back button appears / hides | Hidden by style in a fixed slot, nothing moves; also hidden while a restore runs or after it finishes, and on "Backups are on" (the inner flow tells the host) | Same |
| First run, backup wizard inside it | Back | The one top-bar Back steps through the wizard's pages (they slide back, `BASE`), and leaves it from its first page; the wizard draws no Back of its own there | Instant |
| Welcome | Page dots | Current dot widens 8 → 22pt and fills, `BASE`, ease-in-out (width transition, one small element) | Instant |
| Welcome | Promise text changes | Glyph, title and line rise 8pt and fade in, `BASE`, ease-out, in a fixed-height band so the dots never move | Fade only (no rise) |
| Invite code | Block the next symbol goes into, while focused | Border to ring plus a 1pt outline (no layout shift), `INSTANT` | Same |
| Invite code | Refused (at registration, after "Creating your account…") | The flow slides back to the invite step; blocks' borders turn destructive plus icon and sentence | Appears at once |
| Username | Format status | Icon and text swap as you type (Info → Check / Alert), no debounce, no network | Same |
| Username taken (learned when claiming) | "Pick another username" step slides in; suggestion chips with hover / press wash `INSTANT`; Continue shows "Saving…" | Same, no slide |
| Creating account | Indeterminate bar | 96pt segment slides across the track, 1200ms ease-in-out loop | Static half-opacity full bar |
| Profile | Initials | Update live as the name is typed (text binding) | Same |
| Recovery key | Confirm status | Icon + text swap Key → Check / Alert | Same |
| Connect | Option opened | Chevron swaps right → down (two glyphs, no rotation); panel rises 8pt and fades in, `BASE` | Chevron swaps; panel appears |
| Linked devices on desktop | Link a device | The sheet shows this computer's code and the phone's steps; an indeterminate bar slides while waiting (as the creating bar) | Static bar |
| Scanners (connect, link from a phone, safety number, transfer) | Scan line | Sweeps down and back, 1800ms ease-in-out, alternate, looping | Line rests at the top |
| Backup wizard, restore, transfer | Page changes | Slides 24pt (wizard, transfer) or rises 8pt (restore) and fades, `BASE`, ease-out | Instant |
| Progress bars (backup now, restore, transfer) | Value grows | Fill scales on x from the left, `BASE`, ease-out (transform, not width) | Jumps |
| Transfer (Prompt 10) | Compare and Waiting screens, a failure | The same page change as the other transfer pages (slide 24pt and fade, `BASE`); the six digits appear with the page, never animated on their own | Instant |
| Transfer, new phone (D-0125) | "They match" pressed → waiting for the old phone | The button leaves and the indeterminate bar appears in place, no movement of the page (as the QR's bar) | Instant |
| Transfer, new phone | Code being prepared → QR shown | The indeterminate bar (as "Creating your account") gives way to the QR in place; no movement of the page | Static bar |
| Restore, new device | A typo in the key | Status line appears below the field (icon + sentence, Problem tone), no shake, no layout jump of the field | Same |
| Backups | A problem after a real run | The warning banner and its button appear in the status card in place of the progress bar, colour only | Same |
| Restore stages | Stage done | Circle fills with primary and shows a check, colour `BASE`; "Done" / "In progress" text | Same (colour) |
| Destination rows | Selected | Radio fills primary with a check, `FAST`, "Selected" label | Same |
| Every button, row, chip | Hover / press | From `ui`: wash `INSTANT`, press 0.97 `FAST` settle | Opacity only |
| Sheets (scan, link a device, device, PIN, delete, accounts, destinations) | Open / close | `ui::app_sheet` (native sheet transition) | Native |
| Toasts | Arrive / leave | `ui::toast_layer`: rise 8pt and fade, `BASE` | Fade only |
| Pushed pages | Push / pop | Native stack | Native |

Verified in the running app (macOS host, screenshots in `shots/`): step slides,
progress segments, dots, availability swap, busy bar, scanners, progress bars,
restore stages, destination selection. Reduced motion was not toggled in
the test run (the `reducedMotion` open option is headless-only).

Polish pass: welcome, invite blocks, username line, the shared Back and the
desktop link sheet re-verified in `Polish_account.test.tsx` (shots in
`shots/polish/`).
