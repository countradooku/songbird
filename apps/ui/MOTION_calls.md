### Calls (A8)

Tokens from `ui::motion`; every scale and translate is dropped with
`motion::reduced()` (the helpers `arrive` and `ring_pulse` in
`src/features/calls/surface.rs` check it once, at build).

| Change | Motion | Reduced |
| --- | --- | --- |
| Call control press (mute, camera, share, end, accept, decline) | Scale 0.94 + opacity 0.8, `FAST`, settle curve; hover opacity 0.88 | Opacity only |
| Toggle on/off (mute, camera, share, hand) | Fill and ink cross-fade with the press transition, `FAST`; glyph swaps (Mic ↔ MicOff, Video ↔ VideoOff) by remaking the glyph | Same (colour only) |
| Call pills (Minimise, Return to call, Stop sharing, Admit/Deny) | Wash deepens, scale 0.97, `FAST` | Wash only |
| Calls tab rows, segmented All / Missed | Row accent wash `INSTANT`; segment fill fades `BASE` (ui layer) | Same |
| Ringing (outgoing Calling/Ringing/Connecting, lobby, incoming) | Ring pulse behind the avatar: scale 1 → 1.4 while fading 0.9 → 0, 1800ms ease-out, looped (`Animation::timing(..).looped(None)`); stops when the call connects (the ring leaves with its `when`) | Still ring at 1.18× and 60% opacity |
| Call surface opens (phone full screen, desktop panel over the content area right of the rail) | Fades in from 0.98, `SLOW` (phone) / from 0.99, `BASE` (panel), ease-out | Appears at once |
| Panel minimise → corner player | Player rises 8pt from 0.96 and fades in, `BASE`; panel leaves at once (leaving faster than entering) | Appears at once |
| Corner player → panel (Return to call) | Panel grows in from 0.99, `BASE` | At once |
| Phone minimise → "Tap to return to call" bar | Bar slides down 8pt and fades in, `BASE` | Fade-free, at once |
| Ringing card (desktop) | Rises 12pt from 0.96 and fades in, `SLOW` | At once |
| Group tiles arrive (people join, admitted from the lobby) | Each tile fades in from 0.96, `SLOW`, as it joins (staggered by the join times of the mock) | At once |
| Video switches on (1:1) | Big tile fades in from 0.98 `SLOW`; self-view rises 8pt from 0.9, `BASE` | At once |
| Notices (sharing bar, "3 people waiting") | Slide down 8pt and fade in, `BASE` | At once |
| Timer "00:42" | No motion: changes every second, tabular figures so it does not jitter | Same |
| Status line (Calling… → Ringing… → Connecting… → 00:00) | Text swaps in place; announced to screen readers | Same |
| Mic level meter (desktop devices sheet) | Five bars scale on Y in looped ease-in-out timings, 260–540ms; dims at 40% when muted | Still bars |
| Sheets on the call (verify, participants, more, devices, share) | `ui::calls_controls::call_sheet`: dark call surface, native sheet transition; desktop panel centred on the stage above the controls | Native |
| Call link sheet (Calls tab) | The ui layer's `app_sheet` (native sheet transition) | Native |
| Ended state "Call ended · 2:31" | Controls give way to the line; the layer clears after 2.5s (instant unmount) | Same |

Verified in the macOS screenshots (`shots/calls-*.png`): end states of
every line above. The loops (ring pulse, level meter) and enter motions
were checked only as their resting frames — a still screenshot cannot
show the movement.
