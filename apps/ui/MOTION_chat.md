# Motion inventory — A5 conversation

Tokens from `ui::motion`; every motion goes through `Motion::play` / transitions, which land at their end
(no movement) when `motion::reduced()` is on. Colour and opacity fades stay under reduced motion.

| Change | Tool and tokens | Reduced motion |
| --- | --- | --- |
| Message sent | Its row rises 8pt and fades in, `SLOW`, ease-out (`list::rise`, played once on the cell showing `Conv::fresh`; recycled cells play nothing) | Appears in place |
| Send ↔ mic | Glyph swap: old glyph shrinks to 0.5, turns −30° and fades, new grows in, `BASE`, ease-in-out | Opacity cross-fade only |
| Play ↔ pause (voice) | Same glyph swap, `BASE` | Cross-fade only |
| Voice progress | Waveform bars fill in the accent, 100ms clock (a value that updates often: no easing) | Same |
| Speed 1× / 1.5× / 2× | Label changes in place | Same |
| Reaction added | The chip pops in (`MotionPreset::PopIn`) only when the user just reacted (`Conv::popped`) | Appears in place |
| Reaction bar press | Emoji scales to 1.18 while pressed, `FAST` | Opacity 0.7 |
| Message menu opens | Focus view: the backdrop dims in (`FAST` fade); a copy of the bubble is lifted in place over it with a 1.0 → 1.03 → 1.0 pop (`BASE`); the reaction bar (directly above the message) and the actions menu (directly below, or above the bar when there is no room) each grow from 0.97, slide 6pt and fade, `SLOW`, ease-out. All parts stay 8pt (and the safe area) inside the window; the message moves (clipped if taller than the room) only when neither placement fits. Same on desktop and phone | Appears at once (no pop) |
| More menu (header) | `nsh_base` menu popup grows from 0.97 and slides 6pt, `FAST`; leaves the same way | Fade only |
| Typing dots | Three dots breathe (opacity 0.35–1, 3pt lift), 1100ms loop, 160ms stagger | Static dots at 0.6 |
| Nudge received or sent | Conversation shakes on X (±9pt decaying), 420ms | No shake (the nudge line still shows) |
| Swipe to reply (phones) | Bubble follows the finger 1:1 (capped at 64pt + rubber band), reply mark fades in by distance; release returns with `BASE` ease-out | Same follow; return is still a short timing (user-driven) |
| Hold to record (phones) | Red dot breathes (opacity loop 1200ms); slide left cancels, up locks | Dot static |
| Jump to latest | Button fades and scales in from 0.9, `FAST`; press scales 0.94 | Fade only |
| Jump to a quoted / searched message | List scrolls (animated), the row flashes the highlight token, `SLOW` colour fade | Same (colour) |
| Reply / edit bar | Rises 6pt and fades in, `BASE`, ease-out | Fade only |
| Poll vote | Vote bars change width with `BASE` transition | Instant |
| Desktop hover actions button | Fades in on hover / focus, `INSTANT` | Same |
| Sheets (attach, emoji, forward, delete, timer, creators) | `ui::app_sheet` native sheet transition | Native |
| Attach popover (desktop) | Anchored above the paperclip, its leading edge on the button, kept 8pt inside the window; grows from 0.97, slides 6pt up, fades, `FAST`, ease-out. Phones keep the `app_sheet` | Appears at once |
| Page push (chat info, message info, media) | Native stack transition | Native |
| Bubble/row hover & press | `pressable`: dims to 0.7, `FAST` | Same |
| Open with reply / search (`chat::reply_to`, `chat::search_in`) | The chat opens as usual (pane or push); the reply bar then rises in as above, or the search bar replaces the header | As above |
