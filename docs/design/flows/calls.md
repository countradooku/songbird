# Flow: calls (A8)

**Goal:** voice and video calls as easy as WhatsApp's, always end-to-end encrypted, with call
links and a lobby. Module: `features/calls.rs` (`calls_tab`, `start_call`, `call_layer`).

## Entry points

Chat header phone/video; Calls tab (New call, Create call link, Schedule, recents, favourites);
notification / CallKit / ConnectionService; call link `/call#…`; desktop `Ctrl/Cmd+Shift+C`.

## Steps

| # | Screen | Content |
| --- | --- | --- |
| 1 | Calls tab | Header "Calls", + (New call); rows: Create call link, Schedule call; Favourites (avatars); Recent (name, ↙/↗/missed icon + "Missed", time, video/voice icon; tap = call back, (i) = call info) |
| 2 | Outgoing | Avatar, name, "Calling…" → "Ringing…", "End-to-end encrypted", controls: mute, speaker, camera, end |
| 3 | Incoming | Full screen (system UI on phones): avatar, name, "Songbird video call", Accept / Decline / Message ("Can't talk now", "Call you later", custom) |
| 4 | Connected 1:1 | Timer, remote video full, self view draggable PiP; controls bar auto-hides after 4 s (video) |
| 5 | Group call | Grid up to 32 video (2×2, 3×3, speaker view), 128 audio-only; tiles with speaking ring, muted icon, hand; Participants list (host: mute, remove) |
| 6 | Starting a group call | "Ring everyone" or "Start quietly" (members see "Join call" in the chat) |
| 7 | Call link | Create: name, "Ask to join" (lobby) toggle, Share/Copy, admin token kept on the device; joining via link: preview "Join *Book club*?" + name card, camera/mic preview, **Join**; lobby: "The host will let you in." |
| 8 | Verify (optional) | In-call ⋯ › Verify: same short code on both screens; "If the code matches, nobody else is in this call." |
| 9 | Ended | "Call ended · 12:04" 2 s, then back; quality prompt never shown |

## States

| State | Copy |
| --- | --- |
| No answer | "No answer" + Call again / Message |
| Busy / declined | "{name} is on another call" / "Call declined" |
| Reconnecting | Banner over video "Reconnecting…" (tone every 3 s, stops at 30 s) |
| Poor connection | Tile icon + "Poor connection"; suggest "Turn off video" |
| Low-data mode | "Using less data" chip |
| Permissions denied | "Songbird needs microphone access for calls. **Open settings**" |
| Offline | "You're offline. Calls need a connection." |
| Group full | "This call is full (32 people with video). Join with audio only?" |
| Removed from call | "The host removed you from this call." |
| Link expired | "This call link has expired." |
| Missed (list) | Phone-missed icon + "Missed", not red-only |

## Copy

| Key | String |
| --- | --- |
| call.e2ee | End-to-end encrypted |
| call.calling | Calling… |
| call.ringing | Ringing… |
| call.lobby.guest | The host will let you in. |
| call.lobby.host | {name} wants to join. Let in / Decline |
| call.ring.choice | Ring everyone · Start quietly |
| call.verify | If the code matches on both screens, nobody else is in this call. |
| call.link.lobby | Ask to join: you approve each person before they enter. |

## Accessibility

- System call UIs on iOS/Android give native accessibility; in-app controls labelled with state
  ("Microphone, on").
- Active speaker changes announced at most every 5 s; captions out of scope (open question).
- Keyboard on desktop: M mute, V video, Ctrl/Cmd+E end, Space push-to-talk (optional).
- Contrast: accept glyph in dark fails 3:1 today (brand.md FAIL #5).

## Motion

| Change | Motion | Reduced |
| --- | --- | --- |
| Call screen in | Slide up / scale from avatar, `SLOW` | Fade |
| Controls hide/show | Fade, `BASE` | Same |
| Speaking ring | Opacity pulse with audio level, max 4 Hz | Static ring |
| Tile layout change | Tiles move to new grid, `BASE` | Instant |
| Connect | Avatar ring settles into video, `SLOW` | Fade |

## Open questions (owner)

1. Group call default: ring everyone (WhatsApp) or start quietly?
2. Captions/transcription on device for calls: later or never?
3. Call link expiry default (D-0088 sets bounds): 30 days?
4. Show the verification code by default in 1:1 calls, or only on request (proposal: on request)?
