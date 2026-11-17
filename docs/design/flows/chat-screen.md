# Flow: chat list and chat screen (A5, A7)

**Goal:** everything a WhatsApp user does in a chat works the way they expect, with ticks that
don't rely on colour and security stated once. Modules: `features/chats.rs`, `features/chat.rs`,
`features/media.rs`.

## Entry points

Chats row; notification; search result; deep link `songbird://chat/<id>`; desktop: list pane
selection, pop-out window.

## Chat list

| Element | Spec |
| --- | --- |
| Header | "Chats", **+** (New chat), ⋯ (Starred, Linked devices, Select chats, Read all) |
| Search | Under the header; searches chats, messages, media types (local) |
| Filter chips | All · Unread · Favourites · Groups · Channels · custom lists · **+** |
| Top rows | Archived (count), Message requests (count) — only when non-empty |
| Row | avatar (presence), title (+ verified shield, WhatsApp tag, mute/pin icons), preview (sender: in groups; "typing…", "Draft: …"), time, unread badge / @ badge, ticks for my last message |
| Swipe | leading: Read/Unread, Pin; trailing: Archive, More (Mute, Lock, Add to list, Delete) |
| Long-press / right-click | Same actions as a menu |

## Chat screen

| Area | Spec |
| --- | --- |
| Header | Back (phones), avatar + name + subtitle (presence/status line/"typing…"/member names), video call, voice call, ⋯ |
| ⋯ menu | Chat info, Search, Media links and files, Mute, Disappearing messages, Chat wallpaper, Nudge (1:1), Add to list, Export chat, Clear chat, Block, Report |
| History | Encryption notice at the top; date chips; bubbles (component-library §4); unread divider "{n} unread messages"; jump-to-bottom button with unread count |
| Pinned bar | Under header when messages are pinned; tap cycles |
| Composer | Smile (emoji/stickers/GIF), field, Paperclip (attach sheet), Camera, Mic ↔ Send |
| Long-press a message | Reaction bar (6 + more) above, actions below: Reply, Forward, Copy, Edit (own, ≤ 15 min), Pin, Star, Info (own), Delete; More: Select, Report, Save, Keep (disappearing) |
| Delete | "Delete for me" / "Delete for everyone" (own, within window; the window remaining shown: "Available for 2 more hours") |
| Message info | Delivered/Read per member with times (groups); "Read" hidden when the reader turned receipts off |

## States

| State | Behaviour / copy |
| --- | --- |
| Empty chat | Encryption notice + "Say hello to {name}." |
| Loading history | 6 skeleton bubbles alternating sides |
| Offline | Bar under header "Waiting for network…"; messages queue with clock tick |
| Send failed | Failed tick + "Not sent. Tap to retry." |
| Blocked | Composer replaced: "You blocked {name}. **Unblock**" |
| Request (incoming) | Composer replaced by Accept / Block / Report bar (`message-requests-block-report.md`) |
| Announcement group | "Only admins can send messages." |
| Disappearing on | Timer glyph in header subtitle; system line "Messages disappear after 7 days." |
| Media expired (30 days undelivered) | "This file is no longer available. Ask {name} to send it again." |
| Left group | "You're no longer in this group." Composer hidden |

## Copy

| Key | String |
| --- | --- |
| e2ee.notice | Messages and calls are end-to-end encrypted. Only people in this chat can read them. |
| unread.divider | {n} unread messages |
| tick.sending / sent / delivered / read / played / failed | Sending / Sent / Delivered / Read / Played / Not sent. Tap to retry. |
| delete.everyone | Delete for everyone |
| delete.me | Delete for me |
| delete.confirm | Delete this message for everyone? People may have seen it already. |
| edit.bar | Editing message |
| edited.meta | Edited |
| forwarded | Forwarded |
| forwarded.many | Forwarded many times |
| deleted | This message was deleted |
| nudge.sent | You sent a nudge |
| nudge.received | {name} nudged you |
| nudge.limit | You can nudge {name} again in a few seconds. |

## Accessibility

- History is a list; each bubble one focus stop; actions via rotor/actions menu (Reply, React,
  More); swipe-to-reply duplicated as an action.
- New incoming messages announced politely when the chat is open, without moving focus.
- Ticks: label per state; read is a filled disc + label, never colour alone.
- Composer: send with Enter on desktop (setting), Cmd/Ctrl+Enter alternative; voice recording
  via double-tap-and-hold alternative button "Record voice message" with a stop button.
- Text scales to 200 %; bubbles max width 75 % (phone) / 560 pt (desktop).

## Motion

| Change | Motion | Reduced |
| --- | --- | --- |
| Send | Bubble rises 6 pt from composer and fades in, `BASE` | Fade |
| Incoming | Fade + 4 pt rise, `FAST` | Fade |
| Tick change | Glyph cross-fade, read disc fills, `FAST` | Cross-fade |
| Long-press menu | Bubble lifts (scale 1.02), backdrop dims, menu springs in, `SLOW` | Fade |
| Reaction added | Pop scale 1.2 → 1, `BASE` | Fade |
| Swipe to reply | Follows finger; reply glyph appears at 48 pt; spring back | Action only |
| Nudge | Chat shakes 3 × 6 pt, 360 ms | Highlight fade |
| Jump to message | Scroll + highlight wash 1 s | Highlight only |

## Open questions (owner)

1. Edit window: 15 minutes (WhatsApp) — confirm.
2. Delete-for-everyone window: WhatsApp ~2 days; Songbird proposal 24 h?
3. Pinned chats limit 5 (WhatsApp 3)?
4. Long-press menu: cap at 8 actions + More (proposal) vs WhatsApp's full list.
