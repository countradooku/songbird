# Flow: first chat and inviting friends (A4, A5, A12)

**Goal:** find a person without phone numbers, start the first chat, or invite someone who isn't
on Songbird yet, without uploading an address book.

## Entry points

- Onboarding step 9 tiles; Chats empty state; Chats › **+** (New chat).
- A username link or QR (`/u#…`); You › Invite friends.

## Steps: find by username

| # | Screen | Content | Action |
| --- | --- | --- | --- |
| 1 | New chat | Search field "Username", rows: New group, New community, New channel, New broadcast, Scan QR code, Note to self, Invite a friend; then recent contacts | Type username |
| 2 | Result | Exact match only: one row with avatar, name, @username; or "No one found" | Tap row |
| 3 | Not found, with code option | The server answers "not found" both for unknown names and for a missing/wrong username key (PROTOCOL §4.3), so the app cannot tell. "No one found" state shows "Have a code from them? **Add code**" (4–10 digit field) | Enter code, retry |
| 4 | Chat | Empty chat with encryption notice; composer focused; header "Ana" | Send |
| 5 | Request sent | First message shows ticks; system line "Ana will see your message in Message requests until they reply." | — |

## Steps: QR

Scan QR code → scanner frame (component-library §7) → recognised → profile preview (name, @username)
→ **Message**. Showing my QR: You profile card › QR, or New chat › Scan QR › "My code" tab.

## Steps: invite a friend

| # | Screen | Content | Action |
| --- | --- | --- | --- |
| 1 | Invite friends | "You have 4 invites left." Explanation; list of active codes (expires in N days, Revoke) | **Create invite** |
| 2 | Share | Code `XXXX-…` + link, "Valid for 7 days, one person." | Share sheet / Copy |
| 3 | After sign-up | When the friend joins via a personal link, a chat with the inviter opens on their side (Prompt 11); inviter is not notified by the server (no graph stored) | — |

## States

| State | Copy |
| --- | --- |
| Not found / wrong key (identical by design) | "No one found with that username. Check the spelling, or ask them for their link." |
| Rate limited | "Too many searches. Try again in a few minutes." |
| Offline | "You're offline. Search works when you're connected." |
| No invites left | "You've used all your invites. You'll get more soon." Create disabled |
| Invite-only off | Invite screen becomes "Share Songbird" with the store link |
| Empty contacts | "No chats yet. Find someone by username or invite a friend." |

## Copy

| Key | String |
| --- | --- |
| new.search | Username |
| new.hint | Songbird finds people only by their exact username. |
| invite.title | Invite friends |
| invite.left | You have {n} invites left. |
| invite.body | Each invite works once and lasts 7 days. Songbird doesn't record who invited whom. |
| invite.share | Join me on Songbird, a private messenger. My invite code: {code} {link} |
| request.line | {name} will see your message in Message requests until they reply. |

## Accessibility

- Search result announced ("1 result" / "No one found").
- QR always has a text alternative (username, link copy).
- Invite code read in groups.

## Motion

| Change | Motion | Reduced |
| --- | --- | --- |
| Result appears | Row fades in, `FAST` | Same |
| QR recognised | Frame colour + scale 1.02 pulse, `BASE`, haptic | Colour only |

## Open questions (owner)

1. Default invite validity (7 days per PROTOCOL §4.2 cap) and single use: confirm.
2. Share message text: include "made in Europe"?
3. Show "No one found" vs "Needs a code" separately? (Protocol answers both as 404 on purpose:
   proposal keeps one message.)
