# Flow: WhatsApp chats (A15, Prompt 14)

**Goal:** opt in to chatting with WhatsApp users through the EU's third-party chats, knowing
exactly what Meta will learn, and tell bridged chats apart at a glance. **Behind the legal gate**
(Prompt 14 Gate 0): the whole feature is hidden until the owner clears it. Module:
`features/whatsapp.rs`. Data: `ChatKind::WhatsApp`, `Settings::whatsapp_linked`.

## Entry points

You › WhatsApp chats; Chats empty state (once enabled) "Chat with WhatsApp friends"; New chat ›
WhatsApp contact.

## Steps: opt in

| # | Screen | Content |
| --- | --- | --- |
| 1 | Intro | "Chat with people on WhatsApp without leaving Songbird. Messages stay end-to-end encrypted." **Continue** |
| 2 | What Meta learns | Plain list from the Prompt 14 privacy review: your WhatsApp-facing ID, who you chat with on WhatsApp and when, message sizes and times, your device count. "Meta can't read your messages." "Your Songbird-only chats are not affected." |
| 3 | Choose identity | Interop identifier as Meta's process defines (phone number if Meta requires it — open question) |
| 4 | Verify | Meta's identity verification step |
| 5 | On | "WhatsApp chats are on." Toggle to turn off ("Deletes your WhatsApp link. WhatsApp chats stay as history, read-only.") |

## Bridged chats

| Element | Spec |
| --- | --- |
| Chat list | `tag("WhatsApp")` with `whatsapp` token dot; never Songbird's primary colour |
| Header | Name + "WhatsApp" subtitle |
| Notice at top | "End-to-end encrypted. This chat goes through WhatsApp: Meta sees who talks to whom and when." |
| Hidden features | Nudges, chat scenes, sound stickers, polls/events (until supported), edits beyond WhatsApp's support, view once (as WhatsApp allows) — controls absent, not disabled |
| Unsupported incoming | "This message type isn't supported in Songbird yet. Open WhatsApp to see it." |
| Safety number | WhatsApp security code format (`safety-number.md`) |
| Groups | Only what Meta's interop supports at the time; otherwise not offered |

## States

| State | Copy |
| --- | --- |
| Not available in country | "WhatsApp chats work only in the EU." |
| WhatsApp user hasn't enabled third-party chats | "{name} hasn't turned on third-party chats in WhatsApp." |
| Gateway down | Banner "WhatsApp chats are unavailable right now. Songbird chats work normally." |
| Opted out | Chats read-only with "WhatsApp chats are off. **Turn on**" |

## Accessibility

"WhatsApp" is part of every bridged chat's accessible name; the tag is text, not just a colour.

## Motion

None special.

## Open questions (owner)

1. Legal gate (Prompt 14 Gate 0) and the exact "what Meta learns" list after the Reference Offer
   review.
2. If Meta requires a phone number for the interop identity, is that acceptable as opt-in?
3. Show WhatsApp chats in the main list (proposal, tagged) or a separate filter only?
