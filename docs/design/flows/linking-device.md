# Flow: linking a device (A4, D-0052)

**Goal:** add a desktop or tablet by scanning a QR code, in under a minute, with a confirmation
the server cannot fake, and see and remove devices later. Module: `features/devices.rs`
(`linked_devices`). Limits: one primary + up to 5 linked devices (PROTOCOL §4.6).

## Entry points

New device: Welcome › I have Songbird on another device › Link to my phone (desktop shows the QR
at once). Primary: You › Account › Linked devices › **Link a device**; Chats ⋯ › Linked devices.

## Steps

| # | New device (desktop) | Primary (phone) |
| --- | --- | --- |
| 1 | QR + "Open Songbird on your phone › You › Linked devices › Link a device, and scan this code." Code refreshes every 10 min | Linked devices list › **Link a device** |
| 2 | — | Device unlock (biometrics) |
| 3 | — | Scanner; recognised |
| 4 | "Confirm on your phone" | "Link *MacBook Pro*?" with device name; if two-step PIN or passkey set, ask it (PROTOCOL §4.7) |
| 5 | Progress "Linking…" | **Link** |
| 6 | "Syncing your chats…" (history transfer, encrypted) | Device appears as pending, then active; notification on all devices "A new device was linked" |
| 7 | Chats | Done |

## Linked devices page

This device (primary), then each: icon by kind, name (editable on that device), "Active 2 h ago",
**Remove**. Footer: "You can link up to 5 devices. Each one can read your messages from when it
was linked." Remove: confirm "Remove *MacBook*? It will be signed out and stop getting messages."

## States

| State | Copy |
| --- | --- |
| QR expired | "This code expired. **Show a new code**" |
| Limit reached | "You've linked 5 devices. Remove one to link another." |
| Wrong PIN | "That PIN isn't right. {n} tries left before a pause." |
| PIN locked | "Too many tries. Try again in {time}." |
| Confirmation mismatch (server sent a different device) | "We couldn't confirm this device, so it wasn't linked. Try again with both devices together." |
| Offline | "Both devices need to be online to link." |
| Unknown device appeared | Banner "A new device was linked: {name}. Not you? **Remove it**" (destructive action) |

## Copy

| Key | String |
| --- | --- |
| ld.qr | Open Songbird on your phone, go to You › Linked devices › Link a device, and scan this code. |
| ld.confirm | Link {device}? It will be able to read and send your messages. |
| ld.footer | You can link up to 5 devices. Each one can read your messages from when it was linked. |
| ld.new | A new device was linked: {name}. Not you? Remove it |

## Accessibility

QR alternative: "Can't scan? Link with a code" shows a short text code to type on the phone (open
question 1). Device list rows labelled with kind and last active.

## Motion

QR refresh cross-fade `BASE`; success check `BASE`; reduced: fades.

## Open questions (owner)

1. Text-code alternative to the QR for people who can't scan (accessibility) — needs a protocol
   addition.
2. History sync to linked devices: full history (WhatsApp) or last 90 days?
