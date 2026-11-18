# Flow: message requests, blocking and reporting (A5, D-0062, D-0063)

**Goal:** strangers can't land in the chat list; the user decides with Accept, Block or Report,
and understands what a report sends. Data: `Chat::request`, `Contact::blocked`; reports are
franked and sealed to the moderation key (PROTOCOL §5.14).

## Entry points

Chats › Message requests row; notification "New message request" (no preview until accepted,
setting); contact/group info › Block / Report; long-press a message › Report; chat ⋯ › Report.

## Steps: a request

| # | Screen | Content |
| --- | --- | --- |
| 1 | Message requests | List: avatar (blurred photo until accepted), name, @username, "Not in your contacts", first line, time; ⋯ Delete all |
| 2 | Request chat | Messages shown (media not auto-downloaded, links not previewed); top card: "{name} isn't in your contacts. They won't know you've seen this until you accept." Groups in common: n. Bottom bar: **Accept** · Block · Report |
| 3a | Accept | Moves to Chats; read receipts start; sender sees normal ticks from now |
| 3b | Block | Sheet: "Block {name}? They won't be able to message or call you. They won't be told." **Block** / Block and report |
| 3c | Report | Report sheet (below) |

## Steps: report

| # | Screen | Content |
| --- | --- | --- |
| 1 | Reason | Spam · Scam or fraud · Harassment · Child safety · Violence or threats · Something else |
| 2 | What's sent | "We'll send Songbird's moderators the last 5 messages from {name} (you can pick others) and who sent them. Nothing else in this chat is sent." List of messages with checkboxes (default: the last 5 from that sender) |
| 3 | Options | Also block {name} (on) · Also leave the group (groups) |
| 4 | Sent | "Thanks. Moderators will review it. You can see your reports in You › Help › My reports." |

## Blocked list

You › Privacy › Blocked: rows with Unblock; **Block someone** (username search). Blocked
contacts' chats stay with composer replaced by "You blocked {name}. Unblock".

## States

| State | Copy |
| --- | --- |
| No requests | Row hidden; page empty state "No message requests." |
| Requests off (Nobody) | Page footnote "You've turned off message requests." |
| Report limit | "You've sent a lot of reports recently. Try again later." |
| Report offline | Queued: "Your report will be sent when you're online." |
| Report can't be verified (old message, no franking) | Sent anyway; no user-facing difference |

## Copy

| Key | String |
| --- | --- |
| mr.card | {name} isn't in your contacts. They won't know you've seen this until you accept. |
| mr.accept / block / report | Accept / Block / Report |
| blk.confirm | Block {name}? They won't be able to message or call you. They won't be told. |
| rep.what | We'll send Songbird's moderators the messages you choose and who sent them. Nothing else in this chat is sent. |
| rep.done | Thanks. Moderators will review it. |

## Accessibility

Accept/Block/Report as a toolbar with labelled buttons; message checkboxes in the report sheet
labelled with sender and first words; blurred avatars have alt "Photo hidden until you accept".

## Motion

Accepted chat leaves the requests list (`BASE`, collapse); reduced: instant.

## Open questions (owner)

1. Default number of messages attached to a report (proposal 5, user can change).
2. Notify for requests with preview off by default (proposal) or on?
3. Child-safety reports: show a link to national hotlines (per country)?
