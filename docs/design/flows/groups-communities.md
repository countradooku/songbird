# Flow: groups, communities and channels (A6)

**Goal:** create and run a group, community or private channel with WhatsApp's controls, and
explain the difference between them in one sentence each. Module: `features/groups.rs`.

## Entry points

Chats › + › New group / New community / New channel; Communities tab (+, empty state); group
link `/g#…`; group info › Add to community.

## Create a group

| # | Screen | Content | Action |
| --- | --- | --- | --- |
| 1 | Add members | Search by username, recent contacts with checkboxes; selected chips on top | **Next** (0 allowed: "Create with just you") |
| 2 | Name & photo | Name (required, ≤ 100), photo, disappearing timer (default from settings), "Members can: Send messages ✓ · Add members ☐ · Edit info ☐" | **Create** |
| 3 | Created | Chat opens; system lines "You created *Family*", "You added Mara and Ion"; card "Invite more people with a link" → link sheet | — |

People whose "who can add me" forbids it: "Mara can't be added directly. Send them an invite
link instead?" → sends the link in a 1:1 chat.

## Group info

Header (photo, name, "Group · 12 members"), buttons Audio · Video · Search · Add; Description;
Media, links and files; Starred; Events; Notifications; Wallpaper; Save to Photos; Disappearing
messages; Lock chat; Advanced chat privacy; **Encryption** ("End-to-end encrypted"); **Permissions**
(admins); **Invite link**; **Join requests (n)**; **Community**; Members (owner/admin tags, "You");
Change log; Leave group; Report group.

| Page | Spec |
| --- | --- |
| Permissions | Members can: Edit group info · Send messages · Add other members · Pin messages · Start calls. Admins: Approve new members · Delete anyone's messages. Footnote per toggle. |
| Member sheet | Message, Call, Verify safety number, Make admin / Dismiss as admin, Make owner (owner only), Remove from group |
| Invite link | Link + QR, Share, Copy, Approve new members toggle, Reset link ("The old link stops working"), Limit uses / expiry |
| Join requests | Rows with Approve / Decline; "Requests expire after 7 days." |

## Communities

| # | Screen | Content |
| --- | --- | --- |
| 1 | Intro (first time) | "A community brings related groups together, with an announcements group everyone in it gets." **Create community** / Join with a link |
| 2 | Name, description, photo | **Create** |
| 3 | Add groups | Existing groups where I'm admin (checkbox), Create new group | 
| 4 | Community home | Header, Announcements (pinned), Groups you're in, Groups you can join (Join / Ask to join), Events, Channels; ⋯ Community info |

Community info: Members, Invite, Permissions (who can add groups: admins only / everyone), Edit,
Delete community ("The groups stay; only the community goes"), Leave community, Report.

## Private channels

Create: name, description, photo, "Followers can react ✓". Info: followers count, admins, invite
link, reactions toggle, Delete channel. Readers: posts with reactions, Mute, Leave, Report.
Explain once at creation: "Followers can see each other's devices, so channels suit people who
know each other." (PROTOCOL §6.10.)

## One-sentence explanations (shown at creation)

| Type | Sentence |
| --- | --- |
| Group | Up to 1,024 devices chat together; everyone can send unless you change it. |
| Community | Related groups under one roof, with an announcements group for everyone. |
| Channel | You post, followers read and react. Up to 2,048 devices. |

## States

| State | Copy |
| --- | --- |
| Group full | "This group is full." |
| Link invalid / reset | "This link isn't valid or has expired." |
| Waiting for approval | "Your request to join was sent. An admin will let you in." |
| Declined / expired request | "Your request wasn't approved." (no reason) |
| Removed | "You were removed from this group." |
| Communities empty | "No communities yet. Communities bring related groups together." **Create community** · Join with a link |
| Offline action | Actions queue with "Will update when you're online." |

## Accessibility

- Member list virtualised; roles in labels ("Ana, admin").
- Permission toggles each with footnote as description.
- Join request actions reachable without swipe.

## Motion

| Change | Motion | Reduced |
| --- | --- | --- |
| Member chip added | Chip scales in from 0.9, `FAST` | Fade |
| Join approved | Row collapses, `BASE` | Instant |

## Open questions (owner)

1. Default "members can add others": off (WhatsApp default is on for small groups)?
2. Ownership transfer: allowed (proposal yes), and must a group always have an owner?
3. Community size display: groups up to 100 (D-0072) — show the limit?
