# Information architecture

Status: **proposal for the owner.** The four-tab layout is already in `apps/ui/src/nav.rs`
(`Tab::Chats, Calls, Communities, You`) and `apps/ui/DESIGN.md`; this file justifies it and adds
what is not yet decided (channels' home, deep links). Decisions needed are marked **Owner**.

## 1. Top level

| Tab | Holds | Why |
| --- | --- | --- |
| **Chats** (default) | Chat list with filters, search, archived, message requests, new chat | 80–90 % of sessions start and end here (WhatsApp habit). |
| **Calls** | Recent calls, favourites, new call, call links, schedule | WhatsApp users look for calls in a tab; links need a home. |
| **Communities** | Communities, their groups, private channels the user joined or runs | Groups-of-groups and channels are "places", not conversations. |
| **You** | Profile, presence, status line, all settings, backups, plans, help | One visible home for settings on every platform (WhatsApp hides it in ⋮ on Android). |

Order follows WhatsApp Android (Chats first) since the thumb lands there; iOS WhatsApp users
find Chats by label and icon either way. Labels always visible (never icon-only tabs).

Alternatives considered:

| Option | For | Against |
| --- | --- | --- |
| A. Chats · Calls · Communities · You (proposed) | Familiar, four targets, settings visible | Communities tab may look empty for new users (empty state explains and offers "Join with a link") |
| B. WhatsApp iOS order (Updates · Calls · Communities · Chats · Settings) | Exact iOS muscle memory | Five tabs, Updates needs Status (dropped) |
| C. Chats · Calls · You (communities inside Chats) | Simplest | Communities lost; channel admins have no home |

**Owner:** confirm A.

## 2. Layouts

| Width | Layout |
| --- | --- |
| Phone (< 760 pt) | Bottom tab bar; native stack per tab; system headers; chat pushes over the tab bar (tab bar hidden in a chat). |
| Tablet / desktop (≥ 760 pt) | Left **rail** (72 pt: logo, four sections, presence avatar at the bottom) · **list pane** (360 pt, resizable 300–480) · **detail pane** with its own stack (chat, then chat info as a right panel ≥ 1100 pt or pushed below). |
| Desktop extras | Pop-out chat windows, call window, tray icon, menu bar, shortcuts (`flows/desktop.md`). |

The selected chat persists across tab switches on desktop (detail pane keeps the chat open while
the list shows Calls).

## 3. Where channels live

Private channels only (public channels not built, D-0065 §4).

| Place | Shows |
| --- | --- |
| Chats › **Channels** chip | Channels the user follows, like chats (unread, mute, last post). This is where reading happens. |
| Communities › **Channels** section | Channels the user follows or runs, with New channel and Join with a link. This is where managing happens. |
| A community's home | Channels attached to that community (if any). |

Rationale: WhatsApp puts channels in Updates next to Status; with Status gone, readers find
posts with their chats, and admins find tools next to communities. **Owner:** confirm.

## 4. Where Status went

WhatsApp's Status (24 h stories) is removed:

- It needs a separate audience model and a large media pipeline for a feature many WhatsApp
  users never post to.
- Songbird's own expression is the **status line** (Yahoo-style "In a meeting until 3", with
  expiry) and **presence** (online, away, busy, invisible), set from You's profile card and
  shown under the name in chat headers and contact rows.
- Privacy: You › Privacy › Status line (Everyone / My contacts / Nobody).

Users coming from WhatsApp who look for Status: You tab search and Help have an article "Where is
Status?". **Owner:** confirm removal (reversible later as an opt-in "Moments" feature).

## 5. Deep links (proposal)

All links work as `https://<web domain>/…` (opens the app if installed, else a page explaining
how to get it) and as `songbird://…` (in-app only). **Secrets go in the fragment (`#`)** so the
web server never sees them; this matches what the protocol already defines.

| Purpose | HTTPS form | App scheme | Defined by | Status |
| --- | --- | --- | --- | --- |
| Invite to the beta | `https://songbird.chat/i#<invite code>` | `songbird://invite#<code>` | Proposal (PROTOCOL §4.2 code format) | New |
| Username link (profile) | `https://songbird.chat/u#<link>` | `songbird://u#<link>` | PROTOCOL §4.3 (handle + key) | Path proposed |
| Group / community join | `https://songbird.chat/g#<handle><secret>` | `songbird://g#…` | PROTOCOL §6.8 | Defined |
| Channel join | same as group (`/g#`) | | Channels are groups (§6.10) | Defined |
| Call link | `https://songbird.chat/call#<root>` | `songbird://call#<root>` | PROTOCOL §8.4 | Defined |
| Sticker / emoji pack | `https://songbird.chat/pack#<id>.<key>` | `songbird://pack#…` | PROTOCOL §7.4 | Defined |
| Proxy | `https://songbird.chat/proxy#host[:port]` | `songbird://proxy#host[:port]` | D-0011 | Defined |
| Link a device (QR only) | — | `songbird://link#<channel>.<key>` | PROTOCOL §4.6 | QR payload, never a web link |
| Open a chat (internal) | — | `songbird://chat/<local id>` | Proposal | Notifications and widgets only; never shared |

Rules: the app shows what a link will do before doing it ("Join *Family* group?" with member
count when known); links from inside chats get the same confirmation; unknown or malformed links
show "This link isn't valid or has expired." **Owner:** the web domain for links (open in
DECISIONS: `songbird.chat` or a short domain), and whether `/i#` invite links exist or invites stay
codes only.

## 6. Global entry points

| Action | Phone | Desktop |
| --- | --- | --- |
| New chat | Chats header **+** | `Ctrl/Cmd+N`, list header + |
| Search | Chats search field (pull down on iOS) | `Ctrl/Cmd+K` (chats), `Ctrl/Cmd+F` (in chat) |
| Settings | You tab | You in rail, `Ctrl/Cmd+,` |
| New call | Calls header | `Ctrl/Cmd+Shift+C` |
| Scan QR | Chats + › Scan QR; You profile card | Not on desktop (shows QR instead) |
