# Flow: the You tab and settings (A10, A9)

**Goal:** every setting a WhatsApp user knows is where they'd guess, the ten most used are at
most two taps from You, and every toggle says what it does in one line. Module:
`features/settings.rs` (`you_tab`). Data: `store::model::Settings` (synced as encrypted records).
Parity with WhatsApp: `../parity-map.md`.

## The You tree

| Group | Row (page) | Contents (rows, defaults) |
| --- | --- | --- |
| Profile card | Edit profile | Photo, Name, About, @username (→ Account › Username), QR |
| | Presence | Online · Away · Busy · Invisible |
| | Status line | Text + emoji, expiry: 1 h, 4 h, Today, This week, Never |
| — | Starred messages | |
| **Account** | Username | Change, Username link (Share, QR, Reset link), Username key ("Find me only with a code"), Find me by username (on) |
| | Security | Two-step PIN (off), Passkeys, Recovery key (View — needs device unlock), Security notifications (on) |
| | Linked devices | `linking-device.md` |
| | Plan | Free / Plus / Family (`plans-paywall.md`) |
| | Add account | |
| | Request my data | GDPR export |
| | Delete if inactive | 6 months / 1 year (default) / 2 years |
| | Delete account | |
| **Privacy** | Privacy centre | `privacy-centre.md` (card at the top of Privacy) |
| | Who can see my… | Last seen (My contacts), Online (Same as last seen), Profile photo (My contacts), About (Everyone), Status line (My contacts) |
| | Who can add me to groups | My contacts |
| | Message requests | Everyone / Nobody |
| | Read receipts | on · Typing indicator on |
| | Default message timer | Off |
| | Live location | (list of chats sharing) |
| | Calls | Silence unknown callers (off), Relay all calls (off) |
| | Blocked | list |
| | App lock | off (biometrics / device code, lock after: immediately, 1 min, 15 min, 1 h) |
| | Chat lock | Hide locked chats (off), Secret code |
| | Screen security | Block screenshots (off), Hide in app switcher (off) |
| | Link previews | on |
| | Camera effects | on |
| | Parental controls | `parental-controls.md` |
| **Chats** | Appearance | Theme (System), Chat wallpaper, Animations (on) |
| | Lists | |
| | Broadcast lists | |
| | Default reactions | 👍 ❤️ 😂 😮 😢 🙏 |
| | Enter sends | off phones / on desktop |
| | Save to Photos | off |
| | Keep chats archived | on |
| | Voice message transcripts | off (on device) |
| | Nudges | on · Sound stickers autoplay (on) |
| | Archive all · Clear all · Delete all | |
| **Backups** | Backups | `backups.md` |
| **Notifications** | Messages | Notifications, Sound, Vibrate, Reactions |
| | Groups | same + Only @mentions |
| | Calls | Ringtone, Vibrate |
| | Show message content | on |
| | Badge count · In-app sounds · Reminders · Sound style (Calm/Playful) · Nudges · Reset | |
| **Storage and data** | Manage storage · Network usage · Auto-download (photos Wi-Fi+mobile, audio Wi-Fi+mobile, video Wi-Fi, documents Wi-Fi) · Upload in HD (off) · Low data calls (off) · Proxy (off) | |
| **WhatsApp chats** | `whatsapp-chats.md` (hidden until the legal gate passes) | |
| **Accessibility** | High contrast · Reduce motion (System) · Text size (System) | |
| **Language** | System default, then list | |
| **Help** | Help centre · Contact support · My reports · Terms and privacy · About (version, licences, transparency report) · Design system (debug builds) | |
| **Invite friends** | `first-chat-invite.md` | |
| Desktop only | Launch at login (off), Close to tray (on), Shortcuts | |

Top-10 settings and their path depth (tree test targets, usability-plan.md task 8):
last seen (Privacy, 2), blocked (2), notification sound (2), storage (2), linked devices (2, also
Chats ⋯), two-step PIN (3), theme (3: Chats › Appearance › Theme; also Accessibility 2), backups
(1), read receipts (2), app lock (2).

## Patterns

- Audience pickers open a sheet with three radio rows + footnote ("Only people you've chatted
  with").
- Every toggle row has a footnote under the group explaining the effect in one sentence.
- Settings sync to all devices; per-device ones (app lock, notifications, auto-download,
  launch at login) say "On this device".
- Search (desktop and phones): field at the top of You, matches row titles and synonyms
  ("dark mode" → Theme, "phone number" → Username, "status" → Status line, "security code" →
  Safety number).

## States

| State | Copy |
| --- | --- |
| Saving | No spinner; change applies at once, syncs in background |
| Sync failed | Row footnote "Not synced to your other devices yet." |
| Offline + server-enforced setting (message requests, find me, inactivity, plan) | "You're offline. This will update when you're connected." |
| Destructive (clear/delete all, delete account) | `confirm` dialog with consequence; delete account needs PIN/passkey/recovery key |

## Copy (footnotes)

| Row | Footnote |
| --- | --- |
| Read receipts | If you turn this off, you won't see other people's read receipts either. Groups always show who read. |
| Message requests: Nobody | People who aren't your contacts can't message you. |
| Find me by username | When off, people can reach you only with your link or QR code. |
| Username key | People need this code as well as your username to find you. |
| Relay all calls | Calls go through Songbird's servers so the other person can't see your IP address. Calls may be a little slower. |
| Block screenshots | Other apps and screenshots see a blank screen. |
| Link previews | Your phone fetches previews for links you send. The site sees your IP address. |
| Show message content | Shows who wrote and what they said on your lock screen. Songbird's notifications never carry message content through Apple or Google. |
| Delete if inactive | If you don't open Songbird for this long, your account and its data are deleted. |

## Accessibility

- Every row a button with its value in the name ("Last seen, My contacts").
- Groups are headed sections; search results announced.
- Destructive rows use `danger` and the word ("Delete account"), never colour alone.

## Motion

Native push/pop between pages; toggles `FAST`; sheet `SLOW`. Reduced: fades.

## Open questions (owner)

1. Read receipts in groups: always on (proposal, matching WhatsApp) or follow the toggle?
2. Inactivity default: 1 year?
3. Show Backups as a top-level You group (proposal) or under Chats like WhatsApp?
4. Settings search on phones in the first release?
