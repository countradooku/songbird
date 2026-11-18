# Flow: desktop and tablets (A13)

**Goal:** a desktop app that feels native on macOS, Windows and Linux, is fully usable by
keyboard, and keeps WhatsApp Desktop's habits (list + chat side by side). Modules:
`src/shell.rs` (rail + list + detail), `features/desktop.rs` (shortcuts, menus, tray, pop-outs).
Layout switch: `ui::wide()` at ≥ 760 pt.

## Layout

| Region | Width | Content |
| --- | --- | --- |
| Rail | 72 pt | Feather logo, Chats, Calls, Communities, You (icon + label), bottom: my avatar with presence (menu: presence, status line, Linked devices, Quit) |
| List pane | 360 pt (300–480, draggable divider; double-click resets) | The section's list with header and search |
| Detail pane | rest (min 420) | Chat, call, settings page, or empty state "Select a chat to start messaging" + "Messages are end-to-end encrypted." |
| Info panel | 360 pt, ≥ 1100 pt windows | Chat/group info beside the chat; narrower windows push it in the detail stack |

Tablets (≥ 760 pt) use the same layout with touch sizes (`ui::TOUCH`).

## Window and system

| Feature | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Menu bar | App, File, Edit, View, Chat, Window, Help | In-window menu via Alt; context menus | Same as Windows; GNOME: header-bar menu |
| Tray / menu bar icon | Template icon with unread dot; click shows window | Tray with unread badge overlay | StatusNotifier if available |
| Badge | Dock badge count | Taskbar overlay | Launcher API count where supported |
| Notifications | UNUserNotification with reply | Toast with reply box | libnotify/portal with actions |
| Close button | Hides window (app keeps running) | Close to tray (setting, default on) | Same as Windows |
| Launch at login | Setting (off) | Setting (off) | Autostart desktop file |
| Pop-out chat | Window › Open in new window / drag a chat out | Same | Same |
| Call window | Separate, always-on-top option, PiP when minimised | Same | Same |

## Shortcuts (Cmd on macOS, Ctrl elsewhere)

| Action | Keys |
| --- | --- |
| New chat | Mod+N |
| Search chats | Mod+K |
| Search in chat | Mod+F |
| Next / previous chat | Mod+Tab / Mod+Shift+Tab (also Alt+↓/↑) |
| Unread next | Mod+Shift+U |
| Jump to chat 1–9 | Mod+1…9 |
| Settings | Mod+, |
| Reply to selected | Mod+R (or → on focused bubble) |
| Edit last message | ↑ in empty composer |
| Send | Enter (Shift+Enter newline; setting swaps) |
| Mute chat | Mod+Shift+M |
| Archive chat | Mod+E |
| Start voice / video call | Mod+Shift+C / Mod+Shift+V |
| Mute / camera in call | M / V (when call window focused) |
| Shortcut sheet | Mod+/ |
| Zoom text | Mod+= / Mod+− / Mod+0 |

## States

| State | Behaviour |
| --- | --- |
| Not linked | Full-window QR (`linking-device.md`) |
| Primary offline | Desktop works independently (multi-device), no dependency on the phone |
| Narrow window (< 760) | Phone layout inside the window |
| Offline | Status in rail avatar menu + bar in detail pane |

## Accessibility

- Full keyboard: Tab moves rail → list → detail → composer; F6 cycles panes; focus visible ring.
- Screen readers: panes are landmarks ("Navigation", "Chat list", "Conversation").
- Respect OS high contrast (Windows) by switching to HC tokens.

## Motion

Pane changes don't animate (desktop calm); detail content cross-fades `INSTANT`; pop-out window
uses the OS animation.

## Open questions (owner)

1. Close-to-tray default on Windows/Linux (proposal on), and is a tray needed at all on GNOME?
2. Linux packaging target first: Flatpak (proposal) or .deb/.rpm?
3. Web client: not in beta (parity-map §16) — confirm.
