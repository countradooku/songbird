# Desktop: what NSH 0.5.1 has, what Songbird uses, and the gaps

Checked against `nsh-core-0.5.1/src/element/desktop.rs`, `element/ambient.rs`, `keymap.rs`,
`website/modules/nsh-desktop.md` and `examples/tray`.

## Used (exists in NSH)

| Need | NSH API | Where |
| --- | --- | --- |
| Keyboard shortcuts | `on_key`, `on_key_with(KeyOptions { when })`, `key_label` | `features::desktop::install_shortcuts`, `shortcuts_sheet` |
| Native app menus (File/Edit/View/Chat/Window/Help, macOS app menu) | `set_application_menu`, `MenuItem`, `MenuRole` | `features::desktop::desktop_menus` |
| Tray / menu bar icon with unread count | `set_tray(tray().icon().title([TrayTitleRun]).menu())` | `desktop_tray` (in `install_shortcuts`), toggle in `desktop_settings` |
| Chat in its own window | `open_window(window().id().title().content())` | `features::desktop::pop_out_chat(store, chat)`, File → Open chat in new window |
| Dropping files on a view | `on_file_drag_enter`, `on_file_drag_leave`, `on_file_drop` (`FileDropEvent`) | `features::desktop::on_file_drop(view, hint, f)` |
| Badge on the app icon | `set_badge(count)` | Not wired (the notifications owner, A9, should call it with `total_unread`) |
| Notifications | `show_notification`, `request_notification_permission` | A9's area |

Notes: `on_key` panics on reserved keys (⌘Q, ⌘H, ⌘M, ⌃⌘F on macOS; Ctrl+Q, Alt+F4, F11 elsewhere);
`keys.rs` tests every shortcut against the parser and `reserved()` for macOS, Windows and Linux.
Windows opened with `open_window` render beside the root, outside its context, so
`pop_out_chat` provides the store again in the window.

## Gaps (NSH lacks these)

| Missing | Mocked as | Native module that would fill it |
| --- | --- | --- |
| Launch at login | `Settings.launch_at_login` toggle only | macOS `SMAppService.mainApp.register()`; Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value (or `StartupTask` for MSIX); Linux XDG autostart `~/.config/autostart/chat.songbird.app.desktop`. A small `#[native_module]` per platform. |
| Share sheet (invites) | App-drawn share sheet (Copy / Messages / Mail / More) | iOS `UIActivityViewController`, Android `Intent.ACTION_SEND`, macOS `NSSharingServicePicker`, Windows `DataTransferManager`. |
| Real QR code | Deterministic stand-in pattern (`ui::qr_code`) | Not NSH: app-core can encode with the `qrcode` crate and hand the matrix to the UI. |
| Dock / taskbar menu (recent chats) | — | macOS `applicationDockMenu`, Windows Jump Lists. |
| Tray icon as a template with a coloured unread dot | Count as title text (Windows shows the icon alone) | Windows overlay icon (`ITaskbarList3::SetOverlayIcon`) for a count on the taskbar button. |
| Global "show Songbird" hot key | Available (`register_global_shortcut`) but not used: needs a user setting first | — |
| `Window` content sharing per-surface globals | Popped-out chats share the app's engine; `nav` globals are per surface, so a pushed page in a popped window may show in the main window. Needs checking once `chat::conversation` exists. | — |

## Platform skins: what NSH 0.5.1 draws natively, and the gaps

Checked against `nsh-core-0.5.1/src/effects.rs` (`GlassEffect`, `BackdropMaterial`,
`MacOsBackdrop`), `element/builder.rs` (`ripple`, `elevation`, `backdrop_material`,
`macos_backdrop`) and `nsh-base-0.5.1/src/button.rs`. Songbird's skins live in `src/ui/skin.rs`.

| Skin | Native in NSH, used | Gap (drawn by the app, or missing) |
| --- | --- | --- |
| Apple | `glass_effect(Regular)` + `glass_tint_color` on the floating tab bar and header control capsules (Liquid Glass on iOS 26 / macOS 26, backdrop blur before); `macos_backdrop(Sidebar, BehindWindow)` under the Mac source list | Headers are not translucent over scrolling content: features lay the header out beside their lists, not over them, so there is no scroll-edge effect (NSH has none either). The `header_large_title` system header is not used: Songbird draws its own headers so desktops and phones share one header. Sheets are solid (no glass detents). |
| Material | `elevation` on the FAB; `ripple` on view-based pressables (the menu trigger) | **`nsh_base::button` takes no `ripple`** (it is a component, not a view): buttons, rows and tabs show an M3 state layer instead of the ink ripple. No dynamic colour (Material You wallpaper seed): the tonal palette is seeded from Dusk violet by hand in `theme.json`. No predictive-back shape animation of our sheets. |
| Fluent | — | **No Mica or Acrylic** (`MacOsBackdrop` is macOS-only, `glass_effect` Apple-only): Songbird uses Fluent's own non-Mica fallback, solid layered surfaces with 1px strokes. No reveal-highlight or Segoe Fluent Icons (Lucide shapes stand in). No NavigationView compact/minimal modes: the pane is always open. |
| Adwaita | — | No native header bar or `AdwNavigationSplitView`: the header bar is drawn; no CSD integration of the window controls into it. No accent-colour portal: the accent is Dusk violet, not the user's GNOME accent. |
| All | `os()`, `is_desktop()`, `idiom()` pick the skin | Only `SONGBIRD_SKIN` (debug) can preview other skins on one machine: the native hooks (glass, vibrancy, ripple, elevation) render only on their own OS, so a Material preview on a Mac shows the state layer and shadow, not the Android ripple. |
