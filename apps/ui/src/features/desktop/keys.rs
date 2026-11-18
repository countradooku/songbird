//! The desktop shortcuts as data: one table for the key bindings, the
//! menus and the cheat sheet, so they never disagree. Plain Rust, tested
//! against NSH's keystroke parser for every desktop OS.

/// What a shortcut does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// The ⌘K jump-to palette (`jump.rs`).
    JumpTo,
    Search,
    NewChat,
    NextChat,
    PreviousChat,
    Tab(usize),
    Shortcuts,
    MarkRead,
    Settings,
}

/// The cheat sheet's groups, in order.
pub const GROUPS: [&str; 3] = ["Chats", "Navigation", "Help"];

/// One shortcut: its keystroke (NSH syntax: `mod` is ⌘ on macOS, Ctrl
/// elsewhere), what it does, the group it shows in, and whether it is
/// bound as a key (some only show in menus, as alternates).
pub struct Shortcut {
    pub keys: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub command: Command,
}

pub const SHORTCUTS: &[Shortcut] = &[
    Shortcut { keys: "mod+k", label: "Jump to a chat, person or setting", group: "Chats", command: Command::JumpTo },
    Shortcut { keys: "mod+f", label: "Search chats", group: "Chats", command: Command::Search },
    Shortcut { keys: "mod+n", label: "New chat", group: "Chats", command: Command::NewChat },
    Shortcut { keys: "mod+shift+u", label: "Mark as read", group: "Chats", command: Command::MarkRead },
    Shortcut { keys: "mod+]", label: "Next chat", group: "Navigation", command: Command::NextChat },
    Shortcut { keys: "mod+[", label: "Previous chat", group: "Navigation", command: Command::PreviousChat },
    Shortcut { keys: "ctrl+tab", label: "Next chat", group: "Navigation", command: Command::NextChat },
    Shortcut { keys: "ctrl+shift+tab", label: "Previous chat", group: "Navigation", command: Command::PreviousChat },
    Shortcut { keys: "mod+1", label: "Chats", group: "Navigation", command: Command::Tab(0) },
    Shortcut { keys: "mod+2", label: "Calls", group: "Navigation", command: Command::Tab(1) },
    Shortcut { keys: "mod+3", label: "Spaces", group: "Navigation", command: Command::Tab(2) },
    Shortcut { keys: "mod+4", label: "You", group: "Navigation", command: Command::Tab(3) },
    Shortcut { keys: "mod+,", label: "Settings", group: "Navigation", command: Command::Settings },
    Shortcut { keys: "mod+/", label: "Keyboard shortcuts", group: "Help", command: Command::Shortcuts },
];

/// Shown in the cheat sheet only: keys the platform or a screen handles.
pub const EXTRA: &[(&str, &str, &str)] = &[
    ("escape", "Close this list, a sheet or a menu", "Help"),
    ("enter", "Send a message", "Chats"),
    ("shift+enter", "New line in a message", "Chats"),
];

/// The keystroke the menus show for `command` (its first binding).
pub fn keys_for(command: Command) -> Option<&'static str> {
    SHORTCUTS.iter().find(|s| s.command == command).map(|s| s.keys)
}

/// The next (`step` 1) or previous (`step` -1) item of `ids` after
/// `current`, wrapping around; the first (or last) when nothing is open.
pub fn cycle<T: Copy + PartialEq>(ids: &[T], current: Option<T>, step: i32) -> Option<T> {
    if ids.is_empty() {
        return None;
    }
    let n = ids.len() as i32;
    let at = current.and_then(|c| ids.iter().position(|x| *x == c));
    let next = match at {
        Some(i) => (i as i32 + step).rem_euclid(n),
        None if step >= 0 => 0,
        None => n - 1,
    };
    Some(ids[next as usize])
}

#[cfg(test)]
mod tests {
    use nsh_core::{keymap::Keystroke, platform::Os};

    use super::*;

    #[test]
    fn every_shortcut_parses_and_is_free_on_every_desktop() {
        for os in [Os::MacOs, Os::Windows, Os::Linux] {
            for s in SHORTCUTS {
                let k = Keystroke::parse(s.keys, os).unwrap_or_else(|e| panic!("{}: {e}", s.keys));
                assert_eq!(k.reserved(os), None, "{} is reserved on {os:?}", s.keys);
                // Bound globally, so none may be a key a text field types.
                assert!(
                    !k.edits_text() || s.keys.contains("tab"),
                    "{} would be taken from text fields",
                    s.keys
                );
            }
            for (keys, _, _) in EXTRA {
                Keystroke::parse(keys, os).unwrap_or_else(|e| panic!("{keys}: {e}"));
            }
        }
    }

    #[test]
    fn no_keystroke_is_bound_twice() {
        for (i, a) in SHORTCUTS.iter().enumerate() {
            for b in &SHORTCUTS[i + 1..] {
                assert_ne!(a.keys, b.keys);
            }
        }
    }

    #[test]
    fn groups_cover_every_shortcut() {
        assert!(SHORTCUTS.iter().all(|s| GROUPS.contains(&s.group)));
        assert!(EXTRA.iter().all(|(_, _, g)| GROUPS.contains(g)));
    }

    #[test]
    fn cycling_wraps_both_ways() {
        let ids = [10, 20, 30];
        assert_eq!(cycle(&ids, Some(20), 1), Some(30));
        assert_eq!(cycle(&ids, Some(30), 1), Some(10));
        assert_eq!(cycle(&ids, Some(10), -1), Some(30));
        assert_eq!(cycle(&ids, None, 1), Some(10));
        assert_eq!(cycle(&ids, None, -1), Some(30));
        assert_eq!(cycle(&ids, Some(99), 1), Some(10));
        assert_eq!(cycle::<u64>(&[], None, 1), None);
    }

    #[test]
    fn menus_find_their_keys() {
        assert_eq!(keys_for(Command::NewChat), Some("mod+n"));
        assert_eq!(keys_for(Command::JumpTo), Some("mod+k"));
        assert_eq!(keys_for(Command::Search), Some("mod+f"));
    }
}
