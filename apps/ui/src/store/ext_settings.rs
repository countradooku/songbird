//! A10 settings: the state the settings screens need beyond `Settings`
//! and `Profile` (custom status expiry, app lock delay, ringtone, chat
//! lists' order, broadcast lists, parental rules, profile links), and the
//! intents that change it. Plain Rust and one global signal, so the merge
//! into `model.rs` later is a move, not a rewrite.
//!
//! **Mock.** Each of these is an encrypted settings record in app-core
//! (Prompt 9: one record per setting, last-writer-wins on a hybrid logical
//! clock); here it lives in memory.

use std::time::Duration;

use nsh_core::prelude::*;

use super::{Audience, ChatId, ContactId, Minutes, NOW, Presence, Settings, Store};

/// When a custom status clears itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusExpiry {
    HalfHour,
    Hour,
    FourHours,
    Today,
    Week,
    Never,
}

impl StatusExpiry {
    pub const ALL: [StatusExpiry; 6] = [
        StatusExpiry::HalfHour,
        StatusExpiry::Hour,
        StatusExpiry::FourHours,
        StatusExpiry::Today,
        StatusExpiry::Week,
        StatusExpiry::Never,
    ];

    pub fn label(self) -> &'static str {
        match self {
            StatusExpiry::HalfHour => "30 minutes",
            StatusExpiry::Hour => "1 hour",
            StatusExpiry::FourHours => "4 hours",
            StatusExpiry::Today => "Today",
            StatusExpiry::Week => "This week",
            StatusExpiry::Never => "Don't clear",
        }
    }

    /// The minute the status clears, from `now` (mock minutes, where 0 is
    /// Tuesday 10:24). "Today" ends at midnight, "This week" on Sunday
    /// night.
    pub fn until(self, now: Minutes) -> Option<Minutes> {
        let minute_of_day = (10 * 60 + 24 + now).rem_euclid(24 * 60);
        let to_midnight = 24 * 60 - minute_of_day;
        match self {
            StatusExpiry::HalfHour => Some(now + 30),
            StatusExpiry::Hour => Some(now + 60),
            StatusExpiry::FourHours => Some(now + 4 * 60),
            StatusExpiry::Today => Some(now + to_midnight),
            // Tuesday → the end of Sunday: today plus five more days.
            StatusExpiry::Week => Some(now + to_midnight + 5 * 24 * 60),
            StatusExpiry::Never => None,
        }
    }
}

/// "until 11:24", "until tomorrow 00:00", "until Sunday".
pub fn until_label(until: Option<Minutes>, now: Minutes) -> String {
    let Some(at) = until else {
        return "Until you clear it".into();
    };
    let day = super::day_of(at) - super::day_of(now);
    match day {
        0 => format!("Until {}", super::clock(at)),
        1 if super::clock(at) == "00:00" => "Until midnight".into(),
        1 => format!("Until tomorrow {}", super::clock(at)),
        _ => "Until Sunday night".into(),
    }
}

/// How soon app lock locks after leaving the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockAfter {
    #[default]
    Immediately,
    Minute,
    Hour,
}

impl LockAfter {
    pub fn label(self) -> &'static str {
        match self {
            LockAfter::Immediately => "Immediately",
            LockAfter::Minute => "After 1 minute",
            LockAfter::Hour => "After 1 hour",
        }
    }
}

/// Who a supervised child may hear from (parental controls).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChildContact {
    #[default]
    ApprovedOnly,
    ContactsAndRequests,
}

impl ChildContact {
    pub fn label(self) -> &'static str {
        match self {
            ChildContact::ApprovedOnly => "Approved contacts only",
            ChildContact::ContactsAndRequests => "Contacts, and requests I approve",
        }
    }
}

/// The rules a parent sets (a policy signed with the parent's key).
#[derive(Debug, Clone, PartialEq)]
pub struct ParentalRules {
    pub child_name: String,
    pub who_can_message: ChildContact,
    pub groups_need_approval: bool,
    pub block_unknown_calls: bool,
    pub discoverable: bool,
    pub nudges: bool,
    /// Quiet hours (no notifications), e.g. "21:00–07:00".
    pub quiet_hours: Option<&'static str>,
}

impl Default for ParentalRules {
    fn default() -> Self {
        Self {
            child_name: "Maria".into(),
            who_can_message: ChildContact::ApprovedOnly,
            groups_need_approval: true,
            block_unknown_calls: true,
            discoverable: false,
            nudges: false,
            quiet_hours: Some("21:00–07:00"),
        }
    }
}

/// A broadcast list: one message, sent to each person separately.
#[derive(Debug, Clone, PartialEq)]
pub struct Broadcast {
    pub id: u64,
    pub name: String,
    pub members: Vec<ContactId>,
}

/// The extra settings state.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingsExt {
    /// When the custom status clears; `None` keeps it.
    pub status_until: Option<Minutes>,
    pub status_emoji: String,
    /// The online audience follows last seen (WhatsApp's "Same as last seen").
    pub online_same_as_last_seen: bool,
    pub app_lock_after: LockAfter,
    pub security_notifications: bool,
    pub ringtone: &'static str,
    pub message_tone: &'static str,
    pub protect_ip_in_calls: bool,
    pub app_icon: u8,
    /// The user's chat lists, in their order.
    pub lists: Vec<String>,
    pub broadcasts: Vec<Broadcast>,
    pub parental: ParentalRules,
    /// Mock: show the child's side of parental controls.
    pub child_view: bool,
    pub links: Vec<String>,
    pub account_report: Option<String>,
    /// A parent's policy applies to this account (Prompt 9): the settings it
    /// locks show as locked.
    pub supervised: bool,
}

impl Default for SettingsExt {
    fn default() -> Self {
        Self {
            status_until: None,
            status_emoji: "💬".into(),
            online_same_as_last_seen: false,
            app_lock_after: LockAfter::Immediately,
            security_notifications: true,
            ringtone: "Songbird",
            message_tone: "Chirp",
            protect_ip_in_calls: false,
            app_icon: 0,
            lists: vec!["Family".into(), "Work".into(), "Friends".into()],
            broadcasts: vec![Broadcast {
                id: 1,
                name: "Family news".into(),
                members: vec![5, 12, 3],
            }],
            parental: ParentalRules::default(),
            child_view: false,
            links: vec!["songbird.chat".into()],
            account_report: None,
            supervised: false,
        }
    }
}

/// Songbird's own sounds (ringtones and message tones).
pub const RINGTONES: [&str; 6] = [
    "Songbird",
    "Dawn chorus",
    "Robin",
    "Wren",
    "Skylark",
    "Nightingale",
];
pub const MESSAGE_TONES: [&str; 5] = ["Chirp", "Tweet", "Flutter", "Pip", "None"];

/// Settings rows a search matches: by the title, or by any keyword, each
/// word of the query found (case and diacritics of ASCII ignored).
pub fn matches(query: &str, title: &str, keywords: &str) -> bool {
    let hay = format!("{} {}", title, keywords).to_lowercase();
    query
        .split_whitespace()
        .all(|w| hay.contains(&w.to_lowercase()))
}

/// A proxy link's host: `https://songbird.chat/proxy#host:port`, a
/// `songbird://proxy?host=…` link, or a bare host. `None` if it is not one.
pub fn proxy_host(link: &str) -> Option<String> {
    let link = link.trim();
    let host = if let Some(rest) = link.split_once("/proxy#").map(|(_, h)| h) {
        rest
    } else if let Some((_, q)) = link.split_once("proxy?host=") {
        q.split('&').next().unwrap_or_default()
    } else if !link.contains('/') && !link.contains(' ') {
        link
    } else {
        return None;
    };
    let name = host.split(':').next().unwrap_or_default();
    let valid = name.contains('.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    valid.then(|| host.to_lowercase())
}

/// The new place of a list moved by `delta` (−1 up, +1 down), clamped.
pub fn moved(len: usize, at: usize, delta: i32) -> usize {
    (at as i64 + delta as i64).clamp(0, len.saturating_sub(1) as i64) as usize
}

impl Store {
    /// The settings screens' extra state.
    pub fn ext(&self) -> Signal<SettingsExt> {
        global::<SettingsExt>()
    }

    pub fn ext_update(&self, f: impl FnOnce(&mut SettingsExt)) {
        self.ext().update(f);
        crate::backend::records::changed(*self);
    }

    /// Sets the custom status ("In a meeting") with its expiry, and clears
    /// it when that comes. mock: app-core writes the encrypted profile and
    /// sends contacts a "profile changed" signal (Prompt 9).
    pub fn set_status(&self, line: String, emoji: String, expiry: StatusExpiry) {
        let now = NOW;
        let until = expiry.until(now);
        let line = line.trim().to_string();
        self.profile_update(|p| p.status_line = (!line.is_empty()).then(|| line.clone()));
        self.ext_update(|x| {
            x.status_until = until;
            x.status_emoji = emoji;
        });
        if let Some(until) = until {
            // mock: a real expiry runs on the clock; the demo clears after
            // the same number of seconds as minutes, so it can be seen.
            let s = *self;
            let secs = (until - now).max(1) as u64;
            set_timeout(Duration::from_secs(secs), move || {
                if s.ext().with_untracked(|x| x.status_until == Some(until)) {
                    s.clear_status();
                }
            });
        }
    }

    pub fn clear_status(&self) {
        self.profile_update(|p| p.status_line = None);
        self.ext_update(|x| x.status_until = None);
    }

    // ------------------------------------------------------------ server-enforced settings

    /// Applies a server-enforced setting here at once, then on the server
    /// when the account is live; a refusal (a parent's lock, a linked device
    /// loosening) puts the old value back and says why.
    fn server_setting<T: Clone + 'static>(
        &self,
        get: fn(&Settings) -> T,
        set: fn(&mut Settings, T),
        value: T,
        call: impl std::future::Future<Output = Result<(), crate::backend::Problem>> + 'static,
    ) {
        let before = self.settings.with_untracked(get);
        let v = value.clone();
        self.settings_update(|x| set(x, v));
        if crate::backend::is_live() && crate::backend::registered() {
            let s = *self;
            spawn(async move {
                if let Err(p) = call.await {
                    s.settings_update(|x| set(x, before));
                    crate::backend::live().update(|l| l.problem = Some(p.0));
                }
            });
        }
    }

    /// Found by my username, or only through my link and QR code.
    pub fn set_discoverable(&self, on: bool) {
        self.server_setting(
            |x| x.discoverable,
            |x, v| x.discoverable = v,
            on,
            crate::backend::account::set_discoverable(on),
        );
    }

    /// Message requests from everyone, or from nobody.
    pub fn set_message_requests(&self, everyone: bool) {
        self.server_setting(
            |x| x.message_requests,
            |x, v| x.message_requests = v,
            everyone,
            crate::backend::account::set_requests(everyone),
        );
    }

    /// Who can add me to groups. "Nobody" is "My contacts" on the server
    /// (proved by my access key); the app also turns contacts' adds into
    /// invitations I accept.
    pub fn set_groups_add(&self, a: Audience) {
        let contacts = a != Audience::Everyone;
        self.server_setting(
            |x| x.groups_add,
            |x, v| x.groups_add = v,
            a,
            crate::backend::account::set_groups(contacts),
        );
    }

    /// Delete my account after 6, 12 or 24 months unused.
    pub fn set_inactivity(&self, months: u8) {
        self.server_setting(
            |x| x.inactivity_months,
            |x, v| x.inactivity_months = v,
            months,
            crate::backend::account::set_inactivity(months),
        );
    }

    /// Takes the server's copy of its settings (at start, when live).
    pub fn refresh_server_settings(&self) {
        if !(crate::backend::is_live() && crate::backend::registered()) {
            return;
        }
        let s = *self;
        spawn(async move {
            if let Ok(v) = crate::backend::account::get().await {
                s.settings_update(|x| {
                    x.discoverable = v.discoverable;
                    x.message_requests = v.requests_everyone;
                    x.inactivity_months = v.inactivity_months;
                    if !v.groups_contacts {
                        x.groups_add = Audience::Everyone;
                    } else if x.groups_add == Audience::Everyone {
                        x.groups_add = Audience::Contacts;
                    }
                });
                s.ext_update(|x| x.supervised = v.supervised);
            }
        });
    }

    pub fn set_presence(&self, presence: Presence) {
        self.profile_update(|p| p.presence = presence);
    }

    /// Turns nudges off (or back on) from one person. mock: an encrypted
    /// contact record in app-core.
    pub fn set_nudges_off(&self, contact: ContactId, off: bool) {
        self.contacts.update(|cs| {
            if let Some(c) = cs.iter_mut().find(|c| c.id == contact) {
                c.nudges_off = off;
            }
        });
    }

    // ------------------------------------------------------------ chat lists

    pub fn create_list(&self, name: String) -> bool {
        let name = name.trim().to_string();
        if name.is_empty()
            || self
                .ext()
                .with_untracked(|x| x.lists.iter().any(|l| l.eq_ignore_ascii_case(&name)))
        {
            return false;
        }
        self.ext_update(|x| x.lists.push(name));
        true
    }

    pub fn rename_list(&self, from: &str, to: String) -> bool {
        let to = to.trim().to_string();
        if to.is_empty() || to == from {
            return false;
        }
        self.ext_update(|x| {
            if let Some(l) = x.lists.iter_mut().find(|l| *l == from) {
                *l = to.clone();
            }
        });
        self.chats.update(|cs| {
            for c in cs.iter_mut() {
                for l in c.lists.iter_mut() {
                    if l == from {
                        *l = to.clone();
                    }
                }
            }
        });
        true
    }

    pub fn delete_list(&self, name: &str) {
        self.ext_update(|x| x.lists.retain(|l| l != name));
        self.chats.update(|cs| {
            for c in cs.iter_mut() {
                c.lists.retain(|l| l != name);
            }
        });
    }

    pub fn move_list(&self, name: &str, delta: i32) {
        self.ext_update(|x| {
            if let Some(at) = x.lists.iter().position(|l| l == name) {
                let to = moved(x.lists.len(), at, delta);
                let item = x.lists.remove(at);
                x.lists.insert(to, item);
            }
        });
    }

    /// How many chats a list holds.
    pub fn list_count(&self, name: &str) -> usize {
        self.chats.with(|cs| {
            cs.iter()
                .filter(|c| c.lists.iter().any(|l| l == name))
                .count()
        })
    }

    // ------------------------------------------------------------ chats in bulk

    /// Archives every chat. mock: an encrypted chat-state record each.
    pub fn archive_all(&self) {
        let ids: Vec<ChatId> = self
            .chats
            .with(|cs| cs.iter().filter(|c| !c.archived).map(|c| c.id).collect());
        for id in ids {
            self.toggle_archive(id);
        }
    }

    /// Clears the messages of every chat on this device.
    pub fn clear_all(&self) {
        let ids: Vec<ChatId> = self.chats.with(|cs| cs.iter().map(|c| c.id).collect());
        for id in ids {
            self.clear_chat(id);
        }
    }

    pub fn create_broadcast(&self, name: String, members: Vec<ContactId>) {
        let id = self.id();
        self.ext_update(|x| x.broadcasts.push(Broadcast { id, name, members }));
    }

    pub fn delete_broadcast(&self, id: u64) {
        self.ext_update(|x| x.broadcasts.retain(|b| b.id != id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_times() {
        // Now is 10:24.
        assert_eq!(StatusExpiry::Hour.until(0), Some(60));
        assert_eq!(StatusExpiry::Today.until(0), Some(13 * 60 + 36));
        assert_eq!(StatusExpiry::Never.until(0), None);
        assert_eq!(until_label(StatusExpiry::Hour.until(0), 0), "Until 11:24");
        assert_eq!(
            until_label(StatusExpiry::Today.until(0), 0),
            "Until midnight"
        );
        assert_eq!(
            until_label(StatusExpiry::Week.until(0), 0),
            "Until Sunday night"
        );
        assert_eq!(until_label(None, 0), "Until you clear it");
        // 4 hours from 22:00 is tomorrow.
        let late = 11 * 60 + 36;
        assert_eq!(
            until_label(StatusExpiry::FourHours.until(late), late),
            "Until tomorrow 02:00"
        );
    }

    #[test]
    fn search_matches_titles_and_keywords() {
        assert!(matches(
            "read",
            "Privacy",
            "last seen read receipts blocked"
        ));
        assert!(matches("DARK", "Appearance", "theme dark light"));
        assert!(matches("last seen", "Privacy", "last seen"));
        assert!(!matches("wallpaper", "Privacy", "last seen"));
        assert!(matches("", "Anything", ""));
    }

    #[test]
    fn proxy_links() {
        assert_eq!(
            proxy_host("https://songbird.chat/proxy#relay.example.org:443").as_deref(),
            Some("relay.example.org:443")
        );
        assert_eq!(
            proxy_host("songbird://proxy?host=Relay.Example.org&x=1").as_deref(),
            Some("relay.example.org")
        );
        assert_eq!(
            proxy_host("relay.example.org").as_deref(),
            Some("relay.example.org")
        );
        assert_eq!(proxy_host("not a link"), None);
        assert_eq!(proxy_host("localhost"), None);
        assert_eq!(proxy_host("https://example.org/page"), None);
    }

    #[test]
    fn moving_lists_clamps() {
        assert_eq!(moved(3, 0, -1), 0);
        assert_eq!(moved(3, 0, 1), 1);
        assert_eq!(moved(3, 2, 1), 2);
        assert_eq!(moved(0, 0, 1), 0);
    }
}
