//! Extra state and intents for invites, plans, support, WhatsApp chats
//! and the desktop (A12, A13, A15). `Store` is shared, so this state lives
//! in one surface global (`Extras`) and is changed only through the
//! `impl Store` intents below.
//!
//! **Mock.** Purchases, invites, support requests and WhatsApp linking
//! are app-core calls that do not exist yet; each intent says which.

use std::time::Duration;

use nsh_core::{prelude::*, storage::Storage};

use super::{Plan, Store};

/// Storage key: the user hid the tray / menu bar icon.
const TRAY_HIDDEN_KEY: &str = "tray-hidden";

/// Monthly or yearly billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Billing {
    #[default]
    Monthly,
    Yearly,
}

/// One invite code of the user's. Only whether it was used is known to
/// the UI; who used it is never shown (the server does not tell us either).
#[derive(Debug, Clone, PartialEq)]
pub struct InviteCode {
    pub code: String,
    pub used: bool,
}

/// A seat of a Family plan.
#[derive(Debug, Clone, PartialEq)]
pub struct FamilySeat {
    pub id: u64,
    pub name: String,
    /// Invited, not joined yet.
    pub pending: bool,
}

/// How the WhatsApp link stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhatsAppLink {
    #[default]
    Idle,
    /// Waiting for the code to be entered (or the QR scanned) on the phone.
    Pairing,
}

/// The extras' state, one per surface.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Extras {
    /// Show WhatsApp chats in their own filter instead of in All chats.
    pub whatsapp_separate: bool,
    pub whatsapp_link: WhatsAppLink,
    pub billing: Billing,
    /// The paid plan ends at the end of the period instead of renewing.
    pub cancels_at_period_end: bool,
    pub family: Vec<FamilySeat>,
    /// The tray / menu bar icon is hidden by the user.
    pub tray_hidden: bool,
    /// Support requests sent this session (mock).
    pub support_sent: u32,
    /// Purchase in progress (the store sheet is busy).
    pub purchasing: bool,
}

/// The extras' global.
pub fn extras() -> Signal<Extras> {
    global::<Extras>()
}

/// The user's invite code number `i`: 24 Crockford base32 symbols in six
/// groups of four, as the server issues them (proto
/// `registration::invite`). Pure, deterministic per seed.
pub fn invite_code(seed: u64, i: u32) -> String {
    use super::ext_onboarding::{INVITE_GROUP, INVITE_LEN};
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(u64::from(i).wrapping_mul(1_442_695_040_888_963_407))
        ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = String::new();
    for n in 0..INVITE_LEN {
        if n > 0 && n % INVITE_GROUP == 0 {
            out.push('-');
        }
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 29;
        out.push(ALPHABET[(x % ALPHABET.len() as u64) as usize] as char);
    }
    out
}

/// The personal invite link: opens a chat with the user after signup.
pub fn personal_link(username: &str) -> String {
    format!(
        "https://songbird.chat/i/{}",
        username.trim_start_matches('@').to_lowercase()
    )
}

const ANNOUNCEMENT_KEY: &str = "announcement-dismissed";

impl Store {
    // ------------------------------------------------------------ invites

    /// The user's invite codes, used ones first. The counts come from the
    /// session (`invites_used`, `invites_left`).
    /// mock: app-core `invites.list()`.
    pub fn invite_codes(&self) -> Vec<InviteCode> {
        let (used, left) = self.session.with(|s| (s.invites_used, s.invites_left));
        let seed = self.me.with(|m| m.seed);
        (0..used + left)
            .map(|i| InviteCode {
                code: invite_code(seed, i),
                used: i < used,
            })
            .collect()
    }

    // ------------------------------------------------------------ plans

    /// The current plan.
    pub fn plan(&self) -> Plan {
        self.settings.with(|s| s.plan)
    }

    /// Buys `plan` through the platform's store. The sheet shows as busy
    /// for a moment, as a store's confirmation does.
    /// mock: app-core `billing.purchase(plan, period)` after StoreKit /
    /// Play Billing / the EU provider confirms; the server grants it.
    pub fn purchase(&self, plan: Plan, billing: Billing, done: impl FnOnce() + 'static) {
        let s = *self;
        extras().update(|e| e.purchasing = true);
        set_timeout(Duration::from_millis(900), move || {
            s.settings_update(|x| x.plan = plan);
            extras().update(|e| {
                e.purchasing = false;
                e.billing = billing;
                e.cancels_at_period_end = false;
                if plan == Plan::Family && e.family.is_empty() {
                    e.family = vec![FamilySeat {
                        id: 1,
                        name: "Ana Popescu".into(),
                        pending: false,
                    }];
                }
            });
            done();
        });
    }

    /// Asks the store for purchases made on another device. Returns
    /// whether one was found.
    /// mock: app-core `billing.restore()`; nothing to restore here.
    pub fn restore_purchases(&self) -> bool {
        self.plan() != Plan::Free
    }

    /// Turns off renewal: the plan stays until the end of the period.
    /// mock: on iOS and Android this happens in the store's own page;
    /// app-core `billing.cancel()` for the EU provider.
    pub fn cancel_renewal(&self) {
        extras().update(|e| e.cancels_at_period_end = true);
    }

    pub fn resume_renewal(&self) {
        extras().update(|e| e.cancels_at_period_end = false);
    }

    /// Invites someone to the Family plan (up to six people in all).
    /// mock: app-core `billing.family_invite()` returns a link.
    pub fn family_invite(&self, name: String) {
        let id = nsh_core::time::unix_ms() as u64;
        extras().update(|e| {
            if e.family.len() < 5 {
                e.family.push(FamilySeat {
                    id,
                    name,
                    pending: true,
                });
            }
        });
    }

    pub fn family_remove(&self, id: u64) {
        extras().update(|e| e.family.retain(|m| m.id != id));
    }

    // ------------------------------------------------------------ support

    /// Sends a support request. Logs are attached only when the user said
    /// so, and only the scrubbed form they previewed.
    /// mock: app-core `support.send(topic, message, logs)`; nothing leaves
    /// the device here.
    pub fn send_support(&self, topic: &str, message: &str, include_logs: bool) {
        let _ = (topic, message, include_logs);
        extras().update(|e| e.support_sent += 1);
    }

    // ------------------------------------------------------------ announcement

    /// Whether the announcement `id` was dismissed (kept across runs).
    pub fn announcement_dismissed(&self, id: &str) -> bool {
        Storage::get_item(ANNOUNCEMENT_KEY).is_some_and(|v| v == id)
    }

    pub fn dismiss_announcement(&self, id: &str) {
        if let Err(e) = Storage::set_item(ANNOUNCEMENT_KEY, id) {
            log::warn!("{e}");
        }
    }

    // ------------------------------------------------------------ WhatsApp

    pub fn whatsapp_linked(&self) -> bool {
        self.settings.with(|s| s.whatsapp_linked)
    }

    /// Starts linking: a pairing code and QR show until the phone accepts.
    /// mock: app-core `bridge.whatsapp.begin_link()`; the phone "accepts"
    /// after a few seconds.
    pub fn begin_whatsapp_link(&self, done: impl FnOnce() + 'static) {
        let s = *self;
        extras().update(|e| e.whatsapp_link = WhatsAppLink::Pairing);
        set_timeout(Duration::from_millis(3500), move || {
            if extras().with_untracked(|e| e.whatsapp_link == WhatsAppLink::Pairing) {
                s.settings_update(|x| x.whatsapp_linked = true);
                extras().update(|e| e.whatsapp_link = WhatsAppLink::Idle);
                done();
            }
        });
    }

    pub fn cancel_whatsapp_link(&self) {
        extras().update(|e| e.whatsapp_link = WhatsAppLink::Idle);
    }

    /// Unlinks at once: the bridge session is deleted and WhatsApp chats
    /// stop syncing.
    /// mock: app-core `bridge.whatsapp.unlink()`.
    pub fn unlink_whatsapp(&self) {
        self.settings_update(|x| x.whatsapp_linked = false);
    }

    /// Whether WhatsApp chats show in All chats (else in their own filter).
    pub fn whatsapp_in_all(&self) -> bool {
        !extras().with(|e| e.whatsapp_separate)
    }

    pub fn set_whatsapp_separate(&self, separate: bool) {
        extras().update(|e| e.whatsapp_separate = separate);
    }

    // ------------------------------------------------------------ desktop

    /// The user's own "Open at login" switch: the system's login item
    /// (NSH 0.6: `SMAppService` on macOS, the Run key on Windows, an XDG
    /// autostart entry on Linux). Shown at once; put back, with a toast, if
    /// the system refuses. On macOS the system may then wait for the user's
    /// approval in Login Items.
    pub fn set_launch_at_login(&self, on: bool) {
        self.settings_update(|x| x.launch_at_login = on);
        let s = *self;
        spawn(async move {
            if nsh_core::element::desktop::set_launch_at_login(on)
                .await
                .is_err()
            {
                s.settings_update(|x| x.launch_at_login = !on);
                crate::ui::toast(if on {
                    "Songbird could not be set to open at login"
                } else {
                    "Songbird could not be removed from login items"
                });
            }
        });
    }

    /// Reads the login item as the system has it now (the user may change
    /// it in the system's settings): call when the switch shows.
    pub fn refresh_launch_at_login(&self) {
        let s = *self;
        spawn(async move {
            let on = nsh_core::element::desktop::launch_at_login().await;
            s.settings_update(|x| x.launch_at_login = on);
        });
    }

    /// Shows or hides the tray / menu bar icon. While it shows, closing the
    /// window keeps Songbird running there (D-0098). Remembered.
    pub fn set_tray_hidden(&self, hidden: bool) {
        extras().update(|e| e.tray_hidden = hidden);
        if hidden {
            if let Err(e) = Storage::set_item(TRAY_HIDDEN_KEY, "1") {
                log::warn!("tray choice not saved: {e}");
            }
        } else {
            Storage::remove_item(TRAY_HIDDEN_KEY);
        }
    }

    /// The tray choice saved by an earlier run.
    pub fn restore_tray_choice(&self) {
        let hidden = Storage::get_item(TRAY_HIDDEN_KEY).is_some();
        extras().update(|e| e.tray_hidden = hidden);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_codes_are_stable_and_readable() {
        let a = invite_code(42, 0);
        assert_eq!(a, invite_code(42, 0));
        assert_ne!(a, invite_code(42, 1));
        assert_eq!(a.len(), "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX".len());
        // What the invite step accepts, unchanged by its cleaning.
        let clean = super::super::ext_onboarding::normalize_invite(&a);
        assert_eq!(super::super::ext_onboarding::format_invite(&clean), a);
        for ch in clean.chars() {
            assert!(!"ILOU".contains(ch), "{a} is not Crockford");
        }
    }

    #[test]
    fn personal_link_is_lowercase_without_at() {
        assert_eq!(personal_link("@Radu"), "https://songbird.chat/i/radu");
    }
}
