//! Songbird's tokens on top of `theme.json`: the custom colour roles as
//! functions (so a misspelt token is one place to fix), the radius tiers,
//! the type scale, spacing and motion. Feature code reads these, never
//! raw values.

use nsh_base::theme;
use nsh_core::prelude::*;

/// A custom colour role from `theme.json`. A missing token shows as the
/// destructive colour so it is caught in review instead of hiding.
fn role(name: &str) -> AdaptiveColor {
    theme().color(name).unwrap_or(theme().destructive)
}

/// Named colour roles the default shadcn set does not have.
pub mod c {
    use super::role;
    use nsh_base::theme;
    use nsh_core::prelude::AdaptiveColor;

    pub fn background() -> AdaptiveColor { theme().background }
    pub fn foreground() -> AdaptiveColor { theme().foreground }
    pub fn card() -> AdaptiveColor { theme().card }
    pub fn popover() -> AdaptiveColor { theme().popover }
    pub fn primary() -> AdaptiveColor { theme().primary }
    pub fn on_primary() -> AdaptiveColor { theme().primary_foreground }
    pub fn secondary() -> AdaptiveColor { theme().secondary }
    pub fn on_secondary() -> AdaptiveColor { theme().secondary_foreground }
    pub fn muted() -> AdaptiveColor { theme().muted }
    pub fn muted_fg() -> AdaptiveColor { theme().muted_foreground }
    pub fn accent() -> AdaptiveColor { theme().accent }
    pub fn on_accent() -> AdaptiveColor { theme().accent_foreground }
    pub fn destructive() -> AdaptiveColor { theme().destructive }
    pub fn on_destructive() -> AdaptiveColor { role("destructive-foreground") }
    pub fn border() -> AdaptiveColor { theme().border }
    pub fn input() -> AdaptiveColor { theme().input }
    pub fn ring() -> AdaptiveColor { theme().ring }
    pub fn sidebar() -> AdaptiveColor { theme().sidebar }
    pub fn sidebar_accent() -> AdaptiveColor { theme().sidebar_accent }

    pub fn chat_bg() -> AdaptiveColor { role("chat-bg") }
    pub fn bubble_out() -> AdaptiveColor { role("bubble-out") }
    pub fn on_bubble_out() -> AdaptiveColor { role("bubble-out-foreground") }
    pub fn bubble_in() -> AdaptiveColor { role("bubble-in") }
    pub fn on_bubble_in() -> AdaptiveColor { role("bubble-in-foreground") }
    pub fn bubble_meta() -> AdaptiveColor { role("bubble-meta") }
    pub fn tick_read() -> AdaptiveColor { role("tick-read") }
    pub fn link() -> AdaptiveColor { role("link") }
    pub fn success() -> AdaptiveColor { role("success") }
    pub fn on_success() -> AdaptiveColor { role("success-foreground") }
    pub fn warning() -> AdaptiveColor { role("warning") }
    pub fn warning_bg() -> AdaptiveColor { role("warning-bg") }
    pub fn danger_bg() -> AdaptiveColor { role("danger-bg") }
    pub fn info_bg() -> AdaptiveColor { role("info-bg") }
    pub fn online() -> AdaptiveColor { role("online") }
    pub fn call_accept() -> AdaptiveColor { role("call-accept") }
    pub fn call_decline() -> AdaptiveColor { role("call-decline") }
    pub fn call_bg() -> AdaptiveColor { role("call-bg") }
    pub fn on_call() -> AdaptiveColor { role("call-foreground") }
    pub fn overlay() -> AdaptiveColor { role("overlay") }
    pub fn mention() -> AdaptiveColor { role("mention") }
    pub fn whatsapp() -> AdaptiveColor { role("whatsapp") }
    pub fn highlight() -> AdaptiveColor { role("highlight") }
    /// A switch's knob: near-white in both themes.
    pub fn switch_thumb() -> AdaptiveColor { role("switch-thumb") }
    /// A switch's off track: a light fill, outlined in `input`.
    pub fn switch_track() -> AdaptiveColor { role("switch-track") }
    /// A switch's on track (a deeper violet than `primary` in dark, so the
    /// light knob keeps 3:1 on it).
    pub fn switch_on() -> AdaptiveColor { role("switch-on") }
    /// A raised surface on a recessed one: the selected segment.
    pub fn raised() -> AdaptiveColor { role("raised") }
    /// The secondary button's fill: distinct from cards, sheets and popovers.
    pub fn control() -> AdaptiveColor { role("control") }
    /// Initials on the avatar hues: white in both themes (large text).
    pub fn on_avatar() -> AdaptiveColor { role("avatar-foreground") }

    /// One of the eight avatar hues; `seed` is data (a contact's id).
    pub fn avatar(seed: u64) -> AdaptiveColor {
        let names = [
            "avatar-1", "avatar-2", "avatar-3", "avatar-4", "avatar-5", "avatar-6", "avatar-7",
            "avatar-8",
        ];
        role(names[(seed % 8) as usize])
    }
}

/// Radius tiers: the skin's (`ui::skin`), which `theming` also writes
/// into the theme's `radius*` tokens for `nsh_base`'s own popups.
pub mod radius {
    use nsh_core::prelude::*;

    use crate::ui::skin::spec;

    /// Controls and popups.
    pub fn control() -> Points { px(spec().radius.control) }
    /// Tags, small chips, inner fills.
    pub fn sm() -> Points { px(spec().radius.small) }
    /// Cards and grouped lists.
    pub fn lg() -> Points { px(spec().radius.card) }
    /// Chat bubbles.
    pub fn bubble() -> Points { px(spec().radius.bubble) }
    /// Sheets' top corners.
    pub fn sheet() -> Points { px(spec().radius.sheet) }
}

/// The type scale, in points. Phones get a step up for body text (16pt
/// minimum, as the guides ask); desktops stay compact.
pub mod font {
    use nsh_core::prelude::*;

    pub const CAPTION: f32 = 12.0;
    pub const SMALL: f32 = 13.0;
    pub const BODY_DESKTOP: f32 = 14.0;
    pub const BODY_MOBILE: f32 = 16.0;
    pub const TITLE: f32 = 17.0;
    pub const HEADING: f32 = 20.0;
    pub const DISPLAY: f32 = 28.0;

    /// Body text for the current platform family.
    pub fn body() -> f32 {
        if is_desktop() { BODY_DESKTOP } else { BODY_MOBILE }
    }
}

/// Motion tokens (ms). Calm: nothing over 360ms, leaving faster than
/// entering, and every use checks [`reduced`].
pub mod motion {
    pub const INSTANT: f32 = 120.0;
    pub const FAST: f32 = 180.0;
    pub const BASE: f32 = 240.0;
    pub const SLOW: f32 = 360.0;
    pub const PRESS_SCALE: f32 = 0.97;
    pub const ICON_PRESS_SCALE: f32 = 0.94;
    /// The soft settle curve for presses.
    pub const SETTLE: (f32, f32, f32, f32) = (0.22, 1.0, 0.36, 1.0);

    /// Whether the user asked for reduced motion.
    pub fn reduced() -> bool {
        nsh_core::prelude::reduce_motion()
    }
}

/// Minimum touch target on phones (iOS 44pt, Android 48dp: we use 48).
pub const TOUCH: f32 = 48.0;
