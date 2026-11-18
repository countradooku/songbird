//! The Floating design's two surfaces (`REDESIGN.md`): **panes**, the
//! inset rounded cards the desktop window holds (list, conversation,
//! info), and **capsules**, the chat header and the composer floating over
//! a conversation. Each skin draws them in its own language; features use
//! these and never style a pane or capsule of their own.
//!
//! The signatures are the contract between the shell, the chat list and
//! the conversation: change the look inside, keep the API.
//!
//! Geometry, in points (every value on the 4pt grid but the platform's
//! own control heights):
//!
//! ```text
//!  canvas ┌──────────────────────────────────────────────────────────┐
//!         │ ● ● ●            (macOS: the traffic lights, MARGIN in)   │
//!         │ ┌ list 340 ┐ GAP ┌ conversation ─────────┐ GAP ┌ info 320┐│
//!  MARGIN │ │ header   │     │ ( header capsule )    │     │         ││
//!         │ │ ...      │     │                       │     │         ││
//!         │ │ dest bar │     │ ( composer capsule )  │     │         ││
//!         │ └──────────┘     └───────────────────────┘     └─────────┘│
//!         └──────────────────────────────────────────────────────────┘
//! ```
//!
//! The list pane's header row and the conversation's header capsule share
//! one band: [`CAPSULE_INSET`] from the pane's top, [`capsule_height`]
//! tall. Both titles centre on that band, so the two pane tops read as
//! one line.

use nsh_core::{element::StyleRefinement, prelude::*};

use super::parts::hairline;
use super::skin::{Skin, skin, spec};
use super::tokens::c;

/// The window's canvas behind the panes.
pub fn canvas() -> AdaptiveColor {
    c::canvas()
}

/// A pane's surface: the page colour, so anything built for a page (a
/// tab's root, a pushed page) sits in a pane with no seam.
pub fn pane_bg() -> AdaptiveColor {
    c::pane()
}

/// A pane's corner radius, per skin (`SkinSpec::radius.pane`: Apple 16,
/// Material 24, Fluent 8, Adwaita 12).
pub fn pane_radius() -> f32 {
    spec().radius.pane
}

/// The window's outer margin and the gap between panes.
pub const MARGIN: f32 = 12.0;
pub const GAP: f32 = 10.0;

/// The list pane's width.
pub const LIST_W: f32 = 340.0;

/// The info pane's width (chat and group info, beside the conversation).
pub const INFO_W: f32 = 320.0;

/// The narrowest a conversation pane gets: a readable column of bubbles
/// (72% of it for a bubble) with the header capsule's title and actions.
pub const CONVERSATION_MIN_W: f32 = 400.0;

/// The window is wide enough for the info pane beside the conversation;
/// narrower, chat info opens over the conversation in its own pane.
/// Reading subscribes to the window's width.
pub fn fits_info_pane() -> bool {
    let need = 2.0 * MARGIN + LIST_W + 2.0 * GAP + INFO_W + CONVERSATION_MIN_W;
    super::parts::wide() && window().width >= px(need)
}

/// How far a capsule floats in from its pane's edges (the header capsule
/// from the top, the list pane's header row likewise). With each skin's
/// capsule height the band ends on the platform's header height: Apple
/// 8 + 44 = 52, Material 8 + 48 = 56, Fluent 8 + 40 = 48.
pub const CAPSULE_INSET: f32 = 8.0;

/// The panes' top edge in the window: the margin, or on macOS (where the
/// traffic lights sit on the canvas over a hidden title bar) the title
/// bar's height, which the shell sets to the margin above the lights, the
/// lights, and the same margin under them. Reading subscribes (full
/// screen gives the bar back to the system and this falls to the margin).
pub fn pane_top() -> f32 {
    let bar = nsh_core::element::desktop::title_bar().top.0;
    if bar > 0.0 { bar.max(MARGIN) } else { MARGIN }
}

/// The header band of a pane: from its top edge to the bottom of the
/// floating header capsule (or of the list pane's header row).
pub fn header_band() -> f32 {
    CAPSULE_INSET + capsule_height()
}

/// A pane: the surface, its radius, its edge and clipping. The canvas is
/// quiet enough that a hairline carries the edge; only Apple adds a very
/// soft shadow (its windows' surfaces float on the desktop the same way).
/// Material separates by tone alone.
pub fn pane_style(st: StyleRefinement) -> StyleRefinement {
    let st = st
        .bg(move || c::pane())
        .rounded(px(pane_radius()))
        .overflow_hidden();
    match skin() {
        Skin::Apple => st
            .border(hairline())
            .border_color(move || c::pane_border())
            .shadow_sm()
            .shadow_color(c::foreground().opacity(0.05)),
        Skin::Fluent | Skin::Adwaita => {
            st.border(hairline()).border_color(move || c::pane_border())
        }
        Skin::Material => st,
    }
}

/// A view styled as a pane, for the caller to size and fill.
pub fn pane() -> View {
    view().style_when(|| true, pane_style)
}

/// A capsule's height on this platform (the header and the composer's
/// resting height).
pub fn capsule_height() -> f32 {
    match skin() {
        Skin::Apple => 44.0,
        Skin::Material => 48.0,
        Skin::Fluent => 40.0,
        Skin::Adwaita => 42.0,
    }
}

/// A capsule floating over a conversation: fully rounded, glass on Apple
/// (the fill is what shows where the system has no Liquid Glass), the
/// skin's raised surface elsewhere: Material's surface-container-high by
/// tone alone, Fluent's layer and Adwaita's card with a hairline.
pub fn capsule_style(st: StyleRefinement) -> StyleRefinement {
    let st = st.rounded_full();
    match skin() {
        Skin::Apple => st
            .bg(move || c::capsule().opacity(0.72))
            .border(hairline())
            .border_color(move || c::capsule_border())
            .shadow_sm()
            .shadow_color(c::foreground().opacity(0.06)),
        Skin::Material => st.bg(move || c::capsule()),
        Skin::Fluent | Skin::Adwaita => st
            .bg(move || c::capsule())
            .border(hairline())
            .border_color(move || c::capsule_border()),
    }
}

/// Wraps `child` as a floating capsule (Apple adds the system's glass).
pub fn capsule(child: impl IntoElement) -> View {
    let v = view().style_when(|| true, capsule_style).child(child);
    if skin() == Skin::Apple {
        v.glass_effect(nsh_core::GlassEffect::Regular)
            .glass_tint_color(Some(c::capsule().opacity(0.35)))
    } else {
        v
    }
}

/// A header's group of actions on a capsule (the large-title header, a
/// list pane's header): the buttons in a row, 2pt in from the capsule's
/// ends so their own rounded hover sits inside its curve.
pub fn action_capsule(actions: impl IntoElement) -> View {
    capsule(view().flex_row().items_center().px(px(2.0)).child(actions))
}
