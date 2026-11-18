//! Pieces the extras screens added to the `ui` layer: an external link,
//! a bullet line, a key cap for shortcuts, a QR code and a plan card
//! surface. Built from tokens only, like the rest of `ui`.

use nsh_base::{button, theme};
use nsh_core::prelude::*;

use super::{
    icons::{Icon, icon},
    tokens::{c, font, motion, radius},
};

/// An external link (a web page the system browser opens): underlined, the
/// `link` colour, role Link. Only for URLs, never for in-app actions.
pub fn link(label: impl Into<SharedString>, url: &'static str) -> nsh_base::ButtonElement {
    let label: SharedString = label.into();
    button()
        .on_press(move || {
            let _ = open_url(url);
        })
        .role(AccessibilityRole::Link)
        .accessibility_label(label.clone())
        .self_start()
        .cursor_pointer()
        .rounded(move || radius::sm())
        .transition_opacity()
        .duration(motion::INSTANT)
        .hover(|s| s.opacity(0.8))
        .active(|s| s.opacity(0.6))
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(
            text(label)
                .text_size(px(font::body()))
                .underline()
                .text_color(move || c::link()),
        )
}

/// A line of a list with a leading glyph: what a plan includes, what
/// WhatsApp can see. `glyph` sets meaning by shape (check, minus, eye).
pub fn bullet(glyph: Icon, tint: fn() -> AdaptiveColor, label: impl IntoReactive<SharedString>) -> View {
    view()
        .flex_row()
        .items_start()
        .gap_2()
        .child(
            icon(glyph, 16.0)
                .mt(px(2.0))
                .text_color(move || tint())
                .accessibility_elements_hidden(true),
        )
        .child(
            text(label)
                .flex_1()
                .text_size(px(font::SMALL + 1.0))
                .line_height(px(20.0)),
        )
}

/// A keyboard key as menus show it ("⌘K", "Ctrl+K"), in the mono face.
/// One fixed height and a minimum width, so caps of one key line up as a
/// column down a list.
pub fn key_cap(label: impl IntoReactive<SharedString>) -> View {
    cap(label, font::CAPTION)
}

/// Whether a cap shows one of the symbol glyphs (⌘ ⇧ ⌃ ⌥ ⇥ ↩ …), which the
/// mono face draws at about 60% of a letter's height.
fn is_glyph(k: &str) -> bool {
    let mut chars = k.chars();
    matches!((chars.next(), chars.next()), (Some(c), None) if "⌘⇧⌃⌥⇥↩⏎⌫⌦⎋↑↓←→⇞⇟↖↘".contains(c))
}

/// A key cap whose label is sized `size`: glyph caps are drawn larger, so
/// "⌘" stands as tall as "K" beside it.
fn cap(label: impl IntoReactive<SharedString>, size: f32) -> View {
    view()
        .h(px(22.0))
        .px(px(6.0))
        .min_w(px(22.0))
        .items_center()
        .justify_center()
        .rounded(move || radius::sm())
        .bg(move || c::secondary())
        .border_1()
        .border_color(move || c::border())
        .role(AccessibilityRole::KeyboardKey)
        .child(
            text(label)
                .text_size(px(size))
                .font_weight(FontWeight::MEDIUM)
                .font_family(move || theme().font_mono.clone().unwrap_or_else(|| "monospace".into()))
                .text_color(move || c::foreground()),
        )
}

/// The keys of a shown keystroke, one cap each: "Ctrl+Shift+Tab" splits
/// at `+`; Apple's "⇧⌘U" peels its modifier symbols off the key.
pub fn key_parts(shown: &str) -> Vec<String> {
    if shown.len() > 1 && shown.contains('+') && !shown.ends_with("++") {
        return shown.split('+').filter(|p| !p.is_empty()).map(String::from).collect();
    }
    let mut parts = Vec::new();
    let mut rest = shown;
    while let Some(c) = rest.chars().next().filter(|c| "⌃⌥⇧⌘".contains(*c)) {
        if rest.len() == c.len_utf8() {
            break;
        }
        parts.push(c.to_string());
        rest = &rest[c.len_utf8()..];
    }
    if !rest.is_empty() {
        parts.push(rest.to_string());
    }
    parts
}

/// A keystroke as separate caps with a hair of space between them; read
/// as one label by screen readers.
pub fn key_combo(shown: &str) -> View {
    view()
        .flex_row()
        .items_center()
        .gap_1()
        .role(AccessibilityRole::Text)
        .label(shown.to_string())
        .children(key_parts(shown).into_iter().map(|k| {
            let size = if is_glyph(&k) { font::CAPTION + 4.0 } else { font::CAPTION };
            cap(k, size).accessibility_elements_hidden(true)
        }))
}


/// A selectable card: a plan, a provider. `selected` draws the primary
/// ring (and the caller says it in words too).
pub fn select_card(selected: impl Fn() -> bool + Copy + 'static) -> View {
    view()
        .rounded(move || radius::lg())
        .bg(move || c::card())
        .border_1()
        .border_color(move || if selected() { c::primary() } else { c::border() })
        .transition_colors()
        .duration(motion::BASE)
        .p_4()
        .gap_2()
}


#[cfg(test)]
mod key_tests {
    use super::key_parts;

    #[test]
    fn keystrokes_split_into_caps() {
        assert_eq!(key_parts("⌘K"), ["⌘", "K"]);
        assert_eq!(key_parts("⌃⇧⇥"), ["⌃", "⇧", "⇥"]);
        assert_eq!(key_parts("Ctrl+Shift+Tab"), ["Ctrl", "Shift", "Tab"]);
        assert_eq!(key_parts("⌘"), ["⌘"]);
        assert_eq!(key_parts("Esc"), ["Esc"]);
        assert_eq!(key_parts("Ctrl++"), ["Ctrl++"]);
    }
}
