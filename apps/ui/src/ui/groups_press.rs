//! Pressable surfaces for content the `Row` builder cannot hold (rows whose
//! text follows data in a virtual list, chips with an avatar, action
//! tiles, the media viewer's light-on-dark controls). One press, hover and
//! focus treatment per kind, from the tokens.

use nsh_base::button;
use nsh_core::prelude::*;

use super::{
    parts::row_wash,
    skin::{PressStyle, spec},
    tokens::{c, motion},
};

/// What a pressable surface is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Press {
    /// A list row: the wash fills the row (no scale, as rows do).
    Row,
    /// An action tile or a round photo button: wash and a press scale.
    Tile,
    /// A chip: fades on hover, fills on press.
    Chip,
    /// A control on the dark media stage (`call-bg`): light ink, fades on
    /// hover, scales on press.
    OnDark,
}

/// A button with the app's feedback for `kind`. Give it a label
/// (`accessibility_label`) when its content is not text.
pub fn press_surface(kind: Press, on_press: impl Fn() + 'static) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    let press = spec().press;
    // Scales are Apple's and Songbird's: Material, Fluent and Adwaita
    // tiles answer with their state layer or fill alone.
    let scales = !reduced && press == PressStyle::Highlight;
    let b = button()
        .on_press(on_press)
        .cursor_pointer()
        .transition()
        .duration(motion::INSTANT)
        .ease_bezier(
            motion::SETTLE.0,
            motion::SETTLE.1,
            motion::SETTLE.2,
            motion::SETTLE.3,
        )
        .disabled_style(|s| s.opacity(0.4));
    match kind {
        Press::Row => b
            .hover(move |s| s.bg(move || row_wash(press, false)))
            .active(move |s| s.bg(move || row_wash(press, true)))
            .focus_visible(|s| s.bg(move || c::accent())),
        Press::Tile => b
            .hover(|s| s.bg(move || c::accent()))
            .active(move |s| {
                let s = s.bg(move || c::accent());
                if scales {
                    s.scale(motion::PRESS_SCALE)
                } else {
                    s
                }
            })
            .focus_visible(|s| {
                s.outline(px(2.0))
                    .outline_offset(px(2.0))
                    .outline_color(move || c::ring())
            }),
        Press::Chip => b
            .hover(|s| s.opacity(0.85))
            .active(|s| s.bg(move || c::accent()))
            .focus_visible(|s| s.outline(px(2.0)).outline_color(move || c::ring())),
        Press::OnDark => b
            .text_color(move || c::on_call())
            .hover(|s| s.opacity(0.8))
            .active(move |s| {
                let s = s.opacity(0.7);
                if reduced {
                    s
                } else {
                    s.scale(motion::ICON_PRESS_SCALE)
                }
            })
            .focus_visible(|s| {
                s.outline(px(2.0))
                    .outline_offset(px(2.0))
                    .outline_color(move || c::on_call())
            }),
    }
}
