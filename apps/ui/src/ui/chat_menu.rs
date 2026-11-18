//! The app's menu: `nsh_base`'s menu (a popup at the trigger on desktops,
//! a sheet on phones; keyboard, Escape and back built in) drawn from
//! tokens. Added for the conversation's "More" menu; any screen with an
//! overflow menu can use it.

use nsh_base::{menu, menu_item, menu_separator};
use nsh_core::{element::StyleRefinement, prelude::*};

use super::{
    icons::{Icon, icon},
    skin::{PressStyle, spec},
    tokens::{c, font, motion, radius},
};

/// The popup surface: popover colour, border, shadow; it grows in from
/// 0.97 and fades (desktops), leaving faster.
fn surface(s: StyleRefinement) -> StyleRefinement {
    let s = s
        .min_w(px(220.0))
        .p_1()
        .rounded(radius::lg())
        .border_1()
        .border_color(c::border())
        .bg(c::popover())
        .shadow_lg();
    if motion::reduced() {
        s
    } else {
        s.transition_all().duration(motion::FAST).ease_out()
    }
}

fn starting(s: StyleRefinement) -> StyleRefinement {
    if motion::reduced() {
        s.opacity(0.0)
    } else {
        s.opacity(0.0).scale(0.97).translate_y(px(-6.0))
    }
}

/// A menu opened by `trigger` (an icon-sized pressable this makes, with
/// `label` for screen readers).
pub fn app_menu(glyph: Icon, label: &'static str, items: Vec<AnyElement>) -> AnyElement {
    let reduced = motion::reduced();
    let side = if is_desktop() { 32.0 } else { 44.0 };
    let sp = spec();
    let press = sp.press;
    menu()
        .offset(px(4.0))
        .popup_style(surface)
        .popup_starting_style(starting)
        .popup_ending_style(starting)
        .backdrop_style(|s| s.bg(c::overlay()))
        .trigger(
            view()
                .label(label)
                .role(AccessibilityRole::Button)
                .size(px(side))
                .items_center()
                .justify_center()
                .rounded(px(sp.radius.icon_button))
                .text_color(move || c::foreground())
                .cursor_pointer()
                // Android draws its own ripple on this (a plain view).
                .when(press == PressStyle::Ripple, |v| {
                    v.ripple(nsh_core::Ripple {
                        borderless: true,
                        ..Default::default()
                    })
                })
                .transition()
                .duration(motion::FAST)
                .hover(|s| s.bg(move || c::accent()))
                .active(move |s| {
                    let s = s.bg(move || c::accent());
                    if reduced || press != PressStyle::Highlight {
                        s
                    } else {
                        s.scale(motion::ICON_PRESS_SCALE)
                    }
                })
                .focus_visible(|s| s.outline(px(2.0)).outline_color(move || c::ring()))
                .child(icon(glyph, if is_desktop() { 18.0 } else { 22.0 })),
        )
        .children(items)
        .into_element()
}

/// One item: an icon and a label; `danger` items are red (and come last,
/// after a [`menu_rule`]).
pub fn menu_entry(
    glyph: Icon,
    label: impl Into<SharedString>,
    danger: bool,
    on_select: impl Fn() + 'static,
) -> AnyElement {
    let label: SharedString = label.into();
    let ink = move || {
        if danger {
            c::destructive()
        } else {
            c::foreground()
        }
    };
    menu_item()
        .on_select(on_select)
        .accessibility_label(label.clone())
        .flex_row()
        .items_center()
        .gap_3()
        .px_3()
        .min_h(px(if is_desktop() { 34.0 } else { 48.0 }))
        .rounded(move || radius::control())
        .hover(|s| s.bg(move || c::accent()))
        .active(|s| s.bg(move || c::accent()))
        .focus(|s| s.bg(move || c::accent()))
        .child(icon(glyph, 18.0).text_color(ink))
        .child(text(label).text_size(px(font::body())).text_color(ink))
        .into_element()
}

/// A rule between groups of items.
pub fn menu_rule() -> AnyElement {
    // A hairline, inset like the items' text so it reads as a group break.
    let hairline = 1.0 / pixel_ratio().max(1.0);
    menu_separator()
        .h(px(hairline))
        .my_1()
        .mx_3()
        .bg(move || c::border())
        .into_element()
}

/// A bare pressable area (a bubble's quote, a poll option, a tile): the
/// button role, keyboard focus with the ring, the pointer, and a press
/// that dims. The caller draws what is inside.
pub fn pressable() -> nsh_base::ButtonElement {
    nsh_base::button()
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .active(|s| s.opacity(0.7))
        .focus_visible(|s| {
            s.outline(px(2.0))
                .outline_offset(px(1.0))
                .outline_color(move || c::ring())
        })
        .disabled_style(|s| s.opacity(0.45))
}
