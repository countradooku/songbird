//! Controls the settings screens need that the core set lacks: a radio
//! row for one-of-many choices, a colour swatch, a square tile (emoji,
//! app icons), a pill with a leading shape (presence), a "Learn more"
//! expander, a highlighted call-out card and a decorative QR code. Built
//! once here, from tokens, with their states and motion.

use nsh_base::{button, collapsible};
use nsh_core::prelude::*;

use super::{
    icons::{Icon, icon},
    parts::icon_tile,
    tokens::{c, font, motion, radius},
};

fn row_height() -> f32 {
    if is_desktop() { 44.0 } else { 56.0 }
}

/// One option of a one-of-many choice: a title, an optional line under
/// it, and a filled check circle when chosen (shape, not colour alone).
pub fn radio_row(
    title: impl Into<SharedString>,
    subtitle: Option<&'static str>,
    selected: impl Fn() -> bool + Copy + 'static,
    on_press: impl Fn() + 'static,
) -> AnyElement {
    let title: SharedString = title.into();
    let reduced = motion::reduced();
    button()
        .on_press(on_press)
        .role(AccessibilityRole::Radio)
        .selected(selected)
        .accessibility_label(title.clone())
        .cursor_pointer()
        .transition_colors()
        .duration(motion::INSTANT)
        .hover(|s| s.bg(move || c::accent()))
        .active(|s| s.bg(move || c::accent()))
        .focus_visible(|s| s.bg(move || c::accent()))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_4()
                .py_2()
                .min_h(px(row_height()))
                .child(
                    view()
                        .flex_1()
                        .gap(px(2.0))
                        .child(text(title).text_size(px(font::body())))
                        .child(subtitle.map(|s| {
                            text(s)
                                .text_size(px(font::SMALL))
                                .line_height(px(18.0))
                                .text_color(move || c::muted_fg())
                        })),
                )
                .child(
                    view()
                        .size(px(22.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .border_2()
                        .border_color(move || if selected() { c::primary() } else { c::input() })
                        .bg(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT })
                        .text_color(move || c::on_primary())
                        .when(!reduced, |v| v.transition_colors().duration(motion::FAST))
                        .child(
                            icon(Icon::Check, 14.0)
                                .opacity(move || if selected() { 1.0_f32 } else { 0.0 })
                                .when(!reduced, |v| v.transition_opacity().duration(motion::FAST)),
                        ),
                ),
        )
        .into_element()
}

/// A round colour swatch; the chosen one gets a ring and a check.
pub fn swatch(
    label: impl Into<SharedString>,
    fill: impl Fn() -> AdaptiveColor + Copy + 'static,
    selected: impl Fn() -> bool + Copy + 'static,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    let side = if is_desktop() { 36.0 } else { 44.0 };
    button()
        .on_press(on_press)
        .selected(selected)
        .role(AccessibilityRole::Radio)
        .accessibility_label(label.into())
        .size(px(side + 6.0))
        .items_center()
        .justify_center()
        .rounded_full()
        .border_2()
        .border_color(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT })
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .active(move |s| if reduced { s.opacity(0.85) } else { s.scale(motion::ICON_PRESS_SCALE) })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(
            view()
                .size(px(side))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(fill)
                .border_1()
                .border_color(move || c::border())
                .text_color(move || c::foreground())
                .child(
                    view()
                        .size(px(20.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || c::card())
                        .text_color(move || c::primary())
                        .opacity(move || if selected() { 1.0_f32 } else { 0.0 })
                        .when(!reduced, |v| v.transition_opacity().duration(motion::FAST))
                        .child(icon(Icon::Check, 13.0)),
                ),
        )
}

/// A square tile holding `content` (an emoji, an app icon). Selected
/// tiles take the primary border.
pub fn tile(
    label: impl Into<SharedString>,
    size: f32,
    selected: impl Fn() -> bool + Copy + 'static,
    on_press: impl Fn() + 'static,
    content: impl IntoElement,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    button()
        .on_press(on_press)
        .selected(selected)
        .accessibility_label(label.into())
        .size(px(size))
        .items_center()
        .justify_center()
        .rounded(move || radius::control())
        .bg(move || c::secondary())
        .border_2()
        .border_color(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT })
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .hover(|s| s.bg(move || c::accent()))
        .active(move |s| {
            let s = s.bg(move || c::accent());
            if reduced { s } else { s.scale(motion::PRESS_SCALE) }
        })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(content)
}

/// A selectable pill with a leading mark (a presence shape) and a label.
pub fn option_pill(
    label: &'static str,
    leading: impl IntoElement,
    selected: impl Fn() -> bool + Copy + 'static,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    button()
        .on_press(on_press)
        .selected(selected)
        .role(AccessibilityRole::Radio)
        .accessibility_label(label)
        .flex_row()
        .items_center()
        .gap_1()
        // BtnSize::Sm's height: pills and the small buttons beside them line up.
        .h(px(if is_desktop() { 28.0 } else { 36.0 }))
        .px(px(10.0))
        .rounded_full()
        .bg(move || if selected() { c::accent() } else { c::secondary() })
        .border_1()
        .border_color(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT })
        .cursor_pointer()
        .transition()
        .duration(motion::INSTANT)
        .hover(|s| s.opacity(0.85))
        .active(move |s| if reduced { s.opacity(0.8) } else { s.scale(motion::PRESS_SCALE) })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(leading)
        .child(
            text(label)
                .text_size(px(if is_desktop() { font::SMALL } else { font::SMALL + 1.0 }))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || if selected() { c::on_accent() } else { c::foreground() }),
        )
}

/// A "Learn more" disclosure: a quiet trigger whose chevron turns, and
/// text revealed under it with a clipped height (no reveal with reduced
/// motion).
pub fn expander(trigger: impl Into<SharedString>, body: impl Into<SharedString>) -> AnyElement {
    let trigger: SharedString = trigger.into();
    let open = signal(false);
    let reduced = motion::reduced();
    collapsible()
        .open(move || open.get())
        .reveal(!reduced)
        .content(
            text(body.into())
                .pt_1()
                .text_size(px(font::SMALL))
                .line_height(px(18.0))
                .text_color(move || c::muted_fg()),
        )
        .child(
            view()
                .on_press(move || open.update(|o| *o = !*o))
                .role(AccessibilityRole::Button)
                .focusable(true)
                .label(trigger.clone())
                .accessibility_state(move || AccessibilityState { expanded: Some(open.get()), ..Default::default() })
                .self_start()
                .flex_row()
                .items_center()
                .gap_1()
                .py_1()
                .cursor_pointer()
                .hover(|s| s.opacity(0.8))
                .focus_visible(|s| s.outline(px(2.0)).outline_color(move || c::ring()))
                .text_color(move || c::link())
                .child(text(trigger).text_size(px(font::SMALL)).font_weight(FontWeight::MEDIUM))
                .child(
                    icon(Icon::ChevronDown, 14.0)
                        .rotate(move || if open.get() { deg(180.0) } else { deg(0.0) })
                        .when(!reduced, |v| v.transition_transform().duration(motion::BASE)),
                ),
        )
        .into_element()
}

/// A highlighted call-out card (the "What Songbird can see" entry): an
/// icon tile, a title, one sentence, and pressable as a whole.
pub fn callout(glyph: Icon, title: &'static str, message: &'static str, on_press: impl Fn() + 'static) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    button()
        .on_press(on_press)
        .accessibility_label(title)
        .mx_4()
        .flex_row()
        .items_center()
        .gap_3()
        // The rows' insets and tile, so the title sits on their text spine.
        .px_4()
        .py_3()
        .rounded(move || radius::lg())
        .bg(move || c::info_bg())
        .border(super::parts::hairline())
        .border_color(move || c::border())
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .hover(|s| s.opacity(0.92))
        .active(move |s| if reduced { s.opacity(0.85) } else { s.scale(0.99) })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(icon_tile(glyph).bg(move || c::card()))
        .child(
            view()
                .flex_1()
                .min_w(px(0.0))
                .gap(px(2.0))
                .child(text(title).text_size(px(font::body())).font_weight(FontWeight::SEMIBOLD))
                .child(
                    text(message)
                        .text_size(px(font::SMALL))
                        .line_height(px(18.0))
                        .text_color(move || c::muted_fg()),
                ),
        )
        .child(icon(Icon::ChevronRight, 18.0).text_color(move || c::muted_fg()))
}
