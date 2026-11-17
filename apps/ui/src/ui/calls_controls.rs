//! The call screens' controls: round buttons on the dark call surface
//! (mute, camera, end, accept, decline) and a quiet pill for secondary
//! call actions. Shape and colour both carry meaning: accept is a green
//! circle with a phone, decline and end a red circle with the phone-off
//! glyph, and a toggled control fills light with dark ink.

use nsh_base::{SheetEvent, button, sheet};
use nsh_core::{PointerEvents, prelude::*};

use super::{
    icons::{Icon, icon},
    parts::{hairline, wide},
    tokens::{c, font, motion, radius},
};

/// What a call control means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallTone {
    /// A toggle or action on the call surface.
    Neutral,
    /// Answer (green).
    Accept,
    /// Decline or hang up (red).
    Decline,
}

/// A round call control. `glyph` and `label` may change (mute ↔
/// unmute); `on` fills a toggle that is on. `size` is the circle's side.
/// With `caption`, the label shows under the circle (phones, ringing).
pub fn call_btn(
    glyph: impl Fn() -> Icon + Copy + 'static,
    label: impl Fn() -> SharedString + Copy + 'static,
    tone: CallTone,
    on: impl Fn() -> bool + Copy + 'static,
    size: f32,
    caption: bool,
    on_press: impl Fn() + 'static,
) -> View {
    let reduced = motion::reduced();
    let fill = move || match tone {
        CallTone::Accept => c::call_accept(),
        CallTone::Decline => c::call_decline(),
        CallTone::Neutral if on() => c::on_call(),
        CallTone::Neutral => c::on_call().opacity(0.16),
    };
    let ink = move || match tone {
        CallTone::Neutral if on() => c::call_bg(),
        _ => c::on_call(),
    };
    let circle = button()
        .on_press(on_press)
        .accessibility_label(move || Some(label()))
        .selected(move || tone == CallTone::Neutral && on())
        .size(px(size))
        .rounded_full()
        .items_center()
        .justify_center()
        .bg(fill)
        .text_color(ink)
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .ease_bezier(motion::SETTLE.0, motion::SETTLE.1, motion::SETTLE.2, motion::SETTLE.3)
        .hover(|s| s.opacity(0.88))
        .active(move |s| {
            let s = s.opacity(0.8);
            if reduced { s } else { s.scale(motion::ICON_PRESS_SCALE) }
        })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(3.0)).outline_color(move || c::on_call()))
        .child(dynamic(move || icon(glyph(), (size * 0.42).round())));
    view()
        .items_center()
        .gap(px(6.0))
        .child(circle)
        .child(caption.then(|| {
            text(move || label())
                .text_size(px(font::CAPTION))
                .font_weight(FontWeight::MEDIUM)
                .text_center()
                .number_of_lines(1)
                .text_color(move || c::on_call().opacity(0.86))
                .accessibility_elements_hidden(true)
        }))
}

/// A quiet pill on the call surface ("Minimise", "Participants"). As tall
/// as the round buttons beside it: 36pt on desktops, 40pt on phones.
pub fn call_pill(
    glyph: Icon,
    label: impl Into<SharedString>,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    let label: SharedString = label.into();
    button()
        .on_press(on_press)
        .accessibility_label(label.clone())
        .h(px(if is_desktop() { 36.0 } else { 40.0 }))
        .px_3()
        .flex_row()
        .items_center()
        .gap_2()
        .rounded_full()
        .bg(move || c::on_call().opacity(0.12))
        .text_color(move || c::on_call())
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .hover(|s| s.bg(move || c::on_call().opacity(0.2)))
        .active(move |s| {
            let s = s.bg(move || c::on_call().opacity(0.24));
            if reduced { s } else { s.scale(motion::PRESS_SCALE) }
        })
        .focus_visible(|s| s.outline(px(2.0)).outline_color(move || c::on_call()))
        .child(icon(glyph, 16.0))
        .child(
            text(label)
                .text_size(px(font::SMALL))
                .font_weight(FontWeight::MEDIUM)
                .number_of_lines(1),
        )
}

// ---------------------------------------------------------------- call sheets

/// The call controls' height under the stage on wide windows (56pt
/// circles, 12pt over and 20pt under): call sheets centre above it.
const CONTROLS_H: f32 = 96.0;

/// A sheet over the call: the call's own dark surface and light ink in
/// both themes (a light panel on the dark stage glares), a bottom sheet on
/// phones, a panel centred on the call's stage, above its controls, on
/// wide windows. `left` is where the stage starts (the rail's edge).
pub fn call_sheet(
    open: Signal<bool>,
    title: impl Into<SharedString>,
    left: f32,
    content: impl IntoElement + 'static,
) -> nsh_base::SheetElement {
    let title: SharedString = title.into();
    let content = std::cell::RefCell::new(Some(content.into_element()));
    let panel = wide();
    sheet()
        .open(move || Some(open.get()))
        .backdrop_style(|s| s.bg(c::call_bg().opacity(0.55)))
        .when(panel, |sh| {
            sh.popup_style(move |s| {
                s.top_0()
                    .items_center()
                    .justify_center()
                    .pt_6()
                    .pr_6()
                    .pl(px(left + 24.0))
                    .pb(px(CONTROLS_H))
                    .pointer_events(PointerEvents::BoxNone)
            })
        })
        .on_open_change(move |e: &SheetEvent| {
            if let SheetEvent::OpenChange(next, _) = e {
                open.set(*next);
            }
        })
        .child(
            view()
                .bg(move || c::call_bg())
                .rounded_t(move || radius::sheet())
                .overflow_hidden()
                .border(hairline())
                .border_color(move || c::on_call().opacity(0.16))
                .shadow_lg()
                .text_color(move || c::on_call())
                .when(panel, |v| v.rounded(move || radius::sheet()).w(px(440.0)))
                .child(
                    // A lift over the stage: the call's ink at a whisper.
                    view()
                        .bg(move || c::on_call().opacity(0.05))
                        .when(panel, |v| v.pt_2().pb_4())
                        .when(!panel, |v| v.pb_safe_area_plus(px(16.0)))
                        .child((!panel).then(|| {
                            view()
                                .items_center()
                                .pt(px(6.0))
                                .child(view().w(px(36.0)).h(px(5.0)).rounded_full().bg(move || c::on_call().opacity(0.3)))
                        }))
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .pl_4()
                                .pr_2()
                                .pt(px(if panel { 4.0 } else { 2.0 }))
                                .pb_2()
                                .gap_2()
                                .child(
                                    text(title)
                                        .flex_1()
                                        .number_of_lines(2)
                                        .text_size(px(font::TITLE))
                                        .line_height(px(22.0))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .role(AccessibilityRole::Header),
                                )
                                .child(call_icon_btn(Icon::Close, "Close", move || open.set(false))),
                        )
                        .child(content.borrow_mut().take()),
                ),
        )
}

/// A 44pt icon button in the call's ink.
pub fn call_icon_btn(glyph: Icon, label: impl Into<SharedString>, on_press: impl Fn() + 'static) -> nsh_base::ButtonElement {
    let label: SharedString = label.into();
    button()
        .on_press(on_press)
        .accessibility_label(label)
        .size(px(44.0))
        .rounded_full()
        .items_center()
        .justify_center()
        .text_color(move || c::on_call())
        .cursor_pointer()
        .transition_colors()
        .duration(motion::INSTANT)
        .hover(|s| s.bg(move || c::on_call().opacity(0.1)))
        .active(|s| s.bg(move || c::on_call().opacity(0.16)))
        .focus_visible(|s| s.outline(px(2.0)).outline_color(move || c::on_call()))
        .child(icon(glyph, 20.0))
}

/// A section heading on a call sheet.
pub fn call_section(label: impl IntoReactive<SharedString>) -> Text {
    text(label)
        .px_4()
        .pt_4()
        .pb_2()
        .text_size(px(font::SMALL))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(move || c::on_call().opacity(0.62))
        .role(AccessibilityRole::Header)
}

/// A footnote on a call sheet.
pub fn call_note(label: impl IntoReactive<SharedString>) -> Text {
    text(label)
        .px_4()
        .pt_3()
        .text_size(px(font::SMALL))
        .line_height(px(18.0))
        .text_color(move || c::on_call().opacity(0.62))
}

/// Rows grouped on a call sheet: a card a step lighter than the sheet,
/// rules between rows on the text column.
pub fn call_group(rows: impl IntoIterator<Item = AnyElement>) -> View {
    let mut out = view()
        .mx_4()
        .rounded(move || radius::lg())
        .overflow_hidden()
        .bg(move || c::on_call().opacity(0.07));
    for (i, row) in rows.into_iter().enumerate() {
        if i > 0 {
            out = out.child(view().ml(px(52.0)).h(hairline()).bg(move || c::on_call().opacity(0.12)));
        }
        out = out.child(row);
    }
    out
}

/// A row on a call sheet: an optional leading element (a glyph or an
/// avatar), a title and a subtitle, an optional trailing element; it
/// presses when `on_press` is given.
pub fn call_row(
    leading: Option<AnyElement>,
    title: impl Into<SharedString>,
    subtitle: Option<SharedString>,
    trailing: Option<AnyElement>,
    on_press: Option<Box<dyn Fn()>>,
) -> AnyElement {
    let title: SharedString = title.into();
    let body = view()
        .flex_row()
        .items_center()
        .gap_3()
        .px_4()
        .min_h(px(48.0))
        .py_2()
        .child(leading.map(|l| view().w(px(24.0)).items_center().child(l).text_color(move || c::on_call().opacity(0.85))))
        .child(
            view()
                .flex_1()
                .min_w(px(0.0))
                .gap(px(2.0))
                .child(text(title.clone()).text_size(px(font::body())).number_of_lines(1))
                .child(subtitle.map(|st| text(st).text_size(px(font::SMALL)).line_height(px(18.0)).text_color(move || c::on_call().opacity(0.62)))),
        )
        .child(trailing);
    match on_press {
        Some(f) => button()
            .on_press(move || f())
            .accessibility_label(title)
            .cursor_pointer()
            .transition_colors()
            .duration(motion::INSTANT)
            .hover(|s| s.bg(move || c::on_call().opacity(0.06)))
            .active(|s| s.bg(move || c::on_call().opacity(0.1)))
            .focus_visible(|s| s.bg(move || c::on_call().opacity(0.1)))
            .child(body)
            .into_element(),
        None => body.into_element(),
    }
}
