//! The Lists capsule (All and the user's lists, as one segmented control
//! whose selection slides) and the Unread toggle beside the search field.
//! They replace the filter chips (`REDESIGN.md`, "Removed WhatsApp
//! patterns").
//!
//! The capsule is built here, not with `ui::segmented`: its segments are
//! the user's own lists (owned strings, any number), so it scrolls instead
//! of sharing the width, and its selection is `nsh_base::tabs`'s native
//! indicator, which springs to the chosen segment (at once with reduced
//! motion) and gives the arrow-key behaviour of a tab list.

use nsh_base::{button, tab, tabs};
use nsh_core::prelude::*;

use super::{ChatFilter, animate_change, filter, list_names, model::Filter, pages, surface};
use crate::{store::Store, ui::*};

/// A segment's height; the track adds 4pt around it, so the capsule is
/// 36pt on desktops and 40pt on phones, on the 4pt grid.
fn segment_height() -> f32 {
    if is_desktop() { 28.0 } else { 32.0 }
}

/// The capsule's outer height (the "manage lists" button matches it).
fn track_height() -> f32 {
    segment_height() + 8.0
}

/// The capsule's label size: the row preview's size, so the list keeps to
/// three text sizes.
fn label_size() -> f32 {
    if is_desktop() { font::SMALL } else { font::BODY_DESKTOP }
}

/// Apple and Material draw segmented controls as capsules; Fluent and
/// Adwaita in their control corners (as `ui::segmented` does).
fn round() -> bool {
    matches!(skin(), Skin::Apple | Skin::Material)
}

/// Picks `which`, keeping the Unread toggle as it is.
fn show(which: Filter) {
    let f = filter();
    if f.with_untracked(|x| x.list != which) {
        animate_change();
        f.update(|x| x.list = which);
    }
}

/// What the capsule offers, in order: All, WhatsApp while those chats are
/// kept apart, the user's lists, and the menu's view while it is chosen
/// (so the capsule always shows what the list is showing).
fn segments(s: Store) -> Vec<Filter> {
    let mut out = vec![Filter::All];
    if s.whatsapp_linked() && !s.whatsapp_in_all() {
        out.push(Filter::WhatsApp);
    }
    out.extend(list_names(s).into_iter().map(Filter::List));
    let chosen = filter().with(|x| x.list.clone());
    if chosen.from_menu() {
        out.push(chosen);
    }
    out
}

/// One segment: its label, and the tab's selected state for screen
/// readers and the indicator.
fn segment(which: Filter) -> impl IntoElement {
    let f = filter();
    let label = which.label();
    let held = stored(which);
    let selected = move || f.with(|x| held.with(|w| x.list == *w));
    let material = skin() == Skin::Material;
    tab()
        .selected(selected)
        .on_press(move |_: &()| show(held.get()))
        .accessibility_label(label.clone())
        .h(px(segment_height()))
        .px_3()
        .flex_row()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .child(
            text(label)
                .number_of_lines(1)
                .text_size(px(label_size()))
                // One weight for every segment: a bolder selected label
                // would change its width and make the indicator jump as it
                // lands. Ink says which one is chosen; the indicator says it
                // again in shape.
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || match (selected(), material) {
                    (true, true) => c::on_accent(),
                    (true, false) => c::foreground(),
                    _ => c::muted_fg(),
                })
                .transition_colors()
                .duration(motion::BASE),
        )
}

/// The Lists capsule, scrolling sideways with an edge fade when the lists
/// outgrow the pane; it never wraps. A + after it manages the lists.
pub fn lists_capsule(s: Store) -> View {
    let material = skin() == Skin::Material;
    let track = tabs()
        .accessibility_label("Lists")
        .flex_row()
        .items_center()
        .p_1()
        .flex_shrink(0.0)
        .bg(move || c::secondary())
        .when(round(), |t| t.rounded_full())
        .when(!round(), |t| t.rounded(move || radius::control()))
        // Behind the labels, sliding between them: the raised segment of
        // the platform's segmented control (Material: its secondary
        // container, flat).
        .indicator_style(move |st| {
            let st = st.top_1().bottom_1();
            let st = if round() { st.rounded_full() } else { st.rounded(radius::sm()) };
            if material {
                st.bg(c::accent())
            } else {
                st.bg(c::raised()).border_1().border_color(c::border()).shadow_sm()
            }
        })
        .child(each(move || segments(s), |w: &Filter| w.clone(), |w, _| segment(w.get_untracked())));

    let manage = button()
        .on_press(pages::open_lists)
        .accessibility_label("Manage chat lists")
        .size(px(track_height()))
        .flex_shrink(0.0)
        .rounded_full()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .bg(move || c::secondary())
        .text_color(move || c::muted_fg())
        .transition_colors()
        .duration(motion::INSTANT)
        .hover(|st| st.text_color(move || c::foreground()))
        .active(|st| st.opacity(0.7))
        .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(icon(Icon::Plus, 16.0));

    view()
        .w_full()
        .flex_grow(0.0)
        .overflow_hidden()
        .child(
            scroll().horizontal().scrollbar(false).w_full().child(
                view()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .pl(px(super::row::GUTTER))
                    // Past the fade, so the last segment scrolls clear of it.
                    .pr(px(EDGE_FADE + 8.0))
                    .pt_1()
                    .pb_2()
                    .child(track)
                    .child(manage),
            ),
        )
        .child(edge_fade(surface()))
}

/// The Unread toggle beside the search field: the filter glyph, in the
/// accent ink when on. It applies over whichever list is chosen.
pub fn unread_toggle() -> nsh_base::ButtonElement {
    let f = filter();
    let on = move || f.with(|x: &ChatFilter| x.unread);
    let side = if is_desktop() { 32.0 } else { 44.0 };
    button()
        .on_press(move || {
            // The rows that leave fade and the rest glide together: the
            // list cross-fades instead of jumping (nothing with reduced
            // motion, `animate_change`).
            animate_change();
            f.update(|x| x.unread = !x.unread);
        })
        .accessibility_label("Unread")
        .selected(on)
        .size(px(side))
        .flex_shrink(0.0)
        .rounded_full()
        .items_center()
        .justify_center()
        .cursor_pointer()
        // Off: the search field's own fill, so the two read as one row.
        // On: the selection wash.
        .bg(move || if on() { c::accent() } else { c::secondary() })
        .transition_colors()
        .duration(motion::FAST)
        .hover(|st| st.opacity(0.85))
        .active(|st| st.opacity(0.7))
        .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        // The filter glyph, as Mail's Unread filter: an empty ring read as
        // a radio button. Muted off, the accent ink on the selection wash on.
        .child(
            icon(Icon::Filter, 16.0)
                .text_color(move || if on() { c::primary() } else { c::muted_fg() })
                .transition_colors()
                .duration(motion::FAST),
        )
}
