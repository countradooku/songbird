//! Pinned people: the chats the user pinned, as large avatars above the
//! list (`REDESIGN.md`, "People before lists"). Two rows of four at most;
//! each opens its chat on a press and has the row's menu (right click,
//! held finger).
//!
//! The grid is eight fixed slots, each bound to a position in the pinned
//! list: a pin, an unpin or a reorder rebinds the slots instead of
//! rebuilding the grid, as the virtual list does for rows.

use nsh_base::button;
use nsh_core::prelude::*;

use super::{model::*, row, surface};
use crate::{features, nav, store::Store, ui::*};

/// Columns in the grid.
const COLUMNS: usize = 4;

/// The avatar's side: 52pt on desktops, 48pt on phones.
fn avatar_side() -> f32 {
    if is_desktop() { 52.0 } else { 48.0 }
}

/// The unread ring: 2pt wide, 2pt clear of the avatar. The ring's box is
/// the avatar plus both on each side, and the avatar is centred in it, so
/// ring and avatar share one centre at every size.
const RING: f32 = 2.0;
const RING_GAP: f32 = 2.0;

fn ring_side() -> f32 {
    avatar_side() + 2.0 * (RING + RING_GAP)
}

/// The count pill with its 2pt cut-out of the surface: 20pt high, 24pt
/// with the cut-out.
const PILL_BOX: f32 = 24.0;

/// Where the count pill's box starts, from the ring box's top left: its
/// centre on the ring at half past one (45° from the top, towards the
/// trailing side), so it overlaps the ring a little and never floats off
/// it. Longer counts grow towards the trailing edge from there.
fn pill_origin() -> (f32, f32) {
    let r = ring_side() / 2.0;
    let k = std::f32::consts::FRAC_1_SQRT_2;
    let (cx, cy) = (r + r * k, r - r * k);
    ((cx - PILL_BOX / 2.0).round(), (cy - PILL_BOX / 2.0).round())
}

/// The name under an avatar: a person's first name, a group's name
/// without emoji words; one line, cut with an ellipsis.
fn short_name(r: &ChatRow) -> String {
    if r.group {
        letters(&r.title)
    } else {
        first_name(&r.title)
    }
}

/// The grid, hidden while nothing is pinned. Its frame spans the same
/// 16pt gutters as the search field, the Lists capsule and the rows'
/// avatar column; its columns are equal, 4pt apart.
pub fn grid(s: Store, pinned: Memo<Vec<ChatRow>>) -> View {
    let line = |at: usize| {
        view()
            .flex_row()
            .gap_1()
            .children((0..COLUMNS).map(move |col| slot(s, pinned, at * COLUMNS + col)))
    };
    view()
        .px(px(row::GUTTER))
        .pt_1()
        .pb_2()
        .gap_1()
        .style_when(move || pinned.with(Vec::is_empty), |st| st.hidden())
        .child(line(0))
        .child(line(1).style_when(
            move || pinned.with(|p| p.len() <= COLUMNS),
            |st| st.hidden(),
        ))
}

/// The slot at `at`: an equal column, empty when fewer chats are pinned
/// (so the columns keep their width on a short row).
fn slot(s: Store, pinned: Memo<Vec<ChatRow>>, at: usize) -> View {
    let item = computed(move || pinned.with(|p| p.get(at).cloned()));
    view().flex_1().min_w(px(0.0)).child(when(
        move || item.with(Option::is_some),
        move || {
            let row = computed(move || item.get().unwrap_or_default());
            person(s, row)
        },
    ))
}

/// One pinned person: the avatar in its ring, the name under it.
fn person(s: Store, row: Memo<ChatRow>) -> impl IntoElement {
    let desktop_layout = wide();
    let open = nav::open_chat();
    let selected = move || desktop_layout && open.with(|o| o.0) == Some(row.with(|r| r.id));
    let unread = move || row.with(ChatRow::is_unread);
    let loud = move || row.with(|r| r.is_unread() && !r.muted);
    let (pill_x, pill_y) = pill_origin();

    let ring = view()
        .size(px(ring_side()))
        .rounded_full()
        .items_center()
        .justify_center()
        .border(px(RING))
        // Unread: the accent ring. Muted and unread: a neutral one. Read:
        // none (the ring's box stays, so nothing moves when it appears).
        .border_color(move || match (unread(), loud()) {
            (false, _) => AdaptiveColor::TRANSPARENT,
            (true, true) => c::primary(),
            (true, false) => c::muted_fg(),
        })
        .transition_colors()
        .duration(motion::BASE)
        .child(row::live_avatar(row, avatar_side(), surface()))
        .child(
            view()
                .absolute()
                .left(px(pill_x))
                .top(px(pill_y))
                .p(px(2.0))
                .rounded_full()
                .bg(move || surface()())
                .style_when(move || row.with(|r| r.unread <= 1), |st| st.hidden())
                .child(unread_badge(
                    move || row.with(|r| r.unread),
                    move || row.with(|r| r.muted),
                )),
        );

    let name = text(move || row.with(short_name))
        .w_full()
        .number_of_lines(1)
        .text_center()
        .text_size(px(font::CAPTION))
        .line_height(px(16.0))
        .font_weight(FontWeight::NORMAL)
        .style_when(loud, |st| st.font_weight(FontWeight::SEMIBOLD))
        .text_color(move || c::foreground());

    let trigger = button()
        .on_press(move || features::chat::open(row.with_untracked(|r| r.id)))
        .accessibility_label(move || Some(SharedString::from(row.with(|r| r.spoken()))))
        .selected(selected)
        .w_full()
        .items_center()
        .gap_1()
        .px_1()
        .py_2()
        .rounded(move || radius::control())
        .cursor_pointer()
        .bg(move || {
            if selected() {
                c::accent()
            } else {
                AdaptiveColor::TRANSPARENT
            }
        })
        .transition_colors()
        .duration(motion::INSTANT)
        .hover(move |st| st.bg(move || if selected() { c::accent() } else { c::muted() }))
        .active(|st| st.bg(move || c::accent()))
        // Not in a clipped group: the app's focus ring, not a wash.
        .focus_visible(|st| st.outline(px(2.0)).outline_color(move || c::ring()))
        .child(ring)
        .child(name);

    row::with_menu(s, row, ListScope::Inbox, trigger)
}
