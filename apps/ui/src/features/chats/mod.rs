//! A5: the chat list — filters, pin, mute, archive, row menus, unread
//! counts, message requests, locked chats, local search, new chat.
//!
//! - `model`: what the lists show, as plain data (unit-tested).
//! - `row`: one chat row and its menu (right-click or long-press).
//! - `search`: the results that replace the list while searching.
//! - `pages`: Archived, Message requests, Locked chats, Chat lists.
//! - `new_chat`: the New chat page and what it leads to.

mod model;
mod new_chat;
mod pages;
mod row;
mod search;

use nsh_base::menu;
use nsh_core::{LayoutAnimation, LayoutCurve, LayoutTransition, prelude::*};

use crate::{
    features,
    store::{Store, store},
    ui::*,
};

pub use model::Filter;
use model::ListScope;

// ---------------------------------------------------------------- state

/// The filter chip chosen above the list (kept while the window switches
/// between the phone and desktop layouts).
#[derive(Default, Clone, PartialEq)]
pub struct ChatFilter(pub Filter);

fn filter() -> Signal<ChatFilter> {
    global::<ChatFilter>()
}

/// Every custom list name, in the user's order.
fn list_names(s: Store) -> Vec<String> {
    // The order is the user's (Settings → Lists owns it, `Store::ext`).
    let order = s.ext().with(|x| x.lists.clone());
    s.chats.with(|cs| model::list_names(&order, cs))
}

/// Animates the list's next layout change when it is the user's doing
/// (pin, archive, delete, accept); nothing with reduced motion.
fn animate_change() {
    if !motion::reduced() {
        animate_layout(LayoutAnimation::all(LayoutTransition::new(
            LayoutCurve::EaseInEaseOut,
            motion::BASE,
        )));
    }
}

// ---------------------------------------------------------------- tab

/// The Chats tab (phone) or the list pane (desktop).
pub fn chats_tab() -> AnyElement {
    let s = store();
    let query = signal(String::new());
    let searching = move || query.with(|q| !q.trim().is_empty());
    let desktop = wide();
    view()
        .flex_1()
        .bg(move || c::background())
        .child(app_header("Chats", false, Some(header_actions(desktop).into_element())))
        .child(when(
            move || s.session.with(|x| x.offline),
            || {
                view().px_4().pt_2().child(banner(
                    Tone::Warning,
                    Icon::WifiOff,
                    "You're offline. Messages you send will go out when you're back online.",
                ))
            },
        ))
        .child(
            view()
                .px_4()
                .pt_2()
                .pb_1()
                .child(search_field("Search chats and messages", query)),
        )
        // ⌘K / ⌘F (desktop shortcuts) bring the Chats tab forward; the
        // search field is the first thing there.
        .child({
            let focus = global::<features::desktop::SearchFocus>();
            let seen = stored(focus.get_untracked().0);
            effect(move || {
                let n = focus.get().0;
                if seen.replace(n) != n {
                    crate::nav::tab().set(crate::nav::Tab::Chats);
                }
            });
            view()
        })
        // The list stays mounted while searching, so it keeps its place.
        .child(
            view()
                .flex_1()
                .style_when(searching, |st| st.hidden())
                // Full width and clipped, so the last chip fades under the
                // edge fade instead of being cut.
                .child(view().w_full().flex_grow(0.0).overflow_hidden().child(chips(s)).child(edge_fade(c::background)))
                .child(inbox(s)),
        )
        .child(when(searching, move || search::results(s, query)))
        // The floating button where the platform has one (Material); the
        // others put New chat in the header (skin: `ui::spec().fab`).
        .child((!desktop && spec().fab).then(|| {
            view()
                .absolute()
                .right(px(16.0))
                .bottom(px(16.0))
                .child(fab(Icon::Plus, "New chat", new_chat))
        }))
        .into_element()
}

/// The header's actions: New chat (desktop, and phones whose platform has
/// no floating button) and the list menu.
fn header_actions(desktop: bool) -> View {
    let s = store();
    let item = |glyph: Icon, label: &'static str, f: fn()| {
        row::menu_row(glyph, move || label.to_string(), false).on_select(move || f())
    };
    view()
        .flex_row()
        .items_center()
        .gap_1()
        .child((desktop || !spec().fab).then(|| icon_btn(spec().compose_icon(), "New chat", new_chat)))
        .child(
            menu()
                .offset(px(4.0))
                .popup_style(row::popup_style)
                .backdrop_style(|st| st.bg(c::overlay()))
                .trigger(row::icon_trigger(Icon::More, "More options"))
                .child(item(Icon::Users, "New group", features::groups::new_group))
                .child(item(Icon::Layers, "Chat lists", pages::open_lists))
                .child(
                    row::menu_row(Icon::Check, || "Mark all as read".to_string(), false)
                        .on_select(move || {
                            s.mark_all_read();
                            toast("All chats marked as read");
                        }),
                ),
        )
}

/// The filter chips: All, Unread, Favourites, Groups, Channels, the
/// custom lists, and + to manage them.
fn chips(s: Store) -> Scroll {
    let f = filter();
    let fixed = [Filter::All, Filter::Unread, Filter::Favourites, Filter::Groups, Filter::Channels];
    scroll()
        .horizontal()
        .scrollbar(false)
        .flex_grow(0.0)
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .pl_4()
                // Past the 32pt fade, so the last chip can scroll clear of it.
                .pr(px(40.0))
                .py_2()
                .role(AccessibilityRole::Tablist)
                .children(fixed.into_iter().map(move |which| {
                    let label = which.label();
                    let mine = which.clone();
                    let pick = which.clone();
                    let picked = stored(mine);
                    chip(
                        label,
                        move || f.with(|x| picked.with(|p| x.0 == *p)),
                        move || f.set(ChatFilter(pick.clone())),
                    )
                }))
                .child(when(
                    move || s.whatsapp_linked() && !s.whatsapp_in_all(),
                    move || {
                        chip(
                            "WhatsApp",
                            move || f.with(|x| x.0 == Filter::WhatsApp),
                            move || f.set(ChatFilter(Filter::WhatsApp)),
                        )
                    },
                ))
                .child(each(
                    move || list_names(s),
                    |name: &String| name.clone(),
                    move |name, _| {
                        let name = name.get_untracked();
                        let held = stored(name.clone());
                        chip(
                            name.clone(),
                            move || f.with(|x| held.with(|n| matches!(&x.0, Filter::List(l) if l == n))),
                            move || f.set(ChatFilter(Filter::List(name.clone()))),
                        )
                    },
                ))
                .child(
                    nsh_base::button()
                        .on_press(pages::open_lists)
                        .accessibility_label("Manage chat lists")
                        .size(px(if is_desktop() { 32.0 } else { 38.0 }))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .bg(move || c::secondary())
                        .text_color(move || c::muted_fg())
                        .transition_colors()
                        .duration(motion::INSTANT)
                        .hover(|st| st.opacity(0.85))
                        .focus_visible(|st| st.outline(px(2.0)).outline_color(move || c::ring()))
                        .child(icon(Icon::Plus, 16.0)),
                ),
        )
}

/// The inbox: Archived, Message requests and Locked chats on top, then
/// the chats.
fn inbox(s: Store) -> VirtualList {
    let f = filter();
    let rows = computed(move || {
        let which = f.with(|x| x.0.clone());
        s.chats.with(|cs| {
            s.messages.with(|m| s.contacts.with(|ct| model::rows(cs, m, ct, ListScope::Inbox, &which)))
        })
        .into_iter()
        // WhatsApp chats (A15): gone when unlinked; in All only when the
        // user keeps them together, else under their own chip.
        .filter(|r| !r.whatsapp || (s.whatsapp_linked() && (which != Filter::All || s.whatsapp_in_all())))
        .collect::<Vec<_>>()
    });
    // A list chosen as a filter that was then deleted falls back to All.
    effect(move || {
        let gone = f.with(|x| matches!(&x.0, Filter::List(n) if !list_names(s).contains(n)));
        if gone {
            f.set(ChatFilter(Filter::All));
        }
    });
    row::chat_list(s, rows, ListScope::Inbox)
        .header(top_entries(s))
        .empty(dynamic(move || {
            let which = f.with(|x| x.0.clone());
            let (title, message) = which.empty_copy();
            let glyph = match which {
                Filter::Unread => Icon::Check,
                Filter::Favourites => Icon::Heart,
                Filter::Groups => Icon::Users,
                Filter::Channels => Icon::Megaphone,
                Filter::WhatsApp => Icon::Chats,
                Filter::List(_) => Icon::Layers,
                Filter::All => Icon::Chats,
            };
            let action = match which {
                Filter::All => Some(btn("Start a chat", Variant::Primary, BtnSize::Md, new_chat).into_element()),
                _ => Some(
                    btn("Show all chats", Variant::Ghost, BtnSize::Md, move || f.set(ChatFilter(Filter::All)))
                        .into_element(),
                ),
            };
            empty_state(glyph, title, message, action)
        }))
        .footer(view().h(px(if wide() { 16.0 } else { 88.0 })))
}

/// The entries above the chats, each shown while it has something.
fn top_entries(s: Store) -> View {
    let f = filter();
    let all = move || f.with(|x| x.0 == Filter::All);
    let archived = computed(move || s.chats.with(|cs| model::count(cs, ListScope::Archived)));
    let requests = computed(move || s.chats.with(|cs| cs.iter().filter(|c| c.request).count()));
    let locked = computed(move || s.chats.with(|cs| model::count(cs, ListScope::Locked).0));
    view()
        .child(when(
            move || all() && locked.get() > 0,
            move || entry(Icon::Lock, "Locked chats", move || (String::new(), false), pages::open_locked),
        ))
        .child(when(
            move || all() && archived.get().0 > 0,
            move || {
                entry(
                    Icon::Archive,
                    "Archived",
                    move || {
                        // Unread archived chats in the primary colour (as
                        // a row's unread time); a plain total is muted.
                        let (n, unread) = archived.get();
                        if unread > 0 { (unread.to_string(), true) } else { (n.to_string(), false) }
                    },
                    pages::open_archived,
                )
            },
        ))
        .child(when(
            move || all() && requests.get() > 0,
            move || {
                entry(Icon::Inbox, "Message requests", move || (requests.get().to_string(), true), pages::open_requests)
            },
        ))
}

/// A row above the chats: an icon centred in the avatar column, a label
/// on the chats' text column, and a count (primary while it is unread).
fn entry(
    glyph: Icon,
    label: &'static str,
    value: impl Fn() -> (String, bool) + 'static,
    on_press: fn(),
) -> nsh_base::ButtonElement {
    let value = std::rc::Rc::new(value);
    let spoken = value.clone();
    let shown = value.clone();
    nsh_base::button()
        .on_press(move || on_press())
        .accessibility_label(move || {
            let v = spoken().0;
            Some(SharedString::from(if v.is_empty() { label.to_string() } else { format!("{label}, {v}") }))
        })
        .cursor_pointer()
        .transition_colors()
        .duration(motion::INSTANT)
        .hover(|st| st.bg(move || c::muted()))
        .active(|st| st.bg(move || c::accent()))
        .focus_visible(|st| st.bg(move || c::accent()))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_4()
                .h(px(if is_desktop() { 48.0 } else { 56.0 }))
                .child(
                    view()
                        .w(px(row::avatar_size()))
                        .items_center()
                        .justify_center()
                        .text_color(move || c::muted_fg())
                        .child(icon(glyph, 20.0)),
                )
                .child(
                    text(label)
                        .flex_1()
                        .number_of_lines(1)
                        .text_size(px(font::body()))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(move || c::foreground()),
                )
                .child(
                    text(move || value().0)
                        .text_size(px(font::CAPTION))
                        .font_weight(FontWeight::SEMIBOLD)
                        .tabular_nums()
                        .text_color(move || if shown().1 { c::primary() } else { c::muted_fg() }),
                )
                .child(
                    view()
                        .absolute()
                        .bottom_0()
                        .right_0()
                        .left(px(row::text_inset()))
                        .h(px(row::hairline()))
                        .bg(move || c::border()),
                ),
        )
}

// ---------------------------------------------------------------- entry points

/// Starts a new chat (contact picker, new group, new community, invite).
pub fn new_chat() {
    new_chat::open();
}
