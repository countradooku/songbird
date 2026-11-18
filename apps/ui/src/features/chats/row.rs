//! One chat row, recycled by the list: every part reads the row's data in
//! a binding, so a cell follows whichever chat it shows. Its menu opens on
//! a right click (desktops) or a held finger (phones, as a sheet).

use nsh_base::{MenuItemElement, button, context_menu, menu_item, menu_separator, submenu};
use nsh_core::{
    element::{Position, StyleRefinement},
    prelude::*,
};

use super::{animate_change, filter, list_names, model::*, pages, surface};
use crate::{
    features, nav,
    store::{ChatId, Store},
    ui::*,
};

/// The avatar's side in a chat row.
pub fn avatar_size() -> f32 {
    if is_desktop() { 46.0 } else { 52.0 }
}

/// The preview line's text size: a step under the title.
pub fn preview_size() -> f32 {
    if is_desktop() {
        font::SMALL
    } else {
        font::BODY_DESKTOP
    }
}

/// Each of the row's two lines is this tall, whatever it holds (a badge,
/// a tag or only text), so every row's text block is the same height and
/// sits centred on the avatar.
fn line_height() -> f32 {
    if is_desktop() { 20.0 } else { 22.0 }
}

/// The status glyphs on a row (timer, muted, pinned, a failed send) share
/// one size.
const MARK: f32 = 16.0;

/// The row's leading gutter and the gap after the avatar: where the text
/// column starts. The avatar column sits on the gutter, the same 16pt as
/// the search field's edge and the pinned people's grid above.
pub const GUTTER: f32 = 16.0;
const AVATAR_GAP: f32 = 12.0;

/// The unread dot before the time.
const DOT: f32 = 8.0;

/// Wide layouts draw a row's hover, press and selection as a rounded fill
/// inset in the pane (floating, like the pane itself), not a band from
/// edge to edge; the content keeps its place on the gutter. Phones keep
/// the platform's full-width press.
pub fn fill_inset() -> f32 {
    if wide() { 8.0 } else { 0.0 }
}

/// One device pixel, in points (a hairline).
pub fn hairline() -> f32 {
    1.0 / pixel_ratio().max(1.0)
}

/// A virtual list of chat rows (`rows` in order), keyed by chat.
pub fn chat_list(s: Store, rows: Memo<Vec<ChatRow>>, scope: ListScope) -> VirtualList {
    virtual_list(
        move || rows.with(Vec::len),
        move |at: Position| {
            let row = computed(move || {
                rows.with(|r| r.get(at.index()).cloned())
                    .unwrap_or_default()
            });
            chat_row(s, row, scope, None)
        },
    )
    .keys(move || rows.with(|r| r.iter().map(|x| x.id).collect::<Vec<_>>()))
    .estimated_item_size(px(72.0))
    // No scrollbar drawn over the rows' trailing counts (desktop).
    .scrollbar(false)
    .flex_1()
}

/// Whether the row's chat has a (mock) photo.
fn photo_shown(r: &ChatRow) -> bool {
    if r.group {
        portrait::has_photo(r.seed + 1000)
    } else {
        portrait::has_photo(r.seed)
    }
}

/// An avatar that follows the row: initials on the chat's hue, and a
/// small group or channel mark at its corner (shape, not colour alone),
/// cut out of `surface` (the page on phones, the pane on wide layouts).
pub fn live_avatar(row: Memo<ChatRow>, size: f32, surface: fn() -> AdaptiveColor) -> View {
    view()
        .size(px(size))
        .accessibility_elements_hidden(true)
        .child(
            view()
                .size(px(size))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(move || c::avatar(row.with(|r| r.seed)))
                .overflow_hidden()
                .child(
                    text(move || row.with(|r| initials(&letters(&r.title))))
                        .text_size(px((size * 0.38).round()))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(move || c::on_avatar()),
                )
                // The profile photo over the initials (mock portraits for
                // people, scenes for groups), when the chat has one.
                .child(
                    image(move || {
                        row.with(|r| {
                            if r.group {
                                portrait::scenery(r.seed)
                            } else {
                                portrait::portrait(r.seed)
                            }
                        })
                    })
                    .absolute()
                    .inset_0()
                    .object_fit(ResizeMode::Cover)
                    .style_when(move || !row.with(|r| photo_shown(r)), |st| st.hidden()),
                )
                .child(
                    view()
                        .absolute()
                        .inset_0()
                        .rounded_full()
                        .border_1()
                        .border_color(move || c::border())
                        .opacity(0.6)
                        .style_when(
                            move || !row.with(|r| photo_shown(r)),
                            |st| st.hidden().border_color(AdaptiveColor::TRANSPARENT),
                        ),
                ),
        )
        .child(
            view()
                .absolute()
                .right(px(-2.0))
                .bottom(px(-2.0))
                .size(px(20.0))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(move || surface())
                .style_when(move || !row.with(|r| r.group), |st| st.hidden())
                .child(
                    view()
                        .size(px(16.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || c::secondary())
                        .text_color(move || c::muted_fg())
                        .child(dynamic(move || {
                            let channel = row.with(|r| r.channel);
                            icon(
                                if channel {
                                    Icon::Megaphone
                                } else {
                                    Icon::Users
                                },
                                10.0,
                            )
                        })),
                ),
        )
}

/// A small muted glyph shown while `shown` holds.
fn mark(glyph: Icon, size: f32, shown: impl Fn() -> bool + 'static) -> Svg {
    icon(glyph, size)
        .text_color(move || c::muted_fg())
        .style_when(move || !shown(), |st| st.hidden())
}

/// One chat row in a list; in search results (`query`), the part of the
/// name that matched is highlighted.
pub fn chat_row(
    s: Store,
    row: Memo<ChatRow>,
    scope: ListScope,
    query: Option<Signal<String>>,
) -> impl IntoElement {
    let desktop_layout = wide();
    let open = nav::open_chat();
    let selected = move || desktop_layout && open.with(|o| o.0) == Some(row.with(|r| r.id));
    // Unread and not muted: the name steps up a weight and the dot is the
    // accent. Muted and unread: a neutral dot, the name stays quiet.
    let loud = move || row.with(|r| r.is_unread() && !r.muted);
    let unread = move || row.with(ChatRow::is_unread);
    // What the second line shows: the open chat's draft is in its
    // composer, so its row keeps the last message.
    let shown = computed(move || {
        let open_here = selected();
        row.with(|r| r.shown(open_here).clone())
    });
    let typing = move || shown.with(|p| matches!(p, Preview::Typing(_)));
    let failed = move || {
        shown.with(|p| {
            matches!(
                p,
                Preview::Message {
                    tick: Some(Tick::Failed),
                    ..
                }
            )
        })
    };
    let voice =
        move || row.with(|r| r.voice) && shown.with(|p| matches!(p, Preview::Message { .. }));
    // The name, cut around the query's match (search results).
    let cut = computed(move || {
        let title = row.with(|r| r.title.clone());
        query
            .and_then(|q| q.with(|q| cut_match(&title, q)))
            .unwrap_or((title, String::new(), String::new()))
    });

    // Three text sizes in the whole list: the name (body), the preview a
    // step under it, and caption for the time and the counts. The name
    // leads, the preview is muted, the time is the quietest.
    let title_line = view()
        .flex_row()
        .items_center()
        .h(px(line_height()))
        .gap_1()
        .child(
            text(move || cut.with(|c| c.0.clone()))
                .child(
                    text(move || cut.with(|c| c.1.clone()))
                        .bg(move || c::highlight())
                        .text_color(move || c::foreground()),
                )
                .child(text(move || cut.with(|c| c.2.clone())))
                .flex_shrink(1.0)
                .number_of_lines(1)
                .text_size(px(font::body()))
                .line_height(px(line_height()))
                // One weight step marks an unread chat; the dot by the
                // time says it again in shape, not weight alone.
                .font_weight(FontWeight::NORMAL)
                .style_when(loud, |st| st.font_weight(FontWeight::SEMIBOLD))
                .text_color(move || c::foreground()),
        )
        .child(
            icon(Icon::ShieldCheck, 15.0)
                .text_color(move || c::primary())
                .style_when(move || !row.with(|r| r.verified), |st| st.hidden()),
        )
        .child(mark(Icon::Lock, 15.0, move || row.with(|r| r.locked)))
        // In the tree only for WhatsApp chats: a hidden bordered view still
        // draws a speck of its border on Android.
        .child(when(
            move || row.with(|r| r.whatsapp),
            move || {
                view()
                    .px(px(4.0))
                    .rounded(move || radius::sm())
                    .border_1()
                    .border_color(move || c::whatsapp())
                    .child(
                        text("WhatsApp")
                            .text_size(px(font::CAPTION))
                            .line_height(px(16.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(move || c::whatsapp()),
                    )
            },
        ))
        .child(view().flex_1().min_w(px(8.0)))
        // The unread dot, before the time. Centred on the line box it would
        // sit on the digits' middle; the 2pt drop puts its centre on the
        // time's x-height middle instead (the time is caption text a point
        // below the box centre, with its x-height middle ~3pt above the
        // baseline), so dot and digits read as one optical line.
        .child(
            view()
                .size(px(DOT))
                .rounded_full()
                .flex_shrink(0.0)
                .translate_y(px(2.0))
                .bg(move || if loud() { c::primary() } else { c::muted_fg() })
                .style_when(move || !unread(), |st| st.hidden()),
        )
        .child(
            text(move || row.with(|r| r.when.clone()))
                .flex_shrink(0.0)
                .text_size(px(font::CAPTION))
                .line_height(px(line_height()))
                // The title's baseline: same line box, nudged by the
                // difference of the two sizes' descent.
                .translate_y(px(1.0))
                .tabular_nums()
                .font_weight(FontWeight::NORMAL)
                .text_color(move || c::muted_fg()),
        );

    let preview = text(move || shown.with(|p| p.text().0))
        .flex_1()
        .number_of_lines(1)
        .text_size(px(preview_size()))
        .line_height(px(line_height()))
        .font_weight(FontWeight::MEDIUM)
        .text_color(move || {
            if shown.with(|p| matches!(p, Preview::Draft(_))) {
                c::primary()
            } else {
                c::muted_fg()
            }
        })
        .child(
            text(move || shown.with(|p| p.text().1))
                .font_weight(FontWeight::NORMAL)
                .text_color(move || {
                    if typing() {
                        c::primary()
                    } else {
                        c::muted_fg()
                    }
                }),
        );

    let preview_line = view()
        .flex_row()
        .items_center()
        .h(px(line_height()))
        .gap_1()
        // No delivery ticks on rows (the conversation says it once, under
        // the latest message); only a send that failed shows, as a warning.
        .child(
            view()
                .style_when(move || !failed(), |st| st.hidden())
                .child(ticks(|| Tick::Failed)),
        )
        .child(mark(Icon::Mic, MARK, voice))
        .child(preview)
        // Chat state, at the end with mute and pin: disappearing messages.
        .child(mark(Icon::Timer, MARK, move || {
            row.with(|r| r.disappearing)
        }))
        .child(mark(Icon::BellOff, MARK, move || row.with(|r| r.muted)))
        // Pinned chats are the people above the list; a pin here is one
        // past the grid's eight.
        .child(mark(Icon::Pin, MARK, move || {
            row.with(|r| r.pinned) && scope == ListScope::Inbox
        }))
        .child(
            view()
                .size(px(20.0))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(move || if loud() { c::primary() } else { c::muted_fg() })
                .style_when(move || !row.with(|r| r.mention), |st| st.hidden())
                .child(
                    text("@")
                        .text_size(px(font::CAPTION))
                        .font_weight(FontWeight::BOLD)
                        .text_color(move || {
                            if loud() {
                                c::on_primary()
                            } else {
                                c::background()
                            }
                        }),
                ),
        )
        // The count only when it says more than the dot does (> 1).
        .child(
            view()
                .style_when(move || row.with(|r| r.unread <= 1), |st| st.hidden())
                .child(unread_badge(
                    move || row.with(|r| r.unread),
                    move || row.with(|r| r.muted),
                )),
        );

    let body = view()
        .flex_row()
        .items_center()
        .gap(px(AVATAR_GAP))
        .px(px(GUTTER - fill_inset()))
        .h(px(if is_desktop() { 68.0 } else { 76.0 }))
        .child(live_avatar(row, avatar_size(), surface()))
        .child(
            view()
                .flex_1()
                .min_w(px(0.0))
                .gap(px(2.0))
                .child(title_line)
                .child(preview_line),
        );

    // No separators: rows breathe on their height, and the hover, press
    // and selection fills say where one ends.
    let inset = fill_inset();
    let trigger = button()
        .on_press(move || features::chat::open(row.with_untracked(|r| r.id)))
        .accessibility_label(move || Some(SharedString::from(row.with(|r| r.spoken()))))
        .selected(selected)
        .mx(px(inset))
        .when(inset > 0.0, |b| b.rounded(move || radius::control()))
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
        .focus_visible(|st| st.bg(move || c::accent()))
        .child(body);

    with_menu(s, row, scope, trigger)
}

/// `trigger` with the chat's menu: a right click on desktops, a held
/// finger on phones (as a sheet). Rows and pinned people share it.
pub fn with_menu(
    s: Store,
    row: Memo<ChatRow>,
    scope: ListScope,
    trigger: impl IntoElement,
) -> impl IntoElement {
    context_menu()
        .popup_style(popup_style)
        .popup_starting_style(|st| {
            let st = st.opacity(0.0);
            if motion::reduced() {
                st
            } else {
                st.scale(0.97).translate_y(px(-4.0))
            }
        })
        .popup_ending_style(|st| st.opacity(0.0))
        .backdrop_style(|st| st.bg(c::overlay()))
        .trigger(trigger)
        .child(chat_menu(s, row, scope))
}

// ---------------------------------------------------------------- menus

/// The popup (desktops) or sheet (phones) every chat menu is drawn on.
pub fn popup_style(st: StyleRefinement) -> StyleRefinement {
    if is_desktop() {
        // The app's one menu surface (`ui::app_menu`, the message menu):
        // the large radius outside, the control radius inside (lg − 4pt).
        st.min_w(px(232.0))
            .p_1()
            .rounded(radius::lg())
            .bg(c::popover())
            .border_1()
            .border_color(c::border())
            .shadow_lg()
            .transition_all()
            .duration(motion::FAST)
            .ease_out()
    } else {
        st.pt_2()
            .px_2()
            .pb_safe_area_plus(px(12.0))
            .rounded_t(radius::sheet())
            .bg(c::popover())
    }
}

/// A menu item's height: the same in every menu of the app.
fn item_height() -> f32 {
    if is_desktop() { 34.0 } else { 48.0 }
}

/// A menu row: a glyph, a label (a closure: it may say Pin or Unpin) and
/// the shared states. `danger` makes it red.
pub fn menu_row(
    glyph: Icon,
    label: impl Fn() -> String + 'static,
    danger: bool,
) -> MenuItemElement {
    let ink = move || {
        if danger {
            c::destructive()
        } else {
            c::foreground()
        }
    };
    menu_item()
        .flex_row()
        .items_center()
        .gap_3()
        .px_3()
        .h(px(item_height()))
        .rounded(move || radius::control())
        .cursor_pointer()
        .hover(|st| st.bg(move || c::accent()))
        .focus(|st| st.bg(move || c::accent()))
        .active(|st| st.bg(move || c::accent()))
        .child(icon(glyph, 18.0).text_color(ink))
        .child(
            text(label)
                .flex_1()
                .text_size(px(font::body()))
                .text_color(ink),
        )
}

/// A focusable icon that opens a menu (menus open from their trigger by
/// themselves, so it is not a button).
pub fn icon_trigger(glyph: Icon, label: &'static str) -> View {
    let side = if is_desktop() { 32.0 } else { 44.0 };
    view()
        .size(px(side))
        .rounded_full()
        .items_center()
        .justify_center()
        .focusable(true)
        .role(AccessibilityRole::Button)
        .label(label)
        .cursor_pointer()
        .text_color(move || c::foreground())
        .transition_colors()
        .duration(motion::INSTANT)
        .hover(|st| st.bg(move || c::accent()))
        .focus_visible(|st| st.outline(px(2.0)).outline_color(move || c::ring()))
        .child(icon(glyph, if is_desktop() { 18.0 } else { 22.0 }))
}

pub fn separator_item() -> nsh_base::MenuSeparatorElement {
    menu_separator()
        .h(px(hairline()))
        .my_1()
        .mx_3()
        .bg(move || c::border())
}

/// What a row's menu offers, labels following the chat's state.
fn chat_menu(s: Store, row: Memo<ChatRow>, scope: ListScope) -> View {
    let id = move || row.with_untracked(|r| r.id);
    let flag = move |f: fn(&ChatRow) -> bool| move || row.with(f);
    let pinned = flag(|r| r.pinned);
    let muted = flag(|r| r.muted);
    let archived = flag(|r| r.archived);
    let unread = flag(ChatRow::is_unread);
    let favourite = flag(|r| r.favourite);
    let locked = flag(|r| r.locked);
    view()
        .child((scope == ListScope::Inbox).then(|| {
            menu_row(Icon::Pin, move || (if pinned() { "Unpin chat" } else { "Pin chat" }).into(), false)
                .on_select(move || {
                    animate_change();
                    s.toggle_pin(id());
                })
        }))
        .child(
            menu_row(
                Icon::BellOff,
                move || (if muted() { "Unmute notifications" } else { "Mute notifications" }).into(),
                false,
            )
            .on_select(move || {
                s.toggle_mute(id());
                toast(if s.chat(id()).is_some_and(|c| c.muted) { "Notifications muted" } else { "Notifications on" });
            }),
        )
        .child(
            menu_row(Icon::Archive, move || (if archived() { "Unarchive chat" } else { "Archive chat" }).into(), false)
                .on_select(move || {
                    animate_change();
                    s.toggle_archive(id());
                    toast(if s.chat(id()).is_some_and(|c| c.archived) { "Chat archived" } else { "Chat unarchived" });
                }),
        )
        .child(
            menu_row(Icon::Check, move || (if unread() { "Mark as read" } else { "Mark as unread" }).into(), false)
                .on_select(move || {
                    if unread() {
                        s.mark_read(id());
                    } else {
                        s.mark_unread(id());
                    }
                }),
        )
        .child(
            menu_row(
                Icon::Heart,
                move || (if favourite() { "Remove from favourites" } else { "Add to favourites" }).into(),
                false,
            )
            .on_select(move || {
                s.toggle_favourite(id());
                toast(if s.chat(id()).is_some_and(|c| c.favourite) { "Added to favourites" } else { "Removed from favourites" });
            }),
        )
        .child(lists_submenu(s, row))
        .child(
            menu_row(Icon::Lock, move || (if locked() { "Unlock chat" } else { "Lock chat" }).into(), false)
                .on_select(move || {
                    animate_change();
                    s.toggle_lock(id());
                    let now = s.chat(id()).is_some_and(|c| c.locked);
                    toast(if now { "Chat locked. Find it in Locked chats." } else { "Chat unlocked" });
                }),
        )
        .child(separator_item())
        .child(menu_row(Icon::Trash, || "Delete chat".into(), true).on_select(move || {
            let chat: ChatId = id();
            let title = row.with_untracked(|r| r.title.clone());
            confirm(
                format!("Delete chat with {title}?"),
                "Its messages are deleted from this device. Others in the chat keep their copy.",
                "Delete chat",
                move || delete(s, chat),
            );
        }))
}

/// Deletes a chat and closes it if it was open.
fn delete(s: Store, chat: ChatId) {
    animate_change();
    let open = nav::open_chat();
    if open.with_untracked(|o| o.0) == Some(chat) {
        open.set(nav::OpenChat(None));
    }
    s.delete_chat(chat);
    toast("Chat deleted");
}

/// "Add to list": each list, checked when the chat is in it, and a way
/// to make a new one.
fn lists_submenu(s: Store, row: Memo<ChatRow>) -> impl IntoElement {
    let f = filter();
    submenu()
        .trigger(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .px_3()
                .h(px(item_height()))
                .rounded(move || radius::control())
                .cursor_pointer()
                .hover(|st| st.bg(move || c::accent()))
                .focus(|st| st.bg(move || c::accent()))
                .child(icon(Icon::Layers, 18.0).text_color(move || c::foreground()))
                .child(text("Add to list").flex_1().text_size(px(font::body())))
                .child(icon(Icon::ChevronRight, 16.0).text_color(move || c::muted_fg())),
        )
        .back(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .px_3()
                .h(px(item_height()))
                .child(icon(Icon::Back, 18.0))
                .child(
                    text("Add to list")
                        .text_size(px(font::body()))
                        .font_weight(FontWeight::SEMIBOLD),
                ),
        )
        .child(dynamic(move || {
            list_names(s)
                .into_iter()
                .map(|name| {
                    let held = stored(name.clone());
                    let inside = move || row.with(|r| held.with(|n| r.lists.contains(n)));
                    menu_item()
                        .checked(move || Some(inside()))
                        .close_on_select(false)
                        .on_select(move || {
                            let id = row.with_untracked(|r| r.id);
                            held.with(|n| s.toggle_in_list(id, n));
                            // Taken out of the list being shown: show all.
                            let shown = f.with_untracked(|x| {
                                held.with(|n| matches!(&x.list, Filter::List(l) if l == n))
                            });
                            if shown && !inside() {
                                f.update(|x| x.list = Filter::All);
                            }
                        })
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .px_3()
                        .h(px(item_height()))
                        .rounded(move || radius::control())
                        .cursor_pointer()
                        .hover(|st| st.bg(move || c::accent()))
                        .focus(|st| st.bg(move || c::accent()))
                        .child(
                            view()
                                .size(px(18.0))
                                .rounded(move || radius::sm())
                                .border_2()
                                .items_center()
                                .justify_center()
                                .border_color(
                                    move || if inside() { c::primary() } else { c::input() },
                                )
                                .bg(move || {
                                    if inside() {
                                        c::primary()
                                    } else {
                                        AdaptiveColor::TRANSPARENT
                                    }
                                })
                                .text_color(move || c::on_primary())
                                .child(icon(Icon::Check, 12.0).style_when(
                                    move || !inside(),
                                    |st| st.hidden().border_color(AdaptiveColor::TRANSPARENT),
                                )),
                        )
                        .child(text(name).flex_1().text_size(px(font::body())))
                        .into_element()
                })
                .chain(std::iter::once(separator_item().into_element()))
                .chain(std::iter::once(
                    menu_row(Icon::Plus, || "New list…".into(), false)
                        .on_select(pages::open_lists)
                        .into_element(),
                ))
                .collect::<Vec<_>>()
        }))
}
