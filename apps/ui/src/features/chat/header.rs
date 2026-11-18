//! The conversation's header: back (phones), avatar, title, the subtitle
//! (presence, typing, members, followers, a custom status), verified and
//! WhatsApp marks, calls, and the More menu; or the search bar.

use nsh_core::prelude::*;

use super::{Conv, list, logic};
use crate::{
    features::calls,
    nav,
    store::{ChatKind, presence_label},
    ui::*,
};

/// Followers as people read them: 18,420.
pub(crate) fn thousands(n: u32) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// What shows under the title.
fn subtitle(cv: Conv) -> impl Fn() -> (String, bool) + Copy + 'static {
    let s = cv.s;
    let chat = cv.chat;
    move || {
        let Some(c) = s.chat(chat) else { return (String::new(), false) };
        if let Some(t) = c.typing.as_ref() {
            return match c.kind {
                ChatKind::Direct(_) | ChatKind::WhatsApp(_) => (t.clone(), true),
                _ => (format!("Someone is {t}"), true),
            };
        }
        let line = match c.kind {
            ChatKind::Direct(id) | ChatKind::WhatsApp(id) => match s.contact(id) {
                Some(p) if p.blocked => "Blocked".into(),
                Some(p) => {
                    let presence = presence_label(&p.presence);
                    match (presence.is_empty(), p.status_line) {
                        (false, Some(st)) => format!("{presence} · {st}"),
                        (false, None) => presence,
                        (true, Some(st)) => st,
                        (true, None) => "Tap here for contact info".into(),
                    }
                }
                None => String::new(),
            },
            ChatKind::Group | ChatKind::Community => {
                let mut names: Vec<String> = c
                    .members
                    .iter()
                    .filter_map(|m| m.contact)
                    .map(|id| s.contact_name(Some(id)).split_whitespace().next().unwrap_or_default().to_string())
                    .collect();
                names.push("You".into());
                names.join(", ")
            }
            ChatKind::Channel { followers, .. } => format!("Channel · {} followers", thousands(followers)),
        };
        (line, false)
    }
}

/// The header: the normal one, or search in chat.
pub(crate) fn header(cv: Conv) -> AnyElement {
    let bar = view()
        .bg(move || c::background())
        .border_b_1()
        .border_color(move || c::border())
        .when(!cv.wide, |v| v.pt_safe_area());
    bar.child(when(cv.searching, move || search_bar(cv)).otherwise(move || title_bar(cv))).into_element()
}

fn title_bar(cv: Conv) -> View {
    let (s, chat) = (cv.s, cv.chat);
    let info = computed(move || s.chat(chat));
    let peer = computed(move || s.peer(chat));
    let title = move || info.with(|c| c.as_ref().map(|c| c.title.clone()).unwrap_or_default());
    let seed = info.with_untracked(|c| c.as_ref().map_or(0, |c| c.seed));
    let verified = move || peer.with(|p| p.as_ref().is_some_and(|p| p.verified));
    let muted = move || info.with(|c| c.as_ref().is_some_and(|c| c.muted));
    let whatsapp = info.with_untracked(|c| c.as_ref().is_some_and(|c| matches!(c.kind, ChatKind::WhatsApp(_))));
    let channel = info.with_untracked(|c| c.as_ref().is_some_and(|c| matches!(c.kind, ChatKind::Channel { .. })));
    let direct = peer.with_untracked(Option::is_some);
    let online = move || peer.with(|p| p.as_ref().is_some_and(|p| p.presence == crate::store::Presence::Online));
    let timer = move || info.with(|c| c.as_ref().and_then(|c| c.disappearing));
    let sub = subtitle(cv);
    let size = if cv.wide { 40.0 } else { 38.0 };
    view()
        .h(px(if cv.wide { 60.0 } else { 56.0 }))
        .flex_row()
        .items_center()
        .gap_1()
        .px_2()
        .child((!cv.wide).then(|| icon_btn(Icon::Back, "Back", nav::pop)))
        .child(
            pressable()
                .flex_1()
                .min_w(px(0.0))
                .on_press(move || super::chat_info(chat))
                .accessibility_label(super::say(move || format!("{}, chat info", title())))
                .flex_row()
                .items_center()
                .gap_3()
                .px_1()
                .py_1()
                .rounded(move || radius::control())
                .hover(|st| st.bg(move || c::accent()))
                .child(if direct {
                    avatar_presence(title(), seed, size, online)
                } else {
                    group_avatar(title(), seed, size)
                })
                .child(
                    view()
                        .flex_1()
                        .min_w(px(0.0))
                        .gap(px(1.0))
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_1()
                                .child(
                                    text(title)
                                        .flex_shrink(1.0)
                                        .number_of_lines(1)
                                        .text_size(px(font::TITLE))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .role(AccessibilityRole::Header),
                                )
                                .child(when(verified, || {
                                    icon(Icon::ShieldCheck, 15.0).text_color(move || c::primary()).label("Verified")
                                }))
                                .child(when(muted, || icon(Icon::BellOff, 14.0).text_color(move || c::muted_fg()).label("Muted")))
                                .child(whatsapp.then(|| tag("WhatsApp"))),
                        )
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_1()
                                .child(when(move || timer().is_some(), move || {
                                    view()
                                        .flex_row()
                                        .items_center()
                                        .gap(px(2.0))
                                        .text_color(move || c::muted_fg())
                                        .label(move || format!("Disappearing messages: {}", timer().map(|t| t.label()).unwrap_or("")))
                                        .child(icon(Icon::Timer, 12.0))
                                        .child(text(move || timer().map(|t| t.label()).unwrap_or("")).text_size(px(font::CAPTION)))
                                        .child(text("·").text_size(px(font::CAPTION)))
                                }))
                                .child(
                                    text(move || sub().0)
                                        .flex_shrink(1.0)
                                        .number_of_lines(1)
                                        .text_size(px(font::CAPTION))
                                        .text_color(move || if sub().1 { c::primary() } else { c::muted_fg() }),
                                ),
                        ),
                ),
        )
        .child((!channel).then(|| icon_btn(Icon::Video, "Video call", move || calls::start_call(chat, true))))
        .child((!channel).then(|| icon_btn(Icon::Phone, "Voice call", move || calls::start_call(chat, false))))
        .child(more_menu(cv, direct && !whatsapp))
}

/// Search in chat, Mute, Disappearing messages, Chat info, Select,
/// Nudge; then Clear chat, Block and Report.
fn more_menu(cv: Conv, nudge: bool) -> AnyElement {
    let (s, chat) = (cv.s, cv.chat);
    let peer = s.peer(chat);
    let group = peer.is_none();
    let muted = move || s.chat(chat).is_some_and(|c| c.muted);
    let mut items = vec![
        menu_entry(Icon::Search, "Search", false, move || {
            batch(|| {
                cv.query.set(String::new());
                cv.hit.set(0);
                cv.searching.set(true);
            });
        }),
        menu_entry(Icon::Info, if group { "Group info" } else { "Contact info" }, false, move || super::chat_info(chat)),
        menu_entry(Icon::Check, "Select messages", false, move || cv.selecting.set(true)),
        menu_entry(Icon::BellOff, if muted() { "Unmute notifications" } else { "Mute notifications" }, false, move || {
            s.toggle_mute(chat);
            toast(if muted() { "Notifications muted" } else { "Notifications on" });
        }),
        menu_entry(Icon::Timer, "Disappearing messages", false, move || cv.timer_open.set(true)),
    ];
    if nudge {
        items.push(menu_entry(Icon::Zap, "Send a nudge", false, move || s.nudge_with_echo(chat)));
    }
    items.push(menu_rule());
    items.push(menu_entry(Icon::Trash, "Clear chat", true, move || {
        confirm(
            "Clear this chat?",
            "Messages will be removed from this device. Starred messages are removed too.",
            "Clear chat",
            move || {
                s.clear_chat(chat);
                toast("Chat cleared");
            },
        )
    }));
    if let Some(p) = peer.clone() {
        let id = p.id;
        let name = p.name.clone();
        items.push(menu_entry(Icon::Ban, format!("Block {}", p.name.split_whitespace().next().unwrap_or_default()), true, move || {
            let name = name.clone();
            confirm(
                format!("Block {name}?"),
                "Blocked contacts can't call you or send you messages. They won't be told you blocked them.",
                "Block",
                move || {
                    s.block(id, true);
                    toast(format!("{name} blocked"));
                },
            )
        }));
    }
    items.push(menu_entry(Icon::Flag, "Report", true, move || {
        confirm(
            "Report this chat?",
            "The last five messages are sent to Songbird so we can look into it. Nobody in the chat is told.",
            "Report",
            move || {
                s.report(chat);
                toast("Reported. Thank you.");
            },
        )
    }));
    app_menu(Icon::More, "More options", items)
}

/// Search in chat: the query, which match of how many, older and newer.
fn search_bar(cv: Conv) -> View {
    let (s, chat) = (cv.s, cv.chat);
    let query = cv.query;
    // Matches, newest first.
    let hits = computed(move || {
        let q = query.get();
        if q.trim().chars().count() < 2 {
            return Vec::new();
        }
        s.messages.with(|m| {
            m.get(&chat)
                .map(|v| {
                    v.iter()
                        .rev()
                        .filter(|x| logic::matches_search(&logic::copy_text(x), &q))
                        .map(|x| x.id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
    });
    let show = move |n: usize| {
        if let Some(id) = hits.with_untracked(|h| h.get(n).copied()) {
            cv.hit.set(n);
            if let Some(i) = s.index_of(chat, id) {
                cv.list.scroll_to_index(i as u32, percentage(0.5), px(0.0), true);
            }
            list::flash(cv, id);
        }
    };
    let close = move || {
        batch(|| {
            cv.searching.set(false);
            query.set(String::new());
        });
    };
    view()
        .h(px(if cv.wide { 60.0 } else { 56.0 }))
        .flex_row()
        .items_center()
        .gap_1()
        .px_2()
        .child(icon_btn(Icon::Close, "Close search", close))
        .child(
            view().flex_1().child(
                search_field("Search this chat", query),
            ),
        )
        .child(
            text(move || {
                let n = hits.with(Vec::len);
                if query.with(|q| q.trim().chars().count() < 2) {
                    String::new()
                } else if n == 0 {
                    "No results".into()
                } else {
                    format!("{} of {}", cv.hit.get().min(n - 1) + 1, n)
                }
            })
            .px_1()
            .text_size(px(font::SMALL))
            .tabular_nums()
            .text_color(move || c::muted_fg()),
        )
        .child(
            view()
                .style_with(|st| st.rotate(deg(180.0)))
                .child(icon_btn(Icon::ChevronDown, "Older match", move || {
                    let n = hits.with_untracked(Vec::len);
                    if n > 0 {
                        show((cv.hit.get_untracked() + 1).min(n - 1));
                    }
                })),
        )
        .child(icon_btn(Icon::ChevronDown, "Newer match", move || {
            show(cv.hit.get_untracked().saturating_sub(1));
        }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn followers_have_separators() {
        assert_eq!(super::thousands(18_420), "18,420");
        assert_eq!(super::thousands(999), "999");
        assert_eq!(super::thousands(1_000_000), "1,000,000");
    }
}
