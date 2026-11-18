//! The messages: a virtualized list resting at its end (a chat), each
//! cell bound to the message at its position. Date separators and sender
//! runs come from the neighbours; per-message state (playing, selected,
//! highlighted) lives in `Conv`, keyed by id.

use std::time::Duration;

use nsh_core::prelude::*;

use super::{Conv, bubbles, logic};
use crate::{
    features::devices,
    store::{Body, ChatKind, Message, day_label},
    ui::*,
};

/// A row's message and where it sits among its neighbours.
#[derive(Clone, PartialEq)]
pub(crate) struct Item {
    pub m: Message,
    pub place: logic::Place,
}

/// A cell's current row (a memo: bindings run only when it changes).
pub(crate) type ItemMemo = Memo<Option<Item>>;

/// One field of the row, as a memo of its own.
pub(crate) fn sel<T: PartialEq + Default + 'static>(item: ItemMemo, f: fn(&Item) -> T) -> Memo<T> {
    computed(move || item.with(|i| i.as_ref().map(f).unwrap_or_default()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RowKind {
    System,
    Nudge,
    Bubble,
}

/// How far from the end still counts as "at the end".
const END_SLOP: f32 = 80.0;

/// The jump-to-latest button's side, and the room it takes at the list's
/// end (its side and its 12pt from the bottom).
fn jump_side() -> f32 {
    if is_desktop() { 38.0 } else { 44.0 }
}
const JUMP_ROOM: f32 = 56.0;

/// The list of messages.
pub(crate) fn message_list(cv: Conv) -> impl IntoElement {
    let (s, chat) = (cv.s, cv.chat);
    virtual_list(move || s.message_count(chat), move |at: Position| row(cv, at))
        .keys(move || s.message_ids(chat))
        .estimated_item_size(px(58.0))
        .alignment(ListAlignment::Bottom)
        .follow_end(px(END_SLOP))
        .initial_scroll_at_end()
        .content_padding_top(px(8.0))
        // While scrolled up, the jump-to-latest button floats over the
        // list's end: room for it, so it never covers the last times and
        // ticks.
        .content_padding_bottom(move || px(if cv.following.get() { 10.0 } else { 10.0 + JUMP_ROOM }))
        .footer(typing_indicator(cv))
        .keyboard_dismiss_mode(KeyboardDismissMode::Interactive)
        .event_throttle(100.0)
        .on_scroll(move |e: &ScrollEvent| {
            let at_end = e.offset.y + e.size.height >= e.content_size.height - px(END_SLOP);
            if cv.following.get_untracked() != at_end {
                cv.following.set(at_end);
            }
            if at_end && cv.unseen.get_untracked() > 0 {
                cv.unseen.set(0);
                cv.s.mark_read(cv.chat);
            }
        })
        .flex_1()
        .element_ref(&cv.list)
        .label("Messages")
}

/// A sent message rising in from the composer.
fn rise() -> MotionSpec {
    MotionSpec::new(super::timing(motion::SLOW, Easing::EaseOut))
    .values(MotionChannel::Opacity, [0.0, 1.0])
    .values(MotionChannel::TranslateY, [8.0, 0.0])
}

/// One cell: made once, then bound to whichever message it shows.
fn row(cv: Conv, at: Position) -> View {
    let (s, chat) = (cv.s, cv.chat);
    let item: ItemMemo = computed(move || {
        let (prev, cur, next) = s.message_window(chat, at.index());
        let m = cur?;
        let place = logic::place(prev.as_ref(), &m, next.as_ref());
        Some(Item { m, place })
    });
    let kind = computed(move || {
        item.with(|i| {
            i.as_ref().map(|i| match i.m.body {
                Body::System(_) => RowKind::System,
                Body::Nudge => RowKind::Nudge,
                _ => RowKind::Bubble,
            })
        })
    });
    let id = sel(item, |i| i.m.id);
    let first = sel(item, |i| i.place.first);
    // Photos, videos and maps keep a little more air from the bubble above
    // in a run (their edge is the picture's, not a bubble's).
    let media = sel(item, |i| matches!(i.m.body, Body::Image { .. } | Body::Video { .. } | Body::Location { .. }));
    let day = sel(item, |i| i.place.day_break);
    let day_text = sel(item, |i| day_label(i.m.at));
    // The message just sent rises in once, whichever cell shows it.
    let enter = motion();
    effect(move || {
        let id = id.get();
        if id != 0 && cv.fresh.get_untracked() == Some(id) {
            cv.fresh.set(None);
            let _ = enter.play(rise());
        }
    });
    let lit = move || id.get() != 0 && cv.highlight.get() == Some(id.get());
    view()
        .w_full()
        .items_center()
        .bind_motion(&enter)
        .bg(move || if lit() { c::highlight().opacity(0.55) } else { AdaptiveColor::TRANSPARENT })
        .transition_colors()
        .duration(motion::SLOW)
        .child(
            view()
                .w_full()
                .max_w(px(760.0))
                .px(px(if cv.wide { 20.0 } else { 12.0 }))
                // 2pt between bubbles of one run, 8pt between runs.
                .pt(move || px(if first.get() { 8.0 } else if media.get() { 6.0 } else { 2.0 }))
                .child(when(move || day.get(), move || date_pill(day_text)))
                .child(dynamic(move || {
                    let k = kind.get()?;
                    Some(untracked(|| match k {
                        RowKind::System => system_row(cv, item).into_element(),
                        RowKind::Nudge => nudge_row(cv, item).into_element(),
                        RowKind::Bubble => bubble_row(cv, item),
                    }))
                })),
        )
}

/// "Today", "Yesterday", a weekday or a date, centred.
fn date_pill(label: Memo<String>) -> View {
    // A little more air above (a new day) than below (its first message).
    view().w_full().items_center().pt_1().pb_2().child(
        view()
            .h(px(24.0))
            .px_3()
            .justify_center()
            .rounded_full()
            .bg(move || c::card())
            .shadow_sm()
            .role(AccessibilityRole::Header)
            .child(
                text(move || label.get())
                    .text_size(px(font::CAPTION))
                    .line_height(px(16.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(move || c::muted_fg()),
            ),
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Notice {
    #[default]
    Plain,
    Encryption,
    KeyChange,
    Timer,
}

fn notice_of(t: &str) -> Notice {
    if t.contains("end-to-end encrypted") {
        Notice::Encryption
    } else if t.contains("safety number changed") {
        Notice::KeyChange
    } else if t.contains("isappearing messages") {
        Notice::Timer
    } else {
        Notice::Plain
    }
}

/// A centred notice: the encryption line at the top (lock), a key change
/// (calm, with Verify), the timer, members coming and going.
fn system_row(cv: Conv, item: ItemMemo) -> View {
    let (s, chat) = (cv.s, cv.chat);
    let raw = sel(item, |i| match &i.m.body {
        Body::System(t) => t.clone(),
        _ => String::new(),
    });
    let notice = computed(move || raw.with(|t| notice_of(t)));
    let shown = move || raw.with(|t| t.trim_end_matches(" Tap to verify.").to_string());
    let glyph = move |n: Notice| match n {
        Notice::Encryption => Icon::Lock,
        Notice::KeyChange => Icon::ShieldCheck,
        Notice::Timer => Icon::Timer,
        Notice::Plain => Icon::Info,
    };
    let verify = move || {
        if let Some(peer) = s.peer(chat) {
            devices::safety_number(peer.id);
        } else {
            super::chat_info(chat);
        }
    };
    view().w_full().items_center().py_1().child(
        pressable()
            .on_press(move || {
                if matches!(notice.get_untracked(), Notice::Encryption | Notice::KeyChange) {
                    verify();
                }
            })
            .accessibility_label(super::say(move || raw.get()))
            .max_w(px(520.0))
            .px_3()
            .py_2()
            .gap_2()
            .items_center()
            .rounded(move || radius::control())
            .bg(move || if notice.get() == Notice::Encryption { c::info_bg() } else { c::card() })
            .shadow_sm()
            .child(
                text("")
                    .text_size(px(font::CAPTION))
                    .line_height(px(17.0))
                    .text_center()
                    .text_color(move || c::muted_fg())
                    .child(dynamic(move || {
                        let n = notice.get();
                        Some(untracked(|| icon(glyph(n), 12.0)))
                    }))
                    .child("  ")
                    .child(text(shown)),
            )
            .child(when(
                move || notice.get() == Notice::KeyChange,
                move || btn("Verify", Variant::Ghost, BtnSize::Sm, verify),
            )),
    )
}

/// A nudge: a centred line with a zap (the conversation shakes when one
/// arrives).
fn nudge_row(cv: Conv, item: ItemMemo) -> View {
    let s = cv.s;
    let line = sel(item, |i| if i.m.mine() { "You sent a nudge".to_string() } else { String::new() });
    let from = sel(item, |i| i.m.from);
    let time = sel(item, |i| crate::store::clock(i.m.at));
    let label = move || {
        let l = line.get();
        if l.is_empty() { format!("{} sent you a nudge", s.contact_name(from.get())) } else { l }
    };
    view().w_full().items_center().py_1().child(
        view()
            .flex_row()
            .items_center()
            .gap_2()
            .px_3()
            .py(px(6.0))
            .rounded_full()
            .bg(move || c::card())
            .shadow_sm()
            .label(move || format!("{}, {}", label(), time.get()))
            .child(icon(Icon::Zap, 14.0).text_color(move || c::warning()))
            .child(
                text(label)
                    .text_size(px(font::CAPTION))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(move || c::foreground()),
            )
            .child(text(move || time.get()).text_size(px(11.0)).tabular_nums().text_color(move || c::muted_fg())),
    )
}

/// A sender's message: selection mark, the sender's avatar in groups, the
/// bubble with its reactions; swiped right on phones, it replies.
fn bubble_row(cv: Conv, item: ItemMemo) -> AnyElement {
    let s = cv.s;
    let mine = sel(item, |i| i.m.mine());
    let last = sel(item, |i| i.place.last);
    let from = sel(item, |i| i.m.from);
    let id = sel(item, |i| i.m.id);
    let avatars = s.chat(cv.chat).is_some_and(|c| matches!(c.kind, ChatKind::Group | ChatKind::Community));
    let selected = move || cv.selected.with(|v| v.contains(&id.get()));
    // While selecting, the marks make a column of their own at the
    // leading edge (for both sides' messages), and the chosen rows are
    // tinted: shape and colour.
    let content = view()
        .flex_row()
        .items_end()
        .gap(px(8.0))
        .w_full()
        .rounded(move || radius::control())
        .bg(move || {
            if cv.selecting.get() && selected() { c::primary().opacity(0.1) } else { AdaptiveColor::TRANSPARENT }
        })
        .transition_colors()
        .duration(motion::INSTANT)
        .child(when(cv.selecting, move || select_mark(selected)))
        .child(
            view()
                .flex_1()
                .min_w(px(0.0))
                .flex_row()
                .items_end()
                .gap(px(6.0))
                .style_when(move || mine.get(), |st| st.justify_end())
                .child(avatars.then(|| {
            view().w(px(28.0)).style_when(move || mine.get(), |st| st.hidden()).child(when(
                move || last.get() && !mine.get(),
                move || {
                    dynamic(move || {
                        let from = from.get();
                        Some(untracked(|| avatar(s.contact_name(from), from.unwrap_or(0), 28.0)))
                    })
                },
            ))
        }))
                .child(bubbles::bubble_column(cv, item)),
        );
    // While selecting, the whole row toggles the message.
    let picker = when(cv.selecting, move || {
        pressable()
            .absolute()
            .inset_0()
            .selected(selected)
            .accessibility_label(super::say(move || if selected() { "Selected message" } else { "Select message" }))
            .on_press(move || cv.toggle_selected(id.get_untracked()))
    });
    if is_desktop() {
        return view().child(content).child(picker).into_element();
    }
    // Phones: swipe right to reply. The bubble follows the finger 1:1,
    // the reply mark fades in; past the threshold, release replies.
    let x = animated_value(0.0);
    const REACH: f32 = 64.0;
    view()
        .child(
            view()
                .absolute()
                .left(px(4.0))
                .top_0()
                .bottom_0()
                .justify_center()
                .bind_opacity(&x.interpolate(&[0.0, REACH], &[0.0, 1.0]))
                .accessibility_elements_hidden(true)
                .child(
                    view()
                        .size(px(30.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || c::card())
                        .text_color(move || c::muted_fg())
                        .child(icon(Icon::Reply, 16.0)),
                ),
        )
        .child(
            view()
                .bind_translate_x(&x)
                .claim_touches(TouchClaim::on_pan(PanActivation::horizontal(px(14.0), px(12.0))))
                .on_responder_move(move |e: &ResponderEvent| {
                    if cv.selecting.get_untracked() {
                        return;
                    }
                    let dx = e.gesture.delta.x.0.max(0.0);
                    x.set(if dx > REACH { REACH + (dx - REACH) * 0.2 } else { dx });
                })
                .on_responder_release(move |e: &ResponderEvent| {
                    if !cv.selecting.get_untracked() && e.gesture.delta.x.0 >= REACH {
                        cv.start_reply(id.get_untracked());
                    }
                    let _ = x.timing(0.0, motion::BASE, Easing::EaseOut);
                })
                .on_responder_terminate(move |_: &ResponderEvent| {
                    let _ = x.timing(0.0, motion::FAST, Easing::EaseOut);
                })
                .child(content),
        )
        .child(picker)
        .into_element()
}

/// The round selection mark: a filled check when chosen (shape, not just
/// colour).
fn select_mark(selected: impl Fn() -> bool + Copy + 'static) -> View {
    view()
        .size(px(22.0))
        .ml(px(4.0))
        .mb(px(8.0))
        .rounded_full()
        .items_center()
        .justify_center()
        .border_2()
        .border_color(move || if selected() { c::primary() } else { c::muted_fg() })
        .bg(move || if selected() { c::primary() } else { AdaptiveColor::TRANSPARENT })
        .text_color(move || c::on_primary())
        .accessibility_elements_hidden(true)
        .child(icon(Icon::Check, 14.0).opacity(move || if selected() { 1.0_f32 } else { 0.0 }))
}

/// Three dots breathing in a bubble while the other person types.
fn typing_indicator(cv: Conv) -> AnyElement {
    let (s, chat) = (cv.s, cv.chat);
    let typing = computed(move || s.chat(chat).and_then(|c| c.typing));
    let who = move || match s.peer(chat) {
        Some(p) => format!("{} is typing", p.name),
        None => "Someone is typing".into(),
    };
    when(
        move || typing.with(Option::is_some),
        move || {
            let dots: Vec<Motion> = (0..3)
                .map(|i| {
                    let m = motion();
                    let spec = MotionSpec::new(super::looping(1100.0, i as f32 * 160.0))
                    .values(MotionChannel::Opacity, [0.6, 1.0, 0.35, 0.6])
                    .values(MotionChannel::TranslateY, [0.0, -3.0, 0.0, 0.0]);
                    let _ = m.play(spec);
                    m
                })
                .collect();
            view().w_full().items_center().pt_2().child(
                view().w_full().max_w(px(760.0)).px(px(if cv.wide { 20.0 } else { 12.0 })).child(
                    view()
                        .self_start()
                        .flex_row()
                        .gap(px(4.0))
                        .px_4()
                        .py(px(13.0))
                        .rounded(move || radius::bubble())
                        .rounded_bl(px(6.0))
                        .bg(move || c::bubble_in())
                        .label(who())
                        .role(AccessibilityRole::Text)
                        .children(dots.into_iter().map(|m| {
                            view().size(px(7.0)).rounded_full().bg(move || c::bubble_meta()).bind_motion(&m)
                        })),
                ),
            )
        },
    )
    .into_element()
}

/// The round "jump to latest" button, with how many arrived meanwhile.
pub(crate) fn jump_button(cv: Conv) -> AnyElement {
    when(
        move || !cv.following.get(),
        move || {
            let pop = motion().entering(
                MotionSpec::new(super::timing(motion::FAST, Easing::EaseOut))
                .values(MotionChannel::Opacity, [0.0, 1.0])
                .values(MotionChannel::Scale, [0.9, 1.0]),
            );
            view()
                .absolute()
                // On the messages' gutter (the outgoing bubbles' edge).
                .right(px(if cv.wide { 20.0 } else { 8.0 }))
                .bottom(px(12.0))
                .bind_motion(&pop)
                .child(
                    pressable()
                        .on_press(move || cv.to_latest())
                        .accessibility_label(super::say(move || match cv.unseen.get() {
                            0 => "Scroll to latest message".to_string(),
                            n => format!("Scroll to latest message, {n} new"),
                        }))
                        .size(px(jump_side()))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        // The popover surface with a visible edge: it
                        // stands off the chat background in dark too.
                        .bg(move || c::popover())
                        .border_1()
                        .border_color(move || c::input().opacity(0.45))
                        .text_color(move || c::foreground())
                        .shadow_md()
                        .cursor_pointer()
                        .transition()
                        .duration(motion::FAST)
                        .active(|st| if motion::reduced() { st.opacity(0.85) } else { st.scale(0.94) })
                        .focus_visible(|st| st.outline(px(2.0)).outline_color(move || c::ring()))
                        .child(icon(Icon::ChevronDown, 20.0)),
                )
                .child(when(
                    move || cv.unseen.get() > 0,
                    move || {
                        view()
                            .absolute()
                            .top(px(-8.0))
                            .right(px(-4.0))
                            .child(unread_badge(move || cv.unseen.get(), || false))
                    },
                ))
        },
    )
    .into_element()
}

/// Clears the highlight a jump left (used by search).
pub(crate) fn flash(cv: Conv, id: crate::store::MsgId) {
    cv.highlight.set(Some(id));
    let h = cv.highlight;
    set_timeout(Duration::from_millis(1400), move || {
        if h.get_untracked() == Some(id) {
            h.set(None);
        }
    });
}
