//! The bottom of the conversation: the composer (emoji, a growing
//! input with the chat's draft, attach, send that turns into the mic),
//! the reply and edit bars, the voice recorder; or the bar that replaces
//! the composer (selection, a message request, a blocked contact, an
//! announcement group, a channel).

use std::time::Duration;

use nsh_core::{TouchEvent, TouchPhase, element::input, prelude::*};

use super::{Conv, Rec, logic};
use crate::{
    store::{Body, ChatKind, Role},
    ui::*,
};

/// What the bottom of the conversation shows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Compose,
    Select,
    Request,
    Blocked,
    AdminsOnly,
    Follower,
}

fn mode(cv: Conv) -> Mode {
    let (s, chat) = (cv.s, cv.chat);
    if cv.selecting.get() {
        return Mode::Select;
    }
    let Some(c) = s.chat(chat) else { return Mode::Compose };
    if c.request {
        return Mode::Request;
    }
    if s.peer(chat).is_some_and(|p| p.blocked) {
        return Mode::Blocked;
    }
    match c.kind {
        ChatKind::Channel { admin: false, .. } => Mode::Follower,
        _ => {
            let me_admin = c.members.iter().any(|m| m.contact.is_none() && m.role != Role::Member);
            if c.announcement_only && !me_admin { Mode::AdminsOnly } else { Mode::Compose }
        }
    }
}

/// The bottom bar for the current mode.
pub(crate) fn bottom(cv: Conv) -> AnyElement {
    let current = computed(move || mode(cv));
    view()
        .pb_safe_area()
        .child(dynamic(move || {
            let m = current.get();
            Some(untracked(|| match m {
                Mode::Compose => composer(cv),
                Mode::Select => select_bar(cv),
                Mode::Request => request_bar(cv),
                Mode::Blocked => blocked_bar(cv),
                Mode::AdminsOnly => notice_bar(Icon::Megaphone, "Only admins can send messages"),
                Mode::Follower => follower_bar(cv),
            }))
        }))
        .into_element()
}

/// A calm bar holding one line or a few actions.
fn bar() -> View {
    view()
        .bg(move || c::background())
        .border_t_1()
        .border_color(move || c::border())
        .px_4()
        .py_3()
        .items_center()
}

fn notice_bar(glyph: Icon, line: &'static str) -> AnyElement {
    bar()
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(icon(glyph, 16.0).text_color(move || c::muted_fg()))
                .child(muted(line)),
        )
        .into_element()
}

fn follower_bar(cv: Conv) -> AnyElement {
    let (s, chat) = (cv.s, cv.chat);
    let muted_now = move || s.chat(chat).is_some_and(|c| c.muted);
    bar()
        .child(btn_with_icon(
            move || if muted_now() { "Unmute" } else { "Mute" },
            Some(Icon::BellOff),
            Variant::Ghost,
            BtnSize::Md,
            move || s.toggle_mute(chat),
        ))
        .into_element()
}

fn blocked_bar(cv: Conv) -> AnyElement {
    let (s, chat) = (cv.s, cv.chat);
    bar()
        .child(
            pressable()
                .on_press(move || {
                    if let Some(p) = s.peer(chat) {
                        s.block(p.id, false);
                        toast(format!("{} unblocked", p.name));
                    }
                })
                .accessibility_label("You blocked this contact. Tap to unblock.")
                .py_1()
                .child(muted("You blocked this contact. Tap to unblock.").text_center()),
        )
        .into_element()
}

/// A message request: Block, Report, Accept (they can't see you read it
/// until you accept).
fn request_bar(cv: Conv) -> AnyElement {
    let (s, chat) = (cv.s, cv.chat);
    let peer = s.peer(chat);
    let name = peer.as_ref().map(|p| p.username.clone()).unwrap_or_default();
    bar()
        .gap_3()
        .child(
            text(format!(
                "@{name} is not in your contacts. They won't know you've seen their message until you accept."
            ))
            .text_size(px(font::SMALL))
            .line_height(px(18.0))
            .text_center()
            .max_w(px(520.0))
            .text_color(move || c::muted_fg()),
        )
        .child(
            view()
                .flex_row()
                .gap_2()
                .w_full()
                .max_w(px(520.0))
                .child(view().flex_1().child(btn("Block", Variant::Danger, BtnSize::Md, move || {
                    if let Some(p) = s.peer(chat) {
                        s.block(p.id, true);
                        s.delete_chat(chat);
                        crate::nav::pop();
                        toast("Blocked and deleted");
                    }
                })))
                .child(view().flex_1().child(btn("Report", Variant::Outline, BtnSize::Md, move || {
                    s.report(chat);
                    toast("Reported. Thank you.");
                })))
                .child(view().flex_1().child(btn("Accept", Variant::Primary, BtnSize::Md, move || {
                    s.accept_request(chat);
                    toast("Request accepted");
                }))),
        )
        .into_element()
}

/// Multi-select: how many, then Star, Copy, Forward, Delete.
fn select_bar(cv: Conv) -> AnyElement {
    let s = cv.s;
    let chat = cv.chat;
    let count = move || cv.selected.with(Vec::len);
    let ids = move || cv.selected.get_untracked();
    let any = move || count() > 0;
    view()
        .flex_row()
        .items_center()
        .gap_1()
        .px_2()
        .py_2()
        .bg(move || c::background())
        .border_t_1()
        .border_color(move || c::border())
        .child(icon_btn(Icon::Close, "Cancel selection", move || cv.end_select()))
        .child(
            text(move || match count() {
                0 => "Select messages".to_string(),
                1 => "1 selected".to_string(),
                n => format!("{n} selected"),
            })
            .flex_1()
            .text_size(px(font::body()))
            .font_weight(FontWeight::SEMIBOLD),
        )
        .child(icon_btn(Icon::Star, "Star", move || {
            let ids = ids();
            let all = s.messages.with_untracked(|m| {
                m.get(&chat).is_some_and(|v| v.iter().filter(|x| ids.contains(&x.id)).all(|x| x.starred))
            });
            s.star_messages(chat, &ids, !all);
            toast(if all { "Unstarred" } else { "Starred" });
            cv.end_select();
        })
        .disabled(move || !any()))
        .child(icon_btn(Icon::Copy, "Copy", move || {
            cv.copy(&ids());
            cv.end_select();
        })
        .disabled(move || !any()))
        .child(icon_btn(Icon::Forward, "Forward", move || {
            cv.ask_forward(ids());
        })
        .disabled(move || !any()))
        .child(icon_btn(Icon::Trash, "Delete", move || cv.ask_delete(ids())).disabled(move || !any()))
        .into_element()
}

// ---------------------------------------------------------------- compose

/// The bar above the input: what is being answered or edited.
fn context_bar(cv: Conv) -> AnyElement {
    let (s, chat) = (cv.s, cv.chat);
    let target = computed(move || cv.editing.get().or(cv.reply.get()).and_then(|id| s.message(chat, id)));
    let editing = move || cv.editing.get().is_some();
    when(move || target.with(Option::is_some), move || {
        let enter = motion().entering(
            MotionSpec::new(super::timing(motion::BASE, Easing::EaseOut))
                .values(MotionChannel::Opacity, [0.0, 1.0])
                .values(MotionChannel::TranslateY, [6.0, 0.0]),
        );
        let who = move || {
            if editing() {
                "Edit message".to_string()
            } else {
                target.with(|t| t.as_ref().map(|t| s.contact_name(t.from)).unwrap_or_default())
            }
        };
        let hue = move || match target.with(|t| t.as_ref().and_then(|t| t.from)) {
            Some(id) if !editing() => c::avatar(id),
            _ => c::primary(),
        };
        view()
            .bind_motion(&enter)
            .flex_row()
            .items_center()
            .gap_2()
            .mb_2()
            .rounded(move || radius::lg())
            .overflow_hidden()
            .bg(move || c::card())
            .border_1()
            .border_color(move || c::border())
            .child(view().w(px(4.0)).self_stretch().bg(hue))
            .child(
                dynamic(move || {
                    let edit = editing();
                    Some(untracked(|| icon(if edit { Icon::Edit } else { Icon::Reply }, 16.0).text_color(hue)))
                }),
            )
            .child(
                view()
                    .flex_1()
                    .py_2()
                    .gap(px(1.0))
                    .child(
                        text(who)
                            .text_size(px(font::SMALL))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(hue),
                    )
                    .child(
                        text(move || target.with(|t| t.as_ref().map(|t| t.body.preview()).unwrap_or_default()))
                            .number_of_lines(1)
                            .text_size(px(font::SMALL))
                            .text_color(move || c::muted_fg()),
                    ),
            )
            .child(icon_btn(Icon::Close, if cv.editing.get_untracked().is_some() { "Cancel edit" } else { "Cancel reply" }, move || {
                if cv.editing.get_untracked().is_some() {
                    cv.cancel_edit();
                } else {
                    cv.reply.set(None);
                }
            }))
    })
    .into_element()
}

fn composer(cv: Conv) -> AnyElement {
    // The same column as the messages (`list::row`: 760pt at most, 20pt
    // gutters on desktops, 8pt on phones), so the send button's edge is
    // the outgoing bubbles' edge.
    view()
        .w_full()
        .items_center()
        .pt_2()
        .pb_2()
        .child(
            view()
                .w_full()
                .max_w(px(760.0))
                .px(px(if cv.wide { 20.0 } else { 12.0 }))
                .child(context_bar(cv))
                .child(when(move || cv.rec.get().is_some(), move || recorder(cv)).otherwise(move || input_row(cv))),
        )
        .into_element()
}

/// The growing input with the chat's draft.
/// The composer's height at one line: the send button's side, so the
/// field and the button are one row of equal circles' ends.
fn bar_height() -> f32 {
    if is_desktop() { 42.0 } else { 48.0 }
}

/// The input's line height.
fn input_line() -> f32 {
    if is_desktop() { 20.0 } else { 22.0 }
}

fn input_row(cv: Conv) -> View {
    let (s, chat) = (cv.s, cv.chat);
    let draft = cv.draft;
    let lh = input_line();
    let height = signal(lh);
    // Inside the 1pt border: the input's padding centres one line, and the
    // icon buttons sit centred on that same line (and stay at the bottom
    // as the field grows).
    let inner = bar_height() - 2.0;
    let input_pad = ((inner - lh) / 2.0).floor();
    let icon_side = if is_desktop() { 32.0 } else { 44.0 };
    let icon_pad = ((inner - icon_side) / 2.0).floor();
    let enter_sends = s.settings.with_untracked(|x| x.enter_sends) && is_desktop();
    let placeholder = if s.chat(chat).is_some_and(|c| matches!(c.kind, ChatKind::WhatsApp(_))) {
        "Message on WhatsApp"
    } else {
        "Message"
    };
    view()
        .flex_row()
        .items_end()
        .gap_2()
        .child(
            view()
                .flex_1()
                .flex_row()
                .items_end()
                .min_h(px(bar_height()))
                // Half the one-line height: the same ends as the send
                // button beside it, kept as the field grows.
                .rounded(px(bar_height() / 2.0))
                .bg(move || c::card())
                .border_1()
                .border_color(move || c::border())
                .px(px(icon_pad + 1.0))
                .child(view().py(px(icon_pad)).child(icon_btn(Icon::Smile, "Emoji", move || cv.emoji_open.set(true))))
                .child(
                    input()
                        .element_ref(&cv.input)
                        .test_id("composer")
                        .flex_1()
                        .multiline(true)
                        .value(move || draft.get())
                        .on_change(move |t: &str| {
                            draft.set(t.to_owned());
                            if cv.editing.get_untracked().is_none() {
                                s.set_draft(chat, t.to_owned());
                            }
                        })
                        .submit_behavior(if enter_sends { SubmitBehavior::Submit } else { SubmitBehavior::Newline })
                        .on_submit(move |_: &str| cv.send_draft())
                        .on_content_size_change(move |size: &Size<Points>| {
                            height.set(size.height.0.clamp(lh, lh * 6.0).round());
                        })
                        .placeholder(placeholder.to_string())
                        .label(placeholder)
                        .placeholder_color(|| color(c::muted_fg()))
                        .caret_color(|| color(c::primary()))
                        .selection_color(|| color(c::accent()))
                        .h(move || px(height.get() + 2.0 * input_pad))
                        .px_1()
                        .py(px(input_pad))
                        .text_size(px(font::body()))
                        .line_height(px(lh))
                        .text_color(move || c::foreground()),
                )
                .child(view().py(px(icon_pad)).child({
                    // Desktops: the attach popover opens at the paperclip
                    // (measured as it is pressed).
                    let clip = element_ref();
                    icon_btn(Icon::Paperclip, "Attach", move || {
                        if !cv.wide {
                            cv.attach_open.set(true);
                            return;
                        }
                        spawn(async move {
                            if let Some(m) = clip.measure().await {
                                let size = m.frame.size;
                                cv.attach_at.set(Some((m.page.x.0, m.page.y.0, size.width.0, size.height.0)));
                            }
                            cv.attach_open.set(true);
                        });
                    })
                    .element_ref(&clip)
                })),
        )
        .child(send_button(cv))
}

/// Send when there is text, the mic when there is none: the glyphs swap
/// (shrink and fade out, grow in). Phones: hold the mic to record,
/// release to send, slide left to cancel, up to lock; a tap locks.
fn send_button(cv: Conv) -> View {
    let empty = move || cv.draft.with(|d| d.trim().is_empty());
    let reduced = motion::reduced();
    let glyph = move |g: Icon, shown: fn(bool) -> bool| {
        icon(g, 22.0)
            .absolute()
            .opacity(move || if shown(empty()) { 1.0_f32 } else { 0.0 })
            .scale(move || if shown(empty()) || reduced { 1.0_f32 } else { 0.5 })
            .rotate(move || deg(if shown(empty()) || reduced { 0.0 } else { -30.0 }))
            .transition_all()
            .duration(motion::BASE)
            .ease_in_out()
    };
    let side = bar_height();
    let button = pressable()
        .on_press(move || {
            if !empty() {
                cv.send_draft();
            } else if cv.rec.get_untracked().is_none() && !cv.held_press.get_untracked() {
                start_recording(cv, Rec::Locked);
            }
            cv.held_press.set(false);
        })
        .accessibility_label(super::say(move || if empty() { "Record voice message" } else { "Send" }))
        .size(px(side))
        .rounded_full()
        .items_center()
        .justify_center()
        .bg(move || c::primary())
        .text_color(move || c::on_primary())
        .shadow_sm()
        .active(move |st| if reduced { st.opacity(0.85) } else { st.scale(0.94) })
        .child(glyph(Icon::Mic, |e| e))
        .child(glyph(Icon::Send, |e| !e));
    if is_desktop() {
        return view().child(button);
    }
    // Held: record while the finger stays down; slide left cancels, up
    // locks, lifting sends.
    let from = stored(None::<Point<Points>>);
    view()
        .on_long_press(move || {
                if empty() && cv.rec.get_untracked().is_none() {
                    cv.held_press.set(true);
                    start_recording(cv, Rec::Held);
                }
            })
            .on_touch(move |e: &TouchEvent| {
                let at = e.points.first().map(|p| p.page);
                match e.phase {
                    TouchPhase::Start => {
                        from.replace(at);
                    }
                    TouchPhase::Move => {
                        if cv.rec.get_untracked() != Some(Rec::Held) {
                            return;
                        }
                        let Some((a, b)) = from.with(|f| *f).zip(at) else { return };
                        if b.x.0 - a.x.0 < -110.0 {
                            cv.rec.set(None);
                            toast("Voice message cancelled");
                        } else if b.y.0 - a.y.0 < -80.0 {
                            cv.rec.set(Some(Rec::Locked));
                        }
                    }
                    TouchPhase::End => {
                        if cv.rec.get_untracked() == Some(Rec::Held) {
                            send_recording(cv);
                        }
                    }
                    _ => {
                        if cv.rec.get_untracked() == Some(Rec::Held) {
                            cv.rec.set(None);
                        }
                    }
                }
            })
        .child(button)
}

fn start_recording(cv: Conv, how: Rec) {
    // mock: app-core records from the microphone (permission asked once).
    batch(|| {
        cv.rec_secs.set(0);
        cv.rec.set(Some(how));
    });
    announce_for_accessibility("Recording voice message");
}

fn send_recording(cv: Conv) {
    let secs = cv.rec_secs.get_untracked().max(1);
    cv.rec.set(None);
    cv.send_body(Body::Voice { secs, played: false });
}

/// The recorder's clock, while recording.
pub(crate) fn install_recorder(cv: Conv) {
    effect(move || {
        if cv.rec.get().is_some() {
            let clock = set_interval(Duration::from_secs(1), move || cv.rec_secs.update(|n| *n += 1));
            cleanup(move || clock.cancel());
        }
    });
}

/// Recording: a breathing red dot, the time, slide-to-cancel (held) or
/// Delete and Send (locked, and on desktops).
fn recorder(cv: Conv) -> View {
    let held = move || cv.rec.get() == Some(Rec::Held);
    let dot = motion();
    let _ = dot.play(
        MotionSpec::new(super::looping(1200.0, 0.0))
            .values(MotionChannel::Opacity, [1.0, 0.25, 1.0]),
    );
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .min_h(px(bar_height()))
        .child(
            view()
                .flex_1()
                .flex_row()
                .items_center()
                .gap_3()
                .h(px(bar_height()))
                .px_3()
                .rounded(px(bar_height() / 2.0))
                .bg(move || c::card())
                .border_1()
                .border_color(move || c::border())
                .child(when(move || !held(), move || icon_btn(Icon::Trash, "Delete recording", move || cv.rec.set(None))))
                .child(view().size(px(10.0)).rounded_full().bg(move || c::destructive()).bind_motion(&dot))
                .child(
                    text(move || logic::duration(cv.rec_secs.get()))
                        .text_size(px(font::body()))
                        .tabular_nums()
                        .role(AccessibilityRole::Timer),
                )
                .child(view().flex_1())
                .child(when(held, || {
                    view()
                        .flex_row()
                        .items_center()
                        .gap_1()
                        .text_color(move || c::muted_fg())
                        .child(view().style_with(|st| st.rotate(deg(90.0))).child(icon(Icon::ChevronDown, 16.0)))
                        .child(text("Slide to cancel").text_size(px(font::SMALL)))
                }))
                .child(when(held, || {
                    view()
                        .flex_row()
                        .items_center()
                        .gap_1()
                        .pl_2()
                        .text_color(move || c::muted_fg())
                        .child(icon(Icon::Lock, 14.0))
                        .child(text("Slide up to lock").text_size(px(font::CAPTION)))
                })),
        )
        .child(when(move || !held(), move || {
            pressable()
                .on_press(move || send_recording(cv))
                .accessibility_label("Send voice message")
                .size(px(bar_height()))
                .rounded_full()
                .items_center()
                .justify_center()
                .bg(move || c::primary())
                .text_color(move || c::on_primary())
                .child(icon(Icon::Send, 22.0))
        }))
}
