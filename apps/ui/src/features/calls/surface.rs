//! The active call: the full-screen surface on phones, the call panel on
//! desktops (which shrinks to a corner player), the controls, the tiles
//! of a group call, and the call's sheets (verification, participants,
//! devices, screen sharing, more).

use nsh_core::{PointerEvents, TransformKind, prelude::*};

use super::{
    calls, field, hang_up, panel_keys, ringing, set_minimised, toggle_mute, toggle_video, with_call,
    state::{self, CAMERAS, Layout, MICS, OUTPUTS, Participant, Phase, Share},
};
use crate::{
    store::Store,
    ui::{
        calls_controls::{call_group, call_note, call_row, call_section, call_sheet},
        *,
    },
};

/// What the layer shows: each is its own surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Permission,
    /// Ringing here, or the ended state of a call that rang here and was
    /// never answered (declined, answered elsewhere, missed).
    Ringing,
    Full,
    Mini,
}

/// The layer: a box over the app that lets presses through except on
/// what it draws.
pub fn layer(s: Store) -> AnyElement {
    let mode = field(
        |c| match c.phase {
            Phase::Permission => Mode::Permission,
            Phase::Incoming => Mode::Ringing,
            Phase::Ended(_) if c.incoming && c.connected == 0 => Mode::Ringing,
            _ if c.minimised => Mode::Mini,
            _ => Mode::Full,
        },
        Mode::Full,
    );
    // The layout follows the window: a narrow desktop window gets the
    // phone surfaces, as the shell does.
    let roomy = computed(wide);
    view()
        .absolute()
        .inset_0()
        .pointer_events(PointerEvents::BoxNone)
        .child(dynamic(move || {
            let m = mode.get();
            let roomy = roomy.get();
            untracked(move || match m {
                Mode::Permission => ringing::permission(),
                Mode::Ringing => ringing::incoming(s, roomy),
                Mode::Full if roomy => panel(s),
                Mode::Full => phone_surface(s),
                Mode::Mini if roomy => mini_player(s),
                Mode::Mini => phone_bar(),
            })
        }))
        .into_element()
}

// ------------------------------------------------------------------ motion

/// Fades and grows in from `from` scale once mounted (`SLOW`, ease-out);
/// at once with reduced motion.
pub(super) fn arrive(from: f32, lift: f32, ms: f32) -> View {
    let reduced = motion::reduced();
    let v = animated_value(if reduced { 1.0 } else { 0.0 });
    if !reduced {
        let _ = v.timing(1.0, ms, Easing::EaseOut);
    }
    view()
        .bind_opacity(&v)
        .bind_scale(&v.interpolate(&[0.0, 1.0], &[from, 1.0]))
        .bind_translate_y(&v.interpolate(&[0.0, 1.0], &[lift, 0.0]))
}

/// A calm ring that breathes out from behind an avatar while a call
/// rings: scale 1 → 1.4 and fading, 1.8s, looped. Still with reduced
/// motion.
pub(super) fn ring_pulse(size: f32) -> View {
    let outer = size * 1.5;
    let off = (outer - size) / 2.0;
    let reduced = motion::reduced();
    let v = animated_value(0.0);
    if !reduced {
        let _ = Animation::timing(&v, 1.0, Timing::new(1800.0, Easing::EaseOut)).looped(None).start();
    }
    let ring = view()
        .absolute()
        .top(px(off))
        .left(px(off))
        .size(px(size))
        .rounded_full()
        .bg(move || c::on_call().opacity(0.22))
        .accessibility_elements_hidden(true);
    let ring = if reduced {
        ring.scale(1.18_f32).opacity(0.6_f32)
    } else {
        ring.bind_scale(&v.interpolate(&[0.0, 1.0], &[1.0, 1.4]))
            .bind_opacity(&v.interpolate(&[0.0, 1.0], &[0.9, 0.0]))
    };
    view().size(px(outer)).child(ring)
}

/// Who a call is with, as a picture: the person's portrait for a 1:1
/// call (`seed` is their contact id), the group's own picture for a group
/// call (`seed` is the chat's), never a person's face for a group.
pub(super) fn call_avatar(name: impl Into<SharedString>, seed: u64, group: bool, size: f32) -> View {
    if group { group_avatar(name, seed, size) } else { avatar(name, seed, size) }
}

/// A big avatar with the ring pulse behind it while the call rings.
pub(super) fn ringing_avatar(name: String, seed: u64, group: bool, size: f32, ringing: impl Fn() -> bool + Copy + 'static) -> View {
    let outer = size * 1.5;
    let off = (outer - size) / 2.0;
    view()
        .size(px(outer))
        .child(when(ringing, move || ring_pulse(size)))
        .child(view().absolute().top(px(off)).left(px(off)).child(call_avatar(name.clone(), seed, group, size)))
}

/// The mic level: five bars moving while the microphone is on (mock: a
/// loop, not the real level). Still when muted or with reduced motion.
fn level_meter() -> View {
    let muted = field(|c| c.muted, false);
    let reduced = motion::reduced();
    view()
        .flex_row()
        .items_end()
        .gap(px(3.0))
        .h(px(16.0))
        .label(move || if muted.get() { "Microphone off" } else { "Microphone level" })
        .role(AccessibilityRole::Image)
        .children((0..5).map(move |i| {
            let v = animated_value(0.3);
            if !reduced {
                let peaks = [0.9, 0.6, 1.0, 0.5, 0.8];
                let ms = 260.0 + i as f32 * 70.0;
                let _ = Animation::sequence([
                    Animation::timing(&v, peaks[i], Timing::new(ms, Easing::EaseInOut)),
                    Animation::timing(&v, 0.25, Timing::new(ms, Easing::EaseInOut)),
                ])
                .looped(None)
                .start();
            }
            view()
                .w(px(4.0))
                .h(px(16.0))
                .rounded_full()
                .bg(move || if muted.get() { c::muted_fg() } else { c::primary() })
                .style_when(move || muted.get(), |s| s.opacity(0.4))
                .bind_transform(TransformKind::ScaleY, &v)
        }))
}

// ------------------------------------------------------------------ shared pieces

/// The lock line: "End-to-end encrypted", pressable for the code.
fn lock_line(verify: Signal<bool>) -> nsh_base::ButtonElement {
    nsh_base::button()
        .on_press(move || verify.set(true))
        .accessibility_label("End-to-end encrypted. Verify this call")
        .flex_row()
        .items_center()
        .gap(px(5.0))
        .px_2()
        .py_1()
        .rounded_full()
        .cursor_pointer()
        .hover(|st| st.bg(move || c::on_call().opacity(0.1)))
        .focus_visible(|st| st.outline(px(2.0)).outline_color(move || c::on_call()))
        .text_color(move || c::on_call().opacity(0.8))
        .child(icon(Icon::Lock, 13.0))
        .child(text("End-to-end encrypted").text_size(px(font::CAPTION)).font_weight(FontWeight::MEDIUM))
}

/// A person's picture filling a frame, as their camera would: the
/// portrait scaled to cover it (mock: no camera feed yet), or blurred
/// behind a dark scrim as the backdrop of a voice tile. `None` when the
/// person has no photo.
fn feed(seed: u64, blurred: bool) -> Option<View> {
    if !crate::ui::portrait::has_photo(seed) {
        return None;
    }
    let pic = image(crate::ui::portrait::portrait(seed))
        .absolute()
        .inset_0()
        .object_fit(ResizeMode::Cover);
    Some(
        view()
            .absolute()
            .inset_0()
            .accessibility_elements_hidden(true)
            .child(if blurred { pic.blur_radius(px(28.0)) } else { pic })
            // The scrim keeps the name label and the call's light ink
            // readable over any photo.
            .child(view().absolute().inset_0().bg(move || c::call_bg().opacity(if blurred { 0.62 } else { 0.12 }))),
    )
}

/// One person's tile: a video tile (their picture filling it, as the
/// mock's "camera") or a voice tile (their avatar over a dark, blurred
/// backdrop of the same picture), with their name, a muted mark and a
/// raised hand. Marks are glyphs with labels, never colour alone.
fn tile(name: String, seed: u64, video: bool, muted: bool, hand: bool, big: bool) -> View {
    let size = if big { 112.0 } else { 64.0 };
    let label = {
        let mut l = name.clone();
        if muted {
            l.push_str(", muted");
        }
        if hand {
            l.push_str(", hand raised");
        }
        if video {
            l.push_str(", camera on");
        }
        l
    };
    let person = name.trim_end_matches(" (you)").to_string();
    let backdrop = feed(seed, !video);
    let full_feed = video && backdrop.is_some();
    view()
        .flex_1()
        .min_h(px(if big { 220.0 } else { 120.0 }))
        .rounded(move || radius::lg())
        .overflow_hidden()
        .items_center()
        .justify_center()
        .bg(move || c::on_call().opacity(0.07))
        .label(label)
        .role(AccessibilityRole::Image)
        .child(backdrop)
        // No photo: their avatar (initials on their hue) on the dark tile,
        // as in the participants sheet, camera or not.
        .child((!full_feed).then(|| avatar(person.clone(), seed, size)))
        .child(
            view()
                .absolute()
                .left(px(8.0))
                .bottom(px(8.0))
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_1()
                .max_w(relative(0.9))
                .rounded(move || radius::sm())
                .bg(move || c::call_bg().opacity(0.6))
                .accessibility_elements_hidden(true)
                .child(muted.then(|| icon(Icon::MicOff, 13.0).text_color(move || c::on_call())))
                .child(
                    text(name)
                        .number_of_lines(1)
                        .text_size(px(font::CAPTION))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(move || c::on_call()),
                ),
        )
        .child(hand.then(|| {
            view()
                .absolute()
                .left(px(8.0))
                .top(px(8.0))
                .flex_row()
                .items_center()
                .gap_1()
                .px_2()
                .py_1()
                .rounded(move || radius::sm())
                .bg(move || c::on_call())
                .text_color(move || c::call_bg())
                .accessibility_elements_hidden(true)
                .child(icon(Icon::Hand, 13.0))
                .child(text("Hand raised").text_size(px(font::CAPTION)).font_weight(FontWeight::SEMIBOLD))
        }))
}

/// The user's own tile.
fn my_tile(s: Store, big: bool) -> AnyElement {
    let me = s.me.get_untracked();
    let look = field(|c| (c.video, c.muted, c.hand), (false, false, false));
    dynamic(move || {
        let (video, muted, hand) = look.get();
        let name = me.name.clone();
        untracked(move || tile(format!("{name} (you)"), me.seed, video, muted, hand, big))
    })
}

/// A group call's tiles: a grid, or the speaker big with the rest in a
/// strip. Tiles arrive one by one as people join.
fn group_stage(s: Store) -> View {
    let st = calls();
    let joined = computed(move || st.with(|x| x.call.as_ref().map(|c| c.joined()).unwrap_or_default()));
    let layout = field(|c| c.layout, Layout::Grid);
    // Speaker view's big tile: a raised hand first, else the first to join.
    let speaker = computed(move || joined.with(|j| j.iter().find(|p| p.hand).or(j.first()).cloned()));
    // Equal gutters: every cell pads 4pt and the grid pads 4pt, so tiles
    // sit 8pt from each other and from the stage's edges. Cells keep one
    // width (no grow), so a short last row centres instead of stretching.
    let cell = move || {
        view()
            .w(if wide() { relative(1.0 / 3.0) } else { relative(0.5) })
            .p(px(4.0))
    };
    let shape = move || if wide() { 16.0 / 9.0 } else { 1.0 };
    let person = move |p: ReadSignal<Participant>, _i: ReadSignal<usize>| {
        let p = p.get_untracked();
        cell().child(arrive(0.96, 0.0, motion::SLOW).aspect_ratio(shape()).child(dynamic(move || {
            // Follows their mute and hand without remaking the arrival.
            let now = calls().with(|x| {
                x.call.as_ref().and_then(|c| c.participants.iter().find(|q| q.id == p.id).cloned())
            });
            let q = now.unwrap_or_else(|| p.clone());
            untracked(move || tile(q.name, q.seed, q.video, q.muted, q.hand, false))
        })))
    };
    view().flex_1().child(dynamic(move || {
        let l = layout.get();
        untracked(move || match l {
            Layout::Grid => scroll()
                .flex_1()
                .child(
                    view()
                        .flex_row()
                        .flex_wrap()
                        .justify_center()
                        .p(px(4.0))
                        .child(cell().child(view().aspect_ratio(shape()).child(my_tile(s, false))))
                        .child(each(move || joined.get(), |p: &Participant| p.id, person)),
                )
                .into_element(),
            Layout::Speaker => view()
                .flex_1()
                .gap_2()
                .p_2()
                .child(dynamic(move || {
                    let first = speaker.get();
                    untracked(move || match first {
                        Some(p) => tile(p.name, p.seed, p.video, p.muted, p.hand, true).into_element(),
                        None => my_tile(s, true),
                    })
                }))
                .child(
                    scroll()
                        .horizontal()
                        .h(px(132.0))
                        .child(
                            // Centred under the speaker; the speaker is not
                            // repeated here.
                            view()
                                .flex_row()
                                .min_w(relative(1.0))
                                .justify_center()
                                .gap_2()
                                .child(view().w(px(160.0)).child(my_tile(s, false)))
                                .child(each(
                                    move || {
                                        let big = speaker.with(|p| p.as_ref().map(|p| p.id));
                                        joined.with(|j| j.iter().filter(|p| Some(p.id) != big).cloned().collect::<Vec<_>>())
                                    },
                                    |p: &Participant| p.id,
                                    |p, _| {
                                        let p = p.get_untracked();
                                        arrive(0.96, 0.0, motion::SLOW)
                                            .w(px(160.0))
                                            .child(tile(p.name, p.seed, p.video, p.muted, p.hand, false))
                                    },
                                )),
                        ),
                )
                .into_element(),
        })
    }))
}

/// A 1:1 call's stage: their big avatar and status, or their video with
/// the user's self-view in a corner.
fn direct_stage(s: Store, big: f32) -> View {
    let title = calls().with_untracked(|x| x.call.as_ref().map(|c| (c.title.clone(), c.seed)).unwrap_or_default());
    let status = field(state::status, String::new());
    let ringing = field(|c| matches!(c.phase, Phase::Calling | Phase::Ringing | Phase::Connecting | Phase::Lobby), false);
    let video_on = field(|c| c.video && c.phase == Phase::Connected, false);
    let theirs = field(|c| c.participants.first().is_some_and(|p| p.video), false);
    let (name, seed) = title.clone();
    let voice = move || {
        let (name, seed) = (name.clone(), seed);
        view()
            .flex_1()
            .items_center()
            .justify_center()
            .gap_3()
            .px_6()
            .child(ringing_avatar(name.clone(), seed, false, big, move || ringing.get()))
            .child(
                text(name)
                    .text_size(px(font::DISPLAY))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_center()
                    .number_of_lines(2)
                    .role(AccessibilityRole::Header),
            )
            .child(
                text(move || status.get())
                    .text_size(px(font::TITLE))
                    .tabular_nums()
                    .text_center()
                    .text_color(move || c::on_call().opacity(0.8)),
            )
    };
    let (vname, vseed) = title;
    let video = move || {
        let (name, seed) = (vname.clone(), vseed);
        view()
            .flex_1()
            .p_2()
            .child(arrive(0.98, 0.0, motion::SLOW).flex_1().child(tile(name, seed, theirs.get_untracked(), false, false, true)))
            .child(
                view()
                    .absolute()
                    .top(px(16.0))
                    .left(px(0.0))
                    .right(px(0.0))
                    .items_center()
                    .child(
                        text(move || status.get())
                            .px_3()
                            .py_1()
                            .rounded_full()
                            .bg(move || c::call_bg().opacity(0.6))
                            .text_size(px(font::SMALL))
                            .tabular_nums(),
                    ),
            )
            .child(self_view(s))
    };
    view().flex_1().child(when(move || video_on.get(), video).otherwise(voice))
}

/// The user's self-view in a corner, with flip camera on phones.
fn self_view(s: Store) -> View {
    let me = s.me.get_untracked();
    let video = field(|c| c.video, false);
    let front = field(|c| c.front_camera, true);
    let (w, h) = if is_desktop() { (180.0, 112.0) } else { (104.0, 150.0) };
    // The camera runs while the user's video is on, and stops with it and with the call
    // (D-0110). A demo or test camera has no live picture: the portrait stands in.
    let session = crate::camera::use_session(songbird_camera::Purpose::Call, move || video.get(), |_| {});
    let live = crate::camera::has_live_preview();
    let flip = session.clone();
    arrive(0.9, 8.0, motion::BASE)
        .absolute()
        .right(px(20.0))
        .bottom(px(20.0))
        .w(px(w))
        .h(px(h))
        .rounded(move || radius::lg())
        .overflow_hidden()
        .border_2()
        .border_color(move || c::on_call().opacity(0.3))
        .bg(move || if video.get() && !crate::ui::portrait::has_photo(me.seed) { c::avatar(me.seed) } else { c::call_bg() })
        .items_center()
        .justify_center()
        .label(move || if video.get() { "Your camera" } else { "Your camera is off" })
        // The same picture as the user's tile and their row in the
        // participants sheet (mock: the portrait stands for the camera).
        .child(when(move || video.get() && live, move || crate::camera::preview_fill(&session)))
        .child(when(move || video.get() && !live, {
            let n = me.name.clone();
            move || match feed(me.seed, false) {
                Some(f) => f.into_element(),
                None => text(initials(&n)).text_size(px(font::HEADING)).font_weight(FontWeight::SEMIBOLD).text_color(move || c::on_avatar()).into_element(),
            }
        })
        .otherwise(|| view().into_element()))
        .child(when(move || !video.get(), || icon(Icon::VideoOff, 22.0).text_color(move || c::on_call().opacity(0.7))))
        .child((!is_desktop()).then(|| {
            view().absolute().top(px(4.0)).right(px(4.0)).child(call_btn(
                || Icon::FlipCamera,
                move || if front.get() { "Flip to back camera".into() } else { "Flip to front camera".into() },
                CallTone::Neutral,
                || false,
                36.0,
                false,
                move || {
                    with_call(|c| c.front_camera = !c.front_camera);
                    flip.flip();
                },
            ))
        }))
}

/// A quiet pill on a primary-coloured banner: the banner's own ink,
/// on a veil of it.
fn on_primary_pill(glyph: Icon, label: &'static str, on_press: impl Fn() + 'static) -> nsh_base::ButtonElement {
    nsh_base::button()
        .on_press(on_press)
        .accessibility_label(label)
        .h(px(32.0))
        .px_3()
        .flex_row()
        .items_center()
        .gap_2()
        .rounded_full()
        .bg(move || c::on_primary().opacity(0.16))
        .text_color(move || c::on_primary())
        .cursor_pointer()
        .transition_colors()
        .duration(motion::FAST)
        .hover(|st| st.bg(move || c::on_primary().opacity(0.24)))
        .active(|st| st.bg(move || c::on_primary().opacity(0.3)))
        .focus_visible(|st| st.outline(px(2.0)).outline_color(move || c::on_primary()))
        .child(icon(glyph, 14.0))
        .child(text(label).text_size(px(font::SMALL)).font_weight(FontWeight::SEMIBOLD).number_of_lines(1))
}

/// Notices over the stage: screen sharing, the lobby, less data.
fn notices(people: Signal<bool>) -> View {
    let sharing = field(|c| c.sharing, None);
    let waiting = field(|c| c.waiting.len(), 0);
    let first_waiting = field(|c| c.waiting.first().map(|w| (w.id, w.name.clone())), None);
    let hands = field(|c| c.joined().iter().filter(|p| p.hand).map(|p| p.name.clone()).collect::<Vec<_>>(), Vec::new());
    let s = crate::store::store();
    let low = move || s.settings.with(|x| x.low_data_calls);
    view()
        .gap_2()
        .px_3()
        .child(when(move || sharing.get().is_some(), move || {
            arrive(1.0, -8.0, motion::BASE)
                .flex_row()
                .items_center()
                .gap_3()
                .px_3()
                .py_2()
                .rounded(move || radius::control())
                // The brand's colour, not green: green on the call surface
                // means "answer".
                .bg(move || c::primary())
                .text_color(move || c::on_primary())
                .role(AccessibilityRole::Alert)
                .child(icon(Icon::ScreenShare, 18.0))
                .child(
                    text(move || match sharing.get() {
                        Some(Share::Window) => "You are sharing a window",
                        _ => "You are sharing your screen",
                    })
                    .flex_1()
                    .text_size(px(font::SMALL + 1.0))
                    .font_weight(FontWeight::SEMIBOLD),
                )
                .child(on_primary_pill(Icon::Close, "Stop sharing", || {
                    with_call(|c| c.sharing = None);
                    announce_for_accessibility("You stopped sharing your screen");
                }))
        }))
        .child(when(move || waiting.get() > 0, move || {
            arrive(1.0, -8.0, motion::BASE)
                .flex_row()
                .flex_wrap()
                .items_center()
                .gap_2()
                .px_3()
                .py_2()
                .rounded(move || radius::control())
                .bg(move || c::on_call().opacity(0.12))
                .child(icon(Icon::Users, 18.0))
                .child(
                    text(move || match waiting.get() {
                        1 => "1 person waiting".to_string(),
                        n => format!("{n} people waiting"),
                    })
                    .flex_1()
                    .text_size(px(font::SMALL + 1.0))
                    .font_weight(FontWeight::SEMIBOLD),
                )
                .child(dynamic(move || {
                    let first = first_waiting.get();
                    untracked(move || {
                        first.map(|(id, name)| {
                            view()
                                .flex_row()
                                .gap_2()
                                .child(call_pill(Icon::Ban, format!("Deny {name}"), move || with_call(|c| c.admit(id, false))))
                                .child(call_pill(Icon::Check, format!("Admit {name}"), move || with_call(|c| c.admit(id, true))))
                        })
                    })
                }))
                .child(call_pill(Icon::Users, "Review", move || people.set(true)))
        }))
        .child(when(move || !hands.with(Vec::is_empty), move || {
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .px_3()
                .py_2()
                .rounded(move || radius::control())
                .bg(move || c::on_call().opacity(0.12))
                .child(icon(Icon::Hand, 16.0))
                .child(
                    text(move || format!("{} raised a hand", hands.with(|h| h.join(", "))))
                        .text_size(px(font::SMALL + 1.0)),
                )
        }))
        .child(when(low, || {
            view()
                .self_center()
                .flex_row()
                .items_center()
                .gap_1()
                .child(icon(Icon::Zap, 13.0))
                .child(text("Using less data").text_size(px(font::CAPTION)))
                .text_color(move || c::on_call().opacity(0.75))
        }))
}

/// The top bar of the call: minimise, title and lock line, and the
/// group's layout and participants.
fn top_bar(verify: Signal<bool>, people: Signal<bool>) -> View {
    let title = calls().with_untracked(|x| x.call.as_ref().map(|c| c.title.clone()).unwrap_or_default());
    let group = calls().with_untracked(|x| x.call.as_ref().is_some_and(|c| c.group));
    let ended = field(|c| c.ended(), false);
    let count = field(|c| c.joined().len() + 1, 1);
    let layout = field(|c| c.layout, Layout::Grid);
    // Phones: Minimise is a round button, so the centred title and lock
    // line keep their room; both side lanes are equal so the centre is true.
    let roomy = wide();
    let lane = if roomy { 132.0 } else { 88.0 };
    view()
        .flex_row()
        .items_center()
        .gap_2()
        .px_3()
        .py_2()
        .child(
            view().w(px(lane)).flex_row().child(when(move || !ended.get(), move || {
                if roomy {
                    call_pill(Icon::Minimize, "Minimise", || set_minimised(true)).into_element()
                } else {
                    call_btn(|| Icon::Minimize, || "Minimise".into(), CallTone::Neutral, || false, 40.0, false, || set_minimised(true))
                        .into_element()
                }
            })),
        )
        .child(
            view()
                .flex_1()
                .items_center()
                .gap(px(2.0))
                .child(group.then(|| {
                    text(title.clone())
                        .number_of_lines(1)
                        .text_size(px(font::TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .role(AccessibilityRole::Header)
                }))
                .child(lock_line(verify)),
        )
        .child(
            view()
                .w(px(lane))
                .flex_row()
                .justify_end()
                .gap_2()
                .child(group.then(|| {
                    view()
                        .flex_row()
                        .gap_2()
                        .child(call_btn(
                            move || if layout.get() == Layout::Grid { Icon::SpeakerView } else { Icon::Grid },
                            move || if layout.get() == Layout::Grid { "Speaker view".into() } else { "Grid view".into() },
                            CallTone::Neutral,
                            || false,
                            if is_desktop() { 36.0 } else { 40.0 },
                            false,
                            || with_call(|c| c.layout = if c.layout == Layout::Grid { Layout::Speaker } else { Layout::Grid }),
                        ))
                        .child(call_btn(
                            || Icon::Users,
                            move || format!("Participants, {}", count.get()).into(),
                            CallTone::Neutral,
                            || false,
                            if is_desktop() { 36.0 } else { 40.0 },
                            false,
                            move || people.set(true),
                        ))
                })),
        )
}

/// The controls under the stage. Phones: speaker, camera, mute, more,
/// end. Desktops: mute, camera, share, hand (groups), devices, more, end.
fn controls(sheets: Sheets) -> View {
    let muted = field(|c| c.muted, false);
    let video = field(|c| c.video, false);
    let speaker = field(|c| c.speaker, false);
    let hand = field(|c| c.hand, false);
    let sharing = field(|c| c.sharing.is_some(), false);
    let ended = field(|c| c.ended(), false);
    let group = calls().with_untracked(|x| x.call.as_ref().is_some_and(|c| c.group));
    let desktop = is_desktop();
    let compact = !wide();
    // 64pt circles on phones (thumb targets, a caption under each), 56pt
    // on desktops; the gaps are on the 4pt scale.
    let size = if compact { 64.0 } else { 56.0 };
    let s = crate::store::store();
    let mute = move || {
        call_btn(
            move || if muted.get() { Icon::MicOff } else { Icon::Mic },
            move || if compact { "Mute".into() } else if muted.get() { "Unmute".into() } else { "Mute".into() },
            CallTone::Neutral,
            move || muted.get(),
            size,
            compact,
            toggle_mute,
        )
    };
    let camera = move || {
        call_btn(
            move || if video.get() { Icon::Video } else { Icon::VideoOff },
            move || if compact { "Camera".into() } else if video.get() { "Turn camera off".into() } else { "Turn camera on".into() },
            CallTone::Neutral,
            move || video.get(),
            size,
            compact,
            toggle_video,
        )
    };
    let end = move || {
        call_btn(|| Icon::PhoneOff, move || if compact { "End".into() } else { "End call".into() }, CallTone::Decline, || false, size, compact, move || hang_up(s))
    };
    let more = move || {
        call_btn(|| Icon::MoreHorizontal, || "More".into(), CallTone::Neutral, || false, size, compact, move || sheets.more.set(true))
    };
    let build = move || {
    let row = view()
        .flex_row()
        .flex_wrap()
        .justify_center()
        .items_start()
        .gap(px(if compact { 8.0 } else { 12.0 }))
        .px_3()
        .pt_3()
        .pb_safe_area_plus(px(20.0));
    let share = move || {
        call_btn(
            || Icon::ScreenShare,
            move || if compact { "Share".into() } else if sharing.get() { "Stop sharing".into() } else { "Share screen".into() },
            CallTone::Neutral,
            move || sharing.get(),
            size,
            compact,
            move || {
                if sharing.get_untracked() {
                    with_call(|c| c.sharing = None);
                } else {
                    sheets.share.set(true);
                }
            },
        )
    };
    let row = if !compact {
        row.child(mute())
            .child(camera())
            .child(share())
            .child(group.then(|| {
                call_btn(
                    || Icon::Hand,
                    move || if hand.get() { "Lower hand".into() } else { "Raise hand".into() },
                    CallTone::Neutral,
                    move || hand.get(),
                    size,
                    false,
                    || with_call(|c| c.hand = !c.hand),
                )
            }))
            .child(call_btn(|| Icon::Sliders, || "Audio and video settings".into(), CallTone::Neutral, || false, size, false, move || sheets.devices.set(true)))
            .child(more())
            // End stands apart: 32pt from the toggles (gap, spacer, gap).
            .child(view().w(px(8.0)))
            .child(end())
    } else if desktop {
        row.child(share()).child(camera()).child(mute()).child(more()).child(end())
    } else {
        row.child(call_btn(
            || Icon::Speaker,
            || "Speaker".into(),
            CallTone::Neutral,
            move || speaker.get(),
            size,
            true,
            || with_call(|c| c.speaker = !c.speaker),
        ))
        .child(camera())
        .child(mute())
        .child(more())
        .child(end())
    };
    row
    };
    view().child(when(move || !ended.get(), build).otherwise(|| view().h(px(96.0))))
}

/// The call's sheets, opened from the controls.
#[derive(Clone, Copy)]
struct Sheets {
    verify: Signal<bool>,
    people: Signal<bool>,
    more: Signal<bool>,
    devices: Signal<bool>,
    share: Signal<bool>,
}

impl Sheets {
    fn new() -> Self {
        Self { verify: signal(false), people: signal(false), more: signal(false), devices: signal(false), share: signal(false) }
    }
}

/// The surface itself (stage, notices, controls), and its sheets.
fn call_body(s: Store) -> View {
    let sheets = Sheets::new();
    let group = calls().with_untracked(|x| x.call.as_ref().is_some_and(|c| c.group));
    let connected = field(|c| c.phase == Phase::Connected, false);
    let status = field(state::status, String::new());
    let lobby = field(|c| c.phase == Phase::Lobby, false);
    let ended = field(|c| c.ended(), false);
    let stage = if group {
        let title = calls().with_untracked(|x| x.call.as_ref().map(|c| (c.title.clone(), c.seed)).unwrap_or_default());
        view()
            .flex_1()
            .child(
                when(move || connected.get() && !ended.get(), move || group_stage(s))
                    .otherwise(move || {
                        let (name, seed) = title.clone();
                        view()
                            .flex_1()
                            .items_center()
                            .justify_center()
                            .gap_3()
                            .px_6()
                            .child(ringing_avatar(name, seed, true, if is_desktop() { 96.0 } else { 112.0 }, move || !ended.get()))
                            .child(
                                text(move || status.get())
                                    .text_size(px(font::TITLE))
                                    .text_center()
                                    .tabular_nums()
                                    .text_color(move || c::on_call().opacity(0.85)),
                            )
                            .child(when(move || lobby.get(), || {
                                text("An admin of this call link lets people in. You'll join as soon as they do.")
                                    .max_w(px(320.0))
                                    .text_center()
                                    .text_size(px(font::SMALL + 1.0))
                                    .line_height(px(20.0))
                                    .text_color(move || c::on_call().opacity(0.7))
                            }))
                    }),
            )
    } else {
        direct_stage(s, if is_desktop() { 112.0 } else { 128.0 })
    };
    view()
        .flex_1()
        .bg(move || c::call_bg())
        .text_color(move || c::on_call())
        .child(top_bar(sheets.verify, sheets.people))
        .child(notices(sheets.people))
        .child(stage)
        .child(controls(sheets))
        .child(sheets_of(s, sheets))
}

/// Phones: the call fills the screen.
fn phone_surface(s: Store) -> AnyElement {
    panel_keys();
    arrive(0.98, 0.0, motion::SLOW)
        .absolute()
        .inset_0()
        .bg(move || c::call_bg())
        .pt_safe_area()
        .child(call_body(s))
        .into_element()
}

/// Phones, minimised: a bar at the top to go back to the call.
fn phone_bar() -> AnyElement {
    let status = field(state::status, String::new());
    let title = calls().with_untracked(|x| x.call.as_ref().map(|c| c.title.clone()).unwrap_or_default());
    arrive(1.0, -8.0, motion::BASE)
        .absolute()
        .top_0()
        .left_0()
        .right_0()
        .bg(move || c::primary())
        .pt_safe_area()
        .child(
            nsh_base::button()
                .on_press(|| set_minimised(false))
                .accessibility_label(format!("Return to call with {title}"))
                .h(px(40.0))
                .flex_row()
                .items_center()
                .justify_center()
                .gap_2()
                .active(|st| st.opacity(0.85))
                .text_color(move || c::on_primary())
                .child(icon(Icon::Phone, 15.0))
                .child(
                    text(move || format!("Tap to return to call · {}", status.get()))
                        .text_size(px(font::SMALL + 1.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .tabular_nums(),
                ),
        )
        .into_element()
}

/// The desktop rail's width (`shell::rail`): the call panel starts at
/// its edge, so the sections stay whole and reachable beside the call.
const RAIL_W: f32 = 84.0;

/// Desktops: the call fills the content area, edge to edge from the
/// rail's border to the window's right edge, top to bottom. Escape or
/// Minimise shrinks it to the corner player.
fn panel(s: Store) -> AnyElement {
    panel_keys();
    view()
        .absolute()
        .top_0()
        .bottom_0()
        .right_0()
        .left(px(RAIL_W))
        .child(
            arrive(0.99, 0.0, motion::BASE)
                .flex_1()
                .bg(move || c::call_bg())
                .role(AccessibilityRole::Dialog)
                .label("Call")
                .child(call_body(s)),
        )
        .into_element()
}

/// Desktops, minimised: a small always-on-top player in the corner.
fn mini_player(s: Store) -> AnyElement {
    let status = field(state::status, String::new());
    let (title, seed, group) = calls()
        .with_untracked(|x| x.call.as_ref().map(|c| (c.title.clone(), c.seed, c.group)).unwrap_or_default());
    let muted = field(|c| c.muted, false);
    let video = field(|c| c.video, false);
    let sharing = field(|c| c.sharing.is_some(), false);
    arrive(0.96, 8.0, motion::BASE)
        .absolute()
        .right(px(20.0))
        .bottom(px(20.0))
        .w(px(320.0))
        .p_3()
        .gap_3()
        .rounded(move || radius::lg())
        .bg(move || c::call_bg())
        .text_color(move || c::on_call())
        .border_1()
        .border_color(move || c::on_call().opacity(0.14))
        .shadow_lg()
        .role(AccessibilityRole::Dialog)
        .label("Call, minimised")
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_3()
                .child(call_avatar(title.clone(), seed, group, 48.0))
                .child(
                    view()
                        .flex_1()
                        .min_w(px(0.0))
                        .gap(px(2.0))
                        .child(
                            text(title.clone())
                                .number_of_lines(1)
                                .text_size(px(font::body()))
                                .font_weight(FontWeight::SEMIBOLD),
                        )
                        .child(
                            view()
                                .flex_row()
                                .items_center()
                                .gap_1()
                                .text_color(move || c::on_call().opacity(0.75))
                                .child(icon(Icon::Lock, 12.0))
                                .child(text(move || status.get()).text_size(px(font::SMALL)).tabular_nums()),
                        )
                        .child(when(move || sharing.get(), || {
                            text("Sharing your screen").text_size(px(font::CAPTION)).font_weight(FontWeight::MEDIUM).text_color(move || c::on_call().opacity(0.85))
                        }))
                        .child(group.then(|| text("Group call").text_size(px(font::CAPTION)).text_color(move || c::on_call().opacity(0.6)))),
                ),
        )
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(call_btn(
                    move || if muted.get() { Icon::MicOff } else { Icon::Mic },
                    move || if muted.get() { "Unmute".into() } else { "Mute".into() },
                    CallTone::Neutral,
                    move || muted.get(),
                    36.0,
                    false,
                    toggle_mute,
                ))
                .child(call_btn(
                    move || if video.get() { Icon::Video } else { Icon::VideoOff },
                    move || if video.get() { "Turn camera off".into() } else { "Turn camera on".into() },
                    CallTone::Neutral,
                    move || video.get(),
                    36.0,
                    false,
                    toggle_video,
                ))
                .child(view().flex_1())
                .child(call_pill(Icon::Maximize, "Return to call", || set_minimised(false)))
                .child(call_btn(|| Icon::PhoneOff, || "End call".into(), CallTone::Decline, || false, 36.0, false, move || hang_up(s))),
        )
        .into_element()
}

// ------------------------------------------------------------------ sheets

/// Where the call's stage starts: the rail's edge on wide windows (the
/// panel's), the screen's edge on phones.
fn stage_left() -> f32 {
    if wide() { RAIL_W } else { 0.0 }
}

fn sheets_of(s: Store, sheets: Sheets) -> View {
    // The sheets are the call's own surfaces: dark, in the call's ink.
    view()
        .child(verify_sheet(sheets.verify))
        .child(people_sheet(s, sheets.people))
        .child(more_sheet(sheets))
        .child(devices_sheet(sheets.devices))
        .child(share_sheet(sheets.share))
}

/// A line of text on a call sheet, centred, in the call's ink at `alpha`.
fn sheet_line(words: impl Into<SharedString>, alpha: f32, size: f32) -> Text {
    text(words.into())
        .text_center()
        .max_w(px(360.0))
        .self_center()
        .text_size(px(size))
        .line_height(px(size + 6.0))
        .text_color(move || c::on_call().opacity(alpha))
}

/// The verification code: four symbols both people compare.
fn verify_sheet(open: Signal<bool>) -> nsh_base::SheetElement {
    let code = field(|c| (c.phase == Phase::Connected).then(|| state::verification_code(c.id, c.chat)), None);
    let (who, group) = calls().with_untracked(|x| x.call.as_ref().map(|c| (c.title.clone(), c.group)).unwrap_or_default());
    let first = who.split_whitespace().next().unwrap_or("them").to_string();
    let compare = if group {
        "Compare these with the others in the call. If they match, your call is end-to-end encrypted.".to_string()
    } else {
        format!("Compare these with {first}. If they match, your call is end-to-end encrypted.")
    };
    call_sheet(
        open,
        "Verify this call",
        stage_left(),
        view()
            .px_4()
            .pb_4()
            .gap_4()
            .child(dynamic(move || {
                let code = code.get();
                untracked(move || match code {
                    Some(code) => view()
                        .flex_row()
                        .justify_center()
                        .gap_3()
                        .py_2()
                        .label(format!("Code: {}", code.iter().map(|(_, n)| *n).collect::<Vec<_>>().join(", ")))
                        .children(code.into_iter().map(|(sym, name)| {
                            // Tiles a clear step lighter than the sheet.
                            view()
                                .w(px(72.0))
                                .py_3()
                                .items_center()
                                .gap_1()
                                .rounded(move || radius::lg())
                                .bg(move || c::on_call().opacity(0.12))
                                .border(hairline())
                                .border_color(move || c::on_call().opacity(0.16))
                                .accessibility_elements_hidden(true)
                                .child(text(sym).text_size(px(font::DISPLAY + 4.0)))
                                .child(text(name).text_size(px(font::CAPTION)).text_color(move || c::on_call().opacity(0.7)))
                        }))
                        .into_element(),
                    None => view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .p_3()
                        .rounded(move || radius::control())
                        .bg(move || c::on_call().opacity(0.08))
                        .child(icon(Icon::Clock, 16.0))
                        .child(text("The code appears once the call connects.").flex_1().text_size(px(font::SMALL + 1.0)))
                        .into_element(),
                })
            }))
            // A measure narrower than the sheet, so the centred lines
            // balance instead of leaving a word alone on the last line.
            .child(sheet_line(compare, 0.95, font::body()))
            .child(sheet_line(
                "The code is new for every call. Read it aloud to each other. If it doesn't match, end the call and call again.",
                0.65,
                font::SMALL + 1.0,
            )),
    )
}

/// A small text button on a call sheet: `primary` fills it with the
/// brand colour, otherwise a veil of the call's ink.
fn sheet_btn(label: &'static str, primary: bool, on_press: impl Fn() + 'static) -> nsh_base::ButtonElement {
    nsh_base::button()
        .on_press(on_press)
        .accessibility_label(label)
        .h(px(32.0))
        .px_3()
        .items_center()
        .justify_center()
        .rounded_full()
        .bg(move || if primary { c::primary() } else { c::on_call().opacity(0.14) })
        .text_color(move || if primary { c::on_primary() } else { c::on_call() })
        .cursor_pointer()
        .hover(|st| st.opacity(0.88))
        .active(|st| st.opacity(0.8))
        .focus_visible(|st| st.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::on_call()))
        .child(text(label).text_size(px(font::SMALL)).font_weight(FontWeight::SEMIBOLD))
}

/// Everyone in the call, and the lobby for admins. The same pictures as
/// the tiles: each person's portrait, seeded by their contact id.
fn people_sheet(s: Store, open: Signal<bool>) -> nsh_base::SheetElement {
    let st = calls();
    let joined = computed(move || st.with(|x| x.call.as_ref().map(|c| c.joined()).unwrap_or_default()));
    let waiting = computed(move || st.with(|x| x.call.as_ref().map(|c| c.waiting.clone()).unwrap_or_default()));
    let me = s.me.get_untracked();
    let mine = field(|c| (c.muted, c.hand), (false, false));
    let marks = |muted: bool, hand: bool| {
        view()
            .flex_row()
            .gap_2()
            .text_color(move || c::on_call().opacity(0.7))
            .child(hand.then(|| icon(Icon::Hand, 18.0)))
            .child(if muted { icon(Icon::MicOff, 18.0) } else { icon(Icon::Mic, 18.0) })
            .into_element()
    };
    let person = |name: String, seed: u64| Some(avatar(name, seed, 36.0).into_element());
    call_sheet(
        open,
        "In this call",
        stage_left(),
        scroll().max_h(px(460.0)).child(
            view()
                .pb_4()
                .child(when(move || waiting.with(|w| !w.is_empty()), move || {
                    view()
                        .child(call_section("Waiting to join"))
                        .child(call_group([each(
                            move || waiting.get(),
                            |w: &state::Waiting| w.id,
                            move |w, at| {
                                let w = w.get_untracked();
                                let id = w.id;
                                view().child(when(move || at.get() > 0, || view().ml(px(52.0)).h(hairline()).bg(move || c::on_call().opacity(0.12)))).child(call_row(
                                    person(w.name.clone(), w.seed),
                                    w.name.clone(),
                                    Some("Asked to join".into()),
                                    Some(
                                        view()
                                            .flex_row()
                                            .gap_2()
                                            .child(sheet_btn("Deny", false, move || with_call(|c| c.admit(id, false))))
                                            .child(sheet_btn("Admit", true, move || with_call(|c| c.admit(id, true))))
                                            .into_element(),
                                    ),
                                    None,
                                ))
                            },
                        )
                        .into_element()]))
                }))
                // The sheet's title already says "In this call": the section
                // only counts, in tabular figures like every count.
                .child(call_section(move || format!("{} people", joined.with(Vec::len) + 1)).tabular_nums())
                .child(call_group([
                    dynamic(move || {
                        let (m, h) = mine.get();
                        let me = me.clone();
                        untracked(move || call_row(person(me.name.clone(), me.seed), format!("{} (you)", me.name), None, Some(marks(m, h)), None))
                    })
                    .into_element(),
                    each(
                        move || joined.get(),
                        |p: &Participant| (p.id, p.muted, p.hand),
                        move |p, at| {
                            let p = p.get_untracked();
                            let sub = if p.hand { Some("Hand raised".into()) } else if p.muted { Some("Muted".into()) } else { None };
                            // The group's rule sits above the first; the rest
                            // draw their own.
                            view()
                                .child(when(move || at.get() > 0, || view().ml(px(52.0)).h(hairline()).bg(move || c::on_call().opacity(0.12))))
                                .child(call_row(person(p.name.clone(), p.seed), p.name.clone(), sub, Some(marks(p.muted, p.hand)), None))
                        },
                    )
                    .into_element(),
                ])),
        ),
    )
}

/// More: voice ↔ video, verify, and for groups hand, layout and
/// participants. What the control bar already shows is not repeated.
fn more_sheet(sheets: Sheets) -> nsh_base::SheetElement {
    let open = sheets.more;
    let group = calls().with_untracked(|x| x.call.as_ref().is_some_and(|c| c.group));
    let video = field(|c| c.video, false);
    let hand = field(|c| c.hand, false);
    let layout = field(|c| c.layout, Layout::Grid);
    let then = move |f: fn(Sheets)| -> Box<dyn Fn()> {
        Box::new(move || {
            open.set(false);
            f(sheets);
        })
    };
    let glyph = |g: Icon| Some(icon(g, 20.0).into_element());
    // Wide windows show the hand and devices buttons in the bar; the
    // narrow desktop bar shows share but not devices.
    let roomy = wide();
    let narrow_desktop = is_desktop() && !roomy;
    call_sheet(
        open,
        "More",
        stage_left(),
        view()
            .pb_4()
            .gap_3()
            .child(call_group([
                dynamic(move || {
                    let v = video.get();
                    untracked(move || {
                        call_row(
                            glyph(if v { Icon::Phone } else { Icon::Video }),
                            if v { "Switch to voice call" } else { "Switch to video call" },
                            None,
                            None,
                            Some(Box::new(move || {
                                open.set(false);
                                toggle_video();
                            })),
                        )
                    })
                })
                .into_element(),
                call_row(glyph(Icon::ShieldCheck), "Verify this call", None, None, Some(then(|s| s.verify.set(true)))),
            ]))
            .child(group.then(|| {
                call_group([
                    dynamic(move || {
                        let h = hand.get();
                        untracked(move || {
                            call_row(
                                glyph(Icon::Hand),
                                if h { "Lower hand" } else { "Raise hand" },
                                None,
                                None,
                                Some(Box::new(move || {
                                    open.set(false);
                                    with_call(|c| c.hand = !c.hand);
                                })),
                            )
                        })
                    })
                    .into_element(),
                    dynamic(move || {
                        let l = layout.get();
                        untracked(move || {
                            call_row(
                                glyph(if l == Layout::Grid { Icon::SpeakerView } else { Icon::Grid }),
                                if l == Layout::Grid { "Speaker view" } else { "Grid view" },
                                None,
                                None,
                                Some(Box::new(move || {
                                    open.set(false);
                                    with_call(|c| c.layout = if c.layout == Layout::Grid { Layout::Speaker } else { Layout::Grid });
                                })),
                            )
                        })
                    })
                    .into_element(),
                    call_row(glyph(Icon::Users), "Participants", None, None, Some(then(|s| s.people.set(true)))),
                ])
            }))
            .child(narrow_desktop.then(|| {
                call_group([call_row(glyph(Icon::Sliders), "Audio and video settings", None, None, Some(then(|s| s.devices.set(true))))])
            }))
            // Keyboard shortcuts only where there is a keyboard and room.
            .child((is_desktop() && roomy).then(|| {
                call_note(format!(
                    "Shortcuts: M mutes, V turns the camera on or off, Esc minimises, {} hangs up.",
                    key_label("shift+mod+h")
                ))
            })),
    )
}

/// Desktops: microphone, camera and speakers (mock devices), with the
/// microphone's level.
fn devices_sheet(open: Signal<bool>) -> nsh_base::SheetElement {
    let mic = field(|c| c.mic, 0);
    let cam = field(|c| c.camera, 0);
    let out = field(|c| c.output, 0);
    let pick = |names: &'static [&'static str], current: Memo<usize>, set: fn(&mut state::ActiveCall, usize)| {
        call_group(names.iter().enumerate().map(move |(i, name)| {
            call_row(
                None,
                *name,
                None,
                Some(
                    view()
                        .text_color(move || c::on_call())
                        .style_when(move || current.get() != i, |st| st.opacity(0.0))
                        .child(icon(Icon::Check, 18.0))
                        .into_element(),
                ),
                Some(Box::new(move || {
                    with_call(|c| set(c, i));
                    announce_for_accessibility(format!("{name} selected"));
                })),
            )
        }))
    };
    call_sheet(
        open,
        "Audio and video",
        stage_left(),
        scroll().max_h(px(460.0)).child(
            view()
                .pb_4()
                .child(
                    view()
                        .flex_row()
                        .items_end()
                        .pr_4()
                        .child(call_section("Microphone").flex_1())
                        .child(view().pb_2().child(level_meter())),
                )
                .child(pick(&MICS, mic, |c, i| c.mic = i))
                .child(call_section("Camera"))
                .child(pick(&CAMERAS, cam, |c, i| c.camera = i))
                .child(call_section("Speakers"))
                .child(pick(&OUTPUTS, out, |c, i| c.output = i))
                .child(call_note("Devices are read from your computer. Songbird uses them only during calls.")),
        ),
    )
}

/// Desktops: what to share.
fn share_sheet(open: Signal<bool>) -> nsh_base::SheetElement {
    let start = move |what: Share| -> Box<dyn Fn()> {
        Box::new(move || {
            open.set(false);
            with_call(|c| {
                c.sharing = Some(what);
                c.minimised = false;
            });
            announce_for_accessibility("You are sharing your screen");
        })
    };
    call_sheet(
        open,
        "Share your screen",
        stage_left(),
        view()
            .pb_4()
            .child(call_group([
                call_row(
                    Some(icon(Icon::Laptop, 20.0).into_element()),
                    "Entire screen",
                    Some("Everything on your display, including notifications".into()),
                    None,
                    Some(start(Share::EntireScreen)),
                ),
                call_row(Some(icon(Icon::Layers, 20.0).into_element()), "Window", Some("One app's window".into()), None, Some(start(Share::Window))),
            ]))
            .child(call_note("People in the call will see what you share. It's end-to-end encrypted, like the rest of the call.")),
    )
}
