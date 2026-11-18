//! A8: calls — the Calls tab, incoming call, in-call controls, group
//! calls, call links and lobby, verification code, desktop call window.
//!
//! One call at a time lives in a global ([`state::CallState`]); every
//! screen reads it and changes it through the functions here. The call
//! layer, mounted once at the root, drives the mock's clock while a call
//! exists and draws the call: full screen on phones, a panel that
//! shrinks to a corner player on desktops, the ringing card, the ended
//! state.
//!
//! **Mock.** No media yet: no LiveKit, no microphone or camera, no keys.
//! The phases advance on timers ([`state`]); app-core's call API
//! (`app_core::calls`) replaces `begin`, `tick` and the toggles.

mod ringing;
mod state;
mod surface;
mod tab;

use std::time::Duration;

use nsh_core::prelude::*;

use crate::{
    store::{ChatKind, ChatId, Store, store},
    ui::*,
};

pub use state::{CallState, Layout, MicAccess, Share};
use state::{ActiveCall, EndReason, Participant, Phase, Waiting};
pub use tab::calls_tab;

/// The call global.
fn calls() -> Signal<CallState> {
    global::<CallState>()
}

/// Changes the active call, if there is one.
fn with_call(f: impl FnOnce(&mut ActiveCall)) {
    calls().update(|s| {
        if let Some(c) = s.call.as_mut() {
            f(c);
        }
    });
}

/// A memo of one field of the active call: bindings that read it run only
/// when it changes, not on every tick.
fn field<T: Clone + PartialEq + 'static>(f: impl Fn(&ActiveCall) -> T + 'static, none: T) -> Memo<T> {
    let st = calls();
    computed(move || st.with(|s| s.call.as_ref().map(&f).unwrap_or_else(|| none.clone())))
}

/// A call id for the mock (the real one comes from signalling).
fn next_id() -> u64 {
    let n = global::<CallSerial>();
    n.update(|x| x.0 += 1);
    n.with_untracked(|x| x.0)
}

#[derive(Default, Clone, PartialEq)]
struct CallSerial(u64);

/// The chat's title, hue, whether it is a group, and who would be in it.
fn describe(s: &Store, chat: ChatId) -> Option<(String, u64, bool, Vec<Participant>)> {
    let c = s.chat(chat)?;
    let group = !matches!(c.kind, ChatKind::Direct(_) | ChatKind::WhatsApp(_));
    let people: Vec<Participant> = if group {
        c.members
            .iter()
            .filter_map(|m| m.contact)
            .filter_map(|id| s.contact(id))
            .take(7)
            .enumerate()
            .map(|(i, p)| Participant {
                id: p.id,
                name: p.name,
                seed: p.id,
                // mock: a few people join muted, some with video.
                muted: i % 3 == 1,
                hand: false,
                video: i % 2 == 0,
                joins_at: i as u32 * 3,
            })
            .collect()
    } else {
        s.peer(chat)
            .map(|p| Participant { id: p.id, name: p.name, seed: p.id, muted: false, hand: false, video: true, joins_at: 0 })
            .into_iter()
            .collect()
    };
    // A 1:1 call shows the person: their contact id is the portrait's
    // seed everywhere (lists, headers, calls). A group shows its scene.
    let seed = if group { c.seed } else { people.first().map_or(c.seed, |p| p.id) };
    Some((c.title, seed, group, people))
}

/// Opens the call in its first phase, behind the microphone explainer
/// on a desktop's first call.
fn begin(mut call: ActiveCall) {
    if calls().with_untracked(|s| s.call.as_ref().is_some_and(|c| !c.ended())) {
        toast("You're already in a call");
        return;
    }
    let mic = global::<MicAccess>();
    if is_desktop() && mic.get_untracked() != MicAccess::Allowed && call.phase != Phase::Incoming {
        call.after_permission = call.phase;
        call.phase = Phase::Permission;
    }
    if call.phase != Phase::Incoming {
        announce_for_accessibility(format!("Calling {}", call.title));
    }
    calls().set(CallState { call: Some(call) });
}

/// Starts a call in `chat`: a voice call, or a video call with `video`.
/// Direct chats ring the other person; groups start a group call.
pub fn start_call(chat: ChatId, video: bool) {
    let s = store();
    start_call_in(&s, chat, video);
}

fn start_call_in(s: &Store, chat: ChatId, video: bool) {
    let Some((title, seed, group, people)) = describe(s, chat) else { return };
    let mut call = ActiveCall::new(next_id(), title, seed, Phase::Calling);
    call.chat = Some(chat);
    call.group = group;
    call.video = video;
    call.participants = people;
    begin(call);
}

/// Mock: makes `chat` call the user, as a push would (the Calls tab's
/// demo rows use it). The real ring comes from app-core's push handler.
pub fn simulate_incoming(chat: ChatId, video: bool) {
    let s = store();
    simulate_in(&s, chat, video, false);
}

fn simulate_in(s: &Store, chat: ChatId, video: bool, elsewhere: bool) {
    let Some((title, seed, group, people)) = describe(s, chat) else { return };
    let mut call = ActiveCall::new(next_id(), title, seed, Phase::Incoming);
    call.chat = Some(chat);
    call.group = group;
    call.video = video;
    call.participants = people;
    call.answered_elsewhere = elsewhere;
    let name = call.title.clone();
    begin(call);
    if !elsewhere {
        s.ringing.set(Some((chat, video)));
    }
    announce_for_accessibility(format!("{name} is calling"));
}

/// Joins a call link: the user's own links open with the lobby on the
/// admin's side (people waiting); `guest` joins as someone waiting.
fn join_link(name: String, seed: u64, lobby: bool, guest: bool) {
    let phase = if lobby && guest { Phase::Lobby } else { Phase::Connecting };
    let mut call = ActiveCall::new(next_id(), name, seed, phase);
    call.group = true;
    // mock: who is already in the call, and who waits.
    let people = [("Ioana Ștefănescu", 3), ("Andrei Dumitrescu", 4), ("Priya Natarajan", 10)];
    call.participants = people
        .iter()
        .enumerate()
        .map(|(i, (n, id))| Participant {
            id: *id,
            name: (*n).into(),
            seed: *id,
            muted: i == 1,
            hand: false,
            video: i != 1,
            joins_at: i as u32 * 3,
        })
        .collect();
    if lobby && !guest {
        call.waiting = [("Amélie Durand", 8), ("Tomás Silva", 11), ("Cristina Pavel", 14)]
            .iter()
            .map(|(n, id)| Waiting { id: *id, name: (*n).into(), seed: *id })
            .collect();
    }
    begin(call);
}

// ------------------------------------------------------------------ actions

/// Ends the call (hang up, decline, leave the lobby) and logs it.
fn end(s: Store, reason: EndReason) {
    let mut log = None;
    let mut chat = None;
    let mut video = false;
    with_call(|c| {
        log = c.end(reason);
        chat = c.chat;
        video = c.video;
    });
    if let (Some((direction, secs)), Some(chat)) = (log, chat) {
        s.log_call(chat, video, direction, secs);
    }
    if let Some(line) = calls().with_untracked(|st| st.call.as_ref().map(state::status)) {
        announce_for_accessibility(line);
    }
}

fn hang_up(s: Store) {
    let reason = match calls().with_untracked(|st| st.call.as_ref().map(|c| c.phase)) {
        Some(Phase::Incoming) => EndReason::Declined,
        Some(Phase::Lobby) => EndReason::LeftLobby,
        _ => EndReason::Hangup,
    };
    end(s, reason);
}

fn accept(video: bool) {
    with_call(|c| c.accept(video));
}

fn toggle_mute() {
    with_call(|c| c.muted = !c.muted);
    let muted = calls().with_untracked(|s| s.call.as_ref().is_some_and(|c| c.muted));
    announce_for_accessibility(if muted { "Microphone off" } else { "Microphone on" });
}

fn toggle_video() {
    with_call(|c| c.video = !c.video);
    let on = calls().with_untracked(|s| s.call.as_ref().is_some_and(|c| c.video));
    announce_for_accessibility(if on { "Camera on" } else { "Camera off" });
}

fn set_minimised(minimised: bool) {
    with_call(|c| {
        if c.live() && !c.ended() {
            c.minimised = minimised;
        }
    });
}

/// Drives the mock clock and applies what each tick asks. Owned by the
/// call layer's branch, so it runs only while a call exists.
fn drive(s: Store) {
    set_interval(Duration::from_millis(state::TICK_MS), move || {
        let mut step = state::Step::default();
        let mut chat = None;
        let mut video = false;
        let before = calls().with_untracked(|st| st.call.as_ref().map(|c| c.phase));
        with_call(|c| {
            step = c.tick();
            chat = c.chat;
            video = c.video;
        });
        if let (Some((direction, secs)), Some(chat)) = (step.log, chat) {
            s.log_call(chat, video, direction, secs);
        }
        let after = calls().with_untracked(|st| st.call.as_ref().map(|c| c.phase));
        if before != after {
            if let Some(line) = calls().with_untracked(|st| st.call.as_ref().map(state::status)) {
                announce_for_accessibility(line);
            }
        }
        if step.clear {
            calls().set(CallState::default());
        }
    });
}

/// The keys of a call on desktops: M mute, V camera, Escape minimise,
/// Shift+Mod+H hang up. Every one also has a button.
fn keys(s: Store) {
    if !is_desktop() {
        return;
    }
    on_key("shift+mod+h", move |_| hang_up(s));
}

fn panel_keys() {
    if !is_desktop() {
        return;
    }
    on_key("m", |_| toggle_mute());
    on_key("v", |_| toggle_video());
    on_key("escape", |_| set_minimised(true));
}

/// The call layer over everything (incoming ring, active call, mini
/// player). Mounted once at the root; it draws nothing, takes no space
/// and no pointer events while there is no call.
pub fn call_layer() -> AnyElement {
    let s = store();
    let active = field(|_| true, false);
    when(move || active.get(), move || {
        drive(s);
        keys(s);
        surface::layer(s)
    })
    .into_element()
}

