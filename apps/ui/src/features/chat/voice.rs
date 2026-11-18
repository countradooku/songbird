//! Voice notes: playback (mock: a clock moves the position, as the audio
//! player app-core drives will), the speed, and notes playing on.

use std::{collections::HashMap, time::Duration};

use nsh_core::prelude::*;

use super::{Conv, logic};
use crate::store::{Body, MsgId};

/// Which note plays, where each note is, how fast.
#[derive(Clone, Copy)]
pub(crate) struct Player {
    pub playing: Signal<Option<MsgId>>,
    /// Seconds into each note started (kept when paused).
    pub pos: Signal<HashMap<MsgId, f32>>,
    pub speed: Signal<f32>,
}

const TICK_MS: u64 = 100;

impl Player {
    pub fn new() -> Self {
        Player { playing: signal(None), pos: signal(HashMap::new()), speed: signal(1.0) }
    }

    /// Plays or pauses note `id`.
    pub fn toggle(self, cv: Conv, id: MsgId) {
        if self.playing.get_untracked() == Some(id) {
            self.playing.set(None);
            return;
        }
        if let Some(m) = cv.s.message(cv.chat, id)
            && !m.mine()
        {
            // mock: app-core sends the "played" receipt when playback starts.
            cv.s.mark_played(cv.chat, id);
        }
        self.playing.set(Some(id));
    }

    /// The next speed: 1× → 1.5× → 2× → 1×.
    pub fn cycle_speed(self) {
        self.speed.update(|s| {
            *s = if *s < 1.25 {
                1.5
            } else if *s < 1.75 {
                2.0
            } else {
                1.0
            }
        });
    }

    pub fn speed_label(self) -> String {
        let s = self.speed.get();
        if (s - 1.5).abs() < 0.01 { "1.5×".into() } else { format!("{}×", s as u32) }
    }

    /// How far into note `id` playback is, 0..1.
    pub fn fraction(self, id: MsgId, secs: u32) -> f32 {
        let at = self.pos.with(|p| p.get(&id).copied().unwrap_or(0.0));
        (at / secs.max(1) as f32).clamp(0.0, 1.0)
    }

    /// Seconds left (or the length, at rest).
    pub fn remaining(self, id: MsgId, secs: u32) -> u32 {
        let at = self.pos.with(|p| p.get(&id).copied().unwrap_or(0.0));
        secs.saturating_sub(at as u32)
    }

    fn tick(self, cv: Conv) {
        let Some(id) = self.playing.get_untracked() else { return };
        let secs = match cv.s.message(cv.chat, id).map(|m| m.body) {
            Some(Body::Voice { secs, .. }) => secs as f32,
            _ => {
                self.playing.set(None);
                return;
            }
        };
        let step = TICK_MS as f32 / 1000.0 * self.speed.get_untracked();
        let mut done = false;
        self.pos.update(|p| {
            let at = p.entry(id).or_insert(0.0);
            *at += step;
            if *at >= secs {
                p.remove(&id);
                done = true;
            }
        });
        if done {
            let chat = cv.chat;
            let next = cv.s.messages.with_untracked(|m| {
                let v = m.get(&chat)?;
                let i = v.iter().position(|x| x.id == id)?;
                logic::next_voice(v, i).map(|j| v[j].id)
            });
            match next {
                Some(next) => self.toggle(cv, next),
                None => self.playing.set(None),
            }
        }
    }
}

/// Runs the playback clock while a note plays.
pub(crate) fn install(cv: Conv) {
    let player = cv.voice;
    effect(move || {
        if player.playing.get().is_some() {
            let clock = set_interval(Duration::from_millis(TICK_MS), move || player.tick(cv));
            cleanup(move || clock.cancel());
        }
    });
}

/// The waveform: bars in the bubble's quiet ink, the played part in its
/// accent (the user's full-colour bubble draws both from its text colour).
pub(crate) fn waveform(
    cv: Conv,
    id: impl Fn() -> MsgId + Copy + 'static,
    secs: impl Fn() -> u32 + Copy + 'static,
    ink: impl Fn() -> super::theme::Ink + Copy + 'static,
) -> View {
    const BARS: usize = 28;
    let player = cv.voice;
    let shape = computed(move || logic::waveform(id(), BARS));
    view()
        .flex_1()
        .h(px(28.0))
        .flex_row()
        .items_center()
        .gap(px(2.0))
        .accessibility_elements_hidden(true)
        .children((0..BARS).map(move |i| {
            let on = move || player.fraction(id(), secs()) * BARS as f32 > i as f32;
            view()
                .w(px(3.0))
                .rounded_full()
                .h(move || px(4.0 + 22.0 * shape.with(|s| s.get(i).copied().unwrap_or(0.4))))
                .bg(move || if on() { ink().accent } else { ink().quiet })
                .opacity(move || if on() { 1.0_f32 } else { 0.55 })
        }))
}
