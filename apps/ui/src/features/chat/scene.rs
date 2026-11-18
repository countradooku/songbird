//! Chat scenes and sound stickers (Prompt 9, M6).
//!
//! **A scene** is an installed Scene pack chosen in chat info. It is the
//! per-chat record `c/<chat>/scene` (encrypted, synced to the user's
//! devices) and shows as the conversation's background treatment: the
//! pack's artwork scattered faintly over the theme's canvas, behind the
//! messages, never taking a press or a screen reader's attention.
//! mock: telling the chat's members (`Content.scene_change`) is app-core's.
//!
//! **A sound sticker** (a sticker from a Sound stickers pack) plays its
//! sound when it shows if "Sound stickers play automatically" is on, else
//! when its speaker button is pressed. mock: packs carry no audio until the
//! pack service delivers it (A7), so each sticker's sound is a short chirp
//! made on the device from the sticker (NSH's `load_sound` plays it).
//!
//! Motion (MOTION_chat.md "Chat scene"): the scene cross-fades in and out
//! over `SLOW` and is still after that (a background must not compete
//! with the messages); with reduced motion, the same fade. The sheet is
//! the app's sheet; the speaker button presses like every icon button.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

use nsh_core::prelude::*;

use crate::{
    store::{ChatId, MsgId, ext_groups::PackKind, ext_groups::groups_state, store},
    ui::*,
};

/// "Chat scene" in chat info: the scene's name, or None; opens the picker.
pub fn scene_row(chat: ChatId, open: Signal<bool>) -> AnyElement {
    let s = store();
    let name = move || {
        s.chat_scene(chat)
            .map(|p| p.name)
            .unwrap_or_else(|| "None".into())
    };
    Row::new("Chat scene")
        .icon(Icon::Sparkles)
        .trailing(
            view()
                .flex_row()
                .items_center()
                .gap_1()
                .child(muted(name))
                .child(
                    icon(Icon::ChevronRight, 16.0)
                        .mr(px(-4.0))
                        .text_color(move || c::muted_fg()),
                ),
        )
        .on_press(move || open.set(true))
        .build()
}

/// The scene picker: None, then every installed Scene pack.
pub fn scene_sheet(chat: ChatId, open: Signal<bool>) -> AnyElement {
    let s = store();
    let packs = computed(move || {
        groups_state().with(|g| {
            g.packs
                .iter()
                .filter(|p| p.kind == PackKind::Scenes)
                .map(|p| (p.id, p.name.clone(), p.items.join(" ")))
                .collect::<Vec<_>>()
        })
    });
    let current = move || s.scenes().with(|m| m.0.get(&chat).copied());
    let choose = move |pack: Option<u64>| {
        s.set_chat_scene(chat, pack);
        open.set(false);
    };
    view()
        .child(app_sheet(
            open,
            "Chat scene",
            view()
                .gap_3()
                .pb_4()
                .child(
                    footnote(
                        "A scene sits behind this chat's messages, on all your devices. Add more scenes from a pack link in Stickers and packs.",
                    )
                    .px_4(),
                )
                .child(dynamic(move || {
                    let list = packs.get();
                    untracked(move || {
                        let none = radio_row(
                            "None",
                            Some("Just the chat's theme"),
                            move || current().is_none(),
                            move || choose(None),
                        );
                        group_plain(std::iter::once(none).chain(list.into_iter().map(
                            move |(id, name, items)| {
                                radio_row(
                                    format!("{name}  {items}"),
                                    None,
                                    move || current() == Some(id),
                                    move || choose(Some(id)),
                                )
                            },
                        )))
                        .role(AccessibilityRole::Radiogroup)
                        .label("Chat scene")
                    })
                })),
        ))
        .into_element()
}

/// Where each piece of a scene sits (fractions of the canvas), as a calm
/// scatter that never lines up into a grid.
const SPOTS: [(f32, f32, f32); 10] = [
    (0.08, 0.10, 30.0),
    (0.72, 0.06, 24.0),
    (0.40, 0.22, 36.0),
    (0.86, 0.30, 28.0),
    (0.14, 0.42, 26.0),
    (0.58, 0.48, 32.0),
    (0.30, 0.64, 24.0),
    (0.80, 0.70, 30.0),
    (0.10, 0.84, 34.0),
    (0.52, 0.88, 26.0),
];

/// The chat's scene behind its messages: faint, still, decorative.
pub(crate) fn scene_layer(chat: ChatId) -> AnyElement {
    let s = store();
    let items = computed(move || s.chat_scene(chat).map(|p| p.items).unwrap_or_default());
    view()
        .absolute()
        .inset_0()
        .overflow_hidden()
        .accessibility_elements_hidden(true)
        .opacity(move || {
            if items.with(Vec::is_empty) {
                0.0_f32
            } else {
                0.16
            }
        })
        .transition_opacity()
        .duration(motion::SLOW)
        .child(dynamic(move || {
            let list = items.get();
            untracked(move || {
                view()
                    .absolute()
                    .inset_0()
                    .children(SPOTS.iter().enumerate().filter_map(|(i, (x, y, size))| {
                        let glyph = list.get(i % list.len().max(1))?.clone();
                        Some(
                            text(glyph)
                                .absolute()
                                .left(relative(*x))
                                .top(relative(*y))
                                .text_size(px(*size)),
                        )
                    }))
            })
        }))
        .into_element()
}

// ---------------------------------------------------------------- sound stickers

thread_local! {
    /// Decoded sounds, by sticker (a sound plays from memory).
    static SOUNDS: RefCell<HashMap<String, Sound>> = RefCell::new(HashMap::new());
    /// Sound stickers that already played by themselves this session.
    static PLAYED: RefCell<HashSet<(ChatId, MsgId)>> = RefCell::new(HashSet::new());
}

/// A short chirp for a sticker: a 16-bit mono WAV, rising and fading, its
/// pitch from the sticker so each sounds its own.
pub fn chirp(sticker: &str) -> Vec<u8> {
    const RATE: u32 = 22_050;
    let n = (RATE as f32 * 0.32) as usize;
    let seed = sticker
        .chars()
        .map(|c| c as u32)
        .fold(7_u32, |a, c| a.wrapping_mul(31).wrapping_add(c));
    let base = 520.0 + (seed % 9) as f32 * 70.0;
    let mut pcm = Vec::with_capacity(n * 2);
    let mut phase = 0.0_f32;
    for i in 0..n {
        let t = i as f32 / n as f32;
        let freq = base * (1.0 + 0.6 * t);
        phase += std::f32::consts::TAU * freq / RATE as f32;
        let env = (t * 12.0).min(1.0) * (1.0 - t).powi(2);
        let v = (phase.sin() * env * 0.5 * f32::from(i16::MAX)) as i16;
        pcm.extend_from_slice(&v.to_le_bytes());
    }
    let mut w = Vec::with_capacity(44 + pcm.len());
    let len = pcm.len() as u32;
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + len).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16_u32.to_le_bytes());
    w.extend_from_slice(&1_u16.to_le_bytes());
    w.extend_from_slice(&1_u16.to_le_bytes());
    w.extend_from_slice(&RATE.to_le_bytes());
    w.extend_from_slice(&(RATE * 2).to_le_bytes());
    w.extend_from_slice(&2_u16.to_le_bytes());
    w.extend_from_slice(&16_u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&len.to_le_bytes());
    w.extend_from_slice(&pcm);
    w
}

/// Plays a sound sticker's sound (loaded once, then from memory). Silence
/// where nothing plays sound: the sticker still shows.
pub(crate) fn play(sticker: &str) {
    let key = sticker.to_string();
    if let Some(sound) = SOUNDS.with(|m| m.borrow().get(&key).cloned()) {
        sound.play(0.8, 1.0);
        return;
    }
    spawn(async move {
        match load_sound(chirp(&key)).await {
            Ok(sound) => {
                sound.play(0.8, 1.0);
                SOUNDS.with(|m| m.borrow_mut().insert(key, sound));
            }
            Err(e) => log::debug!("sound sticker: {e:?}"),
        }
    });
}

/// Plays a sound sticker by itself once, when it first shows, if the user
/// lets sound stickers play automatically.
pub(crate) fn autoplay(chat: ChatId, id: MsgId, sticker: &str) {
    if !store()
        .settings
        .with_untracked(|x| x.sound_stickers_autoplay)
    {
        return;
    }
    if PLAYED.with(|p| p.borrow_mut().insert((chat, id))) {
        play(sticker);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chirp_is_a_valid_wav_and_differs_by_sticker() {
        let a = chirp("🐦");
        assert_eq!(&a[..4], b"RIFF");
        assert_eq!(&a[8..16], b"WAVEfmt ");
        let data = u32::from_le_bytes([a[40], a[41], a[42], a[43]]) as usize;
        assert_eq!(a.len(), 44 + data);
        assert_ne!(chirp("🐦"), chirp("🔔"));
    }
}
