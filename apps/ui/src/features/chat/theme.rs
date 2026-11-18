//! Per-chat themes (REDESIGN.md "Per-chat themes"): each conversation's
//! canvas and the colour of the user's bubbles. The one place their
//! colours are written: they are per chat, so they can't be `theme.json`
//! tokens, and every other part of the conversation reads them from here.
//!
//! Each palette was drawn by eye, not generated. The canvas is quiet (a
//! breath of the hue over near-white or near-black), the user's bubble is
//! the confident colour with white text, and the dark variants are their
//! own designs: the bubble steps down in lightness, never inverted, so it
//! doesn't glare on a dark canvas. `soft` is the tint the user's cards
//! (polls, events, files, calls, contacts) sit on: those carry the app's
//! own controls, which are drawn for light surfaces, so they keep a pale
//! (light) or deep (dark) wash of the theme instead of the full colour.
//!
//! Every pair is checked in the tests below, against the shipped
//! `theme.json` and every skin's overrides: text on the bubble, the
//! bubble's quieter text, body and muted text on the canvas, and the
//! tokens the cards use on `soft`, all at 4.5:1 or more.

use nsh_core::prelude::*;

use crate::{
    store::{ChatId, ChatTheme, ThemeChoice, store},
    ui::*,
};

/// One theme's colours, light and dark.
#[derive(Clone, Copy)]
struct Palette {
    canvas: AdaptiveColor,
    bubble: AdaptiveColor,
    on_bubble: AdaptiveColor,
    soft: AdaptiveColor,
}

const fn palette(t: ChatTheme) -> Palette {
    // (light, dark) for each role.
    const fn p(
        canvas: (u32, u32),
        bubble: (u32, u32),
        on: (u32, u32),
        soft: (u32, u32),
    ) -> Palette {
        Palette {
            canvas: AdaptiveColor::rgb(canvas.0, canvas.1),
            bubble: AdaptiveColor::rgb(bubble.0, bubble.1),
            on_bubble: AdaptiveColor::rgb(on.0, on.1),
            soft: AdaptiveColor::rgb(soft.0, soft.1),
        }
    }
    match t {
        // Songbird's own violet: the brand primary as the bubble in light,
        // a softer, lifted violet in dark.
        ChatTheme::Dusk => p(
            (0xF3F2F8, 0x0D0C12),
            (0x4B3FA8, 0x5B4EC0),
            (0xFFFFFF, 0xFFFFFF),
            (0xECE8FB, 0x282249),
        ),
        // A dusty raspberry, warm without shouting; wine in dark.
        ChatTheme::Rose => p(
            (0xF8F2F4, 0x110C0E),
            (0xA33A5E, 0x8E3354),
            (0xFFFFFF, 0xFFFFFF),
            (0xF9E5EC, 0x3A1E29),
        ),
        // Burnt umber over parchment: warm, earthy, never yellow.
        ChatTheme::Sand => p(
            (0xF5F3EE, 0x100E0B),
            (0x7D5222, 0x7A5428),
            (0xFFFFFF, 0xFFFFFF),
            (0xF2E7D6, 0x352A1C),
        ),
        // A lichen green, greyed so it reads as nature, not as a brand.
        ChatTheme::Moss => p(
            (0xF1F4EF, 0x0B0E0B),
            (0x41663B, 0x3E6239),
            (0xFFFFFF, 0xFFFFFF),
            (0xE2ECDD, 0x1F3020),
        ),
        // Deep harbour teal-blue.
        ChatTheme::Sea => p(
            (0xEFF4F6, 0x0A0E11),
            (0x1F6480, 0x1F5B75),
            (0xFFFFFF, 0xFFFFFF),
            (0xDCEBF2, 0x132A35),
        ),
        // Blue-grey graphite: the calm one for work.
        ChatTheme::Slate => p(
            (0xF1F3F5, 0x0C0E10),
            (0x44515F, 0x45525F),
            (0xFFFFFF, 0xFFFFFF),
            (0xE1E6EC, 0x242C35),
        ),
        // Ink: near-navy on a cool grey; in dark, indigo on near-black.
        ChatTheme::Night => p(
            (0xECEDF2, 0x060709),
            (0x232744, 0x2E3260),
            (0xFFFFFF, 0xFFFFFF),
            (0xE3E5F0, 0x1B1E35),
        ),
    }
}

/// How strong the bubble's quieter text is (forwarded, the voice note's
/// time, a deleted message): the bubble's text over its own colour.
const QUIET: f32 = 0.80;
/// The wash inner surfaces of the user's bubble take (a quote, a link
/// card): the bubble's text colour, faintly.
const WASH: f32 = 0.14;

/// What a conversation looks like now: its theme under the user's
/// appearance choice. `Copy`, a memo's value (`Conv::look`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Look {
    pub theme: ChatTheme,
    pub choice: ThemeChoice,
}

impl Look {
    /// The chat's look, following its theme and the appearance setting.
    pub fn of(chat: ChatId) -> Memo<Look> {
        let s = store();
        computed(move || Look {
            theme: s.chats.with(|cs| {
                cs.iter()
                    .find(|c| c.id == chat)
                    .map(|c| c.theme)
                    .unwrap_or_default()
            }),
            choice: s.settings.with(|x| x.theme),
        })
    }

    /// High contrast keeps the app's own high-contrast tokens: a theme
    /// never weakens what the user asked to be strong.
    fn high_contrast(self) -> bool {
        self.choice == ThemeChoice::HighContrast
    }

    /// A palette colour under the user's forced appearance (Settings →
    /// Appearance writes the light tokens over the dark ones and back, so
    /// the theme does the same).
    fn fit(self, c: AdaptiveColor) -> AdaptiveColor {
        match self.choice {
            ThemeChoice::Light => AdaptiveColor::new(c.light, c.light),
            ThemeChoice::Dark => AdaptiveColor::new(c.dark, c.dark),
            ThemeChoice::System | ThemeChoice::HighContrast => c,
        }
    }

    /// The conversation's background.
    pub fn canvas(self) -> AdaptiveColor {
        if self.high_contrast() {
            c::chat_bg()
        } else {
            self.fit(palette(self.theme).canvas)
        }
    }

    /// Whether the user's bubbles take the full colour (white text). High
    /// contrast draws them as tinted cards in the tokens instead.
    pub fn confident(self) -> bool {
        !self.high_contrast()
    }

    /// The user's bubble.
    pub fn bubble(self) -> AdaptiveColor {
        if self.high_contrast() {
            c::bubble_out()
        } else {
            self.fit(palette(self.theme).bubble)
        }
    }

    /// Text on the user's bubble.
    pub fn on_bubble(self) -> AdaptiveColor {
        if self.high_contrast() {
            c::on_bubble_out()
        } else {
            self.fit(palette(self.theme).on_bubble)
        }
    }

    /// The tint the user's cards sit on.
    pub fn soft(self) -> AdaptiveColor {
        if self.high_contrast() {
            c::bubble_out()
        } else {
            self.fit(palette(self.theme).soft)
        }
    }

    /// The swatch's bubble colour (the picker shows each theme as it is,
    /// not as the high-contrast look would draw it).
    fn preview(theme: ChatTheme, choice: ThemeChoice) -> (AdaptiveColor, AdaptiveColor) {
        let l = Look {
            theme,
            choice: if choice == ThemeChoice::HighContrast {
                ThemeChoice::System
            } else {
                choice
            },
        };
        (l.canvas(), l.bubble())
    }
}

/// The colours inside one bubble: the user's full-colour bubble draws
/// everything from its own text colour; others' bubbles (and the user's
/// cards) use the app's tokens.
#[derive(Clone, Copy)]
pub(crate) struct Ink {
    pub fill: AdaptiveColor,
    pub text: AdaptiveColor,
    /// Secondary text: forwarded, a file's size, a voice note's time.
    pub quiet: AdaptiveColor,
    pub link: AdaptiveColor,
    pub mention: AdaptiveColor,
    /// An inner surface: a quote, a link preview, a speed chip.
    pub wash: AdaptiveColor,
    /// A control's fill inside the bubble (the play button, the waveform's
    /// played part, the quote's bar).
    pub accent: AdaptiveColor,
    pub on_accent: AdaptiveColor,
}

impl Ink {
    /// The ink of a bubble: the user's (`mine`), and a card or not.
    pub fn of(look: Look, mine: bool, card: bool) -> Ink {
        if mine && look.confident() && !card {
            let on = look.on_bubble();
            return Ink {
                fill: look.bubble(),
                text: on,
                quiet: on.opacity(QUIET),
                link: on,
                mention: on,
                wash: on.opacity(WASH),
                accent: on,
                on_accent: look.bubble(),
            };
        }
        let (fill, text) = if mine {
            (look.soft(), c::foreground())
        } else {
            (c::bubble_in(), c::on_bubble_in())
        };
        Ink {
            fill,
            text,
            quiet: c::bubble_meta(),
            link: c::link(),
            mention: c::mention(),
            wash: c::foreground().opacity(0.06),
            accent: c::primary(),
            on_accent: c::on_primary(),
        }
    }
}

/// A sender's name over the canvas: their avatar's hue at reduced
/// strength (a third of the way to the muted text), then darkened (light)
/// or lightened (dark) until it reads at 4.5:1 on this canvas.
pub(crate) fn sender_ink(contact: u64, canvas: AdaptiveColor) -> AdaptiveColor {
    let (hue, quiet) = (c::avatar(contact), c::muted_fg());
    let soft = |h: Hsla, q: Hsla| h.mix(q, 0.35);
    AdaptiveColor::new(
        legible(soft(hue.light, quiet.light), canvas.light),
        legible(soft(hue.dark, quiet.dark), canvas.dark),
    )
}

/// `ink`, stepped in lightness until it reads on `under` (4.6:1, a hair
/// over AA so rounding never lands under it).
pub(crate) fn legible(ink: Hsla, under: Hsla) -> Hsla {
    let lighten = under.luminance() < 0.5;
    let mut out = ink;
    for _ in 0..50 {
        if out.contrast_ratio(under) >= 4.6 {
            break;
        }
        let l = if lighten { out.l + 0.02 } else { out.l - 0.02 };
        out = out.lightness(l.clamp(0.0, 1.0));
    }
    out
}

// ---------------------------------------------------------------- picker

/// "Theme" in chat info: the chat's theme by name; it opens the picker.
/// Groups' info (`features::groups`) adds the same row with its own
/// `open` signal and [`theme_sheet`].
pub fn theme_row(chat: ChatId, open: Signal<bool>) -> AnyElement {
    let s = store();
    let name = move || {
        s.chats.with(|cs| {
            cs.iter()
                .find(|c| c.id == chat)
                .map(|c| c.theme.label())
                .unwrap_or("Dusk")
        })
    };
    Row::new("Theme")
        .icon(Icon::Palette)
        .trailing(
            view()
                .flex_row()
                .items_center()
                .gap_1()
                .child(muted(name))
                // On the trailing spine with the other rows' chevrons.
                .child(
                    icon(Icon::ChevronRight, 16.0)
                        .mr(px(-4.0))
                        .text_color(move || c::muted_fg()),
                ),
        )
        .on_press(move || open.set(true))
        .build()
}

/// The theme picker: a sheet of swatches, each a small conversation in
/// that theme. Choosing one applies it at once (the conversation behind
/// the sheet cross-fades to it), so the user sees it before closing.
pub fn theme_sheet(chat: ChatId, open: Signal<bool>) -> AnyElement {
    let s = store();
    let current = computed(move || {
        s.chats.with(|cs| {
            cs.iter()
                .find(|c| c.id == chat)
                .map(|c| c.theme)
                .unwrap_or_default()
        })
    });
    let choice = computed(move || s.settings.with(|x| x.theme));
    let grid = view()
        .flex_row()
        .flex_wrap()
        .justify_center()
        .gap_3()
        .px_4()
        .pb_6()
        .role(AccessibilityRole::Radiogroup)
        .label("Chat theme")
        .children(
            ChatTheme::ALL
                .into_iter()
                .map(move |t| swatch_tile(t, current, choice, move || s.set_chat_theme(chat, t))),
        );
    view()
        .child(app_sheet(
            open,
            "Theme",
            view()
                .gap_3()
                .child(
                    footnote(
                        "Only you see this. It tints this chat's background and your messages.",
                    )
                    .px_4(),
                )
                .child(grid),
        ))
        .into_element()
}

/// One theme in the picker: its canvas with a message from someone else
/// and one of yours, its name under it; the chosen one is ringed and
/// checked (shape, not only colour).
fn swatch_tile(
    theme: ChatTheme,
    current: Memo<ChatTheme>,
    choice: Memo<ThemeChoice>,
    pick: impl Fn() + 'static,
) -> AnyElement {
    let reduced = motion::reduced();
    let chosen = move || current.get() == theme;
    let colours = move || Look::preview(theme, choice.get());
    // Phones: a touch-sized tile; desktops: compact.
    let (w, h) = if is_desktop() {
        (72.0, 88.0)
    } else {
        (84.0, 100.0)
    };
    // A bubble in miniature: fully round ends, as the real ones read at
    // this scale.
    let bar = |width: f32| view().h(px(12.0)).w(px(width)).rounded_full();
    pressable()
        .on_press(pick)
        .selected(chosen)
        .role(AccessibilityRole::Radio)
        .accessibility_label(theme.label())
        .items_center()
        .gap_2()
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .active(move |st| {
            if reduced {
                st.opacity(0.85)
            } else {
                st.scale(motion::PRESS_SCALE)
            }
        })
        .focus_visible(|st| {
            st.outline(px(2.0))
                .outline_offset(px(2.0))
                .outline_color(move || c::ring())
        })
        .child(
            view()
                // The ring sits 2pt outside the tile, following its corner.
                .p(px(2.0))
                .rounded(px(spec().radius.card + 4.0))
                .border_2()
                .border_color(move || {
                    if chosen() {
                        c::primary()
                    } else {
                        AdaptiveColor::TRANSPARENT
                    }
                })
                .transition_colors()
                .duration(motion::FAST)
                .child(
                    view()
                        .w(px(w))
                        .h(px(h))
                        .p_2()
                        .gap(px(4.0))
                        .justify_end()
                        .rounded(move || radius::lg())
                        .border_curve(BorderCurve::Continuous)
                        .overflow_hidden()
                        .border(hairline())
                        .border_color(move || c::border())
                        .bg(move || colours().0)
                        .child(bar(w * 0.5).self_start().bg(move || c::bubble_in()))
                        .child(bar(w * 0.6).self_end().bg(move || colours().1))
                        .child(bar(w * 0.35).self_end().bg(move || colours().1)),
                )
                .child(when(chosen, move || {
                    view()
                        .absolute()
                        .top(px(-6.0))
                        .right(px(-6.0))
                        .size(px(20.0))
                        .rounded_full()
                        .items_center()
                        .justify_center()
                        .bg(move || c::primary())
                        .border_2()
                        .border_color(move || c::popover())
                        .text_color(move || c::on_primary())
                        .child(icon(Icon::Check, 12.0))
                })),
        )
        .child(
            text(theme.label())
                .text_size(px(font::CAPTION))
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || {
                    if chosen() {
                        c::foreground()
                    } else {
                        c::muted_fg()
                    }
                }),
        )
        .into_element()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const THEME: &str = include_str!("../../../theme.json");

    fn hex(s: &str) -> Hsla {
        let n = u32::from_str_radix(s.trim_start_matches('#'), 16).expect("a #RRGGBB token");
        AdaptiveColor::rgb(n, n).light
    }

    /// Every value `token` takes in `mode`: the base and each skin's
    /// override (the skins change surfaces and some text).
    fn token(mode: &str, name: &str) -> Vec<Hsla> {
        let t: Value = serde_json::from_str(THEME).unwrap();
        let mut out = vec![hex(t["cssVars"][mode][name]
            .as_str()
            .unwrap_or_else(|| panic!("{name}")))];
        for skin in t["skins"].as_object().into_iter().flatten().map(|(_, v)| v) {
            if let Some(v) = skin[mode][name].as_str() {
                out.push(hex(v));
            }
        }
        out
    }

    fn sides(c: AdaptiveColor) -> [(&'static str, Hsla); 2] {
        [("light", c.light), ("dark", c.dark)]
    }

    fn check(
        what: &str,
        theme: ChatTheme,
        mode: &str,
        fg: Hsla,
        bg: Hsla,
        failures: &mut Vec<String>,
    ) {
        let ratio = fg.contrast_ratio(bg);
        if ratio < 4.5 {
            failures.push(format!("{theme:?} {mode}: {what} {ratio:.2}:1"));
        }
    }

    #[test]
    fn every_theme_reads_at_aa() {
        let mut failures = Vec::new();
        for theme in ChatTheme::ALL {
            let p = palette(theme);
            for (i, (mode, canvas)) in sides(p.canvas).into_iter().enumerate() {
                let bubble = sides(p.bubble)[i].1;
                let on = sides(p.on_bubble)[i].1;
                let soft = sides(p.soft)[i].1;
                check("text on bubble", theme, mode, on, bubble, &mut failures);
                check(
                    "quiet text on bubble",
                    theme,
                    mode,
                    bubble.blend(on.opacity(QUIET)),
                    bubble,
                    &mut failures,
                );
                // A quote's name and text sit on the wash, inside the bubble.
                let wash = bubble.blend(on.opacity(WASH));
                check("text on a quote", theme, mode, on, wash, &mut failures);
                for fg in token(mode, "foreground") {
                    check(
                        "body text on canvas",
                        theme,
                        mode,
                        fg,
                        canvas,
                        &mut failures,
                    );
                    check("text on a card", theme, mode, fg, soft, &mut failures);
                }
                for fg in token(mode, "muted-foreground") {
                    check(
                        "time labels and status on canvas",
                        theme,
                        mode,
                        fg,
                        canvas,
                        &mut failures,
                    );
                }
                check(
                    "Not sent on canvas",
                    theme,
                    mode,
                    token(mode, "destructive")[0],
                    canvas,
                    &mut failures,
                );
                for name in ["primary", "link", "mention", "bubble-meta", "destructive"] {
                    check(name, theme, mode, token(mode, name)[0], soft, &mut failures);
                }
            }
        }
        assert!(failures.is_empty(), "below 4.5:1:\n{}", failures.join("\n"));
    }

    /// Quiet canvases: low chroma (HSL saturation × the distance from
    /// grey), so the bubbles carry the colour.
    #[test]
    fn canvases_are_quiet_and_bubbles_are_not() {
        for theme in ChatTheme::ALL {
            let p = palette(theme);
            for (mode, canvas) in sides(p.canvas) {
                let chroma = canvas.s * (1.0 - (2.0 * canvas.l - 1.0).abs());
                assert!(chroma < 0.03, "{theme:?} {mode} canvas chroma {chroma:.3}");
            }
            // The bubble stands off its canvas: clearly in light; in dark
            // more gently (a bright bubble would glare, and its white text,
            // checked above, carries it), Night the gentlest by design.
            for (mode, bubble) in sides(p.bubble) {
                let (canvas, least) = if mode == "light" {
                    (p.canvas.light, 3.0)
                } else {
                    (p.canvas.dark, 1.5)
                };
                let ratio = bubble.contrast_ratio(canvas);
                assert!(
                    ratio >= least,
                    "{theme:?} {mode}: the bubble on the canvas {ratio:.2}:1"
                );
            }
        }
    }

    #[test]
    fn forced_appearance_and_high_contrast() {
        let light = Look {
            theme: ChatTheme::Rose,
            choice: ThemeChoice::Light,
        };
        assert_eq!(light.canvas().dark, palette(ChatTheme::Rose).canvas.light);
        let dark = Look {
            theme: ChatTheme::Rose,
            choice: ThemeChoice::Dark,
        };
        assert_eq!(dark.bubble().light, palette(ChatTheme::Rose).bubble.dark);
        assert!(
            !Look {
                theme: ChatTheme::Rose,
                choice: ThemeChoice::HighContrast
            }
            .confident()
        );
    }
}
