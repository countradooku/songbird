//! Appearance: the theme (switches the app's tokens live through
//! `theming.rs`), the app icon (Plus), text size and motion notes.

use nsh_core::prelude::*;

use super::{links, section};
use crate::{
    store::{Plan, ThemeChoice, store},
    ui::*,
};

pub fn appearance() {
    super::push("Appearance", content);
}

/// The app icons: the feather on four grounds drawn from tokens.
const ICONS: [&str; 4] = ["Songbird", "Night", "Paper", "Lavender"];

fn content() -> AnyElement {
    let s = store();
    let settings = s.settings;
    let ext = s.ext();
    let plus = move || settings.with(|x| x.plan != Plan::Free);
    view()
        .child(section_title("Theme"))
        // A list of choices, not a segmented control: four labels with
        // "High contrast" don't fit one line on a phone, and each choice
        // says what it does.
        .child(group_plain(
            [
                (ThemeChoice::System, "System", "Follows your device's light or dark setting."),
                (ThemeChoice::Light, "Light", "Always light, whatever your device uses."),
                (ThemeChoice::Dark, "Dark", "Always dark, easier on the eyes at night."),
                (ThemeChoice::HighContrast, "High contrast", "Stronger text, borders and colours, in light or dark."),
            ]
            .into_iter()
            .map(move |(choice, title, line)| {
                radio_row(title, Some(line), move || settings.with(|x| x.theme == choice), move || {
                    s.settings_update(|x| x.theme = choice)
                })
            }),
        )
        .role(AccessibilityRole::Radiogroup)
        .label("Theme"))
        // The Plus tag sits right after the title it qualifies.
        .child(
            view()
                .flex_row()
                .items_end()
                .child(section_title("App icon").pr_0())
                .child(when(move || !plus(), || view().pl_2().pb_2().child(tag("Plus")))),
        )
        .child(
            view()
                .mx_4()
                .p_3()
                .rounded(move || radius::lg())
                .bg(move || c::card())
                .border_1()
                .border_color(move || c::border())
                .flex_row()
                .flex_wrap()
                .gap_3()
                .role(AccessibilityRole::Radiogroup)
                .label("App icon")
                .children(ICONS.iter().enumerate().map(move |(i, name)| {
                    let i = i as u8;
                    let name: &'static str = name;
                    view()
                        .items_center()
                        .gap_1()
                        .child(tile(
                            format!("{name} app icon"),
                            64.0,
                            move || ext.with(|x| x.app_icon == i),
                            move || {
                                if i > 0 && !plus() {
                                    toast("App icons come with Songbird Plus");
                                    links::subscription();
                                } else {
                                    // mock: the platform's alternate-icon API.
                                    s.ext_update(|x| x.app_icon = i);
                                }
                            },
                            view()
                                .relative()
                                .child(app_icon(i))
                                // A lock on the icons Plus unlocks: not colour alone.
                                .child(when(move || i > 0 && !plus(), || {
                                    view()
                                        .absolute()
                                        .right(px(-6.0))
                                        .bottom(px(-6.0))
                                        .size(px(20.0))
                                        .rounded_full()
                                        .items_center()
                                        .justify_center()
                                        .bg(move || c::card())
                                        .border_1()
                                        .border_color(move || c::border())
                                        .text_color(move || c::muted_fg())
                                        .accessibility_elements_hidden(true)
                                        .child(icon(Icon::Lock, 11.0))
                                })),
                        ))
                        .child(text(name).text_size(px(font::CAPTION)).text_color(move || c::muted_fg()))
                }))
                .child(when(move || !plus(), || {
                    muted("Choose another icon with Songbird Plus.").w_full()
                })),
        )
        .child(section(
            "Display",
            vec![
                Row::new("Text size")
                    .icon(Icon::Sliders)
                    .subtitle("Songbird follows your device's text size. Change it in your device's settings.")
                    .build(),
                Row::new("Reduce motion")
                    .icon(Icon::Zap)
                    .subtitle(if motion::reduced() {
                        "On in your device's settings: Songbird keeps movement to fades."
                    } else {
                        "Songbird follows your device's reduce motion setting."
                    })
                    .build(),
            ],
        ))
        .into_element()
}

/// A small app-icon drawing: the feather on a token ground.
fn app_icon(i: u8) -> View {
    view()
        .size(px(44.0))
        .rounded(move || radius::control())
        .items_center()
        .justify_center()
        .accessibility_elements_hidden(true)
        .bg(move || match i {
            1 => c::call_bg(),
            2 => c::card(),
            3 => c::accent(),
            _ => c::primary(),
        })
        .border_1()
        .border_color(move || c::border())
        .text_color(move || match i {
            1 => c::on_call(),
            2 => c::foreground(),
            3 => c::primary(),
            _ => c::on_primary(),
        })
        .child(icon(Icon::Feather, 24.0))
}
