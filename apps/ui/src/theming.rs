//! The user's theme choice (Settings → Appearance): follow the system,
//! always light, always dark, or high contrast. Built at run time from
//! the same `theme.json` the app ships with, so there is one source.
//! The platform skin (`ui::skin`) layers its surfaces (`theme.json`
//! `skins`) and its radii over the base before the user's choice applies.

use nsh_core::prelude::*;
use serde_json::{Map, Value};

use crate::{
    store::{Store, ThemeChoice},
    ui::skin::{self, Skin},
};

const THEME: &str = include_str!("../theme.json");

/// High-contrast overrides: pure surfaces, black or white text, stronger
/// borders and a darker primary. Body text and UI pairs reach AAA (7:1);
/// status and avatar colours inherited from the base theme stay at AA
/// (`docs/design/tools/contrast.py` reports each pair).
const HIGH_CONTRAST_LIGHT: &[(&str, &str)] = &[
    ("background", "#FFFFFF"),
    ("foreground", "#000000"),
    ("card", "#FFFFFF"),
    ("muted", "#F0F0F0"),
    ("muted-foreground", "#262626"),
    ("primary", "#362B8F"),
    ("accent", "#E2DCFA"),
    ("accent-foreground", "#1C1550"),
    ("border", "#4A4A4A"),
    ("input", "#262626"),
    ("ring", "#000000"),
    ("chat-bg", "#FFFFFF"),
    ("bubble-out", "#DCD5F8"),
    ("bubble-out-foreground", "#000000"),
    ("bubble-in", "#F0F0F0"),
    ("bubble-meta", "#262626"),
    ("tick-read", "#2A1F8A"),
    ("link", "#2A1F8A"),
    // Floating panes: the pane is the page's own white, so content made
    // for `background` sits in it seamlessly; the canvas a clear grey step
    // under it, and the strong border carries every pane's edge.
    ("canvas", "#E6E6E6"),
    ("pane", "#FFFFFF"),
    ("pane-border", "#4A4A4A"),
    ("capsule", "#FFFFFF"),
    ("capsule-border", "#4A4A4A"),
];

const HIGH_CONTRAST_DARK: &[(&str, &str)] = &[
    ("background", "#000000"),
    ("foreground", "#FFFFFF"),
    ("card", "#0A0A0A"),
    ("muted", "#141414"),
    ("muted-foreground", "#E0E0E0"),
    ("primary", "#C9C0FF"),
    ("primary-foreground", "#000000"),
    ("accent", "#2A2350"),
    ("accent-foreground", "#FFFFFF"),
    ("border", "#BDBDBD"),
    ("input", "#E0E0E0"),
    ("ring", "#FFFFFF"),
    ("chat-bg", "#000000"),
    ("bubble-out", "#2A2350"),
    ("bubble-out-foreground", "#FFFFFF"),
    ("bubble-in", "#161616"),
    ("bubble-meta", "#E0E0E0"),
    ("tick-read", "#D6CEFF"),
    ("link", "#D6CEFF"),
    // Nothing is darker than the black page, so the canvas steps up
    // instead; the light border, not the fill, makes each pane's edge.
    ("canvas", "#1A1A1A"),
    ("pane", "#000000"),
    ("pane-border", "#BDBDBD"),
    ("capsule", "#0A0A0A"),
    ("capsule-border", "#BDBDBD"),
];

fn vars(theme: &mut Value, mode: &str) -> Map<String, Value> {
    theme["cssVars"][mode].as_object().cloned().unwrap_or_default()
}

/// The theme JSON for a choice, in the current skin.
pub fn theme_json(choice: ThemeChoice) -> String {
    theme_json_for(choice, skin::skin())
}

/// The theme JSON for a choice in `skin`: the skin's surfaces and radii
/// over the base, then the choice (high contrast last, so it always wins).
pub fn theme_json_for(choice: ThemeChoice, skin: Skin) -> String {
    let mut theme: Value = serde_json::from_str(THEME).expect("theme.json is valid");
    // The skins live beside cssVars; the token reader only knows cssVars.
    let skins = theme.as_object_mut().and_then(|o| o.remove("skins")).unwrap_or(Value::Null);
    for mode in ["light", "dark"] {
        if let (Some(over), Some(map)) = (skins[skin.name()][mode].as_object(), theme["cssVars"][mode].as_object_mut()) {
            for (k, v) in over {
                map.insert(k.clone(), v.clone());
            }
        }
    }
    let r = skin.spec().radius;
    if let Some(map) = theme["cssVars"]["theme"].as_object_mut() {
        for (k, v) in [
            ("radius", r.control),
            ("radius-sm", r.small),
            ("radius-lg", r.card),
            ("radius-bubble", r.bubble),
            ("radius-sheet", r.sheet),
        ] {
            map.insert(k.into(), Value::String(format!("{v}px")));
        }
    }
    let light = vars(&mut theme, "light");
    let dark = vars(&mut theme, "dark");
    match choice {
        ThemeChoice::System => {}
        ThemeChoice::Light => theme["cssVars"]["dark"] = Value::Object(light),
        ThemeChoice::Dark => theme["cssVars"]["light"] = Value::Object(dark),
        ThemeChoice::HighContrast => {
            for (mode, over) in [("light", HIGH_CONTRAST_LIGHT), ("dark", HIGH_CONTRAST_DARK)] {
                if let Some(map) = theme["cssVars"][mode].as_object_mut() {
                    for (k, v) in over {
                        map.insert((*k).into(), Value::String((*v).into()));
                    }
                }
            }
        }
    }
    theme.to_string()
}

/// Applies the theme choice now and whenever it changes.
pub fn follow_settings(s: Store) {
    let choice = computed(move || (s.settings.with(|x| x.theme), skin::tracked_skin()));
    skin::install_debug_shortcut();
    // Applied on the first run too: `cargo run` and embedding hosts don't
    // read nsh.json's "theme", so the app sets its own tokens always.
    let applied = stored(None::<(ThemeChoice, Skin)>);
    effect(move || {
        let next = choice.get();
        if applied.with(|a| *a) == Some(next) {
            return;
        }
        applied.with(|a| *a = Some(next));
        let json = theme_json_for(next.0, next.1);
        // The app's own copy first, so views that re-read on the token
        // change below already find the new values (`ui::tokens::role`).
        remember_custom(&json);
        match nsh_base::tokens_of(Some(&json)) {
            Ok(tokens) => set_tokens(tokens),
            Err(e) => log::warn!("theme: {e}"),
        }
    });
}

thread_local! {
    /// Every colour token of the theme last applied, by name: the fallback
    /// for custom names a runtime drops (`ui::tokens::role`).
    static CUSTOM: std::cell::RefCell<std::collections::HashMap<String, AdaptiveColor>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The colour token `name` of the theme last applied, from the app's own
/// copy of it.
pub fn custom_color(name: &str) -> Option<AdaptiveColor> {
    CUSTOM.with_borrow(|m| m.get(name).copied())
}

/// `#RRGGBB` or `#RRGGBBAA` as one mode's colour.
fn parse_hex(s: &str) -> Option<Hsla> {
    let h = s.strip_prefix('#')?;
    let (rgb, alpha) = match h.len() {
        6 => (u32::from_str_radix(h, 16).ok()?, 1.0),
        8 => (u32::from_str_radix(&h[..6], 16).ok()?, u8::from_str_radix(&h[6..], 16).ok()? as f32 / 255.0),
        _ => return None,
    };
    Some(AdaptiveColor::rgb(rgb, rgb).light.opacity(alpha))
}

/// Keeps every colour of the theme file `json` (its light and dark lists).
fn remember_custom(json: &str) {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return };
    let (light, dark) = (&v["cssVars"]["light"], &v["cssVars"]["dark"]);
    let mut map = std::collections::HashMap::new();
    for (k, l) in light.as_object().into_iter().flatten() {
        let d = dark.get(k).unwrap_or(l);
        if let (Some(l), Some(d)) = (l.as_str().and_then(parse_hex), d.as_str().and_then(parse_hex)) {
            map.insert(k.clone(), AdaptiveColor::new(l, d));
        }
    }
    CUSTOM.with_borrow_mut(|m| *m = map);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_apps_copy_of_the_tokens_answers_custom_names() {
        remember_custom(&theme_json_for(ThemeChoice::System, Skin::Apple));
        for name in ["raised", "capsule", "capsule-border", "canvas", "pane", "chat-bg", "overlay"] {
            assert!(custom_color(name).is_some(), "{name}");
        }
        assert!(parse_hex("#0F0D1A80").is_some_and(|c| (c.a - 128.0 / 255.0).abs() < 0.01));
    }

    #[test]
    fn every_skin_overrides_known_tokens_only() {
        let theme: Value = serde_json::from_str(THEME).unwrap();
        let base = theme["cssVars"]["light"].as_object().unwrap();
        for s in Skin::ALL {
            for mode in ["light", "dark"] {
                for k in theme["skins"][s.name()][mode].as_object().into_iter().flatten().map(|(k, _)| k) {
                    assert!(base.contains_key(k), "{s:?} {mode} overrides unknown token {k}");
                }
            }
        }
    }

    #[test]
    fn skins_set_their_radius_and_surfaces() {
        let fluent: Value = serde_json::from_str(&theme_json_for(ThemeChoice::System, Skin::Fluent)).unwrap();
        assert_eq!(fluent["cssVars"]["theme"]["radius"], "4px");
        assert_eq!(fluent["cssVars"]["theme"]["radius-lg"], "8px");
        assert!(fluent.get("skins").is_none(), "skins stay out of the token file");
        let material: Value = serde_json::from_str(&theme_json_for(ThemeChoice::Dark, Skin::Material)).unwrap();
        assert_eq!(material["cssVars"]["light"]["background"], "#141318", "forced dark keeps the skin's dark");
        let hc: Value = serde_json::from_str(&theme_json_for(ThemeChoice::HighContrast, Skin::Adwaita)).unwrap();
        assert_eq!(hc["cssVars"]["dark"]["background"], "#000000", "high contrast wins over the skin");
    }

    /// Content built for `background` sits straight in a pane, so in every
    /// skin and choice the two are the same colour, and the canvas differs.
    #[test]
    fn panes_are_the_page_surface_on_a_distinct_canvas() {
        for (choice, skin) in [ThemeChoice::System, ThemeChoice::HighContrast]
            .into_iter()
            .flat_map(|c| Skin::ALL.map(move |s| (c, s)))
        {
            let t: Value = serde_json::from_str(&theme_json_for(choice, skin)).unwrap();
            for mode in ["light", "dark"] {
                let v = &t["cssVars"][mode];
                assert_eq!(v["pane"], v["background"], "{choice:?} {skin:?} {mode}: pane is the page");
                assert_ne!(v["canvas"], v["pane"], "{choice:?} {skin:?} {mode}: the canvas shows");
            }
        }
    }

    #[test]
    fn every_theme_variant_parses_with_its_custom_tokens() {
        for (choice, skin) in [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark, ThemeChoice::HighContrast]
            .into_iter()
            .flat_map(|c| Skin::ALL.map(move |s| (c, s)))
        {
            let tokens = nsh_base::tokens_of(Some(&theme_json_for(choice, skin))).expect("theme parses");
            for name in [
                "chat-bg", "bubble-out", "bubble-in", "tick-read", "avatar-1", "danger-bg", "primary", "switch-thumb",
                "switch-track", "switch-on", "raised", "control", "canvas", "pane", "pane-border", "capsule",
                "capsule-border",
            ] {
                assert!(tokens.color(name).is_some(), "{name} missing in {choice:?}");
            }
        }
    }
}
