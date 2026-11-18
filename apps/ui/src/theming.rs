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
        match nsh_base::tokens_of(Some(&theme_json_for(next.0, next.1))) {
            Ok(tokens) => set_tokens(tokens),
            Err(e) => log::warn!("theme: {e}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn every_theme_variant_parses_with_its_custom_tokens() {
        for (choice, skin) in [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark, ThemeChoice::HighContrast]
            .into_iter()
            .flat_map(|c| Skin::ALL.map(move |s| (c, s)))
        {
            let tokens = nsh_base::tokens_of(Some(&theme_json_for(choice, skin))).expect("theme parses");
            for name in [
                "chat-bg", "bubble-out", "bubble-in", "tick-read", "avatar-1", "danger-bg", "primary", "switch-thumb",
                "switch-track", "switch-on", "raised", "control",
            ] {
                assert!(tokens.color(name).is_some(), "{name} missing in {choice:?}");
            }
        }
    }
}
