//! Songbird, the app: an NSH Rust UI over app-core.
//!
//! - `ui`: the design system — tokens, icons and every styled control.
//! - `store`: the UI's view of app-core and its intents (mocked until A2).
//! - `nav` and `shell`: navigation and the phone and desktop layouts.
//! - `features`: the screens, one module per area of the prompt set.
//! - `camera`: the camera's sessions and states (D-0110); its platform code, and all `unsafe`,
//!   live in `songbird-camera`, so the app forbids `unsafe`.

#![forbid(unsafe_code)]

pub mod backend;
pub mod camera;
pub mod features;
pub mod nav;
pub mod shell;
pub mod store;
pub mod theming;
pub mod ui;

use nsh_core::prelude::*;

use crate::store::Store;

/// A developer or preview build: debug, or built with `SONGBIRD_PREVIEW_BUILD=1` exactly (for
/// screenshots and notification checks on emulators and devices). Preview builds skip the first
/// run on request, show the Calls tab's test rows and honour `SONGBIRD_DEMO_ARRIVALS`; a release
/// build does none of it, whatever else the variable holds (D-0100).
pub const PREVIEW_BUILD: bool = cfg!(debug_assertions) || is_one(option_env!("SONGBIRD_PREVIEW_BUILD"));

const fn is_one(v: Option<&str>) -> bool {
    match v {
        Some(s) => s.len() == 1 && s.as_bytes()[0] == b'1',
        None => false,
    }
}

#[cfg(test)]
mod preview_tests {
    #[test]
    fn only_exactly_one_marks_a_preview_build() {
        assert!(super::is_one(Some("1")));
        for v in [None, Some(""), Some("0"), Some("true"), Some("11"), Some(" 1")] {
            assert!(!super::is_one(v), "{v:?}");
        }
    }
}

/// The app's UI set (`nsh.json` `"rust"`).
#[native_module("songbird/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

/// Songbird's root: the store, the theme the user chose, the first run
/// or the app, and the layers over everything (calls, toasts).
#[component]
pub fn App() -> impl IntoElement {
    let s = Store::new();
    store::install(s);
    camera::install_for_app();
    backend::restore();
    theming::follow_settings(s);
    features::desktop::install_shortcuts();
    features::notify::install(features::desktop::current_chat);
    features::notify::demo_from_env();
    let onboarded = move || s.session.with(|x| x.onboarded);
    view()
        .flex_1()
        .bg(move || ui::c::background())
        .text_color(move || ui::c::foreground())
        .child(
            when(onboarded, || when(ui::wide, shell::desktop).otherwise(shell::phone))
                .otherwise(features::onboarding::flow),
        )
        .child(features::desktop::jump::layer())
        .child(features::calls::call_layer())
        .child(ui::toast_layer())
}
