//! Songbird, the app: an NSH Rust UI over app-core.
//!
//! - `ui`: the design system — tokens, icons and every styled control.
//! - `store`: the UI's view of app-core and its intents (mocked until A2).
//! - `nav` and `shell`: navigation and the phone and desktop layouts.
//! - `features`: the screens, one module per area of the prompt set.

pub mod backend;
pub mod features;
pub mod nav;
pub mod shell;
pub mod store;
pub mod theming;
pub mod ui;

use nsh_core::prelude::*;

use crate::store::Store;

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
