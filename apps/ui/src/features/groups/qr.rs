//! The QR code of a group's invite link: a real code (D-0110), redrawn when the link is reset.

use nsh_core::prelude::*;

use crate::ui::*;

/// The invite link as a QR code, `module` points per module.
pub fn qr_code(link: impl Fn() -> String + 'static, module: f32) -> View {
    qr_code_live(link, module)
        .role(AccessibilityRole::Image)
        .label("QR code for the invite link")
}
