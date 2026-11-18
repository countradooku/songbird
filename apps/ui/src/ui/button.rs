//! Buttons: one press feedback, one focus ring, one disabled look (a
//! muted surface with a muted label, whatever the variant).
//! Features pick a [`Variant`] and a [`Size`], never colours. Shape,
//! height and press follow the platform skin (`ui::skin`): capsules that
//! dim (Apple), pills with a state layer (Material), 4pt corners that
//! shift fill (Fluent), 6pt corners and a pill for the suggested action
//! (Adwaita).

use nsh_base::button;
use nsh_core::prelude::*;

use super::{
    icons::{Icon, icon},
    skin::{Elevation, PressStyle, spec},
    tokens::{c, motion},
};

/// What the button means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Variant {
    /// The one main action of a screen.
    #[default]
    Primary,
    /// A quieter action beside the primary one.
    Secondary,
    /// Text only, for toolbars and low-emphasis actions.
    Ghost,
    /// A bordered action.
    Outline,
    /// Deletes or leaves; red, used only for that.
    Danger,
}

/// How big. Phones take the touch size whatever the size says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BtnSize {
    Sm,
    #[default]
    Md,
    Lg,
}

impl BtnSize {
    /// The skin's height for this size on this family.
    fn height(self) -> f32 {
        let h = spec().heights();
        match self {
            BtnSize::Sm => h.sm,
            BtnSize::Md => h.md,
            BtnSize::Lg => h.lg,
        }
    }
    fn text(self) -> f32 {
        match self {
            BtnSize::Sm => 13.0,
            BtnSize::Md => if is_desktop() { 14.0 } else { 16.0 },
            BtnSize::Lg => 17.0,
        }
    }
    fn pad(self) -> f32 {
        match self {
            BtnSize::Sm => 12.0,
            BtnSize::Md => 16.0,
            BtnSize::Lg => 22.0,
        }
    }
}

fn fill(variant: Variant) -> AdaptiveColor {
    match variant {
        Variant::Primary => c::primary(),
        Variant::Secondary => c::control(),
        Variant::Ghost | Variant::Outline => AdaptiveColor::TRANSPARENT,
        Variant::Danger => c::destructive(),
    }
}

fn ink(variant: Variant) -> AdaptiveColor {
    match variant {
        Variant::Primary => c::on_primary(),
        Variant::Secondary => c::on_secondary(),
        Variant::Ghost | Variant::Outline => c::primary(),
        Variant::Danger => c::on_destructive(),
    }
}

/// A labelled button. `label` may be a closure for text that changes.
pub fn btn(
    label: impl IntoReactive<SharedString>,
    variant: Variant,
    size: BtnSize,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    btn_with_icon(label, None, variant, size, on_press)
}

/// A button with a leading icon.
pub fn btn_with_icon(
    label: impl IntoReactive<SharedString>,
    leading: Option<Icon>,
    variant: Variant,
    size: BtnSize,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    let sp = spec();
    let corner = if sp.pill_primary && variant == Variant::Primary { super::skin::FULL } else { sp.radius.button };
    let press = sp.press;
    button()
        .on_press(on_press)
        .h(px(size.height()))
        .px(px(size.pad()))
        .flex_row()
        .items_center()
        .justify_center()
        .gap_2()
        .rounded(px(corner))
        .bg(move || fill(variant))
        .text_color(move || ink(variant))
        // Every variant has the same 1pt border so sizes match; Outline
        // draws it in `border`, Secondary in a soft `input` tint (so the
        // button keeps an edge on a sheet or popover in dark), the rest
        // keep it clear until disabled. Fluent's raised buttons add their
        // soft control shadow.
        .border_1()
        .border_color(move || match variant {
            Variant::Outline => c::border(),
            // Adwaita's buttons are flat fills, no outline.
            Variant::Secondary if sp.skin != super::skin::Skin::Adwaita => c::input().opacity(0.4),
            _ => AdaptiveColor::TRANSPARENT,
        })
        .when(sp.elevation == Elevation::Shadow && matches!(variant, Variant::Secondary | Variant::Outline), |b| {
            b.shadow_2xs()
        })
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .ease_bezier(motion::SETTLE.0, motion::SETTLE.1, motion::SETTLE.2, motion::SETTLE.3)
        .hover(move |s| match variant {
            Variant::Ghost | Variant::Outline => s.bg(move || c::accent()),
            _ if press == PressStyle::Fill => s.opacity(0.9),
            _ => s.opacity(0.92),
        })
        .active(move |s| match press {
            // Apple: the highlight dims; a capsule settles a little.
            PressStyle::Highlight => {
                let s = s.opacity(0.7);
                if reduced { s } else { s.scale(motion::PRESS_SCALE) }
            }
            // Material: the state layer deepens; nothing moves.
            PressStyle::Ripple => match variant {
                Variant::Ghost | Variant::Outline => s.bg(move || c::primary().opacity(0.12)),
                _ => s.opacity(0.84),
            },
            // Fluent and Adwaita: the fill shifts a step; nothing moves.
            PressStyle::Fill => match variant {
                Variant::Ghost | Variant::Outline => s.bg(move || c::muted()),
                _ => s.opacity(0.8),
            },
        })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        // One disabled look for every variant: a muted surface with a
        // hairline edge and a muted label that still reads (4.5:1).
        .disabled_style(|s| {
            s.opacity(1.0)
                .bg(c::muted())
                .text_color(c::muted_fg())
                .border_color(c::border())
                .cursor(Cursor::Default)
        })
        .child(leading.map(|i| icon(i, size.text() + 2.0)))
        .child(
            text(label)
                .text_size(px(size.text()))
                .font_weight(FontWeight::SEMIBOLD)
                .number_of_lines(1),
        )
}

/// An icon-only button: a square (circle on phones) of the control
/// height with a required screen-reader label.
pub fn icon_btn(
    glyph: Icon,
    label: impl Into<SharedString>,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    let sp = spec();
    let side = if is_desktop() { 32.0 } else { 44.0 };
    let glyph_size = if is_desktop() { 18.0 } else { 22.0 };
    let press = sp.press;
    button()
        .on_press(on_press)
        .accessibility_label(label.into())
        .size(px(side))
        .items_center()
        .justify_center()
        .rounded(px(sp.radius.icon_button))
        .text_color(move || c::foreground())
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .hover(move |s| if press == PressStyle::Fill { s.bg(move || c::muted()) } else { s.bg(move || c::accent()) })
        .active(move |s| match press {
            PressStyle::Highlight => {
                let s = s.opacity(0.6);
                if reduced { s } else { s.scale(motion::ICON_PRESS_SCALE) }
            }
            PressStyle::Ripple => s.bg(move || c::foreground().opacity(0.12)),
            PressStyle::Fill => s.bg(move || c::secondary()).opacity(0.85),
        })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .disabled_style(|s| s.opacity(0.4))
        .child(icon(glyph, glyph_size))
}

/// A round, filled action (the floating "new chat" button, call controls).
pub fn fab(
    glyph: Icon,
    label: impl Into<SharedString>,
    on_press: impl Fn() + 'static,
) -> nsh_base::ButtonElement {
    let reduced = motion::reduced();
    let sp = spec();
    let material = sp.elevation == Elevation::Tonal;
    let corner = px(sp.radius.fab);
    // The fill and its elevation live on a plain view inside the button,
    // so the press scale moves both. The shadow is tinted with the primary
    // colour, not grey, so it reads as light through the fill rather than
    // dirt under it, and it lifts the button clearly off the rows that
    // scroll beneath (a row's badge peeking past its corner read as a
    // dark blob when the shadow was a faint grey). Material draws its
    // expressive FAB: a 16pt-cornered square on the primary container,
    // with the platform's elevation (level 3) and a state layer.
    button()
        .on_press(on_press)
        .accessibility_label(label.into())
        .size(px(56.0))
        .rounded(corner)
        .cursor_pointer()
        .transition()
        .duration(motion::FAST)
        .ease_bezier(motion::SETTLE.0, motion::SETTLE.1, motion::SETTLE.2, motion::SETTLE.3)
        .hover(|s| s.opacity(0.92))
        .active(move |s| if reduced || material { s.opacity(0.85) } else { s.scale(motion::ICON_PRESS_SCALE) })
        .focus_visible(|s| s.outline(px(2.0)).outline_offset(px(2.0)).outline_color(move || c::ring()))
        .child(
            view()
                .size(px(56.0))
                .items_center()
                .justify_center()
                .rounded(corner)
                .bg(move || if material { c::accent() } else { c::primary() })
                .text_color(move || if material { c::on_accent() } else { c::on_primary() })
                .when(material, |v| v.elevation(px(6.0)).shadow_md().shadow_color(c::foreground().opacity(0.25)))
                .when(!material, |v| v.shadow_lg().shadow_color(c::primary().opacity(0.35)))
                .child(icon(glyph, 24.0)),
        )
}
