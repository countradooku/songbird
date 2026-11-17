//! A decorative QR-style code for invite links.
//!
//! mock: this is NOT a QR encoder. It draws a grid with the three finder
//! squares and a pattern derived from a hash of the link, so the screen
//! looks right and changes when the link is reset. app-core (or a QR
//! crate) will encode the real link; until then the UI says the code is
//! a preview and the link itself is what people share.

use nsh_core::{element::ImageSrc, prelude::*};

use crate::ui::*;

/// Modules per side.
pub const SIDE: usize = 25;

fn hash(text: &str) -> u64 {
    // FNV-1a: stable across runs and platforms.
    text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
}

fn in_finder(x: usize, y: usize) -> Option<bool> {
    let corners = [(0, 0), (SIDE - 7, 0), (0, SIDE - 7)];
    for (cx, cy) in corners {
        // The finder and its one-module light border.
        let (lx, ly) = (x as i64 - cx as i64, y as i64 - cy as i64);
        if (-1..=7).contains(&lx) && (-1..=7).contains(&ly) {
            if !(0..7).contains(&lx) || !(0..7).contains(&ly) {
                return Some(false);
            }
            let ring = lx == 0 || lx == 6 || ly == 0 || ly == 6;
            let core = (2..=4).contains(&lx) && (2..=4).contains(&ly);
            return Some(ring || core);
        }
    }
    None
}

/// The grid for `link`: `true` is a dark module.
pub fn matrix(link: &str) -> Vec<Vec<bool>> {
    let mut x = hash(link) | 1;
    (0..SIDE)
        .map(|row| {
            (0..SIDE)
                .map(|col| {
                    if let Some(v) = in_finder(col, row) {
                        return v;
                    }
                    if row == 6 || col == 6 {
                        return (row + col) % 2 == 0;
                    }
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x % 5 < 2
                })
                .collect()
        })
        .collect()
}

/// The grid as SVG markup in `currentColor`, with a quiet zone.
pub fn svg_markup(link: &str) -> String {
    let m = matrix(link);
    let mut cells = String::new();
    for (y, row) in m.iter().enumerate() {
        for (x, dark) in row.iter().enumerate() {
            if *dark {
                cells.push_str(&format!(r#"<rect x="{}" y="{}" width="1" height="1"/>"#, x + 2, y + 2));
            }
        }
    }
    let n = SIDE + 4;
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{n}" height="{n}" viewBox="0 0 {n} {n}" fill="currentColor" shape-rendering="crispEdges">{cells}</svg>"#
    )
}

/// The code, dark on light in both themes as printed codes are, framed
/// in a white card. `module` is one module's side in points: a whole
/// number, so every module lands on the pixel grid and the code stays
/// crisp at 1x, 2x and 3x. The frame pads 12pt around the code's own
/// quiet zone. Follows `link`.
pub fn qr_code(link: impl Fn() -> String + 'static, module: f32) -> View {
    let module = module.round().max(1.0);
    let code = module * (SIDE + 4) as f32;
    view()
        .p(px(12.0))
        .rounded(move || radius::lg())
        // Paper white in both themes: scanners want the contrast, and a
        // grey plate reads as disabled in light.
        .bg(AdaptiveColor::new(white(), white()))
        .border_1()
        .border_color(move || c::border())
        .text_color(AdaptiveColor::new(black(), black()))
        .role(AccessibilityRole::Image)
        .label("QR code for the invite link")
        .child(svg(move || ImageSrc::svg_markup(&svg_markup(&link()))).size(px(code)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finders_sit_in_three_corners() {
        let m = matrix("https://songbird.chat/g/abc");
        assert!(m[0][0] && m[0][6] && m[6][0] && m[3][3]);
        assert!(!m[1][1] && !m[7][7]);
        assert!(m[0][SIDE - 1] && m[SIDE - 1][0]);
        assert!(!m[1][SIDE - 2]);
    }

    #[test]
    fn the_pattern_follows_the_link() {
        let a = matrix("https://songbird.chat/g/abc");
        assert_eq!(a, matrix("https://songbird.chat/g/abc"));
        assert_ne!(a, matrix("https://songbird.chat/g/abd"));
        assert!(svg_markup("x").starts_with("<svg"));
    }
}
