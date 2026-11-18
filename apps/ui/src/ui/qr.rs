//! Real QR codes (D-0110): `qrcode` encodes, the module matrix is drawn as one SVG path.
//!
//! Always dark modules on a light plate in every theme (many scanners cannot read an inverted
//! code), a 4-module quiet zone, and a whole number of points per module so no module edge
//! falls between pixels. Error correction M: enough for a screen seen at an angle, and small
//! codes (the link code fits version 5, 37×37).

use nsh_core::{element::ImageSrc, prelude::*};
use qrcode::{Color, EcLevel, QrCode};

use super::{c, radius};

/// The quiet zone around a code, in modules (the standard's minimum).
pub const QUIET: usize = 4;

/// A QR code's modules, row by row (`true` dark).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix {
    /// Modules per side.
    pub width: usize,
    /// `width * width` modules.
    pub dark: Vec<bool>,
}

impl Matrix {
    /// Whether the module at column `x`, row `y` is dark.
    #[must_use]
    pub fn at(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.width + x]
    }
}

/// `text` encoded with error correction M, in the smallest version that holds it (`qrcode`
/// picks numeric, alphanumeric or byte segments). `None` when it is too long for any version.
#[must_use]
pub fn encode(text: &str) -> Option<Matrix> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
    let width = code.width();
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == Color::Dark)
        .collect();
    Some(Matrix { width, dark })
}

/// The matrix as an SVG in module units, quiet zone included: one path, a run of dark modules
/// per rectangle.
#[must_use]
pub fn svg_markup(m: &Matrix) -> String {
    let side = m.width + 2 * QUIET;
    let mut d = String::new();
    for y in 0..m.width {
        let mut x = 0;
        while x < m.width {
            if m.at(x, y) {
                let start = x;
                while x < m.width && m.at(x, y) {
                    x += 1;
                }
                d.push_str(&format!(
                    "M{} {}h{}v1h-{}z",
                    start + QUIET,
                    y + QUIET,
                    x - start,
                    x - start
                ));
            } else {
                x += 1;
            }
        }
    }
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{side}" height="{side}" viewBox="0 0 {side} {side}" shape-rendering="crispEdges"><path fill="currentColor" d="{d}"/></svg>"#
    )
}

/// Points per module for a code about `size` points wide: whole, at least 2.
fn module_points(size: f32, width: usize) -> f32 {
    #[allow(clippy::cast_precision_loss)]
    let modules = (width + 2 * QUIET) as f32;
    (size / modules).floor().max(2.0)
}

/// `data` as a QR code about `size` points wide, on its plate. Hidden from screen readers: the
/// caller labels what it is for. Text too long to encode draws an empty plate (no caller
/// passes one: codes are links and keys of fixed size).
pub fn qr_code(data: &str, size: f32) -> View {
    let matrix = encode(data);
    let (markup, side) = match &matrix {
        Some(m) => {
            #[allow(clippy::cast_precision_loss)]
            let side = module_points(size, m.width) * (m.width + 2 * QUIET) as f32;
            (svg_markup(m), side)
        }
        None => (String::new(), size),
    };
    plate(
        svg(ImageSrc::svg_markup(&markup))
            .size(px(side))
            .into_element(),
    )
}

/// A code whose text changes (an invite link that can be reset), `module` points per module.
pub fn qr_code_live(data: impl Fn() -> String + 'static, module: f32) -> View {
    let module = module.round().max(2.0);
    let data = std::rc::Rc::new(data);
    let width = {
        let data = data.clone();
        move || encode(&data()).map_or(21, |m| m.width)
    };
    #[allow(clippy::cast_precision_loss)]
    let side = move || px(module * (width() + 2 * QUIET) as f32);
    plate(
        svg(move || {
            ImageSrc::svg_markup(&encode(&data()).map(|m| svg_markup(&m)).unwrap_or_default())
        })
        .w(side.clone())
        .h(side)
        .into_element(),
    )
}

fn plate(code: AnyElement) -> View {
    view()
        .rounded(move || radius::lg())
        // Light plate, dark modules, in every theme; the quiet zone is in the SVG.
        .bg(move || c::on_call())
        .text_color(move || c::call_bg())
        .border(super::parts::hairline())
        .border_color(move || c::border())
        .self_center()
        .p_1()
        .accessibility_elements_hidden(true)
        .child(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draws `m` as grey pixels (`module` per module, quiet zone white) and reads it back with
    /// the camera's decoder.
    fn read_back(m: &Matrix, module: usize) -> Vec<String> {
        let side = (m.width + 2 * QUIET) * module;
        let mut img = vec![255u8; side * side];
        for y in 0..m.width {
            for x in 0..m.width {
                if m.at(x, y) {
                    for dy in 0..module {
                        let row = ((y + QUIET) * module + dy) * side + (x + QUIET) * module;
                        img[row..row + module].fill(0);
                    }
                }
            }
        }
        songbird_camera::qr::decode_grey(side, side, side, &img)
    }

    #[test]
    fn every_kind_of_code_the_app_draws_reads_back() {
        let link = format!("SONGBIRD:LINK:{}:{}", "0A".repeat(16), "F3".repeat(32));
        for text in [
            link.as_str(),
            "SONGBIRD:SAFETY:052194738460128573910264738190573829104638572910",
            "https://songbird.chat/i/radu",
            "https://songbird.chat/g/0123456789abcdef#k=AbC-dEf_123",
            "radu.42",
        ] {
            let m = encode(text).unwrap();
            assert_eq!(read_back(&m, 3), vec![text.to_string()], "{text}");
        }
    }

    #[test]
    fn the_link_code_fits_version_5() {
        // Upper case keeps it in alphanumeric mode (D-0110, finding 6): 37×37 modules.
        let link = format!("SONGBIRD:LINK:{}:{}", "0A".repeat(16), "F3".repeat(32));
        assert_eq!(encode(&link).unwrap().width, 37);
        // The same in lower case needs byte mode and a larger code.
        assert!(encode(&link.to_lowercase()).unwrap().width > 37);
    }

    #[test]
    fn the_svg_draws_runs_inside_the_quiet_zone() {
        let m = encode("SONGBIRD").unwrap();
        let svg = svg_markup(&m);
        assert!(svg.contains(r#"viewBox="0 0 29 29""#), "{svg}");
        // The top-left finder's first row is one run of seven.
        assert!(svg.contains("M4 4h7v1h-7z"), "{svg}");
    }

    #[test]
    fn modules_are_whole_points() {
        assert!((module_points(184.0, 37) - 4.0).abs() < f32::EPSILON);
        assert!((module_points(20.0, 37) - 2.0).abs() < f32::EPSILON);
        assert!(encode(&"x".repeat(5000)).is_none());
    }
}
