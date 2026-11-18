//! QR codes read on the device from grey frames, with `rqrr` (D-0110): no cloud service, no
//! Google library. What the camera sees is attacker-chosen, so every input is bounded before
//! anything proportional to it is allocated, and only UTF-8 text comes out.
//!
//! Apple platforms read codes with `AVCaptureMetadataOutput` and use this only as a fallback;
//! Android, Windows and Linux feed it frames through a [`Scanner`].

#![forbid(unsafe_code)]

use crate::{Frame, Sink, mailbox};

/// The most pixels decoded per frame; larger frames are scaled down first. 640×480: a link code
/// (37 modules) filling a third of the frame still has 4 pixels a module, and the decoder's
/// cost on a hostile, finder-dense image stays bounded (security review, D-0116).
pub const MAX_PIXELS: usize = 640 * 480;
/// The largest side accepted at all; larger frames are refused unread.
pub const MAX_SIDE: usize = 8192;
/// The most codes decoded from one frame.
pub const MAX_CODES: usize = 4;

/// The texts of the QR codes in a `width`×`height` grey image whose rows are `stride` bytes
/// apart. Empty when the image is malformed or too large, or holds no readable code. Never
/// panics.
#[must_use]
pub fn decode_grey(width: usize, height: usize, stride: usize, data: &[u8]) -> Vec<String> {
    if width == 0
        || height == 0
        || width > MAX_SIDE
        || height > MAX_SIDE
        || stride < width
        || stride
            .checked_mul(height - 1)
            .and_then(|n| n.checked_add(width))
            .is_none_or(|n| data.len() < n)
    {
        return Vec::new();
    }
    let (w, h, pixels) = scaled(width, height, stride, data);
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| pixels[y * w + x]);
    prepared
        .detect_grids()
        .into_iter()
        .take(MAX_CODES)
        .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
        .collect()
}

/// The image as packed rows, scaled down by a whole factor (box average) until it holds at
/// most [`MAX_PIXELS`].
fn scaled(width: usize, height: usize, stride: usize, data: &[u8]) -> (usize, usize, Vec<u8>) {
    let mut factor = 1;
    while (width / factor) * (height / factor) > MAX_PIXELS {
        factor += 1;
    }
    let (w, h) = ((width / factor).max(1), (height / factor).max(1));
    let mut out = Vec::with_capacity(w * h);
    if factor == 1 {
        for row in data.chunks(stride).take(h) {
            out.extend_from_slice(&row[..w]);
        }
        return (w, h, out);
    }
    let area = u32::try_from(factor * factor).unwrap_or(u32::MAX);
    for by in 0..h {
        for bx in 0..w {
            let mut sum = 0u32;
            for dy in 0..factor {
                let row = (by * factor + dy) * stride + bx * factor;
                sum += data[row..row + factor]
                    .iter()
                    .map(|&p| u32::from(p))
                    .sum::<u32>();
            }
            out.push(u8::try_from(sum / area).unwrap_or(u8::MAX));
        }
    }
    (w, h, out)
}

/// The codes in `frame` (its luma).
#[must_use]
pub fn decode_frame(frame: &Frame) -> Vec<String> {
    let Some(luma) = frame.luma() else {
        return Vec::new();
    };
    let (w, h) = (frame.width as usize, frame.height as usize);
    decode_grey(w, h, w, &luma)
}

/// Decodes frames on a thread of its own, the newest frame first: a slow decode skips frames,
/// never delays the camera. Codes go to the capture's [`Sink`]. Dropping it lets the thread end
/// after the frame it is on, without waiting for it: a hostile image that makes one decode slow
/// never holds up the screen that closes the scanner (D-0116).
pub struct Scanner {
    frames: Option<mailbox::Sender<Frame>>,
}

impl Scanner {
    /// A scanner reporting into `sink`.
    #[must_use]
    pub fn start(sink: Sink) -> Self {
        let (frames, rx) = mailbox::channel::<Frame>(1);
        // Detached on purpose (see the type's notes); it ends once `frames` is dropped.
        let _detached = std::thread::Builder::new()
            .name("songbird-qr".into())
            .spawn(move || {
                while let Some(frame) = rx.recv_blocking() {
                    if !sink.is_open() {
                        break;
                    }
                    for text in decode_frame(&frame) {
                        sink.code(&text);
                    }
                }
            })
            .ok();
        Scanner {
            frames: Some(frames),
        }
    }

    /// Offers a frame. A frame still waiting is replaced, so the next decode reads the newest.
    pub fn offer(&self, frame: Frame) {
        if let Some(f) = &self.frames {
            f.send(frame);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Event, Pixels, Rotation};

    /// A version 1 QR code (21×21) of "SONGBIRD", error correction M, drawn with 4-pixel
    /// modules and a 4-module quiet zone. Made with the `qrcode` crate the app draws with,
    /// stored as rows of `#` and `.`.
    pub(crate) const SONGBIRD_V1: [&str; 21] = [
        "#######.#.##..#######",
        "#.....#.##....#.....#",
        "#.###.#.##.##.#.###.#",
        "#.###.#...#.#.#.###.#",
        "#.###.#.#...#.#.###.#",
        "#.....#...###.#.....#",
        "#######.#.#.#.#######",
        "...........##........",
        "#..######...##..#.###",
        ".#..##....#.#.#.#...#",
        "..#.####..#..##.#####",
        "#.#.#....#.#.....##..",
        "...####.#.....#....##",
        "........##.##....##.#",
        "#######.#.#.#####....",
        "#.....#.##.###..#...#",
        "#.###.#.#####.##.####",
        "#.###.#.##.##....##..",
        "#.###.#...#...#.#####",
        "#.....#..#...##.####.",
        "#######.##.#....#..#.",
    ];

    /// `rows` as a grey image: `module` pixels per module, a 4-module white quiet zone.
    pub(crate) fn render(rows: &[&str], module: usize) -> (usize, Vec<u8>) {
        let n = rows.len();
        let side = (n + 8) * module;
        let mut img = vec![255u8; side * side];
        for (y, row) in rows.iter().enumerate() {
            for (x, c) in row.bytes().enumerate() {
                if c == b'#' {
                    for dy in 0..module {
                        let start = ((y + 4) * module + dy) * side + (x + 4) * module;
                        img[start..start + module].fill(0);
                    }
                }
            }
        }
        (side, img)
    }

    #[test]
    fn a_rendered_code_is_read() {
        let (side, img) = render(&SONGBIRD_V1, 4);
        assert_eq!(
            decode_grey(side, side, side, &img),
            vec!["SONGBIRD".to_string()]
        );
    }

    #[test]
    fn a_large_frame_is_scaled_down_and_still_read() {
        // 2,000×1,600 with the code in a corner at 16 px a module: over MAX_PIXELS.
        let (side, code) = render(&SONGBIRD_V1, 16);
        let (w, h) = (2000, 1600);
        let mut img = vec![255u8; w * h];
        for y in 0..side {
            img[y * w..y * w + side].copy_from_slice(&code[y * side..(y + 1) * side]);
        }
        assert!(w * h > MAX_PIXELS);
        assert_eq!(decode_grey(w, h, w, &img), vec!["SONGBIRD".to_string()]);
    }

    #[test]
    fn malformed_and_oversized_images_are_refused_unread() {
        assert_eq!(
            decode_grey(0, 10, 10, &[0; 100]),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            decode_grey(10, 10, 9, &[0; 100]),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            decode_grey(10, 10, 10, &[0; 99]),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            decode_grey(MAX_SIDE + 1, 1, MAX_SIDE + 1, &[0; MAX_SIDE + 1]),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            decode_grey(10, usize::MAX, 10, &[0; 100]),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            decode_grey(64, 64, 64, &[128; 64 * 64]),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn the_scanner_reports_codes_from_frames_once() {
        let (sink, events, _) = Sink::new();
        let scanner = Scanner::start(sink);
        let (side, img) = render(&SONGBIRD_V1, 4);
        let side32 = u32::try_from(side).unwrap();
        let frame = Frame {
            width: side32,
            height: side32,
            rotation: Rotation::Deg0,
            timestamp_us: 0,
            pixels: Pixels::Grey {
                data: img,
                stride: side,
            },
        };
        for _ in 0..3 {
            scanner.offer(frame.clone());
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        drop(scanner); // the thread ends after the frame it is on
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(events.drain(), vec![Event::Code("SONGBIRD".into())]);
    }
}
