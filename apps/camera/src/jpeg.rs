//! Stripping a photo's metadata before it is sent (D-0110, "Privacy"): a JPEG keeps only what
//! draws the image and its orientation. Dropped: EXIF (camera, lens, time, GPS), XMP, ICC
//! profiles (cameras write sRGB or Display P3; the receiver assumes sRGB), maker notes,
//! comments, and anything after the image's end (the depth maps, gain maps and second images
//! phones append).
//!
//! The input is the platform's own encoder's output, but it is parsed as if hostile: every
//! length is checked, nothing proportional to a claimed length is allocated, and it never
//! panics (fuzzed: `fuzz/fuzz_targets/jpeg_strip.rs`).

#![forbid(unsafe_code)]

/// The largest still accepted, in bytes.
pub const MAX_LEN: usize = 64 * 1024 * 1024;

/// Why a JPEG was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Larger than [`MAX_LEN`].
    TooLarge,
    /// Not a JPEG, cut short, or with a segment that does not fit.
    Malformed,
    /// No frame header or no scan: nothing to draw.
    NoImage,
}

/// A stripped JPEG and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stripped {
    /// The image: SOI, a minimal EXIF holding only the orientation (when not upright), the
    /// tables, frame and scans, EOI.
    pub bytes: Vec<u8>,
    /// The EXIF orientation, 1 (upright) to 8.
    pub orientation: u8,
    /// Width in pixels as stored (before orientation).
    pub width: u16,
    /// Height in pixels as stored.
    pub height: u16,
}

impl Stripped {
    /// Width and height as shown, after the orientation (5 to 8 swap them).
    #[must_use]
    pub fn upright_size(&self) -> (u32, u32) {
        let (w, h) = (u32::from(self.width), u32::from(self.height));
        if self.orientation >= 5 {
            (h, w)
        } else {
            (w, h)
        }
    }
}

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOS: u8 = 0xDA;
const APP1: u8 = 0xE1;

/// Whether a segment with this marker is kept: the tables, frame headers and restart interval.
/// Every `APPn` (EXIF, XMP, ICC, JFIF, Adobe, MPF, …), COM and anything unknown is dropped.
fn kept(marker: u8) -> bool {
    matches!(marker,
        0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF // SOFn
        | 0xC4 // DHT
        | 0xCC // DAC
        | 0xDB // DQT
        | 0xDC // DNL
        | 0xDD // DRI
    )
}

fn is_sof(marker: u8) -> bool {
    matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF)
}

/// `input` without its metadata. See the module's notes.
///
/// # Errors
///
/// [`Error`] when it is too large, malformed or holds no image.
pub fn strip(input: &[u8]) -> Result<Stripped, Error> {
    if input.len() > MAX_LEN {
        return Err(Error::TooLarge);
    }
    if input.len() < 4 || input[0] != 0xFF || input[1] != SOI {
        return Err(Error::Malformed);
    }
    let mut body = Vec::with_capacity(input.len());
    let mut orientation = 1u8;
    let mut size = None;
    let mut scans = 0usize;
    let mut i = 2;
    loop {
        // A marker: 0xFF, optional fill bytes 0xFF, then the code.
        if input.get(i) != Some(&0xFF) {
            return Err(Error::Malformed);
        }
        while input.get(i) == Some(&0xFF) {
            i += 1;
        }
        let marker = *input.get(i).ok_or(Error::Malformed)?;
        i += 1;
        match marker {
            EOI => break,
            SOI | 0x00 | 0xD0..=0xD7 | 0x01 => return Err(Error::Malformed),
            _ => {}
        }
        let len = usize::from(u16::from_be_bytes([
            *input.get(i).ok_or(Error::Malformed)?,
            *input.get(i + 1).ok_or(Error::Malformed)?,
        ]));
        let end = i
            .checked_add(len)
            .filter(|&e| len >= 2 && e <= input.len())
            .ok_or(Error::Malformed)?;
        let payload = &input[i + 2..end];
        if marker == APP1
            && orientation == 1
            && let Some(o) = exif_orientation(payload)
        {
            orientation = o;
        }
        if is_sof(marker) {
            if size.is_some() || payload.len() < 5 {
                return Err(Error::Malformed);
            }
            let height = u16::from_be_bytes([payload[1], payload[2]]);
            let width = u16::from_be_bytes([payload[3], payload[4]]);
            if width == 0 {
                return Err(Error::Malformed);
            }
            size = Some((width, height));
        }
        if kept(marker) || marker == SOS {
            // From the marker's last 0xFF: fill bytes before it are dropped.
            body.extend_from_slice(&input[i - 2..end]);
        }
        i = end;
        if marker == SOS {
            if size.is_none() {
                return Err(Error::Malformed);
            }
            scans += 1;
            // Entropy-coded data: up to the next marker other than a stuffed 0xFF00 or a
            // restart marker, which are part of it.
            let start = i;
            loop {
                let ff = input[i..]
                    .iter()
                    .position(|&b| b == 0xFF)
                    .ok_or(Error::Malformed)?;
                i += ff;
                match input.get(i + 1) {
                    Some(0x00 | 0xD0..=0xD7) => i += 2,
                    Some(0xFF) => i += 1, // fill before a marker
                    Some(_) => break,
                    None => return Err(Error::Malformed),
                }
            }
            body.extend_from_slice(&input[start..i]);
        }
    }
    let (width, height) = size.ok_or(Error::NoImage)?;
    if scans == 0 {
        return Err(Error::NoImage);
    }
    // Anything after EOI is dropped.
    let mut bytes = Vec::with_capacity(body.len() + 40);
    bytes.extend_from_slice(&[0xFF, SOI]);
    if orientation != 1 {
        bytes.extend_from_slice(&minimal_exif(orientation));
    }
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&[0xFF, EOI]);
    Ok(Stripped {
        bytes,
        orientation,
        width,
        height,
    })
}

/// The orientation in an APP1 EXIF payload (IFD0 tag 0x0112), when present and valid.
fn exif_orientation(payload: &[u8]) -> Option<u8> {
    let tiff = payload.strip_prefix(b"Exif\0\0")?;
    let big = match tiff.get(..4)? {
        b"MM\0*" => true,
        b"II*\0" => false,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if big {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let b: [u8; 4] = tiff.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let ifd = usize::try_from(u32_at(4)?).ok()?;
    let count = usize::from(u16_at(ifd)?);
    // At most the entries that fit: a claimed count is never trusted.
    for n in 0..count.min(tiff.len() / 12) {
        let entry = ifd.checked_add(2)?.checked_add(n.checked_mul(12)?)?;
        if u16_at(entry)? == 0x0112 && u16_at(entry + 2)? == 3 && u32_at(entry + 4)? == 1 {
            let value = u16_at(entry + 8)?;
            return u8::try_from(value).ok().filter(|v| (1..=8).contains(v));
        }
    }
    None
}

/// An APP1 segment with an EXIF block holding the orientation alone.
fn minimal_exif(orientation: u8) -> [u8; 36] {
    let mut s = [0u8; 36];
    s[..4].copy_from_slice(&[0xFF, APP1, 0x00, 34]);
    s[4..10].copy_from_slice(b"Exif\0\0");
    s[10..14].copy_from_slice(b"MM\0*");
    s[14..18].copy_from_slice(&8u32.to_be_bytes()); // IFD0 right after the header
    s[18..20].copy_from_slice(&1u16.to_be_bytes()); // one entry
    s[20..22].copy_from_slice(&0x0112u16.to_be_bytes()); // Orientation
    s[22..24].copy_from_slice(&3u16.to_be_bytes()); // SHORT
    s[24..28].copy_from_slice(&1u32.to_be_bytes()); // one value
    s[28..30].copy_from_slice(&u16::from(orientation).to_be_bytes());
    // s[30..32] padding, s[32..36] no next IFD.
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len() + 2).unwrap();
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn exif(orientation: u16, gps: &[u8]) -> Vec<u8> {
        // Little-endian EXIF: IFD0 with Make, Orientation, then a GPS-looking blob after it.
        let mut t = b"Exif\0\0II*\0".to_vec();
        t.extend_from_slice(&8u32.to_le_bytes());
        t.extend_from_slice(&2u16.to_le_bytes());
        t.extend_from_slice(&[0x0F, 0x01, 2, 0, 4, 0, 0, 0, b'A', b'c', b'm', 0]); // Make "Acm"
        t.extend_from_slice(&[0x12, 0x01, 3, 0, 1, 0, 0, 0]);
        t.extend_from_slice(&orientation.to_le_bytes());
        t.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        t.extend_from_slice(gps);
        t
    }

    /// A small JPEG's structure (the entropy data is not a real image; the filter never
    /// decodes it).
    fn jpeg(app: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0xFF, SOI];
        v.extend(seg(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
        for a in app {
            v.extend_from_slice(a);
        }
        v.extend(seg(0xDB, &[0; 65]));
        // 8-bit, 480 rows, 640 columns, three components.
        v.extend(seg(
            0xC0,
            &[
                8, 0x01, 0xE0, 0x02, 0x80, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1,
            ],
        ));
        v.extend(seg(0xC4, &[0; 20]));
        v.extend(seg(0xFE, b"shot on someone's phone"));
        v.extend(seg(SOS, &[3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3F, 0]));
        v.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]); // data, stuffing, RST0
        v.extend_from_slice(&[0xFF, EOI]);
        v
    }

    #[test]
    fn metadata_goes_and_the_image_stays() {
        let gps = b"GPS 52.37N 4.89E";
        let input = jpeg(&[
            seg(APP1, &exif(6, gps)),
            seg(
                APP1,
                b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>secret</x:xmpmeta>",
            ),
            seg(0xE2, b"ICC_PROFILE\0\x01\x01lots of profile"),
        ]);
        let mut with_tail = input.clone();
        with_tail.extend_from_slice(b"\xFF\xD8appended depth map\xFF\xD9");
        let out = strip(&with_tail).unwrap();
        for leak in [
            &gps[..],
            b"Acm",
            b"xmpmeta",
            b"ICC_PROFILE",
            b"JFIF",
            b"someone",
            b"depth",
        ] {
            assert!(
                !out.bytes.windows(leak.len()).any(|w| w == leak),
                "{}",
                String::from_utf8_lossy(leak)
            );
        }
        assert_eq!(out.orientation, 6);
        assert_eq!((out.width, out.height), (640, 480));
        assert_eq!(out.upright_size(), (480, 640));
        // The orientation survives in a fresh EXIF block, readable again.
        assert_eq!(exif_orientation(&out.bytes[6..36]), Some(6));
        // The entropy data, with its stuffing and restart marker, is intact.
        assert!(
            out.bytes
                .ends_with(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56, 0xFF, EOI])
        );
        // Stripping again changes nothing.
        assert_eq!(strip(&out.bytes).unwrap().bytes, out.bytes);
    }

    #[test]
    fn an_upright_photo_gets_no_exif_at_all() {
        let out = strip(&jpeg(&[seg(APP1, &exif(1, b""))])).unwrap();
        assert!(!out.bytes.windows(4).any(|w| w == b"Exif"));
        let bare = strip(&jpeg(&[])).unwrap();
        assert_eq!(bare.orientation, 1);
    }

    #[test]
    fn malformed_inputs_are_refused() {
        let good = jpeg(&[]);
        assert_eq!(strip(&[]), Err(Error::Malformed));
        assert_eq!(strip(b"\x89PNG\r\n\x1a\n"), Err(Error::Malformed));
        for cut in [3, 10, 30, good.len() - 2] {
            assert!(strip(&good[..cut]).is_err(), "cut at {cut}");
        }
        // A segment claiming more than there is.
        let mut long = vec![0xFF, SOI, 0xFF, 0xE1, 0xFF, 0xFF];
        long.extend_from_slice(&[0; 10]);
        assert_eq!(strip(&long), Err(Error::Malformed));
        // No scan.
        let mut no_scan = vec![0xFF, SOI];
        no_scan.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        no_scan.extend_from_slice(&[0xFF, EOI]);
        assert_eq!(strip(&no_scan), Err(Error::NoImage));
        assert_eq!(strip(&vec![0; MAX_LEN + 1]), Err(Error::TooLarge));
    }

    #[test]
    fn a_lying_ifd_count_is_bounded() {
        let mut t = b"Exif\0\0MM\0*\0\0\0\x08\xFF\xFF".to_vec();
        t.extend_from_slice(&[0; 24]);
        assert_eq!(exif_orientation(&t), None);
        assert_eq!(exif_orientation(b"Exif\0\0MM\0*\xFF\xFF\xFF\xFF"), None);
    }
}
