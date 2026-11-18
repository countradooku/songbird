//! Frames: what the camera hands a call's encoder or a code scanner.

#![forbid(unsafe_code)]

/// How a frame must be turned to be upright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Rotation {
    /// Upright already.
    #[default]
    Deg0,
    /// A quarter turn clockwise.
    Deg90,
    /// Half a turn.
    Deg180,
    /// Three quarter turns clockwise.
    Deg270,
}

/// A frame's pixels.
#[derive(Clone, PartialEq, Eq)]
pub enum Pixels {
    /// 8-bit luma only (what scanners read).
    Grey {
        /// Rows of `stride` bytes.
        data: Vec<u8>,
        /// Bytes per row, at least the width.
        stride: usize,
    },
    /// NV12: a luma plane and an interleaved half-size chroma plane (what cameras give and
    /// encoders take).
    Nv12 {
        /// The luma plane, rows of `y_stride` bytes.
        y: Vec<u8>,
        /// Bytes per luma row.
        y_stride: usize,
        /// The `CbCr` plane, `height / 2` rows of `uv_stride` bytes.
        uv: Vec<u8>,
        /// Bytes per chroma row.
        uv_stride: usize,
    },
    /// 32-bit BGRA, rows of `stride` bytes.
    Bgra {
        /// The pixels.
        data: Vec<u8>,
        /// Bytes per row, at least four times the width.
        stride: usize,
    },
}

/// One camera frame.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// Width in pixels, as captured (before [`Self::rotation`]).
    pub width: u32,
    /// Height in pixels, as captured.
    pub height: u32,
    /// How to turn it upright.
    pub rotation: Rotation,
    /// When it was captured, in microseconds of the platform's monotonic clock.
    pub timestamp_us: u64,
    /// Its pixels.
    pub pixels: Pixels,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the pixels: they are what the person's camera sees.
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("rotation", &self.rotation)
            .field("timestamp_us", &self.timestamp_us)
            .finish_non_exhaustive()
    }
}

impl Frame {
    /// Whether the planes hold what the size and strides promise. Platform code checks every
    /// frame it builds; readers may rely on it.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let (w, h) = (self.width as usize, self.height as usize);
        if w == 0 || h == 0 {
            return false;
        }
        let fits = |data: &[u8], stride: usize, row: usize, rows: usize| {
            stride >= row && stride.checked_mul(rows).is_some_and(|n| data.len() >= n)
        };
        match &self.pixels {
            Pixels::Grey { data, stride } => fits(data, *stride, w, h),
            Pixels::Nv12 {
                y,
                y_stride,
                uv,
                uv_stride,
            } => fits(y, *y_stride, w, h) && fits(uv, *uv_stride, w.div_ceil(2) * 2, h.div_ceil(2)),
            Pixels::Bgra { data, stride } => w
                .checked_mul(4)
                .is_some_and(|row| fits(data, *stride, row, h)),
        }
    }

    /// The luma of this frame as rows of `width` bytes (BGRA converted with BT.601 weights).
    /// `None` when the frame is inconsistent.
    #[must_use]
    pub fn luma(&self) -> Option<Vec<u8>> {
        if !self.is_consistent() {
            return None;
        }
        let (w, h) = (self.width as usize, self.height as usize);
        let mut out = Vec::with_capacity(w * h);
        match &self.pixels {
            Pixels::Grey { data, stride }
            | Pixels::Nv12 {
                y: data,
                y_stride: stride,
                ..
            } => {
                for row in data.chunks(*stride).take(h) {
                    out.extend_from_slice(&row[..w]);
                }
            }
            Pixels::Bgra { data, stride } => {
                for row in data.chunks(*stride).take(h) {
                    for px in row[..w * 4].as_chunks::<4>().0 {
                        let (blue, green, red) =
                            (u32::from(px[0]), u32::from(px[1]), u32::from(px[2]));
                        // 0.299 R + 0.587 G + 0.114 B, in 1/256ths; at most 255.
                        #[allow(clippy::cast_possible_truncation)]
                        out.push(((77 * red + 150 * green + 29 * blue) >> 8) as u8);
                    }
                }
            }
        }
        Some(out)
    }
}

/// `height` rows of `width` bytes from a plane whose rows are `stride` apart.
#[cfg_attr(not(target_os = "android"), allow(dead_code))] // Android's frames; tested everywhere
pub(crate) fn luma_rows(
    plane: &[u8],
    stride: usize,
    width: usize,
    height: usize,
) -> Option<Vec<u8>> {
    if stride < width {
        return None;
    }
    let mut out = Vec::with_capacity(width.checked_mul(height)?);
    for row in 0..height {
        let start = row.checked_mul(stride)?;
        out.extend_from_slice(plane.get(start..start.checked_add(width)?)?);
    }
    Some(out)
}

/// NV12 from YUV_420_888 planes (any pixel stride), checked against the buffers' lengths.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))] // Android's frames; tested everywhere
pub(crate) fn nv12_from_yuv(
    y: &[u8],
    y_stride: usize,
    u: &[u8],
    v: &[u8],
    uv_stride: usize,
    uv_pixel: usize,
    width: usize,
    height: usize,
) -> Option<Pixels> {
    if width == 0 || height == 0 || y_stride < width || uv_pixel == 0 {
        return None;
    }
    let luma = luma_rows(y, y_stride, width, height)?;
    let (cw, ch) = (width.div_ceil(2), height.div_ceil(2));
    let mut uv = Vec::with_capacity(cw * 2 * ch);
    for row in 0..ch {
        for col in 0..cw {
            let at = row
                .checked_mul(uv_stride)?
                .checked_add(col.checked_mul(uv_pixel)?)?;
            uv.push(*u.get(at)?);
            uv.push(*v.get(at)?);
        }
    }
    Some(Pixels::Nv12 {
        y: luma,
        y_stride: width,
        uv,
        uv_stride: cw * 2,
    })
}

/// NV12 from packed YUYV (YUY2: `Y0 U Y1 V` per two pixels), as webcams give it over V4L2;
/// chroma of every other row. Checked against the buffer's length.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux's frames; tested everywhere
pub(crate) fn nv12_from_yuyv(
    data: &[u8],
    stride: usize,
    width: usize,
    height: usize,
) -> Option<Pixels> {
    if width < 2 || height == 0 || !width.is_multiple_of(2) || stride < width.checked_mul(2)? {
        return None;
    }
    let mut y = Vec::with_capacity(width * height);
    let mut uv = Vec::with_capacity(width * height.div_ceil(2));
    for row in 0..height {
        let start = row.checked_mul(stride)?;
        let line = data.get(start..start.checked_add(width * 2)?)?;
        let (quads, _) = line.as_chunks::<4>();
        for &[y0, u, y1, v] in quads {
            y.extend_from_slice(&[y0, y1]);
            if row % 2 == 0 {
                uv.extend_from_slice(&[u, v]);
            }
        }
    }
    Some(Pixels::Nv12 {
        y,
        y_stride: width,
        uv,
        uv_stride: width,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grey(w: u32, h: u32, stride: usize, len: usize) -> Frame {
        Frame {
            width: w,
            height: h,
            rotation: Rotation::Deg0,
            timestamp_us: 0,
            pixels: Pixels::Grey {
                data: vec![9; len],
                stride,
            },
        }
    }

    #[test]
    fn inconsistent_frames_are_refused() {
        assert!(grey(4, 2, 4, 8).is_consistent());
        assert!(grey(4, 2, 6, 12).is_consistent());
        assert!(!grey(4, 2, 3, 8).is_consistent()); // stride below the width
        assert!(!grey(4, 2, 4, 7).is_consistent()); // short
        assert!(!grey(0, 2, 4, 8).is_consistent());
        assert!(!grey(4, 2, usize::MAX, 8).is_consistent()); // overflow
        assert!(grey(4, 2, 3, 8).luma().is_none());
    }

    #[test]
    fn luma_drops_the_padding_and_converts_bgra() {
        let f = Frame {
            width: 2,
            height: 1,
            rotation: Rotation::Deg0,
            timestamp_us: 0,
            pixels: Pixels::Bgra {
                data: vec![0, 0, 0, 255, 255, 255, 255, 255, 1, 2],
                stride: 10,
            },
        };
        assert_eq!(f.luma(), Some(vec![0, 255]));
        let padded = Frame {
            pixels: Pixels::Grey {
                data: vec![1, 2, 0, 3, 4, 0],
                stride: 3,
            },
            ..f.clone()
        };
        let padded = Frame {
            height: 2,
            ..padded
        };
        assert_eq!(padded.luma(), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn nv12_from_interleaved_and_planar_chroma() {
        // 2×2, Y rows 4 apart; chroma interleaved (pixel stride 2) or planar (1).
        let y = [1, 2, 0, 0, 3, 4, 0, 0];
        let Some(Pixels::Nv12 { y: luma, uv, .. }) =
            nv12_from_yuv(&y, 4, &[10, 20], &[11, 21], 4, 2, 2, 2)
        else {
            panic!("converted")
        };
        assert_eq!((luma, uv), (vec![1, 2, 3, 4], vec![10, 11]));
        let Some(Pixels::Nv12 { uv, .. }) = nv12_from_yuv(&y, 4, &[10], &[11], 1, 1, 2, 2) else {
            panic!("converted")
        };
        assert_eq!(uv, vec![10, 11]);
        // Short planes and odd strides are refused, never read past.
        assert!(nv12_from_yuv(&y[..5], 4, &[10], &[11], 4, 2, 2, 2).is_none());
        assert!(nv12_from_yuv(&y, 1, &[10], &[11], 4, 2, 2, 2).is_none());
        assert!(nv12_from_yuv(&y, 4, &[], &[11], 4, 2, 2, 2).is_none());
        assert!(nv12_from_yuv(&y, usize::MAX, &[10], &[11], 4, 2, 2, 2).is_none());
    }

    #[test]
    fn nv12_from_yuyv_takes_every_other_chroma_row() {
        // 2×2: rows `Y0 U Y1 V`, 4 bytes, stride 6 (padding).
        let data = [1, 10, 2, 11, 0, 0, 3, 20, 4, 21, 0, 0];
        let Some(Pixels::Nv12 { y, uv, .. }) = nv12_from_yuyv(&data, 6, 2, 2) else {
            panic!("converted")
        };
        assert_eq!((y, uv), (vec![1, 2, 3, 4], vec![10, 11]));
        assert!(nv12_from_yuyv(&data[..9], 6, 2, 2).is_none());
        assert!(nv12_from_yuyv(&data, 3, 2, 2).is_none());
        assert!(nv12_from_yuyv(&data, 6, 3, 2).is_none());
    }

    #[test]
    fn a_frame_never_prints_its_pixels() {
        let printed = format!("{:?}", grey(1, 1, 1, 1));
        assert!(!printed.contains("data"), "{printed}");
    }
}
