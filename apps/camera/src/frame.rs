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
    fn a_frame_never_prints_its_pixels() {
        let printed = format!("{:?}", grey(1, 1, 1, 1));
        assert!(!printed.contains("data"), "{printed}");
    }
}
