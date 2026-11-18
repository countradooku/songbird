//! What Windows and Linux share (D-0110, M4): a thread reads frames from the system's camera
//! (Media Foundation, V4L2), and a [`Pump`] routes each one: to the preview, to the scanner, to
//! a call's encoder, and keeps the newest for a photo. The platform code only opens the device
//! and reads frames; everything here is safe Rust, tested with a fake source.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(any(target_os = "windows", target_os = "linux", test)),
    allow(dead_code)
)]

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
};

use crate::{
    Capture, CaptureError, Frame, Pixels, Purpose, Sink, Still, StillCallback, Unavailable, jpeg,
    qr::Scanner,
};

// ---------------------------------------------------------------- preview images

/// A preview image: BGRA, rows of `width * 4` bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Image {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The pixels.
    pub bgra: Vec<u8>,
}

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// The longest side of a preview image: enough for the scanner's box and a call's self-view,
/// and a bounded cost per frame.
pub const PREVIEW_SIDE: u32 = 640;

/// BT.601 full range, in 1/256ths.
fn rgb(y: u8, u: u8, v: u8) -> [u8; 3] {
    let (y, u, v) = (i32::from(y), i32::from(u) - 128, i32::from(v) - 128);
    let c = |x: i32| u8::try_from(x.clamp(0, 255)).unwrap_or(0);
    [
        c(y + ((359 * v) >> 8)),
        c(y - ((88 * u + 183 * v) >> 8)),
        c(y + ((454 * u) >> 8)),
    ]
}

/// `frame` as RGB rows (`width * 3` bytes), scaled down by a whole factor until its longest
/// side is at most `max_side`.
#[must_use]
#[allow(clippy::many_single_char_names)] // pixel arithmetic: x, y, w, h, f
pub fn rgb_scaled(frame: &Frame, max_side: u32) -> Option<(u32, u32, Vec<u8>)> {
    if !frame.is_consistent() {
        return None;
    }
    let (w, h) = (frame.width, frame.height);
    let factor = w.max(h).div_ceil(max_side.max(1)).max(1);
    let (ow, oh) = ((w / factor).max(1), (h / factor).max(1));
    let f = factor as usize;
    let mut out = Vec::with_capacity(ow as usize * oh as usize * 3);
    for oy in 0..oh as usize {
        for ox in 0..ow as usize {
            let (x, y) = (ox * f, oy * f);
            let px = match &frame.pixels {
                Pixels::Grey { data, stride } => {
                    let g = data[y * stride + x];
                    [g, g, g]
                }
                Pixels::Nv12 {
                    y: luma,
                    y_stride,
                    uv,
                    uv_stride,
                } => {
                    let c = (y / 2) * uv_stride + (x / 2) * 2;
                    rgb(luma[y * y_stride + x], uv[c], uv[c + 1])
                }
                Pixels::Bgra { data, stride } => {
                    let i = y * stride + x * 4;
                    [data[i + 2], data[i + 1], data[i]]
                }
            };
            out.extend_from_slice(&px);
        }
    }
    Some((ow, oh, out))
}

/// `frame` as a preview image ([`PREVIEW_SIDE`]).
#[must_use]
pub fn preview_of(frame: &Frame) -> Option<Image> {
    let (width, height, rgb) = rgb_scaled(frame, PREVIEW_SIDE)?;
    let mut bgra = Vec::with_capacity(rgb.len() / 3 * 4);
    let (pixels, _) = rgb.as_chunks::<3>();
    for &[r, g, b] in pixels {
        bgra.extend_from_slice(&[b, g, r, 255]);
    }
    Some(Image {
        width,
        height,
        bgra,
    })
}

/// `frame` as a still: JPEG at full size, through the metadata filter.
///
/// # Errors
///
/// The frame is inconsistent or too large for JPEG (65,535 a side).
pub fn still_of(frame: &Frame) -> Result<Still, CaptureError> {
    let (w, h, rgb) = rgb_scaled(frame, u32::MAX).ok_or(CaptureError::Failed("frame".into()))?;
    let (w16, h16) = (u16::try_from(w), u16::try_from(h));
    let (Ok(w16), Ok(h16)) = (w16, h16) else {
        return Err(CaptureError::Failed("size".into()));
    };
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, 90)
        .encode(&rgb, w16, h16, jpeg_encoder::ColorType::Rgb)
        .map_err(|e| CaptureError::Failed(e.to_string()))?;
    let stripped = jpeg::strip(&out).map_err(|e| CaptureError::Failed(format!("{e:?}")))?;
    let (width, height) = stripped.upright_size();
    Ok(Still {
        bytes: stripped.bytes,
        mime: "image/jpeg",
        width,
        height,
    })
}

/// The newest preview image of each running capture, for the native preview components.
#[derive(Default)]
struct Slot {
    generation: u64,
    image: Option<Arc<Image>>,
    watchers: Vec<Arc<dyn Fn() + Send + Sync>>,
}

static SLOTS: Mutex<Option<HashMap<u64, Slot>>> = Mutex::new(None);

fn slots<R>(f: impl FnOnce(&mut HashMap<u64, Slot>) -> R) -> R {
    f(SLOTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new))
}

/// The newest image of capture `id` and its generation (it grows with every image).
#[must_use]
pub fn latest(id: u64) -> Option<(u64, Arc<Image>)> {
    slots(|s| {
        s.get(&id)
            .and_then(|slot| slot.image.clone().map(|i| (slot.generation, i)))
    })
}

/// Calls `wake` (from the capture's thread) whenever capture `id` has a new image.
pub fn watch(id: u64, wake: Arc<dyn Fn() + Send + Sync>) {
    slots(|s| s.entry(id).or_default().watchers.push(wake));
}

fn publish(id: u64, image: Image) {
    let watchers = slots(|s| {
        let slot = s.entry(id).or_default();
        slot.generation += 1;
        slot.image = Some(Arc::new(image));
        slot.watchers.clone()
    });
    for w in watchers {
        w();
    }
}

fn forget(id: u64) {
    slots(|s| s.remove(&id));
}

// ---------------------------------------------------------------- the pump

/// What a platform's reading thread reports into.
pub struct Pump {
    id: u64,
    purpose: Purpose,
    sink: Sink,
    scanner: Option<Scanner>,
    last: Arc<Mutex<Option<Frame>>>,
    stop: Arc<AtomicBool>,
    running: bool,
}

impl Pump {
    /// Whether the reading thread must end.
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire) || !self.sink.is_open()
    }

    /// The camera runs with `lens` (reported once per start).
    pub fn running(&mut self, lens: &str) {
        if !self.running {
            self.running = true;
            self.sink.running(lens);
        }
    }

    /// The camera cannot run.
    pub fn unavailable(&self, why: Unavailable) {
        self.sink.unavailable(why);
    }

    /// A frame: to the preview, then by purpose. Inconsistent frames are dropped.
    pub fn frame(&mut self, frame: Frame) {
        if !frame.is_consistent() {
            return;
        }
        if let Some(image) = preview_of(&frame) {
            publish(self.id, image);
        }
        match self.purpose {
            Purpose::ScanCode => {
                if let Some(s) = &self.scanner {
                    s.offer(frame);
                }
            }
            Purpose::Call => self.sink.frame(frame),
            Purpose::Photo | Purpose::Video => {
                *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(frame);
            }
        }
    }
}

/// Starts a platform's reading thread for `lens`, reporting into the pump.
pub type Opener = Arc<dyn Fn(&str, Pump) -> std::io::Result<JoinHandle<()>> + Send + Sync>;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A capture run by a reading thread; dropping it stops and joins the thread.
pub struct ThreadCapture {
    id: u64,
    purpose: Purpose,
    sink: Sink,
    open: Opener,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    last: Arc<Mutex<Option<Frame>>>,
}

impl ThreadCapture {
    /// Starts reading `lens` for `purpose`.
    ///
    /// # Errors
    ///
    /// The thread could not start.
    pub fn start(
        purpose: Purpose,
        lens: &str,
        sink: Sink,
        open: Opener,
    ) -> Result<Self, Unavailable> {
        let mut c = ThreadCapture {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            purpose,
            sink,
            open,
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            last: Arc::new(Mutex::new(None)),
        };
        c.spawn(lens)?;
        Ok(c)
    }

    fn spawn(&mut self, lens: &str) -> Result<(), Unavailable> {
        self.stop = Arc::new(AtomicBool::new(false));
        let pump = Pump {
            id: self.id,
            purpose: self.purpose,
            sink: self.sink.clone(),
            scanner: (self.purpose == Purpose::ScanCode).then(|| Scanner::start(self.sink.clone())),
            last: self.last.clone(),
            stop: self.stop.clone(),
            running: false,
        };
        let thread = (self.open)(lens, pump).map_err(|e| Unavailable::Failed(e.to_string()))?;
        self.thread = Some(thread);
        Ok(())
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Capture for ThreadCapture {
    fn set_lens(&mut self, lens: &str) {
        self.halt();
        if let Err(why) = self.spawn(lens) {
            self.sink.unavailable(why);
        }
    }

    fn set_torch(&mut self, _on: bool) -> bool {
        // Webcams have no torch.
        false
    }

    fn capture_photo(&mut self, done: StillCallback) {
        if self.purpose != Purpose::Photo {
            return done(Err(CaptureError::WrongPurpose));
        }
        let frame = self
            .last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        done(frame.map_or(Err(CaptureError::NotRunning), |f| still_of(&f)));
    }

    fn preview_id(&self) -> u64 {
        self.id
    }
}

impl Drop for ThreadCapture {
    fn drop(&mut self) {
        self.halt();
        forget(self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{Event, Rotation};

    fn grey_frame(rows: &[&str], module: usize) -> Frame {
        let (side, data) = crate::qr::tests::render(rows, module);
        let s = u32::try_from(side).unwrap();
        Frame {
            width: s,
            height: s,
            rotation: Rotation::Deg0,
            timestamp_us: 0,
            pixels: Pixels::Grey { data, stride: side },
        }
    }

    /// A source that sends `frame` until stopped.
    fn source(frame: Frame) -> Opener {
        Arc::new(move |lens: &str, mut pump: Pump| {
            let (frame, lens) = (frame.clone(), lens.to_owned());
            std::thread::Builder::new().spawn(move || {
                pump.running(&lens);
                while !pump.stopped() {
                    pump.frame(frame.clone());
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        })
    }

    #[test]
    fn a_scanning_capture_reads_codes_publishes_previews_and_stops() {
        let (sink, events, _) = Sink::new();
        let frame = grey_frame(&crate::qr::tests::SONGBIRD_V1, 4);
        let capture = ThreadCapture::start(Purpose::ScanCode, "cam0", sink, source(frame)).unwrap();
        let id = capture.preview_id();
        let woken = Arc::new(AtomicU64::new(0));
        let w = woken.clone();
        watch(
            id,
            Arc::new(move || {
                w.fetch_add(1, Ordering::Relaxed);
            }),
        );
        std::thread::sleep(Duration::from_millis(300));
        let (generation, image) = latest(id).expect("a preview");
        assert!(generation > 1 && woken.load(Ordering::Relaxed) > 0);
        assert_eq!((image.width, image.height), (116, 116));
        drop(capture);
        assert!(latest(id).is_none(), "forgotten when stopped");
        let got = events.drain();
        assert_eq!(
            got[0],
            Event::Running {
                lens: "cam0".into()
            }
        );
        assert_eq!(
            got.iter()
                .filter(|e| matches!(e, Event::Code(c) if c == "SONGBIRD"))
                .count(),
            1
        );
    }

    #[test]
    fn a_photo_is_the_newest_frame_as_a_clean_jpeg() {
        // The receivers stay alive: a sink whose app is gone stops the reading thread.
        let (sink, _events, _frames) = Sink::new();
        let frame = Frame {
            width: 64,
            height: 48,
            rotation: Rotation::Deg0,
            timestamp_us: 0,
            pixels: Pixels::Nv12 {
                y: vec![200; 64 * 48],
                y_stride: 64,
                uv: vec![128; 64 * 24],
                uv_stride: 64,
            },
        };
        let mut capture =
            ThreadCapture::start(Purpose::Photo, "cam0", sink, source(frame)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let got = Arc::new(Mutex::new(None));
        let g = got.clone();
        capture.capture_photo(Box::new(move |r| *g.lock().unwrap() = Some(r)));
        let still = got.lock().unwrap().take().unwrap().unwrap();
        assert_eq!(
            (still.width, still.height, still.mime),
            (64, 48, "image/jpeg")
        );
        assert!(still.bytes.starts_with(&[0xFF, 0xD8]) && still.bytes.ends_with(&[0xFF, 0xD9]));
        assert!(!still.bytes.windows(4).any(|w| w == b"JFIF" || w == b"Exif"));
        // Not a photo session: refused.
        let (sink, _events2, _frames2) = Sink::new();
        let mut scan =
            ThreadCapture::start(Purpose::ScanCode, "c", sink, source(grey_frame(&["#"], 1)))
                .unwrap();
        scan.capture_photo(Box::new(|r| assert_eq!(r, Err(CaptureError::WrongPurpose))));
    }

    #[test]
    fn call_frames_go_to_the_encoder_and_switching_lens_restarts() {
        let (sink, events, frames) = Sink::new();
        let mut capture =
            ThreadCapture::start(Purpose::Call, "front", sink, source(grey_frame(&["#"], 8)))
                .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_ne!(frames.drain().len(), 0);
        capture.set_lens("usb");
        std::thread::sleep(Duration::from_millis(50));
        let lenses: Vec<_> = events
            .drain()
            .into_iter()
            .filter_map(|e| match e {
                Event::Running { lens } => Some(lens),
                _ => None,
            })
            .collect();
        assert_eq!(lenses, ["front", "usb"]);
    }

    #[test]
    fn colours_convert_and_scale() {
        assert_eq!(rgb(128, 128, 128), [128, 128, 128]);
        assert_eq!(rgb(255, 128, 255), [255, 165, 255]); // G = 255 − 0.714 × 127
        let big = Frame {
            width: 1920,
            height: 1080,
            rotation: Rotation::Deg0,
            timestamp_us: 0,
            pixels: Pixels::Grey {
                data: vec![7; 1920 * 1080],
                stride: 1920,
            },
        };
        let img = preview_of(&big).unwrap();
        assert!(img.width <= PREVIEW_SIDE && img.height <= PREVIEW_SIDE);
        assert_eq!(img.bgra.len(), (img.width * img.height * 4) as usize);
    }
}
