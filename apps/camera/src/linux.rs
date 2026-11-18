//! Linux: V4L2 (D-0110, M4; D-0114), through the `v4l` crate's safe API, and a GTK preview.
//!
//! Each capture opens `/dev/videoN`, asks for YUYV at 1280×720 (the driver picks the nearest),
//! and reads memory-mapped buffers on a thread of its own; [`crate::desktop`] routes the frames.
//! Access is the device node's: a node the user may not open is `Denied` (Settings cannot fix
//! it; the screen says the system turned the camera off).
//!
//! Not here yet: the camera portal with PipeWire, which a Flatpak build needs (its sandbox has
//! no `/dev/video*`). Songbird has no Flatpak build; D-0114 records it as the next step.
//!
//! No `unsafe` in this module.

#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use v4l::{
    Device, FourCC,
    buffer::Type,
    capability::Flags,
    io::{mmap::Stream, traits::CaptureStream},
    video::Capture as _,
};

use crate::{
    Access, AccessCallback, Backend, Capture, Config, Facing, Frame, Lens, Rotation, Sink,
    Unavailable,
    desktop::{Opener, Pump, ThreadCapture},
    frame::nv12_from_yuyv,
};

/// The camera on Linux.
#[derive(Debug, Default)]
pub struct LinuxCamera;

/// Video capture nodes, `/dev/video0` first.
fn nodes() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir("/dev").map_or_else(
        |_| Vec::new(),
        |d| {
            d.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("video"))
                })
                .collect()
        },
    );
    found.sort();
    found
}

/// Whether `node` captures video (not a metadata or output node), with its card name.
fn capture_node(node: &Path) -> Option<String> {
    let dev = Device::with_path(node).ok()?;
    let caps = dev.query_caps().ok()?;
    caps.capabilities
        .contains(Flags::VIDEO_CAPTURE)
        .then_some(caps.card)
}

impl Backend for LinuxCamera {
    fn access(&self) -> Access {
        let nodes = nodes();
        if nodes.is_empty() {
            // No camera: the screens say so once a capture finds no lens.
            return Access::Granted;
        }
        let denied = nodes.iter().all(|n| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(n)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        });
        if denied {
            Access::Denied
        } else {
            Access::Granted
        }
    }

    fn request_access(&self, done: AccessCallback) {
        // No prompt on Linux outside a sandbox: access is the device node's.
        done(self.access());
    }

    fn lenses(&self) -> Vec<Lens> {
        nodes()
            .into_iter()
            .filter_map(|n| {
                let name = capture_node(&n)?;
                Some(Lens {
                    id: n.to_string_lossy().into_owned(),
                    name,
                    facing: Facing::External,
                })
            })
            .take(16)
            .collect()
    }

    fn open(&self, config: Config, sink: Sink) -> Result<Box<dyn Capture>, Unavailable> {
        let open: Opener = Arc::new(|lens: &str, pump: Pump| {
            let lens = lens.to_owned();
            std::thread::Builder::new()
                .name("songbird-v4l2".into())
                .spawn(move || read(&lens, pump))
        });
        Ok(Box::new(ThreadCapture::start(
            config.purpose,
            &config.lens,
            sink,
            open,
        )?))
    }

    fn settings_url(&self) -> Option<&'static str> {
        // GNOME Settings › Privacy › Camera; other desktops ignore it.
        Some("gnome-control-center:privacy")
    }
}

fn unavailable_of(e: &std::io::Error) -> Unavailable {
    match e.raw_os_error() {
        Some(16) => Unavailable::InUse,         // EBUSY
        Some(13 | 1) => Unavailable::SystemOff, // EACCES, EPERM
        Some(2 | 19) => Unavailable::NoCamera,  // ENOENT, ENODEV
        _ => Unavailable::Failed(e.kind().to_string()),
    }
}

/// Reads `lens` until the pump says stop.
fn read(lens: &str, mut pump: Pump) {
    let dev = match Device::with_path(lens) {
        Ok(d) => d,
        Err(e) => return pump.unavailable(unavailable_of(&e)),
    };
    let mut fmt = match dev.format() {
        Ok(f) => f,
        Err(e) => return pump.unavailable(unavailable_of(&e)),
    };
    fmt.width = 1280;
    fmt.height = 720;
    fmt.fourcc = FourCC::new(b"YUYV");
    let fmt = match dev.set_format(&fmt) {
        Ok(f) if f.fourcc == FourCC::new(b"YUYV") => f,
        Ok(_) => return pump.unavailable(Unavailable::Failed("the camera offers no YUYV".into())),
        Err(e) => return pump.unavailable(unavailable_of(&e)),
    };
    let mut stream = match Stream::with_buffers(&dev, Type::VideoCapture, 4) {
        Ok(s) => s,
        Err(e) => return pump.unavailable(unavailable_of(&e)),
    };
    // A driver's sizes are not trusted: at most 8192 a side, as on the other platforms.
    if fmt.width == 0 || fmt.height == 0 || fmt.width > 8192 || fmt.height > 8192 {
        return pump.unavailable(Unavailable::Failed("frame size".into()));
    }
    // Wake at least twice a second, so a stalled camera still sees the stop.
    stream.set_timeout(std::time::Duration::from_millis(500));
    let (w, h, stride) = (fmt.width as usize, fmt.height as usize, fmt.stride as usize);
    while !pump.stopped() {
        let (data, meta) = match stream.next() {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return pump.unavailable(unavailable_of(&e)),
        };
        pump.running(lens);
        let Some(pixels) = nv12_from_yuyv(data, stride.max(w * 2), w, h) else {
            continue;
        };
        let timestamp_us = u64::try_from(meta.timestamp.sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000)
            .saturating_add(u64::try_from(meta.timestamp.usec).unwrap_or(0));
        pump.frame(Frame {
            width: fmt.width,
            height: fmt.height,
            rotation: Rotation::Deg0,
            timestamp_us,
            pixels,
        });
    }
}

// ---------------------------------------------------------------- the preview

mod preview {
    use std::{cell::Cell, rc::Rc, time::Duration};

    use gtk4::{gdk, glib, prelude::*};
    use nsh_platform_linux::{ComponentContext, Components, NativeComponent};

    use crate::desktop::latest;

    /// A picture showing the newest image of the capture its `session` prop names, checked
    /// each display frame (≈ 30 per second) and redrawn only when it changed.
    struct Preview {
        picture: gtk4::Picture,
        session: Rc<Cell<u64>>,
    }

    impl NativeComponent for Preview {
        fn widget(&self) -> gtk4::Widget {
            self.picture.clone().upcast()
        }

        fn set_prop(&mut self, name: &str, value: Option<&serde_json::Value>) {
            if name == "session" {
                self.session
                    .set(value.and_then(serde_json::Value::as_u64).unwrap_or(0));
                if self.session.get() == 0 {
                    self.picture.set_paintable(None::<&gdk::Paintable>);
                }
            }
        }
    }

    /// Registers `songbird/camera`.
    pub fn register(components: &Components) {
        components.register(
            "songbird/camera",
            Rc::new(|_cx: ComponentContext| {
                let picture = gtk4::Picture::new();
                picture.set_content_fit(gtk4::ContentFit::Cover);
                picture.set_can_shrink(true);
                let session = Rc::new(Cell::new(0u64));
                let shown = Rc::new(Cell::new(0u64));
                let (weak, s) = (picture.downgrade(), session.clone());
                glib::timeout_add_local(Duration::from_millis(33), move || {
                    let Some(picture) = weak.upgrade() else {
                        return glib::ControlFlow::Break;
                    };
                    if let Some((generation, image)) = latest(s.get())
                        && generation != shown.get()
                    {
                        shown.set(generation);
                        let bytes = glib::Bytes::from(&image.bgra[..]);
                        let texture = gdk::MemoryTexture::new(
                            i32::try_from(image.width).unwrap_or(0),
                            i32::try_from(image.height).unwrap_or(0),
                            gdk::MemoryFormat::B8g8r8a8,
                            &bytes,
                            image.width as usize * 4,
                        );
                        picture.set_paintable(Some(&texture));
                    }
                    glib::ControlFlow::Continue
                });
                Box::new(Preview { picture, session }) as Box<dyn NativeComponent>
            }),
        );
    }
}

pub use preview::register;
