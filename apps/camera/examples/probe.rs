//! On-device check of the platform camera without the app (D-0110): what access is, which
//! lenses there are, and what a session reports. Nothing is written to disk; frames and photos
//! are described, never printed.
//!
//! ```text
//! cargo run --example probe -- status          # access and lenses; never prompts
//! cargo run --example probe -- ask             # the system prompt
//! cargo run --example probe -- scan 20         # codes seen in 20 s
//! cargo run --example probe -- frames 5        # call frames for 5 s: size, rate, drops
//! cargo run --example probe -- photo           # one still: size, and what metadata is left
//! cargo run --example probe -- check 25        # ask if needed, then frames, photo, scan
//! PROBE_LENS=external cargo run --example probe -- scan 30   # scan with an external lens
//! ```
//!
//! macOS gives a bare binary no camera prompt: run it inside an app bundle with
//! `NSCameraUsageDescription` (see `docs/reports/CAM-M2.md`).

use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use songbird_camera::{Access, Config, Event, Lens, Purpose, Sink, platform};

fn main() {
    // The probe's mode and duration, typed by the person running it: no security decision.
    let args: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args
    let what = args.first().map_or("status", String::as_str);
    let secs = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let Some(cam) = platform() else {
        println!("no camera module on this platform");
        return;
    };
    println!("access: {:?}", cam.access());
    let lenses = cam.lenses();
    for l in &lenses {
        println!(
            "lens: {:?} {:?} ({} chars of id)",
            l.facing,
            l.name,
            l.id.len()
        );
    }
    match what {
        "status" => {}
        "ask" => println!("answer: {:?}", ask(&*cam)),
        "scan" => run(&*cam, &lenses, Purpose::ScanCode, secs),
        "frames" => run(&*cam, &lenses, Purpose::Call, secs),
        "photo" => run(&*cam, &lenses, Purpose::Photo, secs),
        "check" => {
            if cam.access() == Access::NotAsked {
                println!("answer: {:?}", ask(&*cam));
            }
            run(&*cam, &lenses, Purpose::Call, 3);
            run(&*cam, &lenses, Purpose::Photo, 10);
            println!("hold a QR code in front of the camera now");
            run(&*cam, &lenses, Purpose::ScanCode, secs);
        }
        other => println!("unknown: {other}"),
    }
}

fn ask(cam: &dyn songbird_camera::Backend) -> Option<Access> {
    let (tx, rx) = mpsc::channel();
    cam.request_access(Box::new(move |a| {
        let _ = tx.send(a);
    }));
    rx.recv_timeout(Duration::from_secs(120)).ok()
}

fn run(cam: &dyn songbird_camera::Backend, lenses: &[Lens], purpose: Purpose, secs: u64) {
    println!("-- {purpose:?} for up to {secs} s");
    if cam.access() != Access::Granted {
        println!("not granted: run `probe ask` first");
        return;
    }
    let wanted = std::env::var("PROBE_LENS").ok();
    let chosen = match wanted.as_deref() {
        Some("external") => lenses
            .iter()
            .find(|l| l.facing == songbird_camera::Facing::External),
        Some("front") => lenses
            .iter()
            .find(|l| l.facing == songbird_camera::Facing::Front),
        _ => Lens::preferred(lenses, purpose),
    };
    let Some(lens) = chosen else {
        println!("no lens");
        return;
    };
    let (sink, events, frames) = Sink::new();
    let started = Instant::now();
    let mut capture = match cam.open(
        Config {
            purpose,
            lens: lens.id.clone(),
        },
        sink,
    ) {
        Ok(c) => c,
        Err(e) => {
            println!("open failed: {e:?}");
            return;
        }
    };
    let deadline = started + Duration::from_secs(secs);
    let mut first_frame = None;
    let mut count = 0u32;
    let mut size = (0, 0);
    let mut photo_asked = false;
    let (still_tx, still_rx) = mpsc::channel();
    while Instant::now() < deadline {
        for e in events.drain() {
            match e {
                Event::Running { .. } => {
                    println!("running after {} ms", started.elapsed().as_millis());
                }
                Event::Code(text) => println!("code ({} chars): {text}", text.len()),
                Event::Unavailable(u) => println!("unavailable: {u:?}"),
            }
        }
        for f in frames.drain() {
            first_frame.get_or_insert_with(Instant::now);
            count += 1;
            size = (f.width, f.height);
            assert!(f.is_consistent());
        }
        if purpose == Purpose::Photo
            && !photo_asked
            && started.elapsed() > Duration::from_millis(1500)
        {
            photo_asked = true;
            let tx = still_tx.clone();
            capture.capture_photo(Box::new(move |r| {
                let _ = tx.send(r);
            }));
        }
        if let Ok(still) = still_rx.try_recv() {
            match still {
                Ok(s) => {
                    let exif = s.bytes.windows(4).filter(|w| w == b"Exif").count();
                    println!(
                        "photo: {}×{} {} bytes, {} EXIF block(s), GPS text: {}, ends with EOI: {}",
                        s.width,
                        s.height,
                        s.bytes.len(),
                        exif,
                        s.bytes.windows(3).any(|w| w == b"GPS"),
                        s.bytes.ends_with(&[0xFF, 0xD9])
                    );
                }
                Err(e) => println!("photo failed: {e:?}"),
            }
            break;
        }
        pump(Duration::from_millis(20));
    }
    if purpose == Purpose::Call {
        let secs = first_frame.map_or(0.0, |t| t.elapsed().as_secs_f64());
        println!(
            "frames: {count} of {}×{} in {secs:.1} s ({:.1}/s), {} dropped by the mailbox",
            size.0,
            size.1,
            f64::from(count) / secs.max(0.001),
            frames.dropped()
        );
    }
    drop(capture);
    pump(Duration::from_millis(500));
    println!("stopped");
}

/// Waits `d`, serving the main queue as an app's run loop does (AVFoundation delivers photos
/// there).
fn pump(d: Duration) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let until = objc2_foundation::NSDate::dateWithTimeIntervalSinceNow(d.as_secs_f64());
        objc2_foundation::NSRunLoop::mainRunLoop().runUntilDate(&until);
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    std::thread::sleep(d);
}
