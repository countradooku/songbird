# CAM-M4 — Windows and Linux

- Date: 2026-11-18
- Plan: [CAM-plan.md](CAM-plan.md) (D-0110, question 5: portal then V4L2); decision D-0114
- Status: built and tested in the VMs; Linux checked end to end on a virtual camera; Windows
  checked without a camera (the VM has none). **Linux's portal and PipeWire path is not built**
  (below).

## What was built

| Piece | Where |
| --- | --- |
| What both desktops share: a reading thread per capture, a `Pump` that routes each frame (preview, scanner, call, newest for a photo), lens switching by restart, preview images (BGRA, at most 640 a side) with watchers, stills as JPEG in pure Rust through the M1 filter | `apps/camera/src/desktop.rs` (no `unsafe`) |
| Windows: access from the camera privacy switches (device policy → `Restricted`; user or desktop apps off → `Denied`; no prompt exists), lenses from `MFEnumDeviceSources`, NV12 through a source reader with video processing, errors mapped (privacy switch, in use, removed) | `apps/camera/src/windows.rs` |
| Windows preview: the newest image drawn with Direct2D, cover-cropped, redrawn when a new image comes (`ComponentContext::redraw` from the reading thread) | `windows.rs` (`preview`) |
| Linux: V4L2 capture nodes, YUYV at 1280×720 through memory-mapped buffers (`v4l`'s safe API), errors mapped (`EBUSY`, `EACCES`, `ENODEV`) | `apps/camera/src/linux.rs` (no `unsafe`) |
| Linux preview: a `gtk::Picture` fed `MemoryTexture`s, checked each frame and replaced only when the image changed | `linux.rs` (`preview`) |
| YUYV → NV12, tested on every host | `apps/camera/src/frame.rs` |
| Registration from the app: `#[native_components(windows)]`, `#[native_components(linux)]` | `apps/ui/src/lib.rs` |

## Checked

| Check | Result |
| --- | --- |
| `songbird-camera` tests on macOS, Ubuntu 26.04 (aarch64 VM), Windows 11 24H2 (ARM64 VM) | 28 passed on each |
| `cargo clippy --all-targets` (pedantic) on each | clean (after fixing 10 notes on Windows and 3 on Linux: sign-preserving casts of HRESULTs and the reader's stream constant, raw borrows for Direct2D, `f32::midpoint`) |
| `apps/ui` `cargo check --lib` on Linux | builds, with the Linux component registered |
| `apps/ui` on Windows ARM64 | **not built**: the app's `aws-lc-sys` needs `clang-cl`, which the VM's Visual Studio Build Tools lack (the camera crate builds) |

**Linux, end to end** (`v4l2loopback` 0.15.3 loaded as `/dev/video0`, fed the test link code
at 1280×720 YUYV, 15 fps, by GStreamer; the probe of M2):

| Check | Result |
| --- | --- |
| Access, lenses | granted (the node opens); one lens, "SongbirdTestCam" |
| Call frames | 1280×720 NV12, 15.2–15.5 frames/s (the feed's rate), none dropped |
| A photo | 1280×720 JPEG, 28,649 bytes, no EXIF, no JFIF, ends at EOI |
| Scanning | the link code read in full (111 characters), once |

**Windows** (no camera in the VM): access "granted" from the consent store, no lenses, so every
purpose ends in "no lens": the app's "No camera found".

## Not built, and why

- **Linux's camera portal with PipeWire** (the plan's first path, D-0110 question 5 "both"). A
  sandboxed (Flatpak) build has no `/dev/video*` and needs it; Songbird has no Flatpak build
  yet, and outside a sandbox the portal grants every app anyway, so V4L2 directly is what a
  native package uses. It is the next step before a Flatpak exists: `AccessCamera` and
  `OpenPipeWireRemote` through GIO's D-Bus, then a PipeWire stream (`pipewire` 0.10). Recorded
  in D-0114 as open.
- **Video clips** on Windows and Linux: later, as the owner decided (question 3).

## `unsafe`

Only in `windows.rs`: COM calls into Media Foundation, the registry and Direct2D, and reading a
locked media buffer within its reported length; each block has its `SAFETY:` comment.
`desktop.rs` and `linux.rs` forbid `unsafe`.

## New dependencies

- Windows: `windows` 0.62 (the version NSH links) with the Media Foundation, COM, registry,
  Direct2D and DXGI features; `nsh-platform-windows` 0.6.0; `serde_json`.
- Linux: `v4l` 0.14.0 (MIT; `v4l2-sys-mit` bindings, no `libv4l`); `gtk4` 0.11 (as NSH);
  `nsh-platform-linux` 0.6.0; `serde_json`.
- Both: `jpeg-encoder` 0.7.1 ((MIT OR Apache-2.0) AND IJG, pure Rust, no dependencies) for
  stills, instead of WIC on Windows and an unchosen encoder on Linux: one encoder, testable on
  every host.
