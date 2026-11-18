# CAM-M2 — macOS and iOS: AVFoundation from Rust

- Date: 2026-11-18
- Plan: [CAM-plan.md](CAM-plan.md) (D-0110); decision D-0112
- Status: macOS built and checked on this Mac's cameras and in the running app; iOS built for the simulator and
  devices, its camera check waiting for a physical iPhone (the plan's question 4).

## What was built

| Piece | Where |
| --- | --- |
| `AppleCamera` (`Backend`): access from `AVCaptureDevice`'s authorization, the system prompt, lenses from a discovery session (built-in; on macOS also external and Continuity Camera) | `apps/camera/src/apple.rs` |
| `AppleCapture`: one `AVCaptureSession` per capture, started and stopped on its own serial queue; outputs per purpose; lens switching inside a configuration block; the torch under the device lock | `apple.rs` |
| Codes: `AVCaptureMetadataOutput` for QR when the device offers it, else NV12 frames to the `rqrr` scanner thread (M1) | `apple.rs` (`Delegate`, `add_frames`) |
| Call frames: NV12 full range, late frames discarded, planes copied under a read-only lock and checked | `apple.rs` (`frame_of`) |
| Stills: `AVCapturePhotoOutput` in JPEG, through the metadata filter (M1) | `apple.rs` (`PhotoDelegate`, `still_of`) |
| The preview component `songbird/camera`: an `AVCaptureVideoPreviewLayer` on the session its `session` prop names (an `NSView`'s layer on macOS; a `UIView` whose layer class is the preview layer on iOS) | `apple.rs` (`preview`) |
| Registration from the app's crate root: `#[native_components(macos)]`, `#[native_components(ios)]` | `apps/ui/src/lib.rs` |
| Purpose strings and the camera entitlement | `apps/ui/nsh.json` (`ios.infoPlist`, `macos.infoPlist`, `macos.entitlements`) |
| An on-device probe without the app (`status`, `ask`, `scan`, `frames`, `photo`, `check`) | `apps/camera/examples/probe.rs` |

## Checked on this Mac

MacBook Pro (Apple M-series), macOS 27.2.1; the probe in an ad hoc signed bundle with its
own `NSCameraUsageDescription` (macOS refuses a bare binary without a prompt: `ask` answered
`Denied` at once and access stayed "not asked").

| Check | Result |
| --- | --- |
| Access before asking | "not asked"; reading it never prompts |
| Lenses | the built-in camera (front) and an iPhone through Continuity Camera (external) |
| The system prompt | shown with the purpose string; "Allow" → `Granted` |
| Call frames, built-in camera | 1920×1080 NV12, **30.6 frames/s**, running 99–113 ms after opening, every frame consistent; the 2-frame mailbox dropped 1 of 68 while the probe read every 20 ms |
| Call frames, iPhone (Continuity) | 1920×1080, 19.7 frames/s over its first second |
| A photo, built-in camera | 1920×1080 JPEG, 217,497 bytes: **no EXIF block** (upright), no GPS, ends at EOI |
| A photo, iPhone (Continuity) | 1920×1080 JPEG, 334,723 bytes, no EXIF, no GPS, ends at EOI |
| Scanning a link code shown on this Mac's screen, iPhone lens | read in full (111 characters, `SONGBIRD:LINK:5B…:C3…`), **once** |
| Scanning with the built-in camera | the metadata output offers no QR type for it: asking raised an Objective-C exception (fixed: the type list is checked first, and frames go to `rqrr`) |
| Stopping | each capture stopped when dropped, and the next one in the same process opened at once (frames → photo → scan) |

The app itself: a preview build packaged with `nsh package --target macos` carries the purpose
string in `Info.plist` and `com.apple.security.device.camera` in its entitlements (read back with
`PlistBuddy` and `codesign -d --entitlements`). **The owner ran it** (You › Linked devices › Link a
device): the explanation, the system prompt, then the live preview in the sheet, a rounded
220-point square with "Looking for a code…" under it (owner's screenshot, 2026-11-18). Still to
do with the design checklist: the confirmation after a real scan in the app, and screenshots in
light and dark.

## iOS

Built for the simulator and devices (`cargo check` and `clippy` for `aarch64-apple-ios-sim`,
clean; the same module as macOS, with a `UIView` whose layer class is the preview layer). Not
run on a camera: the Simulator has none (it shows "No camera found"), and a physical iPhone with
the owner's personal team is the plan's open question 4.

## Findings and fixes during the milestone

1. **Some Macs' metadata output offers no QR.** Setting a type that is not in
   `availableMetadataObjectTypes` raises `NSInvalidArgumentException`, which aborts a Rust
   program. The capture now checks the list and falls back to frames and `rqrr`; this is the
   plan's fallback, now exercised on real hardware.
2. **The photo output does not keep its delegate.** A photo never arrived until the capture
   held its photo delegates until they are called (`pending`).
3. **Photos arrive on the main queue.** The app's run loop serves it; the probe pumps the main
   run loop while it waits.
4. **The plan's `apple.infoPlist` is `ios.infoPlist` and `macos.infoPlist`** in NSH 0.6's
   `nsh.json` (per platform, read in `nsh-cli`'s `apple.rs`).

## `unsafe`

All of it in `apps/camera/src/apple.rs` (`#![allow(unsafe_code)]` on that module only; the
crate denies it, every other module forbids it). Each block has a `SAFETY:` comment. Kinds:

- calls into AVFoundation, Core Media and Core Video through `objc2`'s generated bindings
  (marked `unsafe` because the bindings cannot prove the frameworks' contracts);
- reading a locked `CVPixelBuffer` plane (`bytes per row × height` bytes, as Core Video
  promises while locked; null and overflow checked);
- `Send` for `AppleCapture` and the session handle (AVFoundation documents sessions, devices,
  inputs and outputs as usable from any thread; ours are used from one at a time);
- one pointer cast from a Core Foundation string constant to `NSString` (toll-free bridged).

Miri cannot run Objective-C; the shared, safe code it covers is M1's.

## New dependencies

On macOS and iOS only, all from the `objc2` family at the versions NSH's platform crates
already link (no new publisher): `objc2` 0.6.5, `block2` 0.6.2, `dispatch2` 0.3.1,
`objc2-foundation`, `objc2-av-foundation`, `objc2-core-media`, `objc2-core-video`,
`objc2-app-kit` (macOS), `objc2-ui-kit` and `objc2-core-foundation` (iOS), 0.3.2, with only the
features used; `nsh-platform-macos`, `nsh-platform-ios` 0.6.0 (the component traits);
`serde_json` 1 (component props).
