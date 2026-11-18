# CAM — The native camera module: plan, milestones and the owner's questions

- Date: 2026-11-18
- Asked for by: the owner, during Prompt 9 (PR #67): linking a device by pasting a text code
  was rejected; the app gets native camera code on every platform that needs it, because the
  camera also serves photos and videos in chat and video calls.
- Status: **proposed, waiting for the owner** (D-0110). No code is written until the owner
  approves.
- Base: `main` at `8271b89` (Prompt 8 merged, PR #65). Prompt 9's linking logic
  (`apps/ui/src/backend/link.rs`) is on `claude/p09-settings-presence-44c936` (PR #67); this
  plan builds on its code format and changes it (finding 6).
- Way of working (as Prompts 7 and 8): one branch and one PR (`claude/camera`), a commit,
  tests, report `docs/reports/CAM-Mn.md` and decision record per milestone, an independent
  security review of the whole diff before the gate, and nothing merged without the owner.
- Skills read: `nsh` (and its `references/tooling.md` on `#[native_components]`, capabilities
  and packaging) because the module is NSH native components; `nsh-design-guides` is read
  before the scanner and capture screens are built (M1, M5). The NSH 0.6 sources were read
  for every claim below (paths given). No skill covers AVFoundation, CameraX, Media Foundation
  or PipeWire; the repository has no project skills for them.

## Summary

One Rust interface, `Camera`, serves four uses: scanning the link code (PROTOCOL §4.6),
scanning a contact's safety-number code, taking photos and videos for chat, and the camera
feed for video calls. Behind it:

| Platform | Capture | Preview | QR decoding | Where the code lives |
| --- | --- | --- | --- | --- |
| macOS | AVFoundation | `AVCaptureVideoPreviewLayer` in an `NSView` | `AVCaptureMetadataOutput` | Rust (`objc2-av-foundation`), `#[native_components(macos)]` |
| iOS | AVFoundation | `AVCaptureVideoPreviewLayer` in a `UIView` | `AVCaptureMetadataOutput` | Rust, `#[native_components(ios)]`, **in the packaged app: no Xcode host needed** (finding 1) |
| Android | CameraX | `PreviewView` | `rqrr` in Rust on CameraX's analysis frames | Kotlin in a new Gradle host `apps/android`, frames to Rust over JNI (finding 2) |
| Windows | Media Foundation source reader | frames drawn with Direct2D | `rqrr` | Rust (`windows` 0.62, already in the tree), `#[native_components(windows)]` |
| Linux | PipeWire through the camera portal; V4L2 when there is no portal | `gtk::Picture` fed with textures | `rqrr` | Rust, `#[native_components(linux)]` |

QR codes the new device shows are drawn by a real encoder (`qrcode`, no default features),
replacing the four stand-ins. Frames never leave the device except end to end encrypted, no
third-party SDK is added anywhere, and no Google service (ML Kit, Play Services) is used.

## Findings that shape the plan

1. **On iOS, a packaged NSH app does register Rust native components.** Prompt 8's finding 7
   said a packaged app registers no native components on mobile. That holds for Android, not
   for iOS in NSH 0.6:
   - `nsh-macros-0.6.0/src/native_components.rs` accepts `windows`, `macos`, `linux` and
     **`ios`**;
   - the iOS release runner `nsh package` generates for Songbird
     (`apps/ui/.nsh/rust/ios-app/main.rs`) calls
     `nsh_platform_ios::set_components(app_components)`, which calls the crate's
     `__nsh_native_components_ios`;
   - `nsh-platform-ios-0.6.0/src/component.rs` has `NativeComponent { fn view(&self) ->
     &UIView; set_prop; command }` and a `ComponentContext` that emits events from any thread;
   - `nsh.json` takes `apple.infoPlist` and `apple.entitlements` (the CLI's `AppleConfig`), so
     `NSCameraUsageDescription` goes in without a host project.
   So the iOS camera is Rust code in the packaged app, shared with macOS (the same
   AVFoundation classes through `objc2-av-foundation`). The Xcode host stays deferred with
   push (D-0099), and the iOS camera does not wait for it. What finding 7 said about the
   notification extension, PushKit and CallKit (extra targets, background modes) still holds.
2. **Android needs the Gradle host now.** `#[native_components]` refuses `android`; Android
   components are Java objects registered with `NshView.registerComponent(name, factory)`
   (`nsh-platform-android-0.6.0/java/com/longbridge/nsh/NshView.java:511`), and the packaged
   app's `AppActivity` is `final` and registers none. The CLI's `AndroidConfig` has only
   `targetSdk` and `usesCleartextTraffic`, so `android.permission.CAMERA` cannot be declared
   either. A Songbird activity in `apps/android` makes the `NshView`, registers
   `songbird/camera`, asks for the permission, and runs the Rust root
   (`NshView.runRustApp("nsh")`, public). This is the host D-0094 §5 planned; only its camera
   part is built now. FCM, UnifiedPush and ConnectionService stay deferred (question 1).
3. **The desktops differ in what a component is.** macOS gives an `NSView`
   (`nsh-platform-macos-0.6.0/src/native.rs:117`), Linux a `gtk::Widget`
   (`nsh-platform-linux-0.6.0/src/native.rs:80`), and Windows **no child window**: a component
   draws into the window's Direct2D context each frame (`nsh-platform-windows-0.6.0/src/
   native.rs:124`, `draw(&self, dc: &ID2D1DeviceContext, size)`). The Windows preview is
   therefore frames copied into an `ID2D1Bitmap` and drawn, asking for a redraw per frame. The
   Rust side reaches a component through `native("songbird/camera")`, its props,
   `on_native_event` and an element ref's `command(name, args)` (`nsh-core-0.6.0/src/element/
   host.rs:689`, `element_ref.rs:418`).
4. **The app has no `unsafe` today, and this module needs it.** AVFoundation through `objc2`,
   COM in Media Foundation, JNI and PipeWire's C library are all `unsafe` calls. Constitution
   rule 5 asks for a recorded exception (question 6).
5. **The iOS Simulator has no camera; the Android emulator does.** The emulator offers a
   virtual scene and the host's webcam; the Simulator offers neither. iOS checks need a
   physical iPhone, signed with the owner's personal team (question 4). macOS checks run on
   this Mac's camera.
6. **Today's link code is larger than it needs to be.** `songbird-link:<channel hex>:<key
   hex>` is lowercase, so a QR code holds it in byte mode. Upper case
   (`SONGBIRD:LINK:<HEX>:<HEX>`, 111 characters) uses QR's alphanumeric mode: version 5 at
   error correction M (37×37 modules) instead of version 7 (45×45), which scans faster and
   from further away. Parsing stays case-insensitive and strict.
7. **The most important attack on QR linking is social, not cryptographic.** In 2025, phishing
   pages disguised Signal's device-link QR codes as group invites and got victims to link the
   attacker's device. Songbird's link code gives the same power. The plan's answer is in
   "Privacy and security" below (link codes only from the live camera, a distinct scheme, a
   confirmation that names what linking gives).
8. **Every scanner use is already mocked in the UI.** `features/devices/mod.rs` has the
   scanner sheet for linking and for safety numbers ("mock: the camera reads …"); the calls
   surface draws a portrait where the camera would be; four functions draw QR-looking
   stand-ins (`ui/extras_parts.rs`, `ui/onboarding_kit.rs`, `ui/settings_controls.rs`,
   `features/groups/qr.rs`).

## The interface

A new crate `apps/camera` (`songbird-camera`), a path dependency of `apps/ui`. All `unsafe` and
platform code lives there; `apps/ui` keeps no `unsafe` and gains
`#![forbid(unsafe_code)]`. `apps/ui`'s crate root holds the `#[native_components(macos |
windows | linux | ios)]` functions (NSH requires them at the root), each a one-line call to
`songbird_camera::register(components)`.

```rust
/// What the app asks for; one at a time per device.
pub enum Purpose { ScanCode, Photo, Video, Call }

pub enum Access { NotAsked, Granted, Denied, Restricted }   // Restricted: MDM, parental

pub enum Unavailable {
    NoCamera,          // none attached, or the Simulator
    InUse,             // another app holds it (macOS, Windows, Android)
    Interrupted,       // a phone call, Split View, Stage Manager without multitasking access
    SystemOff,         // Windows privacy switch, Linux portal says no camera
    Failed(String),    // the platform's error, never shown raw
}

pub enum State { Idle, Asking, Running { lens: Lens }, Denied(Access), Unavailable(Unavailable) }

pub trait Camera: 'static {
    fn access(&self) -> Access;
    fn request_access(&self) -> Task<Access>;     // the system prompt, at the moment of use
    fn lenses(&self) -> Vec<LensInfo>;            // front, back, external; names for desktops
    fn start(&self, purpose: Purpose, lens: LensId) -> Result<Session, Unavailable>;
}

pub struct Session { /* stops the camera on drop */ }
impl Session {
    pub fn state(&self) -> ReadSignal<State>;
    pub fn codes(&self) -> Receiver<ScannedCode>;            // ScanCode: decoded text, deduplicated
    pub fn capture_photo(&self) -> Task<Result<Still, CaptureError>>;
    pub fn record(&self) -> Result<Recording, CaptureError>; // Video
    pub fn frames(&self) -> FrameReceiver;                   // Call: bounded, newest wins
    pub fn set_lens(&self, lens: LensId);
    pub fn set_torch(&self, on: bool);
}

pub fn camera_preview(session: &Session) -> View;            // the native preview
```

- **One provider.** `apps/ui` gets the camera from context (`provide_camera`), the real one in
  the app and `FakeCamera` in tests, as the store is provided today.
- **Frames for calls.** `Frame { width, height, rotation, timestamp, pixels }` where `pixels`
  is NV12 or BGRA in a pooled buffer, or the platform's handle (`CVPixelBuffer` on Apple,
  `HardwareBuffer` on Android) so LiveKit's native buffers can take it without a copy. The
  receiver holds **two** frames and drops the oldest: a slow encoder never slows capture and
  memory stays bounded (invariants 5 and 7 applied on the device). Calls wire this to LiveKit's
  `NativeVideoSource` once app-core (A2) exists; until then the calls surface shows the local
  preview only.
- **Stills and recordings** come back as bytes in memory (`Still { bytes, mime, width,
  height }`), never as a file in a shared folder. Recording writes to the app's private
  temporary directory, encrypted by the media pipeline's key as it is written where the
  platform allows (AVAssetWriter and CameraX write a file; it lives inside the app's container,
  is deleted after sending, and is excluded from backups).
- **Scanning** reports each distinct code once per session. The app's parser
  (`backend::link::parse_code`, safety-number parser) decides what a code is; the camera knows
  nothing of Songbird's formats.
- **States the UI must draw**, each tested: not asked yet (explain, then ask), asking, denied
  (why, and an "Open Settings" button: `UIApplication.openSettingsURLString`,
  `ACTION_APPLICATION_DETAILS_SETTINGS`, `x-apple.systempreferences:…Privacy_Camera`,
  `ms-settings:privacy-webcam`, GNOME Settings › Privacy), restricted (no button: "Your
  organisation or parental controls turned the camera off"), no camera, in use, interrupted.

### Purpose strings (plain language)

- iOS and macOS `NSCameraUsageDescription`: "Songbird uses the camera to scan codes when you
  link a device or verify a contact, to take photos and videos you choose to send, and for
  video calls. Nothing it sees leaves your device unless you send it, and what you send is
  end-to-end encrypted."
- Android, before the system prompt (Android shows no app text in its own): the same sentence,
  on our screen, with "Continue" and "Not now".
- Windows has no prompt; Linux's portal shows its own ("Songbird wants to use the camera").
  The app's screen explains first on both.
- The app asks only when a use starts (tapping "Scan code", the camera button, turning video
  on), never at launch or onboarding.
- Microphone: video clips need it. Its purpose string ("… to record the sound of videos you
  send and for calls …") is added with video capture (M5); call audio is a separate module
  (question 3).

## Platforms

### macOS and iOS (one module, `apple.rs`)

- `AVCaptureSession` with `AVCaptureDeviceInput`; `AVCaptureDevice.DiscoverySession` for
  lenses (iPhone wide, ultra-wide and front; Mac built-in, external and Continuity Camera).
- Preview: `AVCaptureVideoPreviewLayer` as the component view's layer; rotation through
  `AVCaptureDevice.RotationCoordinator` (iOS 17, macOS 14).
- Codes: `AVCaptureMetadataOutput` with `metadataObjectTypes = [.qr]` and a
  `rectOfInterest` matching the viewfinder; decoding is Apple's, on the device. It is in
  macOS 13 and later (to confirm on this Mac in M2; if not, `rqrr` on frames as elsewhere).
- Stills: `AVCapturePhotoOutput`, JPEG (HEIC is a question of the media pipeline, Prompt 6
  sends JPEG today); no location ever (the app never asks for it), and metadata stripped
  again in Rust (see "Privacy").
- Frames: `AVCaptureVideoDataOutput`, `kCVPixelFormatType_420YpCbCr8BiPlanarFullRange`,
  `alwaysDiscardsLateVideoFrames = true`, on its own dispatch queue.
- Video: `AVCaptureMovieFileOutput` (H.264/HEVC, AAC) into the app's container.
- Calls on iPad: `isMultitaskingCameraAccessEnabled` where supported, else the
  `Interrupted` state.
- `nsh.json`: `apple.infoPlist.NSCameraUsageDescription`; on macOS the hardened-runtime
  entitlement `com.apple.security.device.camera`.
- New crates: `objc2-av-foundation`, `objc2-core-media`, `objc2-core-video` 0.3.2 (the same
  `objc2` family and version NSH already links), with only the features used.

### Android (`apps/android`, Kotlin, plus `android.rs` over JNI)

- A minimal Gradle project: `SongbirdActivity` (makes the `NshView`, registers
  `songbird/camera`, runs the Rust root), the manifest with `CAMERA` (and `RECORD_AUDIO` with
  M5), `uses-feature android.hardware.camera.any required="false"`.
- CameraX (`androidx.camera:camera-core`, `-camera2`, `-lifecycle`, `-view`, `-video`;
  Apache-2.0, part of AndroidX, open source, **no Google Play Services**): `Preview` into a
  `PreviewView`, `ImageAnalysis` (YUV_420_888, `STRATEGY_KEEP_ONLY_LATEST`) for codes and
  call frames, `ImageCapture`, `VideoCapture`.
- Codes are decoded **in Rust** with `rqrr`: Kotlin hands the Y plane to the app's library
  (`external fun onFrame(...)`, implemented with the `jni` 0.21 crate NSH already links) and
  Rust decodes on a worker. No ML Kit, no ZXing.
- Permission through the activity's `registerForActivityResult(RequestPermission)`;
  "Don't ask again" is read as `Denied` and the UI sends the person to Settings.
- The build: `nsh package --target android` makes the Rust library and NSH's `nsh.aar`; the
  Gradle project takes both. A script, `apps/android/build.sh`, as `apps/ios/build-simulator.sh`
  does for iOS.
- Gradle dependencies are pinned with verification metadata
  (`gradle/verification-metadata.xml`), so a changed artifact fails the build.

### Windows (`windows.rs`)

- Media Foundation: `MFEnumDeviceSources` for cameras, `IMFSourceReader` with
  `MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING` to NV12 or RGB32, reading on a thread of its own.
  It works for an unpackaged desktop app (WinRT `MediaCapture` needs more ceremony for the same
  frames).
- Preview: the latest frame uploaded to an `ID2D1Bitmap1` and drawn by the component, with
  `ComponentContext::redraw` per frame.
- Access: the Windows privacy switch makes reading fail with `E_ACCESSDENIED`, shown as
  `Denied` with the Settings link. In use: `MF_E_HW_MFT_FAILED_START_STREAMING` and similar,
  shown as `InUse`.
- Stills: a frame encoded to JPEG with WIC (`IWICBitmapEncoder`). Video: `IMFSinkWriter`
  (H.264, AAC), with M5.
- Crates: `windows` 0.62, the version NSH links, with the `Win32_Media_MediaFoundation` and
  `Win32_Graphics_Imaging` features added. No new crate.

### Linux (`linux.rs`)

- First the camera portal (`org.freedesktop.portal.Camera`: `IsCameraPresent`,
  `AccessCamera`, `OpenPipeWireRemote`), called through GIO's D-Bus (`gio`, already linked by
  `gtk4`), which asks the person and works in Flatpak. Then PipeWire (`pipewire` 0.10, binding
  the system's `libpipewire-0.3`) on the remote it returns.
- When there is no portal or it has no camera (`IsCameraPresent` false), V4L2 directly
  (`/dev/video*`, `v4l` 0.14) for packages outside Flatpak (question 5).
- Preview: frames as `gdk::MemoryTexture` (or a dmabuf texture where GTK 4.14 offers it) in a
  `gtk::Picture`.
- Stills: JPEG encoded in Rust (`jpeg-encoder`, pure Rust; question 3 for video on Linux,
  which needs an encoder Linux does not guarantee).

## QR generation

- **Encoder: `qrcode` 0.14.1** (MIT OR Apache-2.0) with `default-features = false`: no
  `image` or `svg`, no dependencies. It returns the module matrix; one `ui::qr_code(matrix,
  side, label)` draws it with views (dark modules on paper white in every theme, a 4-module
  quiet zone), replacing the four stand-ins.
- Alternatives: `qrcodegen` 1.8 (Nayuki's reference implementation, MIT, no dependencies,
  little maintenance; a close second), `fast_qr` (faster, which a 37×37 code does not need).
- Error correction M; the link code in alphanumeric mode (finding 6), version 5.
- Tests: every code the app draws is decoded again by `rqrr` in a test (round trip at each
  size), and a snapshot of one matrix (`insta`) catches an encoder change.

## QR decoding

- `rqrr` 0.11 (MIT OR Apache-2.0, with ISC parts from quirc), `default-features = false` (no
  `image`), on Android, Windows and Linux, and as the fallback on Apple. Pure Rust, on the
  device.
- Alternatives: `rxing` (a ZXing port: many formats, `rayon`, far more code than one QR format
  needs), `quircs` (quirc's port; `rqrr` is quirc's design with safer code).
- A decoder reads attacker-chosen pixels: a fuzz target (`fuzz/qr_decode`, raw grey frames of
  bounded size) joins the nightly run, and frames are capped (1280×720 for scanning) before
  decoding. Whatever decodes is text passed to Songbird's strict parsers.

## Privacy and security

- **Frames stay on the device.** No frame, still or recording is written outside the app's
  private container, sent anywhere except end-to-end encrypted (the media pipeline of Prompt 6
  for chat, LiveKit's E2EE for calls), logged, or kept after its use. Nothing is saved to the
  photo library unless the person chooses "Save".
- **No third-party SDK**: system frameworks (AVFoundation, Media Foundation, PipeWire, V4L2),
  AndroidX CameraX (open source, no Play Services), and three small open-source Rust crates
  for QR and JPEG. No ML Kit, no analytics, no crash reporters.
- **Metadata**: the app never asks for location, so no GPS is added; stills are passed
  through a Rust JPEG filter that keeps only the image and its orientation (drops EXIF, XMP,
  ICC beyond sRGB, maker notes), fuzzed (`fuzz/jpeg_strip`). Videos are written without
  location (`AVCaptureMovieFileOutput.metadata` empty; CameraX `setLocation` never called).
- **Camera on only while seen.** A session stops when its view leaves the screen, the app goes
  to the background, the window is minimised (desktops, except during a call), or the screen
  locks. The system's indicators (green dot, Android indicator, Windows notice) are therefore
  truthful. No background camera use, no `UIBackgroundModes` for it.
- **Link codes come only from the live camera** (finding 7): not from photos, screenshots,
  pasted text or links. The link scheme `SONGBIRD:LINK:` is distinct from group and contact
  links, which open other screens, so a link code shown as a "group invite" does nothing when
  opened as a link. After a scan the primary shows a confirmation before anything is sent:
  "Link a new device? It will read and send all your messages. Only continue if you are
  setting up your own device right now." The new device's name and type are shown again in
  the device list (Prompt 9) and in the `DeviceListChanged` notice to other devices.
- **Codes the camera sees are untrusted.** Each is parsed strictly; anything else is ignored
  without a sound or haptic (no oracle for crafted codes), and there is no "open URL" action
  for unknown codes.
- **Server-side**: nothing changes. The server sees what PROTOCOL §4.6 already lists; no row
  in THREAT_MODEL §1 is added.

## Tests

- **Headless** (`cargo test` in `apps/ui`, `nsh_testing::Headless`), with `FakeCamera`
  scripted per test: access answers (granted, denied, restricted, "ask" then granted), lenses,
  `Unavailable` at start or mid-session, codes (valid link code, a group link, garbage, a
  repeat), stills and frames. Tests cover:
  - each state's screen and its button (Open Settings, Try again, Not now);
  - the system prompt is asked only on a press, never on launch;
  - linking: a scanned link code shows the confirmation, and only "Link" calls
    `link_from_code`; a group link or garbage changes nothing;
  - the session stops when the sheet closes, the app backgrounds, or the view unmounts
    (the fake records start and stop);
  - the frame receiver drops the oldest and never blocks the producer (a unit test with a
    stalled consumer);
  - QR round trips for every drawn code; `rqrr` and `jpeg_strip` fuzz targets.
- **On devices**, recorded per platform in the milestone reports (screenshots, the permission
  prompt, a scan of a real code shown by another device, a still with its metadata dumped):
  - macOS: this Mac's camera, a packaged ad hoc build;
  - iOS: a physical iPhone (question 4); the Simulator for the denied and no-camera states;
  - Android: the emulator's virtual camera and the host webcam;
  - Windows and Linux: VMs with a USB webcam passed through, or the owner's machines
    (question 5).

## Milestones

1. **M1 — interface, fakes and QR.** `songbird-camera` with the trait, `FakeCamera`, frame
   receiver; `qrcode` and `rqrr`; the link code in alphanumeric mode; `ui::qr_code` real; the
   scanner sheet, the states and the link confirmation wired to the interface; headless tests;
   fuzz targets. No platform code yet.
2. **M2 — macOS and iOS.** `apple.rs`; `nsh.json` strings and entitlement; on-device checks on
   this Mac and an iPhone.
3. **M3 — Android.** `apps/android` host with CameraX and the JNI frame path; the emulator.
4. **M4 — Windows and Linux.** Media Foundation; portal, PipeWire and V4L2.
5. **M5 — photos and videos in chat, and frames ready for calls.** The capture screen, the
   metadata filter, sending through the media pipeline; the local preview in the calls
   surface (remote video waits for A2 and LiveKit in the app).
6. **Gate.** Security review of the whole diff, `CAM-gate.md`.

## Dependencies to add (each with its reason)

| Crate / artifact | Where | Reason |
| --- | --- | --- |
| `qrcode` 0.14.1, no default features | `apps/ui` | Real QR codes for the link code, invites and safety numbers; no dependencies |
| `rqrr` 0.11, no default features | `songbird-camera` | On-device QR decoding where the OS has none (Android, Windows, Linux) |
| `objc2-av-foundation`, `objc2-core-media`, `objc2-core-video` 0.3.2 | `songbird-camera`, Apple only | AVFoundation from Rust; same family and version as NSH's `objc2` crates |
| `windows` 0.62 (features added) | `songbird-camera`, Windows only | Media Foundation, WIC; already in the tree through NSH |
| `pipewire` 0.10 | `songbird-camera`, Linux only | Camera streams from the portal; binds the system's libpipewire |
| `v4l` 0.14 | `songbird-camera`, Linux only | Cameras where there is no portal (question 5) |
| `jni` 0.21 | `songbird-camera`, Android only | Frames from Kotlin; already in the tree through NSH |
| `jpeg-encoder` (pure Rust) | `songbird-camera`, Linux only | Stills where the OS has no encoder in reach |
| AndroidX CameraX 1.4.x | `apps/android` | Camera on Android without Play Services; Apache-2.0 |

`gio` and `gtk4` come through NSH already. `apps/ui` is outside the root workspace's
`cargo-vet`; each crate above is still checked with `cargo deny` (licences, advisories) in M1,
and audits are recorded for those with `unsafe` (`rqrr`, `pipewire`, `v4l`).

## Questions for the owner

1. **The Android host now.** The camera needs `apps/android` (finding 2). Recommendation:
   build its minimal form now (the activity, the camera, the permission), and keep FCM,
   UnifiedPush and ConnectionService deferred as decided on 2026-11-18. The iOS host stays
   deferred: the iOS camera works in the packaged app (finding 1).
2. **When the primary has no camera.** PROTOCOL §4.6 has the new device show the code and the
   primary scan it, and only the primary links. A primary that is a desktop without a webcam
   cannot link. Options: (a) say so plainly ("Connect a camera to this computer to link a
   device"); (b) a second direction for that case only, where the primary shows a code and the
   new device scans it (a protocol change to D-0052, with its own review); (c) a typed code,
   which the owner has rejected. Recommendation: (a) now, (b) as follow-up work if testers hit
   it.
3. **Scope of the first build.** Recommendation: preview, scanning, stills and frames on every
   platform; video clips on iOS, Android and macOS; video clips on Windows and Linux later
   (Linux has no encoder it can count on: OpenH264 is a Cisco binary, GStreamer a large
   dependency). Call audio (microphone capture for LiveKit) is a sibling module with the same
   shape, planned with calls in the app.
4. **A physical iPhone** for the iOS checks, signed with the owner's personal team (the
   Simulator has no camera). Is one available, and may the agent use the personal team
   (`69QGT49729`) for a development build?
5. **Linux packaging.** Will Songbird ship as a Flatpak (portal only) or also as native
   packages (portal, then V4L2)? Recommendation: both paths, V4L2 only when the portal is
   absent.
6. **`unsafe` in `songbird-camera`** (constitution rule 5). Recommendation: allow it in that
   crate's platform modules only (`apple.rs`, `windows.rs`, `linux.rs`, `android.rs`); every
   block with a `SAFETY:` comment; `#![deny(unsafe_op_in_unsafe_fn)]`; the shared code
   (`lib.rs`, frames, fakes, JPEG filter) under `#![forbid(unsafe_code)]` and tested with
   Miri; `apps/ui` itself gains `#![forbid(unsafe_code)]`.
7. **Link codes only from the live camera** (finding 7): no picking a screenshot of a code.
   Recommendation: yes. (Safety-number codes could be read from a picked image without that
   risk; recommendation: also camera only, for one simple rule.)
