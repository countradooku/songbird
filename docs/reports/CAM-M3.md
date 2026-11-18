# CAM-M3 — Android: Songbird's Gradle host and CameraX

- Date: 2026-11-18
- Plan: [CAM-plan.md](CAM-plan.md) (D-0110, question 1: the minimal host now); decision D-0113
- Status: built, linted and run on the emulator up to the live preview; scanning a code
  through the JNI frame path is **not yet checked on a device** (see "Checked on the emulator").

## What was built

| Piece | Where |
| --- | --- |
| `apps/android`: a single-module Gradle project (AGP 9.5.1, Gradle 9.9.1, compile and target SDK 36, minimum 26) that compiles NSH's Java sources from the exact `nsh-platform-android` the app's Rust resolves, Songbird's activity and camera, and packs the Rust library and assets `nsh package --target android` builds | `apps/android/build.gradle.kts`, `settings.gradle.kts`, `build.sh` |
| `SongbirdActivity`: NSH's `AppActivity`, plus the camera component and its permission result | `src/main/java/chat/songbird/app/SongbirdActivity.java` |
| `SongbirdHost`: the three package-private helpers of NSH's activity (standalone limits, edge to edge, environment), reached from NSH's own package rather than copied | `src/main/java/com/longbridge/nsh/SongbirdHost.java` |
| `CameraBridge` (Java): access and the permission dialog, lenses from Camera2, one CameraX session per Rust capture with a lifecycle of its own, preview, analysis frames (YUV, keep only latest), photos in memory, camera state errors | `src/main/java/chat/songbird/camera/CameraBridge.java` |
| `CameraPreview`: the `songbird/camera` component, a `PreviewView` (TextureView, so it clips to the rounded box) | `src/main/java/chat/songbird/camera/CameraPreview.java` |
| `android.rs` (Rust): `Backend` and `Capture` over JNI; the six `native*` entry points; QR decoded in Rust from the Y plane (`rqrr`, M1's scanner) | `apps/camera/src/android.rs` |
| YUV_420_888 → NV12, luma rows, the lens list parser: shared and tested on every host | `apps/camera/src/frame.rs`, `lib.rs` |
| The manifest: NSH's (permissions, the Rust flag, the files provider, the activity's flags) with Songbird's activity, `CAMERA`, the camera as an optional feature, and **no Google cloud backup or device transfer** | `src/main/AndroidManifest.xml`, `res/xml/data_extraction_rules.xml` |
| Dependency verification: SHA-256 of every artifact Gradle downloads, strict | `gradle/verification-metadata.xml` (272 components, 91 groups), `gradle.properties` |

## Checked

| Check | Result |
| --- | --- |
| `cargo clippy --all-targets` (pedantic) for `aarch64-linux-android`, macOS and iOS | clean |
| `cargo test` (`songbird-camera`) | 23 passed, the YUV conversion and lens parser among them |
| The JNI entry points are exported from the packaged `libnsh.so` | all six `Java_chat_songbird_camera_CameraBridge_native*` (`llvm-nm -D`) |
| `gradle assembleDebug lint` under strict verification | builds (`songbird-debug.apk`, 49 MB, arm64-v8a and armeabi-v7a); lint **0 errors** |

Lint's findings in Songbird's code, fixed: `Context.getMainExecutor` needs API 28 (the main
handler is used); the activity was held in a static field (now weakly). Disabled with its reason:
`GestureBackNavigation`, because Android 13 and later go through NSH's `OnBackInvokedCallback`
and `onBackPressed` serves Android 12 and older, as in NSH's own activity. NSH's own sources are
not linted here.

## Checked on the emulator

Pixel AVD `songbird-pixel`, Android 16 (API 36), arm64; the debug APK installed in place of
Prompt 8's packaged build; screenshots in the session's scratchpad.

| Step | Result |
| --- | --- |
| Launch | Songbird runs in `SongbirdActivity`; NSH's `libnsh.so` loads; no camera prompt at launch (the notification prompt there is Prompt 8's) |
| You › Linked devices › Link a device | "Allow the camera" with the purpose text; **no system prompt until "Continue"** |
| "Continue" | Android's dialog "Allow Songbird to take pictures and record video?"; "While using the app" → granted |
| No camera (emulator started with `-camera-back imagefile:…`, which this emulator does not support: 0 camera devices) | "No camera found" |
| Virtual scene back camera | the live CameraX preview in the sheet, clipped to the rounded box, "Looking for a code…" |
| Only the emulated front camera | the scanner falls back to it; Android's green camera indicator shows while it runs |
| Scanning a code | **not checked**: the virtual scene's posters are out of the camera's view and the console cannot move it; the host webcam is refused by macOS for an emulator started from a shell (no prompt, as for the bare probe in M2). The Rust path is the one M1 tested (`rqrr` on luma) plus the YUV copy tested here; a run on a phone or with the emulator started from Android Studio is still owed |

## Changes from the plan

- **Java, not Kotlin.** NSH's Android side is Java with no AndroidX; writing the host in Java
  keeps the Kotlin Gradle plugin and standard library out of the build.
- **CameraX 1.6.2** (the current stable), not 1.4.
- **Lenses come from Camera2's `CameraManager`**, which answers synchronously; CameraX binds by
  the same camera id (`Camera2CameraInfo`).
- **No Google backup**: `allowBackup="false"` and data-extraction rules that exclude every
  domain from cloud backup and device transfer. NSH's packaged app allowed both by default;
  Songbird's own encrypted backup is Prompt 10's.

## Supply chain

Gradle resolves the Android Gradle Plugin and its build-time dependencies from Google's Maven
repository and Maven Central, and CameraX (Apache-2.0) with its AndroidX dependencies
(`lifecycle`, `annotation`, `concurrent-futures`, Guava's `listenablefuture`) from Google's. All
272 components are pinned by SHA-256 in `gradle/verification-metadata.xml`, and
`org.gradle.dependency.verification=strict` fails the build on any change. No Google Play
Services, Firebase, ML Kit or analytics is in the APK.

## Not done here

- FCM, UnifiedPush and ConnectionService stay deferred with the rest of D-0099.
- Signing for release (a keystore), and CI for the Android build: with the gate.
