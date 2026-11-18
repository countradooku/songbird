# CAM gate — the native camera module

- Date: 2026-11-18
- Plan: [CAM-plan.md](CAM-plan.md), approved by the owner on 2026-11-18 ("approve all on the
  camera plan"); decisions D-0110 to D-0116; PR #68 (`claude/camera-plan`)
- Status: **approved by the owner on 2026-11-18** ("Approve both"): the gate, and the IJG
  licence for `jpeg-encoder` only (D-0117). The "Not done" items stay open; the iPhone check
  waits for a device.

## What was built

| Milestone | Report | In one line |
| --- | --- | --- |
| M1 | [CAM-M1](CAM-M1.md) | `songbird-camera`'s interface, mailboxes, QR decoding, the JPEG filter, `FakeCamera`; real QR codes; strict code formats; every access state; link confirmation |
| M2 | [CAM-M2](CAM-M2.md) | AVFoundation from Rust on macOS and iOS (no Xcode host for iOS) |
| M3 | [CAM-M3](CAM-M3.md) | `apps/android`: Songbird's Gradle host with CameraX, QR in Rust over JNI |
| M4 | [CAM-M4](CAM-M4.md) | Windows (Media Foundation) and Linux (V4L2), one shared desktop core |
| M5 | [CAM-M5](CAM-M5.md) | The chat camera sheet; the call self-view |

## Evidence

| Where | What was shown |
| --- | --- |
| macOS, this Mac | 1080p NV12 at 30.6 frames/s; a 1920×1080 JPEG with no EXIF or GPS; a link code read through Continuity Camera; **the owner saw the live preview in the running app** |
| Ubuntu VM, `v4l2loopback` | 1280×720 frames at the feed's rate; a clean JPEG; the link code read |
| Android 16 emulator | the explanation, the system prompt only after "Continue", the live preview, the camera indicator; "No camera found" without a camera |
| Windows 11 VM (no camera) | access from the consent store; "no lens" for every purpose |
| Tests | `songbird-camera` 28 on macOS, Ubuntu and Windows; `apps/ui` 161; Android lint 0 errors |
| Clippy (pedantic) | clean for macOS, iOS, Android, Windows and Linux targets |
| Fuzzing | `qr_decode` 4.7 M runs, `jpeg_strip` 33.7 M runs, no crash (M1); the widened `qr_decode` after the review: 66,241 runs in 91 s (727/s, frames up to 2,040 a side), coverage 1,212 edges / 4,714 features (from 536), no crash or timeout |

## Security review

An independent read-only reviewer (a separate agent given the code, not the reports) found no
high-severity issue and no memory-safety bug: every `unsafe` block, the JNI and COM paths, the
parsers and the privacy properties checked out. Its findings and what was done (D-0116):

| # | Severity | Finding | Done |
| --- | --- | --- | --- |
| 1 | medium | A finder-dense image makes one `rqrr` decode slow; dropping the scanner joined that thread on the UI thread | Scanner threads are no longer joined (they end after their frame); decoding capped at 640×480; the fuzz target now reaches large and repeated patterns |
| 2 | medium | A stalled camera hung the UI on close (blocking reads, joined) | Desktop reading threads are no longer joined and publish nothing once stopped; V4L2 reads time out every 500 ms |
| 3 | medium | Apple did not notice a lost session; a photo then could raise an Objective-C exception | Interruption, its end and runtime errors are observed and reported; a photo needs an active, enabled video connection |
| 4 | low | Linux took the driver's frame size unbounded; unchecked multiplications | 8192 a side, checked lengths before allocating, saturating timestamps |
| 5 | low | The app workspaces are outside `cargo deny`/`audit`/`vet` in CI; Gradle checksums are trust-on-first-use, no wrapper | `cargo deny` and `cargo audit` run by hand (below); CI and a pinned wrapper are follow-ups |
| 6 | low | Android sessions unbound each other's use cases; `closed` read across threads; the torch always "true" | Each session unbinds only its own; `volatile`; the torch reflects the camera; the activity's stop closes every camera |
| 7 | info | The link confirmation's "Link device" does not use the scanned code (mock); exported activity intents; no `FLAG_SECURE`; the probe prints codes | For Prompt 9's wiring: use the confirmed code and show the new device before history; `FLAG_SECURE` is the screen-security setting's (Prompt 9) |

**Not changed:** `set_lens` on Apple still reconfigures the session on the caller's thread;
Apple serialises it internally, and moving it to the session queue is a follow-up.

## Supply chain

- `cargo deny` with the repository's `deny.toml` on `apps/camera`: advisories and bans ok;
  licences **fail on `jpeg-encoder`'s IJG** (question 1) and on Zlib (`zlib-rs` through NSH's
  updater, already in the app before this work).
- `cargo audit`: no vulnerabilities; two "unmaintained" notices (`chrono` through `nsh-base`,
  `ttf-parser` through `nsh-macros`), both from NSH.
- Android: 272 components pinned by SHA-256, strict.

## Not done

| Item | Why | Next |
| --- | --- | --- |
| iOS camera on a device | the Simulator has no camera | a physical iPhone with the personal team (plan question 4) |
| Android scan through JNI on a device | the emulator could not be given a code to see | a phone, or the emulator from Android Studio with the Mac's camera |
| Linux camera portal + PipeWire | needed only by a Flatpak build, which does not exist | before a Flatpak |
| Full app build on Windows ARM64 | the VM lacks `clang-cl` for `aws-lc-sys` | a VM or CI runner with Clang |
| Video clips | need the microphone module and encryption as they are written | with app-core's media pipeline |
| Photo upload, call frames to LiveKit | app-core (A2) | A2 |
| CI for the app workspaces; Gradle wrapper with checksum | follow-up | a CI job running test, clippy, deny, audit for `apps/camera` and `apps/ui` |

## Questions for the owner

1. **`jpeg-encoder`'s IJG licence.** Desktop stills are encoded in pure Rust with
   `jpeg-encoder` 0.7.1 ("(MIT OR Apache-2.0) AND IJG"; the IJG licence is permissive, asks for
   an acknowledgement in documentation). Recommendation: allow IJG for this crate only in
   `deny.toml`, with an acknowledgement in the app's licences page.
2. **A physical iPhone** for the iOS camera check (still open from the plan).
3. **Approve the gate**: M1–M5 and the review's fixes, with the items above left open.
