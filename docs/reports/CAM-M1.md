# CAM-M1 — The camera interface, fakes, real QR codes and the scanner screens

- Date: 2026-11-18
- Plan: [CAM-plan.md](CAM-plan.md) (D-0110); decision D-0111
- Status: built and tested; waiting for the owner with the camera gate.

## What was built

| Piece | Where |
| --- | --- |
| `songbird-camera`: `Backend`, `Capture`, `Sink`, `Purpose`, `Access`, `Unavailable`, `Lens`, `Event`, `Still` | `apps/camera/src/lib.rs` |
| Newest-wins bounded mailboxes from camera threads to the app (async and blocking reads) | `apps/camera/src/mailbox.rs` |
| Frames (grey, NV12, BGRA), checked for consistency; luma for scanners | `apps/camera/src/frame.rs` |
| On-device QR decoding with `rqrr`, frames bounded and scaled; a scanner thread | `apps/camera/src/qr.rs` |
| The still metadata filter (keeps the image and its orientation) | `apps/camera/src/jpeg.rs` |
| `FakeCamera`: scripted access, prompt answers, lenses, failures, codes, frames, interruptions; a log of starts and stops | `apps/camera/src/fake.rs` |
| The app's provider, sessions and state views | `apps/ui/src/camera.rs` |
| Real QR codes (`qrcode`, error correction M, one SVG path, light plate in every theme) replacing the four stand-ins | `apps/ui/src/ui/qr.rs`; `features/groups/qr.rs` |
| The link and safety-number code formats, upper case, parsed strictly | `apps/ui/src/features/devices/codes.rs` |
| The link scanner with its confirmation; the safety-number scanner with "match" and "don't match" | `apps/ui/src/features/devices/mod.rs` |
| The new device shows a real link code; the typed-code fallback is gone | `apps/ui/src/features/onboarding/returning.rs` |
| `#![forbid(unsafe_code)]` on the app | `apps/ui/src/lib.rs` |
| Fuzz targets `qr_decode`, `jpeg_strip`, in the nightly run | `fuzz/fuzz_targets/`, `.github/workflows/nightly.yml` |

No platform code yet: `songbird_camera::platform()` returns `None` until M2–M4. A release build
on any platform says "No camera found"; a preview build uses a demo fake that shows the code the
screen's mock expects after 2.2 s, as the mocked flows did before (marked `// mock:`).

## Properties and their evidence

| Property | Evidence |
| --- | --- |
| The camera runs only while its screen shows it, and stops when the sheet closes | `a_scanner_reads_codes_once_and_stops_when_closed` (the fake's log ends in `stop`, nothing running) |
| It stops in the background and starts again on return | `the_camera_stops_in_the_background_and_comes_back` (log `open`, `stop`, `open`) |
| The system prompt comes only from a press, after the purpose is explained | `the_prompt_comes_only_from_a_press` (0 prompts before "Continue", 1 after) |
| A refusal never starts the camera and points to Settings; a restriction offers nothing to press | `a_refusal_points_to_settings_and_never_starts`, `a_restricted_camera_offers_nothing_to_press` |
| No camera, in use, interrupted each have their screen; in use can be retried | `no_camera_says_so`, `a_camera_in_use_can_be_tried_again`, `an_interruption_is_shown` |
| Calls start on the front lens and flip | `a_call_starts_on_the_front_lens_and_flips` |
| Each code is reported once per session; long, empty or control-character codes never | `each_code_is_reported_once_and_odd_ones_never`, `the_codes_kept_are_bounded` |
| A stalled reader never blocks the camera; memory stays bounded | `a_stalled_reader_never_blocks_the_sender` (10,000 frames, 2 kept, 9,998 dropped), `a_full_queue_drops_the_oldest` |
| Frames and stills never print their pixels or bytes | `a_frame_never_prints_its_pixels`, `a_still_never_prints_its_bytes` |
| QR decoding reads real codes, scales large frames, refuses malformed input | `a_rendered_code_is_read`, `a_large_frame_is_scaled_down_and_still_read` (2000×1600), `malformed_and_oversized_images_are_refused_unread`; fuzz `qr_decode` |
| Every code the app draws scans | `every_kind_of_code_the_app_draws_reads_back` (link, safety number, invite and group links, a username, read back with `rqrr`) |
| The link code is a version 5 code (37×37) | `the_link_code_fits_version_5` (lower case would be larger) |
| Only well-formed link codes start linking; look-alikes, the old scheme, a link around a code, non-ASCII look-alikes are ignored | `a_link_code_round_trips_in_either_case`, `anything_else_is_not_a_link` |
| A still keeps its image and orientation, loses EXIF, GPS, XMP, ICC, JFIF, comments and appended data | `metadata_goes_and_the_image_stays`, `an_upright_photo_gets_no_exif_at_all`, `malformed_inputs_are_refused`, `a_lying_ifd_count_is_bounded`; fuzz `jpeg_strip` |

Runs: `apps/camera` `cargo test` 21 passed, `cargo clippy --all-targets` (pedantic) clean;
`apps/ui` `cargo test --lib` 158 passed, `cargo check --all-targets` clean; `cargo deny` on
`apps/camera` with the repository's `deny.toml`: advisories, bans and licences ok. Fuzzing: below.

## Fuzzing

`cargo xtask fuzz --secs 120 <target>` on Apple M5 Pro, macOS 27.2.1, nightly libFuzzer, from the
committed seeds (`seed-songbird-v1`: a real version 1 code at 4 px a module; `seed-exif-gps-tail`:
a JPEG with EXIF, GPS text, XMP-free ICC, a comment and appended data):

| Target | Runs | Coverage (edges / features) | Corpus | Crashes |
| --- | --- | --- | --- | --- |
| `qr_decode` | 4,689,825 in 121 s (38,758/s) | 536 / 2,570 | 514 entries | 0 |
| `jpeg_strip` | 33,651,120 in 121 s (278,108/s) | 182 / 495 | 206 entries | 0 |

Both join the nightly 10-minute runs.

## Changes from the plan

- The link code's format moved from Prompt 9's `backend::link` (`songbird-link:` in lower case)
  to `features::devices::codes` (`SONGBIRD:LINK:` in upper case), next to the safety-number code.
  Prompt 9's `link.rs` (PR #67) should call `codes::link_code` and `codes::parse` so both
  branches agree when they merge; the Prompt 9 session has been told.
- The safety-number code is `SONGBIRD:SAFETY:<60 digits>` and is compared with the number the
  app shows. With app-core it becomes the fingerprint app-core computes; the scheme stays.
- A desktop links by camera too (the plan's question 2, answered "connect a camera"): the "a
  computer has no camera" special case is gone; a desktop without one says "Connect a camera to
  this computer to use it here."
- The screens' look is checked on the running app with M2, when macOS draws the live preview;
  M1's states reuse the app's `empty_state` and `scanner` and add no new control.

## New dependencies

- `rqrr` 0.11.0 (MIT OR Apache-2.0, ISC parts), no default features, in `songbird-camera`:
  pure Rust, no `unsafe` of its own. It brings `g2p` (no `unsafe`) and `lru` 0.18 (`unsafe` in
  its linked list; a widely used crate, which `rqrr` uses for a cache of at most 251 colour
  regions per frame).
- `qrcode` 0.14.1 (MIT OR Apache-2.0), no default features, in `apps/ui`: no dependencies.

## Open for the owner

- Nothing new: M1 needed no decision beyond the approved plan.
