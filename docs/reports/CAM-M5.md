# CAM-M5 — Photos in chat and the camera in calls

- Date: 2026-11-18
- Plan: [CAM-plan.md](CAM-plan.md) (D-0110); decision D-0115
- Status: built and tested headless; video clips not built (below).

## What was built

| Piece | Where |
| --- | --- |
| The chat's "Camera" tile opens a camera sheet: the live preview, Flip and "Take photo"; the photo comes back as a JPEG in memory with its metadata stripped and is sent as an image message | `apps/ui/src/features/chat/sheets.rs` (`camera_sheet`), `chat/mod.rs` (`camera_open`) |
| `Session::take_photo`: the platform's answer, from any thread, back on the engine thread through a task the session owns | `apps/ui/src/camera.rs` |
| A call's self-view runs a `Call` session while the user's video is on and shows the live preview (`preview_fill`); Flip switches the lens; the camera stops when video goes off or the call ends | `apps/ui/src/features/calls/surface.rs` (`self_view`) |
| Headless tests: a photo through the session; a call's camera following the video switch; linking (a group link and garbage ignored, a link code shows the confirmation with the camera stopped, nothing linked before "Link device") | `apps/ui/src/camera/tests.rs`, `features/devices/mod.rs` (`camera_flow`) |

`apps/ui`: `cargo test --lib` **161 passed**.

## What stays a mock, and why

- **Sending the photo.** Encrypting it with the attachment format (Prompt 6) and uploading it
  is app-core's (A2). Until then the message carries the photo's size and the bytes are
  dropped (`// mock:`); they are never written to disk or the photo library.
- **Frames to the other side of a call.** The session's frames (`take_frames`) are ready for
  LiveKit's `NativeVideoSource`; LiveKit in the app comes with app-core. The remote video stays
  the portrait.

## Not built

- **Video clips** (the plan: iOS, Android and macOS now). Recording needs the microphone, a
  sibling module the plan sets apart (question 3), and a file written while recording, which
  must be encrypted as it is written. Both belong with app-core's media pipeline; recorded in
  D-0115 as the next step.
