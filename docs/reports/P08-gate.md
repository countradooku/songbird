# P08 gate — Push and notifications

- Date: 2026-11-18
- Prompt: [08-push.md](../prompts/08-push.md); plan [P08-plan.md](P08-plan.md) (D-0094)
- Milestones: [M1](P08-M1.md) (D-0095), [M2](P08-M2.md) (D-0096), [M3](P08-M3.md) (D-0097),
  [M6](P08-M6.md) (D-0098), [M4](P08-M4.md) and [M5](P08-M5.md) first part (D-0099); the
  security review's fixes (D-0100)
- Branch `claude/p08-push`, PR #65 (merged with `main`'s app redesign, PR #66).
- Status: **approved by the owner on 2026-11-18** ("Approve all"), with the four threat-model
  §1 rows; where alerts go is still the owner's to choose. This gate covers the server side and the app's own
  notifications. The iOS and Android host projects and the real-provider checks are **deferred by
  the owner until the whole app is built** (2026-11-18); they will close M4 and M5.

## The gate, item by item

| Gate item | Result | Evidence |
| --- | --- | --- |
| An offline device receives a wake-up end to end in the integration environment | **Pass** (mock providers) | `gate_m5::an_offline_device_receives_a_push_end_to_end`: Bob writes to Alice's offline phone; delivery stores, coalesces and queues a sealed job; `push` opens her sealed registration from the push database and wakes the phone through mock APNs with the constant, identifier-free alert (a leading and a trailing push, byte-identical); she connects and reads every message in order. With real APNs and FCM: deferred with the host projects |
| Provider outage and recovery tested | **Pass** | `outage_live`: FCM 503 for 3 s, APNs black-holed, `retry-after`, `push` crashed mid-burst: every device woken after recovery, nothing dead-lettered. End to end (`gate_m5`): APNs down while the phone is offline, the messages wait in the mailbox, the wake-up goes out after recovery, the phone reads them in order |
| Push credentials provably present only in this service's runtime | **Pass** | Three checks (D-0097, D-0100): every other service refuses provider settings (4 tests); `cargo xtask secret-scope` in `ci fast`; after every rollout `verify-push-credentials.yml` checks every container's mounts (folder or any parent) and variable names, and that the files are mode 0400 and owned by the push uid alone (65533) |

Everything else the prompt asks for:

| Item | Where |
| --- | --- |
| `services/push` consuming jobs that carry a device reference and a kind | D-0036; rings on their own stream `j:ring` with a 30 s life (M1) |
| Tokens encrypted at rest, apart from other account data, deleted at once when unregistered | Sealed to push's X25519 key (D-0036), in their own database with a credential per service, left out of backups (M1, D-0100) |
| APNs alert with `mutable-content`, generic text; VoIP through PushKit on a separate high-priority path | M1 (`j:ring`, never debounced, expiry 0); a ring reaches APNs in 52 ms behind 10,000 queued wake-ups |
| FCM HTTP v1 high-priority data messages with nothing sensitive | D-0036; a ring is the same message as a wake-up (M1) |
| UnifiedPush via Web Push with RFC 8291 and VAPID | D-0036; tested against the mock |
| Coalescing: collapse IDs plus a short local debounce; every push identical | Leading and trailing coalescing in `delivery` and `push` (M1), proptests that no message is left without a wake-up after it |
| Retries with backoff and jitter, a breaker per provider, a dead-letter stream with alerting, pooled HTTP/2 | D-0036; alerts `JobsDeadLettered`, `PushProviderDown`, `PushPermanentFailures`, … unit-tested with `promtool` (M3) |
| Mute and preferences stay on the device | The app decides (M6: `features::notify::decide`; iOS: `NotifyRules`); the server never learns them; `SILENT` sends wake nobody (M1) |
| Mock APNs and FCM with slow, failing and rate-limiting behaviour | `test_support`: `Slow`, `RateLimited`, `ServerError`, `Unavailable`, `ExpiredAuth`, `Hang`, `Reset`, `outage`/`recover` |
| Pushes per second; p99 from job to provider | M2: a 20,000 burst at 9,800 to 28,600 pushes/s; steady 1,000/s at p50 1.3 to 1.9 ms, p99 6.5 to 11 ms (after fixing one reader connection shared by every stream, which held it to ~850/s) |

## Tests and checks run (Apple M5 Pro, 18 cores, 48 GiB, macOS 27.2.1; compose stores under podman)

- `cargo xtask ci fast`: workflow policy, the push credential scope, rustfmt, clippy (pedantic,
  `-D warnings`), nextest **762 of 762** (8 skipped: live tests without their stores), doctests,
  rustdoc `-D warnings`, `cargo deny`, `cargo audit`, `cargo vet`, the smoke test. Run before and
  after the review's fixes.
- Live suites with SurrealDB, `valkey-hot`, `valkey-jobs`, RustFS and LiveKit: accounts 43 of 43,
  jobs 14 of 14 (`-j 1`), push 12 of 12 (`-j 1`), e2e **64 of 65**, api 69 of 71. The three
  failures are attachment tests that confirm a fetch from `127.0.0.2`, an address macOS does not
  configure on its loopback (it has `127.0.0.1` only); they do not touch Prompt 8 and pass on
  Linux CI. Three e2e tests skip without Iggy, which CI runs.
- `promtool check rules` (8 rules) and `promtool test rules` SUCCESS; `deploy/bin/validate-iac
  ansible` (syntax and lint) passes in a Python 3.12 container with the pinned requirements.
- App (`apps/ui`): 146 tests, among them the notification rules and their wiring on NSH's
  engine headless; iOS rules `swift test` 6 of 6.
- On devices: the Android emulator shows the app's notification for a test call; the iOS
  Simulator delivers our exact APNs payload as a banner; on macOS the notifier fires and the
  system refuses the ad hoc build until Songbird is allowed in Notifications (M4 to M6 reports).
- Not run: fuzzing (no decoder of this phase is new; the job decoder and the `Send` flags are
  covered by proptests, and the existing frame fuzz targets take the new bit); the benchmarks on
  the production host class (with the D-0043 soak, at the end of the project).

## Security review

An independent agent read the whole diff against `main` without running anything: no high
findings, two medium, five low, three informational. All are fixed or recorded in D-0100:

| Finding | Fix | Test or check |
| --- | --- | --- |
| Medium: the post-rollout check could print other containers' secrets | Names, mount sources and variable names only; `no_log` | the template run on a local container |
| Medium: the token move could revive a deleted device's token; concurrent moves could fail | The worker clears and verifies both stores; idempotent `UPSERT` | `push_registrations_live_apart_and_old_rows_move_once`; the deletion gates |
| Low: parent-folder mounts escaped the check | Any mount of the folder or a parent fails | Ansible lint |
| Low: push shared a uid with every service | Push runs as 65533 | the post-rollout check asserts it |
| Low: any value of the preview variable made a preview build | Exactly `1` | `only_exactly_one_marks_a_preview_build` |
| Low: monitoring could be stopped or broken silently; alerts carried private addresses | No lifecycle API, validated reloads by `SIGHUP`, escaped secrets, `instance` dropped | `promtool test rules` |
| Low/info: ring deadlines depend on clocks | `chrony` on every host; residual risk recorded | — |
| Info (three) | Threat-model rows; registry users before production | — |

## Threat model

Four new §1 rows, **approved by the owner on 2026-11-18**: `SILENT` on a send (and what it reveals);
push registrations in their own database; call rings on their own job stream; a call ring's
timing seen by Apple. §3.25 holds the STRIDE rows.

## For the owner

1. **Approve the gate** for what is built: M1, M2, M3, M6 and the first part of M4 and M5, with
   the review's fixes (D-0095 to D-0100).
2. **Approve the four threat-model §1 rows.**
3. **Where alerts go** (D-0097): email through an SMTP relay, a ntfy topic, or a Matrix room.
4. **Deferred until the whole app is built** (your decision, 2026-11-18): the iOS and Android host
   projects, the Apple bundle IDs and filtering entitlement, the Firebase Android app, and the
   real APNs, VoIP and FCM checks.
5. **Before production**, listed so nothing is forgotten:
   - production APNs and FCM keys created straight into SOPS;
   - registry users for `api` and `worker` other than SurrealDB's root (D-0100 §10), and their
     `[*.push_tokens]` sections;
   - the other services' deployed configuration beyond `[common]` (older than Prompt 8);
   - the benchmarks again on the production host class.
