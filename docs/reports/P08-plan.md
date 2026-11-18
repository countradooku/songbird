# P08 — Push and notifications: plan, milestones and gates

- Date: 2026-11-18
- Prompt: [08-push.md](../prompts/08-push.md)
- Status: **awaiting the owner's approval** (D-0094). No milestone starts before it.
- Base: `main` at `2836b4a` (Prompt 7 done, PR #62; the app, PR #63; the registry fix, PR #64).
- Way of working (as Prompt 7): one branch and one PR (`claude/p08-push`). Each milestone gets
  its own commit, tests, report `docs/reports/P08-Mn.md`, decision record (D-0095 onward) and
  threat-model rows marked "awaiting the owner's approval". Then a final gate report, an
  independent security review of the whole diff, and `cargo xtask ci fast` plus the live suites,
  one heavy job at a time. Nothing is merged without the owner.
- Skills: `nsh` (read: NSH 0.6 has local notifications and a badge only, see finding 7) and
  `nsh-design-guides` for the app milestones; `security-review` as an independent read-only
  reviewer before the gate. None covers APNs, FCM or Web Push; the repository has no project
  skills for them.

## What Prompt 8 starts from

Prompt 2, milestone 5 (D-0036) built a first push service. Prompt 8 is closing gaps, not starting
from nothing.

| The prompt asks for | Already there (D-0036, D-0085) | Missing |
| --- | --- | --- |
| `services/push`, the only holder of push credentials | The binary; provider keys only in `config/…/push.toml` | Nothing deploys it with its credentials: Ansible has no push secrets. Nothing *proves* they are only there. |
| Jobs carrying a device reference and a kind | `Work::Push { device, call }` on `j:push`, sealed (AES-256-GCM-SIV) | Calls share the message stream (finding 1) |
| Tokens encrypted at rest, apart from account data, deleted when unregistered | Sealed to push's X25519 key, indexed by a keyed hash, deleted on `410`/`BadDeviceToken`/`UNREGISTERED` | Stored in the registry's own SurrealDB database (finding 5) |
| APNs alert with `mutable-content: 1`, generic text; VoIP through PushKit | Both, ES256 provider token, constant `apns-collapse-id` | VoIP on its own high-priority path (finding 1) |
| FCM HTTP v1, high-priority data messages with nothing sensitive | Done: no `data`, no `notification`, constant `collapse_key` | — |
| UnifiedPush via Web Push, RFC 8291 + VAPID | Done, SSRF-guarded endpoints, RFC 8291 vector | — |
| Coalescing: collapse IDs plus a short local debounce | Collapse IDs; leading-edge debounce in `delivery` and `push` | A wake-up can be lost (finding 2) |
| Retries with backoff and jitter, breaker per provider, dead-letter stream with alerting, HTTP/2 pooling | All but alerting: the queue's full-jitter retries, a breaker per provider, `j:dead`, 1 to 16 HTTP/2 connections per provider | No alerting exists anywhere (finding 6) |
| Mute and preferences stay on the device | The server never receives them; the app's settings screen is mocked | Nothing on the device yet (finding 7) |
| Mocks with slow, failing and rate-limiting behaviour | `MockServer`: `Slow`, `RateLimited`, `ServerError`, `Unavailable`, `ExpiredAuth`, `goaway_all` | A provider that accepts and never answers; resets mid-stream |
| Pushes per second, p99 job to provider | — | Not measured |
| Outage simulation: messages safe, pushes resume | One retry case in `push_live.rs` | Not simulated end to end |

## Findings that shape the plan

1. **Calls queue behind messages.** `api` enqueues call wake-ups on `j:push`, the same stream
   and consumer as message wake-ups. A burst of message wake-ups, or a provider retrying, delays
   the ring. A call that rings 40 s late has already expired (the offer's `EXPIRES` is 60 s,
   D-0085), so a late call push is worse than none. Plan: a stream of its own (`j:push-call`)
   with its own consumer and concurrency. A call job carries its enqueue time inside the seal and
   is dropped after 30 s. It is retried within that window only, never dead-lettered for age.
2. **The debounce can lose a wake-up.** Both debounces (`crates/send/src/push.rs` and
   `services/push`) are leading-edge: the first message wakes, later ones inside the window are
   dropped. A device can wake on message 1, fetch it and go back to sleep. If message 2 is then
   stored inside the window, it gets no wake-up until the next message arrives, possibly hours
   later. Plan: leading and trailing edges. Suppressed wake-ups set a flag, and one trailing
   push goes at the window's end. The pushes stay identical, and a burst becomes at most two.
   Tested with paused time, plus a proptest that no stored message is ever left without a later
   wake-up.
3. **Every stored envelope wakes the device, receipts included.** Sealed sender hides what an
   envelope is, so a delivery receipt, a read receipt or a sync message to one's own devices
   wakes the phone like a message does. On iOS each wake-up must show a notification unless the
   app holds Apple's filtering entitlement (finding 4). Signal's answer is an `urgent` flag that
   the sender sets on the send: receipts and sync are sent non-urgent, are stored as usual, and
   wake nobody. The server learns one bit per send, which it could largely infer from size and
   timing already. Question 1.
4. **Mute on iOS needs an Apple entitlement.** An alert push with `mutable-content: 1` runs the
   Notification Service Extension. Without `com.apple.developer.usernotifications.filtering`, the
   extension cannot suppress the notification, so a muted chat still shows "New message", and so
   does a reaction the user turned off. Only the Apple developer account holder can request that
   entitlement, and Apple grants it on request. The alternative, background pushes
   (`content-available`, priority 5), is throttled by iOS and unreliable: Apple says so. A
   bundle ID is also needed for anything on a device; none is registered yet. Question 2.
5. **Tokens live beside account data.** `push_token` is a table in the registry's SurrealDB
   database. The rows are sealed and keyed-hashed, so the prompt's "apart from other account data"
   holds for content, but not for storage, credentials or backups. A dump of the registry is a
   dump of the push rows; the rows cannot be opened without the push key, but they show how many
   devices registered and when (`at`). Plan: a SurrealDB database of its own, `push`. `api` may
   write it, `push` read and delete, and `worker` delete, each with a credential of its own. It
   is left out of backups, because apps register again at every start. Question 3.
6. **No alerting exists.** Every service exports Prometheus metrics, and the runbooks say "alert
   on `XLEN j:dead`". Nothing scrapes or alerts: there is no Prometheus or Alertmanager in
   `deploy/`. The prompt asks for a dead-letter stream with alerting. Plan: alert rules in the
   repository, tested in CI with `promtool test rules`, and a Prometheus with Alertmanager
   deployed by Ansible. Where alerts go is the owner's choice. Question 4.
7. **The app cannot receive pushes as it is packaged today.** NSH 0.6 offers local notifications
   and a badge only. It has no device-token registration, PushKit, CallKit, notification
   extension, Firebase, UnifiedPush or ConnectionService (read in `nsh-core-0.6.0/src/
   notifications.rs` and nsh.dev's native-components, packaging, iOS and Android pages). A
   packaged app registers no native components and gets no extra targets, background modes,
   Gradle dependencies or manifest services. All of those need the app **embedded in Songbird's
   own host projects**: an Xcode project with the NSE target, and a Gradle project. NSH documents
   that path, and the host owns `Info.plist`, the entitlements and `AndroidManifest.xml`.
   app-core (A2), which decrypts, does not exist yet. So the extension shows the generic text
   for now and later decrypts with A2. Question 5.
8. **A real wake-up can be tested without a phone.** On Apple-silicon Macs, the iOS Simulator
   (Xcode 14 and later) registers with the real APNs **sandbox** and receives its pushes. With
   the sandbox key (Team `69QGT49729`, key `RKG5VDS2AG`, outside the repository) and a
   registered bundle ID, the gate can run: an offline simulator wakes through
   `services/push` → Apple → device. PushKit does not deliver to the Simulator, so VoIP is
   tested against the mock plus one physical-device run. An Android emulator with a Google
   Play image receives real FCM through the `songbird-6fab1` service account, once an Android
   app is registered in that Firebase project.
9. **Proving where credentials are.** "Provably present only in this service's runtime" becomes
   three checks:
   - every other service's configuration refuses unknown fields, so a provider key cannot even
     be configured there;
   - a CI test renders every host's Ansible variables and templates and asserts that the SOPS
     names of provider secrets appear only in the push role's files and the push container's
     mounts;
   - after deployment, a check lists each container's mounts and environment and finds the
     secrets only in `push`.

   Production keys are created at deployment, straight into SOPS, never on a laptop.
10. **Desktop needs no push service, and NSH already has what it needs.** macOS can use APNs,
    but that puts Apple in the loop for a device that is almost always running anyway. Windows'
    only push service is Microsoft's WNS: it needs an MSIX package registered in Microsoft's
    Partner Center, and Microsoft would see every wake-up. Linux has no system push service.
    Signal Desktop uses none of them: it stays connected while running. NSH 0.6 already offers
    the parts for that (read in `nsh-core-0.6.0/src/desktop.rs` and `notifications.rs`):
    - a tray icon (`DesktopCommand::SetTray`);
    - an app that keeps running with its window hidden;
    - a launch-at-login item (`LoginItemBackend`);
    - local notifications and the badge.

    So desktop devices keep their delivery connection in the background and notify locally.
    A fully quit desktop finds its messages in the mailbox (up to 30 days) at the next start,
    and the user's phone, always linked, is still woken. UnifiedPush on Linux (KUnifiedPush,
    ntfy) needs nothing new on the server (Web Push exists). It is recorded as future work, not
    built.

## Architecture changes

- **Streams:** `j:push` (messages; leading and trailing coalescing, 24 h provider expiry) and
  `j:push-call` (calls; no debounce across calls, 30 s life, its own concurrency, retries inside
  the life only). Both sealed as today. The breaker stays per provider, shared by both paths.
  When it is open, call jobs are dropped at the end of their life, not dead-lettered.
- **Identical pushes:** every message push is byte-for-byte the same per provider, as now. On
  FCM and Web Push a call push is **the same message as a message push** (Google and the
  distributor cannot tell them apart). The app wakes, connects and finds the offer. On APNs, a
  call must go through PushKit (Apple's rule for ringing a killed app), so Apple sees "a call
  now" with no payload. That cannot be avoided on iOS. Signal and WhatsApp accept it too.
- **`urgent` (if question 1 is yes):** a flag on `PUT /v1/messages` and the WebSocket send.
  Non-urgent envelopes are stored and delivered as usual and enqueue no push. It is never
  stored or logged.
- **Token database (if question 3 is yes):** the `push` SurrealDB database, its three users,
  a migration that moves existing rows, and the M6 backups changed to skip it.
- **The app (if question 5 is yes):**
  - `apps/ios`: an Xcode host embedding `NativeShell.xcframework`, plus a Notification Service
    Extension target and an App Group.
  - `apps/android`: a Gradle host with the NSH `.aar`, FCM in the Play build, UnifiedPush in a
    build without Google, and `ConnectionService` for calls.
  - A small native module per platform hands the token to the Rust app through NSH's
    `host.call` channel. The app seals nothing itself: it registers through `PUT /v1/push`, as
    the API already defines.
  - Mute and preferences stay in the app's settings store. The extension reads them from the
    App Group and decides what to show.
- **Desktop (macOS, Windows, Linux), in `apps/ui` only:**
  - closing the window hides it, and the app stays in the tray (menu bar on macOS), still
    connected;
  - "Open at login", off by default;
  - new messages and incoming calls raise local notifications through NSH;
  - one notify-or-not function decides, shared with the mobile builds: muted chat, settings
    off, chat already open and focused.
  - No push registration: a desktop device has no row in the token store, and its push jobs
    end as "no registration", as today.

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **The push engine:** `j:push-call` with its life and consumer; leading and trailing coalescing in `delivery` and `push`; `urgent` (Q1); the `push` token database (Q3); mock behaviours "accepts and never answers" and "resets mid-stream". | Live tests: a ring is not delayed behind 10,000 queued message wake-ups; a burst gives at most two pushes and **never leaves a stored message without a later wake-up** (proptest over arrival times); non-urgent sends store and push nothing; a token unregistered by each provider is gone at once; timeouts open the breaker. |
| **M2** | **Numbers and outages:** pushes per second and p99 from enqueue to the provider's answer, against the mocks over TLS and HTTP/2 (criterion and a load run); provider outage (`Unavailable`, black hole, rate limit) and recovery; `valkey-jobs` down; `push` killed mid-burst. | Throughput and p99 recorded with the hardware; every outage ends with **every message still in the mailbox, fetched on reconnect, and pushes resumed** without operator action; dead letters only for the cases the runbook names. |
| **M3** | **Credentials and operations:** Ansible and SOPS for the push host only; the three credential checks (finding 9); alert rules (dead letters, breaker open, push failures, dropped wake-ups, registry busy) with `promtool` tests; Prometheus and Alertmanager (Q4); runbooks. | The rendering test fails if a provider secret is referenced anywhere but push; `promtool test rules` passes in CI; the post-deploy check is scripted. |
| **M4** | **The app on iOS** (Q2, Q5): the Xcode host, APNs registration to `PUT /v1/push`, the NSE showing the generic text and honouring mute from the App Group (with the entitlement), PushKit reported to CallKit and joined to the existing ringing screen. | **An offline iOS Simulator receives a real APNs sandbox wake-up end to end** (compose stack → `push` → Apple → Simulator), the app reconnects and the envelope count rises; NSE unit tests; one VoIP ring on a physical iPhone, recorded. |
| **M5** | **The app on Android:** the Gradle host, FCM registration (Play build), UnifiedPush (no-Google build), high-priority wake to a foreground fetch, `ConnectionService` ring. | **An offline Android emulator receives a real FCM wake-up end to end**; UnifiedPush through a self-hosted distributor (ntfy) in compose. |
| **M6** | **The app on desktop** (finding 10): tray and hidden-window lifecycle, "Open at login", local notifications for messages and calls, the shared notify-or-not rules wired to the notifications settings screen. | Headless tests of the notify-or-not rules (muted, off, focused, call versus message) and of the tray and login settings; on macOS, Windows and Linux, a message arriving with the window closed raises a notification, recorded with screenshots; a quit desktop fetches its waiting messages at start. |
| **M7** | **The gate:** GDPR for the moved token store; the security review of the whole diff; `P08-gate.md`. | The prompt's gate item by item: an offline device wakes end to end in the integration environment, provider outage and recovery tested, credentials provably only in push. |

Order: M1 first; M2 needs M1. M3 can run beside M1 and M2. M4 and M5 need the owner's Apple and
Firebase steps (questions 2 and 5) and M1's API. M6 needs nothing from the server and can run
beside M1 to M3. M7 needs everything.

## Threat-model rows this plan will propose

- `urgent` (if Q1): one bit per send, in memory only, never stored or logged.
- APNs `VoIP` pushes: Apple learns that a device is being rung, and when. FCM and the Web Push
  distributor learn nothing beyond "a wake-up" (already true; restated because calls now use
  them).
- The `push` token database (if Q3): the same sealed rows as today, moved apart; no new field.

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 to 7. Questions 2 and 5 also need steps in your Apple and Google accounts, which only
you can take.

1. **Silent sends.** Recommended: an `urgent` flag, as Signal has. Receipts and sync messages are
   sent non-urgent and wake nobody; the server sees one bit per send, never stored. The
   alternative: every stored envelope wakes the device (battery, and on iOS a visible "New
   message" for a read receipt unless the entitlement in question 2 hides it).
2. **Apple: the bundle IDs and the filtering entitlement.** Recommended: register
   `chat.songbird.app` (from `nsh.json`) with Push Notifications, the extension
   `chat.songbird.app.notify` and the App Group `group.chat.songbird.app`; then request
   `com.apple.developer.usernotifications.filtering` from Apple, the only way to honour mute on
   iOS. Your account is enrolled as an **Individual**, so the app and the request would carry your
   personal name. Enrolling an organisation first changes that, and is easier before the first
   bundle ID than after. Without the entitlement, M4 still ships, but iOS shows every wake-up.
3. **Token storage.** Recommended: a SurrealDB database of its own (`push`), a credential per
   service (`api` writes, `push` reads and deletes, `worker` deletes), left out of backups. The
   alternative keeps the sealed rows in the registry database, as today.
4. **Alerting.** Recommended: Prometheus and Alertmanager on the bastion (admin-only already), the
   rules tested in CI. **Where should alerts reach you?** Email through an SMTP relay you choose,
   a self-hosted ntfy topic, or a Matrix room. The alternative: rules only now, the stack in
   Prompt 12.
5. **The app's host projects.** Recommended: embed the NSH app in Songbird's own Xcode and Gradle
   projects (`apps/ios`, `apps/android`) for the notification extension, PushKit with CallKit,
   FCM, UnifiedPush and ConnectionService. Also register the Android app `chat.songbird.app` in
   Firebase `songbird-6fab1`; its `google-services.json` is kept out of the repository and given
   to CI as a secret. Android ships two builds, Play with FCM and one without Google with
   UnifiedPush (as Molly does). The alternative: server work only now, and the app's push
   once NSH has it, with no date known.
6. **Agent decisions, recorded unless you object:**
   - calls on their own stream with a 30 s life (finding 1);
   - leading and trailing coalescing (finding 2);
   - call pushes identical to message pushes on FCM and Web Push;
   - the debounce stays per process, because provider collapse IDs cover several push
     instances, and M2 measures the duplicates;
   - the two new mock behaviours;
   - the three credential checks (finding 9);
   - real-provider tests read the key paths from the environment (`SONGBIRD_APNS_KEY`,
     `SONGBIRD_FCM_ACCOUNT`) and skip when they are unset, so CI never holds them;
   - desktop without any push service: background connection, tray, local notifications
     (finding 10); Linux UnifiedPush recorded as future work;
   - one branch and one PR for every milestone.
