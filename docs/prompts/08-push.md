# Prompt 8 — Push and notifications

*File: `docs/prompts/08-push.md` · Skills: Rust networking, reliability engineering, security review.*

**Goal:** wake devices fast and reliably, leaking nothing to Apple, Google or anyone else.

**Build `services/push`** (its own binary, the only holder of push credentials):

- **Input:** push jobs from the Valkey Streams queue (`crates/jobs`), carrying only a device reference and a kind (`message` or `call`).
- **Token management:** devices register push tokens through `api`; tokens are stored encrypted at rest, apart from other account data, and deleted at once when a provider reports them unregistered.
- **Providers:**
  - APNs over HTTP/2 with token-based auth. Messages: alert push with `mutable-content: 1` and a generic placeholder text, no identifiers. Calls: VoIP push through PushKit, on a separate high-priority path.
  - FCM HTTP v1: high-priority data messages with no sensitive data.
  - UnifiedPush via Web Push with message encryption and VAPID, to the user's own distributor.
- **Coalescing:** many messages for one device within a short window become one wake-up (APNs `apns-collapse-id`, FCM `collapse_key`, plus a short local debounce). Every push looks identical regardless of what triggered it.
- **Reliability:** retries with exponential backoff and jitter, a circuit breaker per provider, a dead-letter stream with alerting, and HTTP/2 connection pooling per provider.
- **Mute and notification preferences** stay on the device: the notification extension decides what to show. The server never learns which chats are muted.

**Tests and benchmarks:** mock APNs and FCM servers in the test suite (including slow, failing and rate-limiting behaviour); pushes per second and p99 time from job to provider; outage simulation proving messages stay safe in mailboxes and pushes resume.

**Gate:** an offline device receives a wake-up end to end in the integration environment; provider outage and recovery tested; push credentials provably present only in this service's runtime.
