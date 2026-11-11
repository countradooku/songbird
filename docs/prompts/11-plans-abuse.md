# Prompt 11 — Plans, entitlements and abuse prevention

*File: `docs/prompts/11-plans-abuse.md` · Skills: payments integration, privacy engineering, trust and safety, security review.*

**Goal:** Free, Plus, Family and (later) Teams plans enforced everywhere, payments verified server-side with minimal linkage to accounts, and spam and abuse controlled without reading content.

**Build:**

- **Entitlements service** (in `api`): one source of truth for limits (devices, backup space, file size, packs) and feature flags, read by every service through a cached, versioned snapshot. Security features are never gated (constitution).
- **Purchase verification:** App Store Server API and its server notifications, Google Play Developer API and real-time notifications, and an EU payment provider for desktop and web. Store only the entitlement and expiry against the account; keep payment-provider identifiers in a separate store with stricter access. Evaluate anonymous credentials (libsignal's zero-knowledge credential library) to unlink payment from account identity, and record the decision.
- **Family plans:** owner invites up to five members; entitlements shared; leaving or removal handled cleanly.
- **Teams (schema only for now):** reserve the organisation, admin and managed-device model so it can be added without migrations that break privacy guarantees.
- **Abuse controls without content:** layered rate limits; escalating proof-of-work for suspicious registration patterns; message-request throttles for new accounts; metadata-only risk signals (account age, request volume, block and report rates) with documented thresholds; suspension and appeal flows; the franked-report queue from Prompt 4 with an admin review tool and short retention.
- **Legal requests:** a documented process and audited tooling that can export only what the threat model says the server holds; counts feed a twice-yearly transparency report.

**Also build (WhatsApp parity):**

- **Help and feedback:** an in-app support channel that is user-initiated only. Optional debug logs are redacted on the device, attached only with explicit consent, and deleted when the ticket closes.
- **Invite a friend:** personal invite links that open a chat with the inviter after sign-up; no contact upload, no referral tracking beyond a counter.

**Gate:** entitlement checks covered in every service's tests (including expiry and downgrade); purchase verification tested against sandbox environments and replayed notifications; abuse simulations (registration floods, request spam, report brigading) show the controls work without affecting normal users.
