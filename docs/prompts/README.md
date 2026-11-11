# Songbird Backend — Prompt Set

## How to use this prompt set

Fifteen prompts that together build Songbird's entire backend. This folder holds them, one file per prompt and give them to a coding agent such as Claude Code, one at a time.

**Order.** Prompt 0 is the constitution: every other prompt starts by reading it. Then run them in this order. Prompts on the same line can run in parallel sessions once their predecessors pass their gates.

1. Prompt 1 (foundations)
2. Prompt 2 (realtime delivery core)
3. Prompt 3 (identity, devices, keys)
4. Prompts 4, 5 and 6 (messaging content, groups and channels, media)
5. Prompts 7 and 8 (calls, push)
6. Prompts 9, 10 and 11 (settings and presence, backups, plans and abuse)
7. Prompts 12 and 13 (security verification, performance and DR certification). Start them early and rerun them before every release.

Prompt 14 (WhatsApp interoperability) can start once Prompts 3 and 4 pass and the owner has cleared its legal gate. It is the biggest migration lever, so clear that gate early.

Sections marked **Also build (WhatsApp parity)** cover the WhatsApp settings and features that matter for people switching: username key, two-step PIN, passkeys, multiple accounts, broadcast lists, restricted chats, lists and favourites, parental controls, proxy support and more.

**Each session starts with:** *"Read docs/prompts/00-constitution.md, docs/DECISIONS.md and docs/prompts/NN-….md, list the skills available to you and load the best ones for this task, then continue."* Every prompt ends at a gate: the agent stops, writes a report, and waits for you.

**Detailed spec for Prompt 2:** [Songbird Realtime Backend — Master Build Prompt](02a-realtime-master.md). Prompt 2 below summarises it and points the agent to it.

**In scope:** the backend services and the shared Rust crates that define the backend's contract with future apps: the wire protocol, the encrypted content schemas, the backup format, and a Rust client used for testing.

**Out of scope:** the mobile and desktop apps and their UI (until the design exists), stories, AI features, and live location. "Statuses" here means presence and custom status lines (Yahoo-style "Back at 6"), not 24-hour stories.

## Files

- [Prompt 0 — Constitution (read before every task)](00-constitution.md)
- [Prompt 1 — Foundations and platform](01-foundations.md)
- [Prompt 2 — Realtime delivery core](02-realtime.md)
- [Prompt 2a — Realtime master build prompt (detailed spec for Prompt 2)](02a-realtime-master.md)
- [Prompt 3 — Identity, accounts, devices, keys and privacy primitives](03-identity.md)
- [Prompt 4 — Messaging content and conversation features](04-messaging.md)
- [Prompt 5 — Groups, roles, communities and channels](05-groups.md)
- [Prompt 6 — Media, attachments, stickers and packs](06-media.md)
- [Prompt 7 — Voice and video calls with LiveKit](07-calls.md)
- [Prompt 8 — Push and notifications](08-push.md)
- [Prompt 9 — Settings, presence, statuses and Yahoo-style features](09-settings-presence.md)
- [Prompt 10 — Backups: cloud-agnostic format and vault service](10-backups.md)
- [Prompt 11 — Plans, entitlements and abuse prevention](11-plans-abuse.md)
- [Prompt 12 — Security hardening and verification](12-security.md)
- [Prompt 13 — Performance, reliability and disaster-recovery certification](13-certification.md)
- [Prompt 14 — WhatsApp interoperability (EU third-party chats)](14-whatsapp-interop.md)
