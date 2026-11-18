# Songbird design (A1)

"As easy as WhatsApp, as trustworthy as Proton." This folder holds the A1 design documentation:
research, parity, brand, IA, per-flow specs, trust design and the usability test plan. The design
system in code is `apps/ui/DESIGN.md` + `apps/ui/theme.json` + `apps/ui/src/ui/`; these documents
explain, check and extend it.

## Index

| File | What it is |
| --- | --- |
| [teardown.md](teardown.md) | Desk teardown of WhatsApp, Signal, Proton, Threema, Telegram: what each does best, what confuses people, what Songbird takes |
| [parity-map.md](parity-map.md) | Every WhatsApp screen and setting → where it lives in Songbird, with status and reason |
| [brand.md](brand.md) | Logo/icon brief, every colour token (light, dark, high contrast) with WCAG contrast results, typography, icons, motion, sound |
| [ia.md](ia.md) | Navigation proposal: tabs, desktop layout, channels' home, where Status went, deep-link scheme |
| [trust.md](trust.md) | How encryption, key changes, verification, server limits and "what Songbird can see" are presented; wording do/don't |
| [component-library.md](component-library.md) | Every component with states and accessibility, mapped to `apps/ui/src/ui` |
| [usability-plan.md](usability-plan.md) | Test plan with 5–8 WhatsApp users, tasks, gate metrics, script, consent, results template |
| [flows/](flows/) | One spec per flow (below) |
| [tools/contrast.py](tools/contrast.py) | Contrast checker for `theme.json` + high-contrast overrides; exit 1 on failures |
| [reference/](reference/README.md) | Reference screenshots the owner should add (incl. their own WhatsApp) |

Flows: [onboarding](flows/onboarding.md) · [first chat and invites](flows/first-chat-invite.md) ·
[chat screen](flows/chat-screen.md) · [groups and communities](flows/groups-communities.md) ·
[calls](flows/calls.md) · [settings](flows/settings.md) · [privacy centre](flows/privacy-centre.md)
· [parental controls](flows/parental-controls.md) · [backups](flows/backups.md) ·
[linking a device](flows/linking-device.md) · [safety number](flows/safety-number.md) ·
[message requests, block, report](flows/message-requests-block-report.md) ·
[WhatsApp chats](flows/whatsapp-chats.md) · [plans and paywall](flows/plans-paywall.md) ·
[desktop](flows/desktop.md)

## Status (2026-11-17)

| Area | Designed (this folder) | Built (`apps/ui`) | Owner approval |
| --- | --- | --- | --- |
| Tokens, type scale, motion tokens, radii | ✓ (brand.md) | ✓ `theme.json`, `src/ui/tokens.rs`, `src/theming.rs` | Pending; **26 contrast failures to fix first** (brand.md §2.2) |
| `ui` component layer | ✓ (component-library.md) | ✓ buttons, rows, inputs, avatars, ticks, banners, sheets, dialogs, toasts, empty states, skeletons | Pending |
| Shell: four tabs, desktop rail + list + detail | ✓ (ia.md) | ✓ `src/shell.rs`, `src/nav.rs` | Pending (ia.md §1, §3, §4) |
| Logo, app icon | Brief only | Placeholder (Lucide feather) | Pending: designer + owner |
| Sounds | Brief only | — | Pending |
| Deep links | Proposal (ia.md §5) | — | Pending: web domain |
| Onboarding, chats, chat, groups, calls, settings, devices, backups, plans, WhatsApp, desktop | ✓ (flows/) | In progress by feature agents (`src/features/*`, mostly stubs today) | Pending; open questions at the end of each flow |
| Usability testing | Plan ✓ | — | Not run; results template in usability-plan.md §8 |
| Reference screenshots | List ✓ | — | Owner to add |

## How to review

1. Screenshots: from `apps/ui`, run `nsh test Screens*.test.tsx --target macos`; images land in
   `apps/ui/shots/` (today: `phone.png`, `desktop.png`, `onboarding.png`). Compare each against its
   flow spec.
2. Live: `cargo run` in `apps/ui` (desktop) or `nsh run --target ios|android`. Theme switch:
   You › Chats › Appearance › Theme (once built).
3. Contrast: `python3 docs/design/tools/contrast.py --fails` from the repository root.
4. Decisions: each flow and `ia.md`/`brand.md`/`trust.md` ends with **Open questions (owner)**.
   Answer inline or in `docs/DECISIONS.md`; approved answers move into the specs.

## Ground rules

- Specs never claim more privacy than `docs/THREAT_MODEL.md` §1 allows; trust copy changes when
  the threat model changes.
- Feature code composes only `crate::ui::*` (DESIGN.md rules); a look the layer lacks becomes a
  variant there first.
- Copy: sentence case, calm, no exclamation marks in errors, no jargon, no fear.
