# Flow: plans and paywall (A12, Prompt 11)

**Goal:** show what Free, Plus and Family include without nagging, never gate security, and let
people pay through their platform's store or an EU provider. Module: `features/plans.rs`. Data:
`Settings::plan` (`Plan::Free | Plus | Family`).

## Rules

- **Security and privacy are never paid** (constitution, Prompt 11): encryption, safety numbers,
  backups themselves, app lock, PIN/passkeys, proxy, privacy centre are always free.
- No plans in onboarding; no interstitials; no countdowns; no "limited offer".
- A limit is explained at the moment it is hit, once, with the free alternative first.

## Entry points

You › Account › Plan; a limit moment (file too large, device limit, backup space, packs); You
profile card "Plus" tag (for subscribers).

## Steps

| # | Screen | Content |
| --- | --- | --- |
| 1 | Plans | Segmented Free · Plus · Family; comparison table (below); current plan marked "Your plan" |
| 2 | Choose | **Get Plus — {price}/month** or yearly toggle; store sheet (App Store / Google Play) or EU provider on desktop |
| 3 | Done | "You're on Plus. Thank you for supporting Songbird." |
| 4 | Manage | Renewal date, Change plan, Cancel (link to store), Restore purchases |
| 5 | Family | Invite up to 5 members (username), member list, Remove, Leave family |

## Comparison (values: open question 1)

| | Free | Plus | Family |
| --- | --- | --- | --- |
| Encryption, calls, groups, safety numbers, app lock, proxy | ✓ | ✓ | ✓ |
| Linked devices | 5 | 5 | 5 each |
| File size | {n} | {n} | {n} |
| Songbird backup space | {n} | {n} | {n} shared |
| App icons and themes | — | ✓ | ✓ |
| Custom sticker packs | {n} | ∞ | ∞ |
| People | 1 | 1 | up to 6 |

## Limit moments

| Moment | Copy |
| --- | --- |
| File too large | "This file is over {n} on Free. Send a link to it instead, or get Plus for files up to {m}." Secondary: **See Plus** |
| Backup space | "Your Songbird backup space is full. Back up to your own cloud for free, or get more space with Plus." |
| Plus expired | "Plus ended. Everything keeps working; extras like app icons are back to default." |

## States

| State | Copy |
| --- | --- |
| Store unavailable | "Purchases aren't available right now. Try again later." |
| Pending | "Waiting for the store to confirm…" |
| Failed | "The payment didn't go through. You weren't charged." (only when the store says so) |
| Family member | "Plus through {owner}'s Family plan." Leave |

## Accessibility

Comparison is a real table with headers; ✓ read as "included", — as "not included"; prices with
currency and period in words ("4 euros a month").

## Motion

Segmented selection `BASE`; no celebratory animation beyond a check.

## Open questions (owner)

1. Prices and limits per plan (Prompt 11 entitlements).
2. EU desktop payment provider choice.
3. Teams plan timing.
