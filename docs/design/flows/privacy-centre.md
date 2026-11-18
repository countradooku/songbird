# Flow: privacy centre "What Songbird can see" (A10)

**Goal:** a non-technical person can say, after one minute, three things Songbird's servers know
and three they never see, and can fix their own privacy settings in one walkthrough. Module:
`features/settings.rs` (`privacy_centre`). Content source: `docs/THREAT_MODEL.md` §1 (see
`../trust.md` §5).

## Entry points

You › Privacy (card at top: "What Songbird can see"); Encryption sheet in any chat ("What our
servers see"); onboarding "Why no phone number?" sheet; Help.

## Steps

| # | Screen | Content |
| --- | --- | --- |
| 1 | Privacy centre | Heading "What Songbird can see"; intro "We built Songbird so our servers know as little as possible. Here's exactly what they know." |
| 2 | Two lists | "Songbird can see" (8 rows, each expandable with one more sentence and "Kept for…") and "Songbird never sees" (8 rows) — exact rows in `trust.md` §5 |
| 3 | Where your data lives | "Our servers are in the EU, run by Songbird." (exact locations: open question 2) |
| 4 | Check my settings | Walkthrough, 5 cards: Who sees your last seen and photo → Who can message you → Who can add you to groups → App lock → Backups. Each card: current value, change inline, Next. Ends "You're all set." |
| 5 | Learn more | Links: How encryption works · Our threat model (public repository) · Transparency report |

## States

| State | Behaviour |
| --- | --- |
| Offline | Content is bundled; works offline. Walkthrough server-enforced rows show the offline footnote. |
| Content outdated | Footer shows "Last checked against our threat model on {date}" (build-time) |
| Supervised account | Extra card "Your parent set some rules" listing them (`parental-controls.md`) |

## Copy

| Key | String |
| --- | --- |
| pc.title | What Songbird can see |
| pc.intro | We built Songbird so our servers know as little as possible. Here's exactly what they know. |
| pc.can | Songbird can see |
| pc.never | Songbird never sees |
| pc.where | Our servers are in the EU, run by Songbird. |
| pc.check | Check my settings |
| pc.done | You're all set. You can change these any time in Privacy. |
| pc.footer | Full details are in our threat model. Last checked {date}. |

## Accessibility

- Lists are real lists with item counts; expandable rows are disclosure buttons.
- Plain language target: reading age ~12 (Flesch-Kincaid ≤ 7) in English; Romanian reviewed by a
  native speaker.
- Walkthrough progress "2 of 5".

## Motion

Row expand: height + fade, `BASE` (reduced: instant). Walkthrough cards: native push.

## Open questions (owner)

1. Approve the public wording (it is a commitment that must stay true).
2. Name the hosting provider (Hetzner) and cities, or only "EU"?
3. Include an "Apple/Google see" section for push (trust.md §4)?
