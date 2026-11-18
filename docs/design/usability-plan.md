# Usability test plan

Status: **plan only; no sessions have run.** Results go in §8 when they exist. Gates this plan
feeds: **A1** (design approval: IA and settings findability), **A4** (onboarding and identity:
sign-up, safety number comprehension), **A10** (settings and privacy centre comprehension).

## 1. Goals

1. Can WhatsApp users do everyday tasks in Songbird without help?
2. Can they find the ten settings they use most (tree test)?
3. Do they understand what Songbird can and can't see (privacy centre)?
4. Do trust messages (key change, recovery key) inform without frightening?

## 2. Participants

| Criterion | Target |
| --- | --- |
| Count | 5–8 per round (two rounds: before and after fixes) |
| Must | Use WhatsApp daily; own a smartphone |
| Mix | ≥ 2 iPhone and ≥ 2 Android; ≥ 2 aged 55+; ≥ 1 aged 16–20 (with guardian consent if under the national age of digital consent); ≥ 2 Romanian-language sessions; ≥ 1 screen-reader or large-text user if recruitable |
| Exclude | People who work in software security or on messengers |
| Incentive | Gift voucher of fixed value, paid whether or not they finish |

## 3. Setup

- Build: the NSH app on a test phone (iOS and Android) with mocked app-core, seeded data, invite
  code ready. No real accounts or personal data.
- Moderated, 45 minutes, in person or remote with screen share. Think-aloud.
- Recording: screen and audio only, with consent; stored encrypted, deleted 90 days after the
  report.
- Tree test (task 8) on paper cards or an unbranded online tree-test tool with the You tree from
  `flows/settings.md` (labels only, no visuals).

## 4. Tasks and success criteria

| # | Task (as read to the participant) | Success | Gate metric |
| --- | --- | --- | --- |
| 1 | "A friend gave you this invite code. Join Songbird." | Reaches the chat list with a username and saved recovery key | A4: ≥ 80 % unaided; median ≤ 3 min |
| 2 | "Start a chat with your friend *mara.pop* and say hello." | Message sent to the right person | A1: ≥ 90 % unaided; ≤ 60 s |
| 3 | "Make a group called *Family* with Mara and Ion." | Group exists with both members | A1: ≥ 80 %; ≤ 2 min |
| 4 | "Call Mara on video, then hang up." | Call started and ended | A1: ≥ 90 %; ≤ 30 s |
| 5 | "Make sure you won't lose your chats if you lose your phone." | Backup turned on with any destination | A1/A10: ≥ 70 % unaided; ≤ 3 min |
| 6 | "Mara's safety number changed. What do you think happened? What would you do?" | Gives a benign likely reason, does not say they'd stop using the app | A4: ≥ 80 % non-alarmed (SEQ ≥ 5) |
| 7 | "Open *What Songbird can see*. Tell me three things Songbird knows and three it doesn't." | 5 of 6 correct | A10: ≥ 80 % of participants ≥ 5/6 |
| 8 | Tree test: find (a) who can see last seen, (b) blocked people, (c) notification sound, (d) storage used, (e) linked devices, (f) two-step PIN, (g) theme/dark mode, (h) backups, (i) read receipts, (j) app lock | Correct leaf chosen first time | A1/A10: ≥ 80 % direct success per item; no item < 60 % |
| 9 | "Turn off read receipts." (in the app) | Done | A10: ≥ 90 %; ≤ 45 s |
| 10 | "Someone you don't know sent you a message. Decide what to do with it." | Finds Message requests, accepts/blocks/reports with understanding | A10: ≥ 80 % |

Per task also record: time, errors (wrong taps before success), assists, Single Ease Question
(SEQ, 1–7).

Overall: SUS (System Usability Scale) after the session; target ≥ 75 (A1).

## 5. Script

1. **Welcome (3 min).** "Thank you for helping. We're testing the app, not you. There are no
   wrong answers. Please think aloud: say what you look for and what you expect. I can't help
   during tasks, but you can stop at any time."
2. **Consent (2 min).** Read §6, sign, confirm recording.
3. **Background (3 min).** Which messengers do you use daily? What do you use most in WhatsApp?
   Have you ever changed a WhatsApp privacy setting? Which?
4. **First impression (2 min).** Show the welcome screen: "What do you think this app is for?"
5. **Tasks 1–7, 9, 10 (25 min).** Read each task card; after each: SEQ, then "Was anything
   surprising?"
6. **Tree test (5 min).**
7. **Wrap-up (5 min).** SUS; "What one thing would stop you switching? What one thing would make
   you switch?"; "In your own words, what does Songbird promise?"

Neutral prompts only: "What are you looking for?", "What do you expect here?". Never name the
target screen.

## 6. Consent (summary, full form in the participant pack)

- What: a 45-minute session testing an unreleased app; screen and voice recorded.
- Use: only to improve the app; quotes anonymised; no face recording.
- Storage: encrypted, deleted 90 days after the report; never shared outside the team.
- Rights (GDPR): withdraw at any time, during or after, and have recordings deleted; contact
  address on the form. Lawful basis: consent (Art. 6(1)(a)).
- Minors: below the national age of digital consent (13–16 depending on country, THREAT_MODEL §5)
  a parent or guardian signs as well and may be present.
- Payment does not depend on finishing.

## 7. Analysis

- Success rates with 90 % adjusted-Wald confidence intervals (small samples).
- Issues logged with severity: 1 blocker, 2 major (slows, causes error), 3 minor, 4 cosmetic;
  each linked to a flow spec and a fix owner.
- Gate pass: every metric in §4 met, or the owner accepts the gap with a fix plan.

## 8. Results template

### Round <n> — <date>, build <commit>

| P# | Platform | Age band | Language | WhatsApp years | Notes |
| --- | --- | --- | --- | --- | --- |
| P1 | | | | | |

| Task | Success (n/N) | 90 % CI | Median time | Mean SEQ | Gate target | Met? |
| --- | --- | --- | --- | --- | --- | --- |
| 1 Sign up | | | | | ≥ 80 %, ≤ 3 min | |
| 2 Start a chat | | | | | ≥ 90 %, ≤ 60 s | |
| 3 Create a group | | | | | ≥ 80 %, ≤ 2 min | |
| 4 Video call | | | | | ≥ 90 %, ≤ 30 s | |
| 5 Backup | | | | | ≥ 70 %, ≤ 3 min | |
| 6 Key change comprehension | | | | | ≥ 80 % non-alarmed | |
| 7 Privacy centre | | | | | ≥ 80 % score ≥ 5/6 | |
| 9 Read receipts | | | | | ≥ 90 %, ≤ 45 s | |
| 10 Message request | | | | | ≥ 80 % | |

| Tree item | Direct success | Indirect success | Fail | First click (most common) |
| --- | --- | --- | --- | --- |
| a Last seen | | | | |
| b Blocked | | | | |
| c Notification sound | | | | |
| d Storage used | | | | |
| e Linked devices | | | | |
| f Two-step PIN | | | | |
| g Theme | | | | |
| h Backups | | | | |
| i Read receipts | | | | |
| j App lock | | | | |

SUS mean: __ (target ≥ 75)

| # | Issue | Task | Participants | Severity | Flow spec | Proposed fix | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | | | | | | | |

Quotes (anonymised, P#): …
