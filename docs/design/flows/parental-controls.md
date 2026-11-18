# Flow: parental controls (A10, Prompt 9)

**Goal:** a parent supervises a child's account without ever reading the child's messages, and
the child always sees which rules apply. Data: `Settings::parental_controls`; policy signed by
the parent's key (Prompt 9).

## Entry points

Parent: You › Privacy › Parental controls › **Supervise a child's account**. Child: same row
shows "Supervised by {parent}" (read-only rules).

## Steps (linking, in person)

| # | Parent's screen | Child's screen |
| --- | --- | --- |
| 1 | Intro: "You'll set who can contact your child. You can never read their messages or see their calls." **Continue** | You › Privacy › Parental controls › **Be supervised** |
| 2 | Scanner | QR "Show this to your parent" |
| 3 | Confirm child "{name} (@user)" + same 6-digit code on both | Same code; **Confirm** |
| 4 | Rules: Who can contact (Approved contacts only / Contacts and message requests), Group invites need my approval (on), Calls from non-contacts (blocked), Find by username (off), Nudges (off), Supervision ends at age {n} (from the child's birth year, per country) | Waiting… |
| 5 | **Start supervising** | Summary of rules, **OK** |
| 6 | Parental controls page: rules, Approval requests (contacts, groups), Stop supervising | Banner in You: "Supervised by {parent}. **See rules**" |

## Day to day

| Event | Child | Parent |
| --- | --- | --- |
| Stranger messages (approved-only) | Nothing delivered; sender sees nothing special | — |
| Child wants a new contact | "Ask {parent} to approve {name}" → request | Notification "{child} wants to chat with {name} (@user)" Approve / Decline |
| Group invite | "Waiting for {parent} to approve" | Approve / Decline with group name if the child shares it |
| Unlinking | Only at the set age, or by the parent | Stop supervising (confirm) |

## States

| State | Copy |
| --- | --- |
| Under the age of digital consent at sign-up (13–16 by country) | "You'll need a parent or guardian to set up Songbird with you." |
| Parent offline | Requests wait; child sees "Waiting for {parent}" |
| Codes don't match | "The codes don't match. Start again, with both phones together." |

## Copy

| Key | String |
| --- | --- |
| pc.parent.promise | You can never read their messages, see their calls or browse their contacts. |
| pc.child.banner | Supervised by {parent}. See rules |
| pc.child.rules | {parent} chose these rules. You can see them here at any time. |
| pc.end | Supervision ends automatically when you turn {age}. |

## Accessibility

Code comparison read digit by digit; rules list readable by child in plain words; no hidden
rules.

## Motion

Standard push/pop; code match: both screens show a check, `BASE`.

## Open questions (owner)

1. Age source: child enters birth year at linking (proposal) or at sign-up for everyone?
2. Allow two parents to supervise one child?
3. Prompt 9 says the parent never browses the child's contacts. Proposal: the parent sees only
   pending requests and keeps no list of past approvals. Confirm.
