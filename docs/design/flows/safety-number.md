# Flow: safety numbers and verification (A4)

**Goal:** anyone can check they're talking to the right person by scanning or comparing a number,
and key changes are explained without fear. Module: `features/devices.rs` (`safety_number`). Data:
`Contact::safety_number` (60 digits, 12 groups of 5), `verified`, `key_changed`. Wording rules:
`../trust.md`.

## Entry points

Chat info › Encryption › Safety number; key-change system line › Verify; group member sheet ›
Verify safety number; encryption notice sheet › "How to check".

## Steps

| # | Screen | Content |
| --- | --- | --- |
| 1 | Safety number | Heading "Safety number with Ana"; QR (240 pt); 12 groups of 5 digits in 3 rows of 4 (monospace); "Key directory: checked ✓" line |
| 2 | Explanation | "If Ana's screen shows the same number, nobody is in between you. Compare in person, or scan each other's code." |
| 3 | Scan | **Scan Ana's code** → scanner → match: "Numbers match. Ana is verified." / no match: "These numbers don't match. Make sure you're scanning Ana's code for this chat." |
| 4 | Manual | Toggle **Mark as verified** (after comparing aloud or by another channel) |
| 5 | Verified | Shield-check shown next to Ana's name everywhere; system line "You marked Ana as verified." |

## States

| State | Copy |
| --- | --- |
| Not verified (default) | No badge anywhere; screen offers Scan / Mark as verified |
| Verified | "You verified Ana on {date}." **Clear verification** |
| Changed since verification | "Ana's safety number changed on {date}. This usually means they reinstalled Songbird or got a new phone. Compare again to verify." |
| Key directory check failed | "We couldn't confirm Ana's keys with the public key directory. Compare in person before sharing anything sensitive." |
| Key directory unreachable (offline) | "Couldn't reach the key directory. We'll check again later." |
| Camera denied | "Allow camera access to scan, or compare the numbers instead." |
| WhatsApp chat | Shows WhatsApp's security code format and "Compare this with the code in Ana's WhatsApp." |

## Copy

| Key | String |
| --- | --- |
| sn.title | Safety number with {name} |
| sn.body | If {name}'s screen shows the same number, nobody is in between you. Compare in person, or scan each other's code. |
| sn.match | Numbers match. {name} is verified. |
| sn.nomatch | These numbers don't match. Make sure you're scanning {name}'s code for this chat. |
| sn.changed.line | {name}'s safety number changed. This usually means they reinstalled Songbird or got a new phone. Verify |
| sn.kt.ok | Key directory: checked |

## Accessibility

- Digits read in groups of five; "Copy number" action for sharing over another channel.
- Scan success/failure announced and paired with haptic.
- Verified shield has the text ", verified" in names.

## Motion

Match: frame turns `primary`, check scales in, `BASE` (reduced: colour only). No shaking or red
on mismatch.

## Open questions (owner)

1. Show the key-directory line at all, or only on failure? (Proposal: show "checked" quietly.)
2. Group verification: per member only (proposal), no group-wide number.
