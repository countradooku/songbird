# Runbook: legal requests, transparency and support

Owner: the legal contact, with counsel; support staff for tickets. Prompt 11, M6 (D-0126 §9–§11,
D-0132). Protocol: `docs/PROTOCOL.md` §14.8–§14.10. **Counsel still has to review this process
before the first real request** (an open owner item).

## What Songbird can give

Only what the account's **own data export** shows (`GET /v1/account/export`): the account row,
devices and their public keys, username and links, groups it is in, plan level, standing,
support tickets it attached itself to, sizes of its settings store. **Never** message,
attachment, call or backup content (end-to-end encrypted; no key on any server), **never**
payments (billing holds no account; tokens are unlinkable), **never** IP addresses (not logged,
invariant 6), **never** contacts (they live on devices).

## A request arrives

1. Log it in counsel's case register (offline, not on any Songbird server): a case reference,
   the authority, its country, the legal basis, the account named (account ID, username or
   phone number: there are no phone numbers).
2. Counsel checks: lawful under the law that applies (Songbird's establishment, the EU), specific
   (one account, a stated offence), verified (the authority is who it says, through a known
   channel). Anything else is refused.
3. Refused, or nothing held (no such account; content asked for):

   ```bash
   songbird-admin legal record --case <ref> --country <XX> --kind data --outcome rejected \
     --confirm songbird/songbird --addr <registry> ...
   ```

   Kinds: `data`, `preservation`, `takedown`, `other`. Outcomes: `rejected`, `nothing-held`,
   `complied` (a preservation or takedown done; no data given).

4. Lawful and specific, data asked for:

   ```bash
   songbird-admin legal export --account <hex> --case <ref> --country <XX> \
     --out /secure/case-<ref>.json --confirm songbird/songbird --addr <registry> ...
   ```

   The file (mode 0600, must not exist) holds the case reference, the scope statement and the
   export. It is audit-logged (case, country, account, who, when) and counted. Hand it over
   through counsel; delete the local copy once delivered.

5. **Notify the user** unless a court order forbids it, and then as soon as it lapses. Counsel
   records the notification in the register.

A preservation request keeps nothing the account could not delete itself; Songbird's
retention (mailbox 30 days, tickets 90 days, …) is the answer to "what will still be there".

## Transparency report (every half-year)

```bash
songbird-admin transparency --half 2026-H2 --addr <registry> ... > transparency-2026-H2.md
```

It prints, from counts only: requests by country, kind and outcome; how many led to data; the
accounts limited or suspended right now by source (`auto`, `moderator`). Counsel reviews it, then
it is published. The registry's `legal` table holds counts per half-year, country, kind and
outcome, never a case or an account.

## Support tickets

Staff hold the **support key** (X25519) offline, like the moderation key. Set it up once:

```bash
songbird-admin support keygen --out /secure/support.key   # prints the public key
```

and put the public key in `[api.support] key`. Then:

```bash
songbird-admin support list --addr <registry> ...                       # priority first
songbird-admin support open --ticket <hex> --key /secure/support.key ... # JSON lines
songbird-admin support reply --ticket <hex> --file reply.txt ...         # sealed to the user
songbird-admin support close --ticket <hex> --confirm songbird/songbird ... # deletes it all
```

- A ticket names an account only if the user attached it (an appeal, a billing question);
  `priority` means that account is on Plus. Anonymous tickets are as valid as any other.
- Logs come only with the user's consent, shown to them first, scrubbed on the device. **Close
  a ticket when it is solved**: that deletes it and every message, logs included. Untouched for
  90 days, the worker deletes it anyway.
- An appeal (`kind appeal`) goes to the moderator on call: see [abuse.md](abuse.md#appeals).
- Never ask a user for their recovery key, PIN or messages. Songbird staff cannot read them and
  never need them.

## Failures

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `/v1/support…` answers 503 | `[api.support]` missing, or the registry or `valkey-hot` down | Check the config and the stores |
| A user's ticket "disappeared" | Closed, or untouched for 90 days | Ask them to open a new one |
| `support open` prints "does not open with this key" | The support key was rotated after the ticket was opened | Use the previous key file; keep old keys until their tickets close |
| `legal export` fails "no such account" | Deleted, or a wrong ID | Record `nothing-held` |
