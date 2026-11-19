# P11 — Plans, entitlements and abuse prevention: plan, milestones and gates

- Date: 2026-11-19
- Prompt: [11-plans-abuse.md](../prompts/11-plans-abuse.md)
- Status: **approved by the owner on 2026-11-19** ("Approve all"), every recommendation (D-0126).
- Base: branch `claude/p11-plans-abuse-e05ed3`, cut from Prompt 10's branch
  (`claude/p10-backups-40584b`, PR #69, waiting for its gate). Prompt 11 builds on the vault's
  quotas and on D-0119's promise to re-decide the vault's link to the account. Once #69 is
  merged, this branch is rebased onto `main` so its PR shows only Prompt 11.
- Way of working (as Prompts 7 to 10): one branch and one PR. Each milestone gets its own
  commit, tests, report `docs/reports/P11-Mn.md`, decision record (D-0127 onward) and
  threat-model rows marked "awaiting the owner's approval". Then `cargo xtask ci fast`, the live
  suites (one heavy job at a time, `-j 1`, or `-j 2` for stores and e2e, with the environment of
  `ci.yml`'s compose job, without Iggy locally), an independent read-only security review of the
  whole diff by a separate agent given the code and not my conclusions, and
  `docs/reports/P11-gate.md`. Nothing is merged without the owner.
- Skills: `nsh` and `nsh-design-guides` before the app milestone (M7); `security-review` for
  the independent review (M8). No skill covers App Store Server API, Google Play Developer API,
  an EU payment provider, VOPRFs (RFC 9497) or Privacy Pass (RFC 9578). I read the
  specifications, the providers' documentation and the exact pinned crate sources instead. A
  `songbird-invariants` checklist (constitution) is still only proposed.

## What Prompt 11 starts from

| The prompt asks for | Already there | Missing |
| --- | --- | --- |
| One source of truth for limits, read by every service through a cached, versioned snapshot | Limits scattered in configuration: devices (`[api.keys.devices] max_devices = 6`, D-0047), the vault (`[api.vault]` 5 GiB, 100,000 chunks, 2 vaults, D-0119), file size (`[api.attachments] max_bytes`, 2 GiB), upload bytes per day (`[api.media.budgets]`, 10 GiB), pack size (300 MiB). A model for the snapshot: `LiveDirectory` (`crates/send/src/directory.rs`), an `arc-swap` snapshot reloaded when the registry's version row changes, read lock-free by `api` and `delivery` | A plan catalogue, per-account entitlements, one snapshot every service reads, downgrade and expiry rules. THREAT_MODEL §4's "Plan and entitlements" row is "reserved" |
| Purchase verification (App Store, Google Play, an EU provider) | Nothing. The app's Subscription page is a mock (`apps/ui/src/features/plans/`: Free, Plus €2.99, Family €4.99, mock renewal dates); `docs/design/flows/plans-paywall.md` leaves prices, limits and the EU provider to the owner | Everything: verification, notifications, the separate payment store |
| Anonymous credentials (libsignal's zero-knowledge credential library) | D-0047: libsignal is AGPL-3.0-only and is never linked; Songbird implements Signal's protocols on permissive crates and proves byte compatibility with vectors from a scratch tool (`tools/libsignal-vectors`). `crates/keys/src/username.rs` already has Signal's `Sho` and a poksho prover/verifier on `curve25519-dalek` 5 | The evaluation and a credential scheme |
| Family plans | The app mocks a member list (`store/ext_extras.rs`) | Everything |
| Teams (schema only) | Nothing | The reserved tables |
| Layered rate limits | GCRA budgets in `valkey-hot` under keyed names almost everywhere: registration per IP range and deployment, usernames, the key directory, profiles, message requests per sender, pair and recipient (`crates/send/src/gate.rs`), reports per reporter, uploads, calls, the record store, the vault | One view of the layers; budgets that depend on an account's age and standing |
| Escalating proof of work | Argon2id challenges with fixed difficulty from configuration (`crates/pow`, D-0048) | Difficulty that rises with suspicious registration patterns |
| Message-request throttles for new accounts | One set of request budgets for every account | Tighter budgets for young accounts |
| Metadata-only risk signals | Blocks counted per blocked account (`blockctr`, keyed); reports verified with franking but sealed to the offline moderation key, so **the server cannot count reports per account** | Signals, thresholds, what they trigger |
| Suspension and appeal | Nothing | An account standing, what it stops, how to appeal |
| The franked-report queue with an admin review tool and short retention | `POST /v1/reports` (D-0063); `songbird-admin reports` opens the queue with the offline key; retention 1–90 days from configuration | Decisions (dismiss, restrict, suspend), their audit, deletion on decision |
| Legal requests and a transparency report | GDPR export (`crates/accounts/src/gdpr.rs`) of what the server holds per account; `songbird-admin`'s audit log (`tools/admin/src/audit.rs`) | The process, the tool, the register of counts, the report |
| Help and feedback | The app's mocked contact form and its log scrubber (`plans/help.rs`, `plans/catalog.rs`) | The server side, consent, deletion at close |
| Invite a friend | Invite codes without inviter (D-0038); username links (§4.3); the app's mocked invite screens | Links that open a chat with the inviter after sign-up |

## Findings that shape the plan

1. **libsignal's credential library cannot be linked, and does not need porting for payments.**
   `zkcredential` and `zkgroup` are AGPL-3.0-only (D-0047). Porting them is possible on the
   `Sho` and poksho code we already have, but their power (credentials with hidden attributes,
   proven in zero knowledge) is needed only when a credential must be bound to a value the
   issuer must not see. Payments need less: "someone paid for Plus for December" and "this
   account has Plus until 31 December". That is exactly what **Privacy Pass** gives
   (RFC 9578, privately verifiable tokens on the **VOPRF of RFC 9497**, ristretto255 with
   SHA-512): the issuer evaluates a PRF on a blinded random nonce and proves (DLEQ) it used the
   published key; the client unblinds; redeeming the (nonce, output) pair later cannot be linked
   to its issuance, even by a server holding every record. Metadata rides on the key: **one key
   per (level, month)**, derived from a secret. About 400 lines on `curve25519-dalek` 5 and
   aws-lc-rs's SHA-512, checked against the RFC's published vectors, no new dependency. This is
   what Signal itself does for donations (receipt credentials: issuance on the payment side,
   anonymous redemption on the account side), with a simpler, standardised primitive.

2. **The payment side and the account side then share no identifier.**
   - **Billing** (payment side) verifies a purchase with Apple, Google or the EU provider, keeps
     the subscription's state under a keyed hash of the provider's identifier (paid-through
     date, revoked, tokens issued this month), and issues at most N blinded tokens per
     subscription per month (Plus 2: one and a spare for a reinstall; Family 7: six seats and a
     spare). It never sees an account.
   - **`api`** (account side) redeems a token on a signed request: checks the PRF under the
     month's key, burns the nonce (nullifier), and stores **the level and expiry day against
     the account**, as the prompt asks. It never sees a payment.
   - Monthly tokens whatever the billing period: a yearly subscriber's app fetches next month's
     token in the last days of each month. A refund or chargeback stops new tokens, so it costs
     at most the rest of the month; nothing on the account side needs to know.
   - Apple's `appAccountToken` and Google's `obfuscatedExternalAccountId` are **never set**: the
     stores themselves never get a Songbird account ID either.
   - What stays linkable: **timing and the IP address** of an issuance followed by a redemption
     (the servers never log IPs, invariant 6; the app redeems renewals at a random time within
     a day, and a first purchase at once because the user is waiting); and a server that served
     **one user its own key** could tag them. Keys are derived per (level, month) and published
     at an unauthenticated endpoint; the app refuses a key that differs from the one fetched on
     another connection. Publishing the key list in the key transparency log is proposed for
     Prompt 12. Both are stated in the threat model.

3. **Payment secrets and records belong in a process of their own.** The Apple In-App Purchase
   key, the Google service account, the EU provider's API key, the token-issuing secret and the
   billing database's credentials should not sit in `api`, the largest attack surface.
   Recommended: a small **`services/billing`** (the `service` crate's bootstrap, hyper, rustls)
   with its own SurrealDB **database and credentials** (as push got its own database, D-0095)
   and no access to the registry. `api` holds only the redemption keys (derived from the same
   token secret, per month). The provider webhooks (App Store Server Notifications V2, Google
   real-time developer notifications through Pub/Sub push, the EU provider's webhook) land on
   billing, never on `api`.

4. **Families can be unlinked too.** With seat tokens, the server never needs to know who is in
   whose family. The owner's app fetches the Family subscription's tokens each month, redeems
   one, and hands one to each member through a **family mailbox**: a random family ID with up
   to five slots, each holding the month's token sealed to a key that only the member's invite
   link carries. Members fetch their slot without an account (keyed by a random slot ID and
   the hash of a slot secret) and redeem the token on their own account. The server sees that a
   family with *k* slots exists and when slots are fetched; never an account. **Removal**
   empties a slot at once (no further tokens); the member keeps Plus to the end of the month
   they already redeemed. **Leaving** deletes one's own slot. Member accounts get the Plus level
   (the server cannot tell a Family member from a Plus subscriber). Backup space is therefore
   per member, not a shared pool, which an unlinked server cannot enforce.

5. **Entitlements change numbers, never safety.** Never gated, on any plan: encryption, safety
   numbers, verification, disappearing messages, app lock, the PIN and passkeys, the proxy,
   backups themselves (and restore, always, whatever the vault's size), every privacy setting,
   calls, groups, reporting, blocking, GDPR export and deletion. A **downgrade never deletes
   anything**: over a limit means nothing new is added (no new linked device, vault writes
   refused but reads and restores always allowed, no new pack) until the user is back under it.
   An entitlement **expires on its own** (each entry carries its last day; every reader compares
   it with the clock), so a stale snapshot or a dead worker can never extend it.

6. **One snapshot, small, holding only exceptions.** `crates/entitlements` defines the plan
   catalogue (limits and flags per level, from configuration, with a catalogue version) and the
   per-account snapshot: only accounts that differ from the default (Free, older than 30 days,
   in good standing), so it stays small. Entries: level and last day; young accounts and their
   creation day; standing (limited or suspended, with its last day). Loaded with `arc-swap`,
   reloaded when an `entver` version row changes (as `LiveDirectory`). Read by `api` (limits,
   standing), `delivery` (standing, young-account request budgets), `calls` (standing) and
   `worker` (expiry sweep, risk signals). A failed reload keeps the last snapshot; entries still
   expire by date.

7. **The server cannot count reports per account today, and a risk signal needs it.** Reports
   are sealed to the offline moderation key (D-0063). Counting them per reported account adds
   one thing to THREAT_MODEL §1: a keyed counter (HMAC of the reported account) of **verified
   reports in the last 30 days**. Franking makes brigading hard already (a report needs a real
   message from the target to the reporter, and one message counts once however many people
   report it); counting **distinct reported messages** keeps it so.

8. **Automatic actions only slow outreach; only people suspend.** Signals (account age,
   request volume and the share of requests never answered, blocks received per request sent,
   distinct reported messages) move an account to **limited**: tighter request budgets, no new
   group invite links, a proof of work on each request. It lifts by itself after a quiet week.
   **Suspension** is a moderator's decision, from franked reports, in the review tool, with a
   reason category, an end date or none, and an audit entry. A suspended account cannot send
   or start calls, but can still receive, export its data, delete itself and **appeal** through
   the support channel. A brigade can at most slow its target's new conversations for a week,
   never cut off their contacts.

9. **Escalating proof of work keys on what registration already sees.** The challenge's
   difficulty rises with the requesting range's and the deployment's recent registrations
   (GCRA tokens already counted), and resets as they calm. Bounds are fixed in `crates/pow`, so
   a phone never meets more than the ceiling (measured: the default must stay under 2 s on a
   mid-range phone and the ceiling under about 30 s).

10. **Legal requests can only produce what §1 lists.** `songbird-admin legal export` reuses the
    GDPR export's queries for one account, adds nothing, needs a case reference and
    `--confirm`, and writes the audit log. A register of **counts only** (by half-year,
    requesting country, type, outcome) feeds `songbird-admin transparency`, which writes the
    twice-yearly report. Case files stay offline with counsel, not in the registry.

11. **Support can be useful without being a data sink.** A ticket is sealed to the support key
    (X25519, as reports), carries a reply key the app made for it, and is fetched and answered
    by a random ticket ID with a bearer secret. The account ID is attached only when the user
    chooses ("about my account": appeals, billing), and priority only follows from an attached
    account with Plus. Logs are scrubbed on the device (the existing scrubber), shown to the
    user before sending, attached only with their explicit consent, and **deleted when the
    ticket closes**; an unanswered ticket goes after 90 days.

12. **Invite a friend needs no server change.** The link carries, in its fragment, the
    registration code (in invite-only mode) and the inviter's contact card (account ID, profile
    key, identity key's fingerprint). After sign-up the friend's app opens a chat with the
    inviter from the fragment: no lookup the server could tie to the inviter beyond an ordinary
    first message. "Invites used" is counted by the inviter's own app, asking for the status of
    its own codes by hash; the server keeps no per-inviter counter (D-0038).

13. **The vault can be unlinked from the account the same way** (D-0119 §3). Writes today need
    the owning account's primary. With tokens: the account fetches **daily vault tokens** of
    its level (at most a few a day) and **vault creation tokens** (two per 180 days); the vault
    accepts a write session for a day from a token, never an account. The server then knows a
    vault's size and generation, but not whose it is. What changes: deleting the account can no
    longer delete the vault (the app deletes it first, as it holds the access secret); a vault
    nobody writes for **12 months** is deleted (the default inactivity period, D-0047); the
    GDPR export no longer mentions it. Worst case, one free account keeps about 5 vaults alive
    (25 GiB), bounded by the creation tokens.

14. **Real sandboxes need the owner's accounts.** App Store sandbox needs the products in App
    Store Connect and an In-App Purchase key; Google Play needs the app on a testing track,
    licence testers, a service account linked in the Play Console and a Pub/Sub topic; the EU
    provider needs a test-mode account. Until then every verifier is tested against emulators
    written from the providers' documentation, with test certificate chains, replayed and
    reordered notifications; the gate's sandbox item waits for the owner's credentials, as
    Prompt 10's OAuth apps did. StoreKit 2 and Play Billing in the app need the native hosts,
    deferred until the whole app is built (as push, P08).

## Plans and limits (question 3)

Recommended numbers; prices are the app's mock until the owner decides.

| | Free | Plus | Family |
| --- | --- | --- | --- |
| Price | — | €2.99 a month, €29.99 a year | €4.99 a month, €49.99 a year |
| People | 1 | 1 | the owner and up to 5 members, each with Plus |
| Linked devices (besides the primary) | 5 | 10 | 10 each |
| Largest file | 2 GiB | 4 GiB (if §7.1's format allows; checked in M1) | 4 GiB |
| Uploads per day | 10 GiB | 50 GiB | 50 GiB each |
| Songbird backup space | 5 GiB, 100,000 chunks | 50 GiB, 1,000,000 chunks | 50 GiB each |
| New packs per month | 5 | 50 | 50 each |
| App icons, chat themes | — | ✓ (checked by the client: settings are encrypted) | ✓ |
| Priority support | — | ✓ | ✓ |
| Everything in finding 5 | ✓ | ✓ | ✓ |

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **Entitlements:** `crates/entitlements` (catalogue, levels, flags, the exception snapshot, expiry by date, `#![forbid(unsafe_code)]`); the `ent` table and the `entver` version row; enforcement in `api` (device limit, vault quota and count, file size, daily upload bytes, packs per month), with downgrade rules (finding 5); the snapshot followed by `api`, `delivery`, `calls` and `worker`; `GET /v1/entitlements` (signed: level, last day, limits, flags, catalogue version); `songbird-admin plans grant` (staff, testers, goodwill; audited); the Teams tables reserved (`org`, `org_admin`, `org_member`, `org_device`, empty, with their threat-model row); PROTOCOL §12.1–12.3. | Tests per service: each limit on Free and Plus, **expiry** (an entry past its day reads as Free with no sweep), **downgrade** (over the limit: nothing deleted, nothing new added, restores still work), a stale snapshot never extends an entitlement; the snapshot's reload on a version change; property tests of the catalogue's rules (a higher level never has a lower limit; security flags never appear in the catalogue). |
| **M2** | **Anonymous tokens:** `crates/tokens`: RFC 9497 VOPRF (ristretto255-SHA512) with batched DLEQ proofs, per-(level, month) key derivation, token encoding (RFC 9578's token type 0x0001 shape, our own domain); `POST /v1/entitlements/redeem` (signed; nullifier burnt in SurrealDB until the month's end plus a margin); the published key list; the app-side client in `crates/client`. PROTOCOL §12.4. | The RFC's vectors byte for byte; our own vectors with fixed randomness and an independent re-derivation in Python (as `transfer_check.py`); a token redeems once, never under another month's or level's key; issuance and redemption records cannot be joined (a test with every table dumped); a server that evaluates under another key is caught by the DLEQ proof; fuzz targets for every decoder; issuance and redemption cost on the target hardware. |
| **M3** | **Billing:** `services/billing` (own database and credentials, no registry access); App Store: signed transactions and notifications (JWS, `x5c` chain to the pinned Apple Root CA G3 with `rustls-webpki`, ES256), the App Store Server API (ES256 JWT) for current status; Google Play: `subscriptionsv2.get`, acknowledgement, real-time notifications by Pub/Sub push (Google's OIDC token checked); the EU provider: checkout, subscription, webhook (fetch by ID), cancel; subscription state under keyed provider IDs; monthly token caps; `POST /v1/billing/tokens` (no account). Emulators of all three providers from their documentation; compose and CI wiring; a runbook. | Each verifier against its emulator: valid, expired, refunded, revoked, upgraded, family-shared, grace period; **replayed, duplicated and reordered notifications** change nothing twice; forged chains, wrong bundle or package names, sandbox receipts in production all refused; token caps per subscription and month; billing's tables hold no account ID (a schema test). **Sandbox runs on App Store, Google Play and the EU provider's test mode once the owner's credentials exist** (question 11). |
| **M4** | **Family plans** (question 5): the family mailbox (`fam`, `fam_slot`: random IDs, sealed slot boxes, the management token's hash), invite links with the slot secret, removal and leaving; the owner's monthly seat run in `crates/client`. **The vault on tokens** (question 6): daily vault tokens and creation tokens, write sessions, the 12-month expiry in the worker, the app deleting its vault before deleting the account, `vault_owner` dropped by migration. PROTOCOL §11.8 and §12.5. | Live: an owner and five members each reach Plus; removal stops the next month's token and the member falls back to Free after their month; leaving; a sixth member is refused; the server's tables name no member account (dump test). The vault suite of Prompt 10 passes unchanged on token sessions; no table links a vault to an account; a vault untouched for 12 months goes; an account's creation tokens bound its vaults. |
| **M5** | **Abuse controls:** escalating proof of work (finding 9); young-account request budgets in `delivery`'s gate; the verified-report counter (finding 7); risk signals and their thresholds (`docs/RUNBOOKS/abuse.md`); the `limited` and `suspended` standings in the snapshot, enforced in `api`, `delivery` and `calls`; `songbird-admin moderation` (queue, open, decide: dismiss, limit, suspend, lift; audited; a report deleted on decision); appeals as support tickets of kind "appeal". PROTOCOL §12.6. | **Abuse simulations** (live, compose stack): a registration flood from many ranges raises the work and caps accounts per hour while a normal sign-up keeps its time; request spam from fresh accounts is throttled and then limited while a normal new user's first ten conversations go through; a report brigade of 200 accounts against one person changes nothing without that person's messages, and with one message counts once; a suspended account cannot send or call but receives, exports, deletes and appeals; every threshold has a test at, below and above it. |
| **M6** | **Legal, transparency, support, invites:** `songbird-admin legal export` and `register`, `songbird-admin transparency`; `docs/RUNBOOKS/legal-requests.md`; the support channel (`POST /v1/support/tickets`, fetch and reply by ticket ID and secret, sealed to the support key, optional account, logs only with consent, deletion at close, 90 days at most) and `songbird-admin support`; `POST /v1/invites/status` (codes by hash, for the inviter's own counter); the invite-link format. | The legal export of a test account equals its GDPR export's server-held part, never more (a test lists §1's rows); the transparency report from a register; a ticket opens only with the support key; logs absent without consent; a closed ticket leaves no row and no object; an invite link opens a chat with the inviter after sign-up with no server request naming the inviter. |
| **M7** | **The app (`apps/ui`):** the Subscription page from the real entitlement and catalogue; desktop checkout with the EU provider in the browser, the subscriber secret kept in app storage, token fetch and redemption (renewals at a random time); Family: invite link, members, remove, leave, the monthly seat run; limit moments made real (file too large, device limit, backup space, packs); the "limited" and "suspended" screens with appeal; Help: contact form with the log preview and consent; Invite a friend with the real link. StoreKit 2 and Play Billing: deferred to the native hosts (finding 14). | Headless NSH tests of every flow; a live desktop instance buys Plus in the provider's test mode (or its emulator until the owner's account exists), restarts, keeps Plus, downgrades on expiry; a family of two instances; screenshots of every changed screen, light and dark. |
| **M8** | **The gate:** the security review of the whole diff; fixes; `P11-gate.md`. | The prompt's gate item by item: entitlement checks in every service's tests, purchase verification on sandboxes and replayed notifications, the abuse simulations. |

Order: M1 first. M2 needs nothing but the workspace. M3 needs M2. M4 needs M1 to M3. M5 needs
M1. M6 needs M5 for appeals. M7 needs M1 to M6. M8 needs everything. M2 and M5 could run in
parallel sessions; recommended sequentially (one PR, shared files in `api` and the registry).

## Threat-model rows this plan will propose

- **§1 (new rows):** per account, its level and last day (`ent`) and where it came from
  (token, grant or, later, organisation); redeemed token nullifiers (hash of the nonce, until
  the month's end and a margin); in billing's own database, per subscription: a keyed hash of
  the provider's identifier, the provider, the level, the paid-through day, revoked, tokens
  issued this month; the provider's identifiers themselves (Apple's original transaction ID,
  Google's purchase token, the EU provider's customer and subscription IDs) in billing only;
  VAT evidence for direct sales (country, amount, date; ten years under EU rules, to confirm
  with counsel); family mailboxes (random IDs, slot count, sealed boxes, fetch times, never an
  account); per account, its standing (limited or suspended, reason category, last day) and,
  while young, its creation day in the snapshot; keyed counters of verified reports per
  reported account (30 days); support tickets (sealed, optional account, deleted at close);
  the legal register (counts only); the reserved Teams tables (empty). If question 6 is
  approved, the vault rows lose their owner and gain a last-write day (12 months).
- **§3.28 (new STRIDE table):** forged or replayed receipts and notifications; token double
  spending; tagging users with their own keys; timing correlation of issuance and redemption;
  refund and chargeback abuse; family seat resale; a billing database breach; a stale or
  unreachable snapshot; registration floods; request spam; report brigading; false suspensions
  and their appeal; a moderator insider; support logs leaking; over-disclosure in legal
  requests; invite links leaking the inviter.
- **§4:** the plan row filled in (level and last day, set only by redemption or a grant; never
  by a client's claim); standing.
- **§6:** timing correlation and key consistency (finding 2); app stores knowing that an Apple
  or Google account pays Songbird (outside our control); VAT records; removal from a family
  taking effect at the month's end.

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 to 10.

1. **Scope.** Recommended: the milestones above, including a separate `billing` service
   (finding 3). The alternative: billing as a module of `api` with its own database credentials
   (fewer moving parts, payment secrets in `api`'s process).
2. **Payment linkage.** Recommended: anonymous tokens (Privacy Pass on the RFC 9497 VOPRF, our
   own implementation checked against the RFC's vectors); billing and accounts share no
   identifier; monthly tokens; refunds cost at most the month (findings 1, 2). The evaluated
   alternatives: porting libsignal's `zkcredential` (the same unlinkability for payments, much
   more cryptographic code to own, needed only for hidden attributes); plain linkage (the
   account ID next to the provider's IDs in a stricter store), simpler but a breach or a
   subpoena of billing names who pays.
3. **Plans and limits.** Recommended: the table above. Or name other numbers or prices.
4. **The EU payment provider for desktop and web.** Recommended: **Mollie** (Amsterdam; EU data
   residency; cards, SEPA Direct Debit, iDEAL, Bancontact; recurring payments by mandate;
   webhooks that carry only an ID, fetched back over the API). Songbird is then the merchant of
   record and files EU VAT through OSS. Alternatives: Paddle (merchant of record, handles VAT;
   a UK company); Stripe (Stripe Payments Europe, Ireland; a US parent under the CLOUD Act);
   Adyen (Dutch, enterprise contracts). Vouchers payable in cash (as Mullvad and Proton accept)
   fit the token model later.
5. **Family.** Recommended: unlinked seats through the family mailbox; removal takes effect at
   the end of the month the member already holds; backup space per member (finding 4). The
   alternative: a linked family table (instant removal, a shared backup pool, and the server
   knows who is in whose family).
6. **Unlink the vault from the account** (D-0119 §3). Recommended: yes, on the same tokens, with
   the 12-month expiry (finding 13). The alternative: keep it linked and stated, as now.
7. **Abuse.** Recommended: automatic actions only limit outreach and lift after a quiet week;
   suspension only by a moderator; the counter of verified reports per reported account added
   to §1; thresholds in the runbook, tuned in M5 by the simulations (findings 7 to 9).
8. **Suspension.** Recommended: a suspended account receives, exports, deletes and appeals, but
   cannot send or call. The stricter alternative: refused at sign-in except for export,
   deletion and appeal.
9. **Support.** Recommended: sealed tickets, the account only when the user attaches it, logs
   only with consent and deleted at close, unanswered tickets gone after 90 days (finding 11).
10. **Legal requests.** Recommended: the tool, the counts-only register and a transparency
    report every January and July; case files offline with counsel (finding 10).
11. **The owner's accounts and credentials** (needed for the gate's sandbox item, not to
    start): App Store Connect products (Plus and Family, monthly and yearly, one subscription
    group) and an In-App Purchase key; the app on a Google Play testing track with licence
    testers, a Play service account and a Pub/Sub topic; a test-mode account at the chosen EU
    provider; counsel on VAT records and the legal-request process.
12. **Teams.** Recommended: schema only now (four empty tables, their threat-model row, and
    "organisation" as a future source of entitlements), as the prompt says.
13. **The app.** Recommended: M7 as written; StoreKit 2 and Play Billing with the native hosts
    after the whole app is built (as push).
14. **Agent decisions, recorded unless you object:**
    - our own RFC 9497 VOPRF on `curve25519-dalek` 5 and aws-lc-rs (no new dependency);
    - one key per (level, month), derived from a secret shared by billing and `api` only;
    - token caps: Plus 2 a month, Family 7 a month;
    - Apple's `appAccountToken` and Google's `obfuscatedExternalAccountId` never set;
    - JWS chains checked with `rustls-webpki` (in the tree) against the pinned Apple Root CA G3;
      Google's OIDC and service-account JWTs with aws-lc-rs;
    - the snapshot holds only exceptions; entitlements expire by date at every reader;
    - downgrades never delete; restores always work;
    - escalating proof of work within `crates/pow`'s fixed bounds;
    - young accounts: the first 30 days;
    - one branch and one PR for every milestone.
