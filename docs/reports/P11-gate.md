# P11 gate — Plans, payments and abuse controls

- Date: 2026-11-19
- Plan: [P11-plan.md](P11-plan.md) (D-0126, approved by the owner on 2026-11-19, "Approve all")
- Milestones:
  - [M1](P11-M1.md): entitlements. One catalogue, one snapshot, every limit by plan (D-0127).
  - [M2](P11-M2.md): anonymous plan tokens on RFC 9497's POPRF (D-0128).
  - [M3](P11-M3.md): billing as a service of its own, with Apple, Google and Mollie verified server-side (D-0129).
  - [M4](P11-M4.md): Family seats without a family graph, and the vault unlinked from the account (D-0130).
  - [M5](P11-M5.md): abuse controls without content (D-0131).
  - [M6](P11-M6.md): support, legal requests and invites without a data sink (D-0132).
  - [M7](P11-M7.md): the app on real plans (D-0133).
- The security review's fixes: D-0134.
- Branch: `claude/p11-plans-abuse-e05ed3`, rebased onto `main` after Prompt 10 merged.
- Status: **waiting for the owner**. The threat-model rows marked Prompt 11 (THREAT_MODEL §1, §3.27, §3.28, §4 and §6) await approval.

## The gate, item by item

| Gate item | Result | Evidence |
| --- | --- | --- |
| Entitlement checks covered in every service's tests, including expiry and downgrade | **Pass** (see the notes after the table) | Expiry is checked by date at every reader, and a stale snapshot never extends an entitlement (`crates/entitlements`). In `api`:<br>• devices (`the_plan_sets_the_device_limit_and_a_downgrade_keeps_devices`);<br>• file size, daily bytes and packs (`the_plan_sets_file_size_daily_bytes_and_packs`);<br>• the vault quota after a downgrade (`gate_p10::the_quota_is_the_owners_plan_and_a_downgrade_keeps_the_backup`).<br>Redemption: a token redeems once, for its month only (`plans_live`).<br>`delivery` and the send path enforce standings (`gate_p11`). The worker's sweeps are covered by the live registry tests.<br>`calls` and `push` hold no per-account limit: `api` enforces the call endpoints (`gate_p11::a_suspended_account…`). |
| Purchase verification tested against sandbox environments and replayed notifications | **Pass against emulators; the real sandboxes wait for the owner** | Apple: the `x5c` chain to the pinned root, the marker OIDs, environment and bundle, notifications V2 and the Server API. Google: OIDC push tokens and the Play API. Mollie: checkout, webhooks fetched back, cancel.<br>All of these are tested against emulators written from the providers' documentation (`billing_live`, 8 tests; unit tests, 13).<br>Replayed and reordered notifications are ignored. Each Mollie payment counts once, however often its webhook is replayed (added by the review). Caps hold under concurrency.<br>The App Store sandbox, Play licence testers and Mollie test mode need the owner's accounts (an open owner item). |
| Abuse simulations: registration floods, request spam and report brigading are controlled, and normal users are not affected | **Pass** | Registration flood: the proof of work grows for the flooding range and barely for others (`registration_live::a_registration_flood…`).<br>Request spam: a new account is slowed, then limited by the blocks of people it messaged. Contacts are unaffected, a brigade of strangers changes nothing for an established user, and re-blocks count once (`gate_p11::request_spam…`).<br>Report brigade: 200 accounts without messages from the target change nothing. Five distinct recipients are needed (`gate_p11::a_report_brigade…`).<br>Suspension: no sending, while receiving, export, deletion and appeal still work (`gate_p11::a_suspended_account…`).<br>Prompt 4's gate is unchanged (`gate_p04`, 5 of 5). |
| Also: help and feedback (user-initiated, logs redacted on device, only with consent, deleted at close) | **Pass** | Tickets are sealed to the support key and deleted with every message at close, or after 90 days (`support_live`, `plans_live::support_tickets…`). The app's form offers "About my account" and attaches the previewed, scrubbed log only after consent (`preview/Screens_plans_p11.test.tsx`, `apps/ui` unit tests). |
| Also: invite a friend (a personal link opens a chat with the inviter after sign-up; no contact upload; only a counter) | **Pass for the link and the counter; the chat opening waits for app-core** | The link carries the inviter's card only in its fragment (`invite_link` tests, fuzzed). The inviter counts its own codes by hash (`plans_live::an_inviter_sees_only…`). Opening the chat after sign-up needs app-core's first message (A2), which the app does not have yet. |

Notes on the first row:

- `billing` has no plan limits (it issues tokens); its caps are tested.
- The app (`apps/ui`) reads the entitlement; its tests cover the screens, not the limits.

## The security review

An independent agent reviewed the whole Prompt 11 diff, read-only. It was given the code, not my conclusions. It reported 13 findings. Each is listed below with what was done (D-0134).

| # | Finding | Done |
| --- | --- | --- |
| 1 | A replayed Mollie webhook extended a paid plan without end | **Fixed:** each payment counts once, its period runs from `paidAt`, and only the first payment turns renewal on. Test: `mollie_checkout_webhooks_and_cancel`. |
| 2 | A checkout cleared a revocation | **Fixed:** a revoked row takes no checkout (409 `revoked`), and the app starts over with a new secret. Same test. |
| 3 | Stored timestamps could join issuance to redemption | **Fixed for storage:** whole days only on both sides; API answers keep the row's stamp; a transaction the app presents counts by its day. Test: `billing_keeps_no_account…` checks the times are days.<br>Kept tokens are redeemed at a random moment.<br>A first purchase is still redeemed at once (stated). |
| 4 | Vault day passes fetched next to the vault write | **Fixed:** passes are fetched up to a week ahead at start-up.<br>A first backup, and a vault's creation, still fetch at once (stated). |
| 5 | Token-key pinning was trust-on-first-use and could be bypassed with a new ID | **Fixed:** the app trusts only keys shipped with the build. A development build pins the first key and refuses any other; a release build without keys refuses plans. Backups share the pin. |
| 6 | One user could limit another (one reporter; block, unblock, block) | **Fixed:** a reporter counts once per sender, and a block consumes the request mark. Test: `gate_p11` (re-blocks). |
| 7 | The support key came unpinned from the server | **Fixed:** shipped, or pinned in development builds. |
| 8 | Unbudgeted provider calls from unauthenticated endpoints | **Fixed for Google** (key refetch at most once a minute). **Mollie webhooks: not budgeted.** A range budget could refuse Mollie itself, so this is recorded as an open risk with the runbook's mitigation (the edge's rate limit). |
| 9 | Range budget resettable; IPv6 range wrong | **Fixed:** the whole IPv6 /48, and only idle ranges are evicted. Test: `ranges_have_a_budget`. |
| 10 | `/v1/invites/status` unbudgeted | **Fixed:** 60 an hour per account. Codes stay unbound to their creator, since knowing the code is needed to ask (D-0038). |
| 11 | Staff `support open` not audited | **Fixed:** `open` and `reply` need `--confirm` and are audit-logged; tickets are looked up by ID. |
| 12 | The client took any 409 as redeemed | **Fixed:** only `spent`. |
| 13 | App secrets in plain app storage | **Not changed:** this is the development stand-in for the Keychain / Keystore, like the identity seed; it moves with them (A0). |

## Tests and checks run

Run on an Apple M5 Pro with macOS 27.2.1, the compose stores under podman, and no Iggy locally.

- `cargo xtask ci fast`, after the review's fixes and the rebase onto `main`: **pass** (952 tests).
- Live suites, before the review's fixes, run in full (`-j 1`; e2e `-j 2`):
  - Workspace: 861 passed, 7 failed. All 7 failures are known and not caused by Prompt 11:
    - **The macOS loopback:** `api_live::attachments_upload_exactly_…` and `media_live::fetches_are_confirmed_…` need the 127.0.0.2 source address.
    - **Concurrency flakes:** `push::outage_live` (4) and `surreal::live` (1) fail when run in parallel with the others; run alone, they pass (4 of 4 and 2 of 2). Neither file changed in Prompt 11.
  - e2e: 82 passed, 1 failed (`gate_p06::an_encrypted_file_…`, the same macOS loopback issue).
- Live suites, after the review's fixes, for everything those fixes touched:
  - billing: 21 of 21;
  - accounts `support_live` and `entitlements_live`: 6 of 6;
  - api `plans_live`: 6 of 6;
  - e2e `gate_p04`, `gate_p10` and `gate_p11`: 16 of 16.
- `apps/ui`: 205 unit tests pass, and the headless `Screens_plans_p11.test.tsx` passes. It covers desktop and phone, light and dark; the 20 screenshots were checked by eye.
- Fuzz: `tokens`, `billing_inputs` (769,377 runs) and `invite_link` (23 million runs). No crash.
- A Python re-derivation of the token vectors runs in CI.

## For the owner

1. **Approve the gate and the threat-model rows** (§1, §3.27, §3.28, §4, §6).
2. **Provider accounts:** App Store Connect (sandbox), Play Console (licence testers) and Mollie (test mode). These are needed to run the real sandboxes.
3. **Counsel:** VAT records, and the legal-request process (`docs/RUNBOOKS/legal-requests.md`), before the first real request.
4. **Before release:**
   - Check the pinned Apple Root CA - G3 SHA-256 against apple.com (`APPLE_ROOT_G3_SHA256`).
   - Ship the deployment's token and support public keys in the app (`SHIPPED_TOKEN_KEYS`, `SHIPPED_SUPPORT_KEY`).
5. **Deferred, as planned:** StoreKit 2 and Play Billing (native hosts), and the chat that opens after an invite (app-core).
