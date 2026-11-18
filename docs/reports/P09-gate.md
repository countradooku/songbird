# P09 gate — Settings, presence, statuses and Yahoo-style features

- Date: 2026-11-18
- Plan: [P09-plan.md](P09-plan.md) (D-0101, approved by the owner on 2026-11-18, "Approve all")
- Milestones:
  - [M1](P09-M1.md) the record store (D-0102);
  - [M2](P09-M2.md) discoverability, group adds and profiles (D-0103);
  - [M3](P09-M3.md) presence and nudges (D-0104);
  - [M4](P09-M4.md) parental supervision (D-0105);
  - [M5](P09-M5.md) the app's settings, app lock and proxy (D-0106);
  - [M6](P09-M6.md) the app's presence, profiles, nudges, contacts, device and parental linking
    (D-0107).
- The security review's fixes: D-0108.
- The camera module (PR #68, D-0110 to D-0118) is merged into this branch at the owner's word
  ("Merge #68 here, resume").
- Branch `claude/p09-settings-presence-44c936`, draft PR songbirdchat/songbird#67.
- Status: **awaiting the owner's approval.** The threat-model rows marked "awaiting the owner"
  (THREAT_MODEL §1, §3.26, §4, §5) go with it.

## The gate, item by item

| Gate item | Result | Evidence |
| --- | --- | --- |
| Convergence property tests pass | **Pass** | `crates/sync/tests/convergence.rs`: proptest `devices_converge_on_the_newest_edit_of_each_key` (2–4 devices, skewed clocks, offline edits, random sync order); `a_device_with_a_clock_days_ahead_never_pins_a_key`. Live: two devices through the real store; eight concurrent writers lose nothing (`storage_live`). The app: `two_devices_converge_through_the_store`, `saved_contacts_converge_between_devices` |
| Presence reaches only allowed contacts; invisible sends nothing | **Pass** | `gate_p09::presence_reaches_only_contacts_and_invisible_sends_nothing`: a batch without a stranger's access key is refused whole and reaches nobody; with both keys both are reached. The answer is the same 204 whether a device is offline, a key is wrong or a device is unknown. Invisible: the rules never build a batch and the server's count does not move. Proptest `invisible_never_sends_anything`; the app's `invisible_sends_nothing_ever` |
| Nudge rate limits tested | **Pass** | `gate_p09::nudges_are_held_to_their_budgets_and_blocks_drop_them`: the pair burst (3), another sender's own budget, the sender's budget across recipients (5), a block drops them. A nudge sent as an ordinary ephemeral event never arrives as attention (D-0108) |
| The server's view of every setting matches the threat model | **Pass** | THREAT_MODEL §1 (what the server holds) and §4 (server-enforced settings, who changes each, where it is enforced), checked against the code by the security review. `a_hidden_account_is_found_only_through_its_own_link`, `group_adds_from_contacts_only_need_the_access_key`, `a_parents_policy_locks_rules_and_only_the_parent_or_the_date_ends_it` (the `superv` row's fields), `device_only_settings_are_never_records` |

The plan's scope inventory goes further than the prompt: every row of the app's Settings
screens. It is covered milestone by milestone in M5 and M6. Rows owned by later prompts are left
for them: backups (Prompt 10), the plan (Prompt 11) and WhatsApp (Prompt 14).

## Tests and checks run (Apple M5 Pro, macOS 27.2.1; compose stores under podman; no Iggy locally)

- `cargo xtask ci fast`: **pass**.
  - workflow policy, push-credential scope, rustfmt, clippy (pedantic, `-D warnings`);
  - nextest **815 of 815** (8 skipped: live tests without their stores);
  - doctests, rustdoc (`-D warnings`), cargo deny, audit and vet;
  - smoke (every service starts, serves health and metrics, drains on SIGTERM).
- The live suites, one heavy job at a time (`-j 1`):
  - songbird-e2e gates P03, P04, P05, P09, invariants and send_api: 50 of 51, then the P09 gate
    again after its count was fixed (below): **4 of 4**, so **51 of 51**;
  - songbird-accounts and songbird-worker: **44 of 44**, run again after the review's fixes;
  - songbird-api: **74 of 76**. The two failures are this Mac's loopback, not Prompt 9:
    - `api_live::attachments_upload_exactly_and_go_after_the_last_fetch` and
      `media_live::fetches_are_confirmed_and_the_last_one_deletes` send from 127.0.0.2;
    - macOS's `lo0` has only 127.0.0.1, so the connection never opens (status 0);
    - on Linux CI the whole of 127.0.0.0/8 answers;
    - Prompt 9 changed neither test (one config field, `storage: None`, in `api_live`'s stack).
- The app (`apps/ui`): **199 of 199**, among them headless tests on the real engine:
  - the lock;
  - settings and contacts surviving a restart;
  - linking by camera only from a scanned code.
- Fuzz target `storage` builds; it runs 10 minutes in the nightly `ci full`, not run locally.

Fixed while running them:
- One rustdoc link in `crates/sync`.
- One clippy index in the router.
- The unsigned policy endpoint borrowed the device-linking settings for its IP budget, so it
  answered 503 where those are off. It now has its own budget with the profiles service.
- The presence gate's count for an allowed batch that reached nobody.

## Security review

An independent read-only review of the whole diff was done by a separate agent, given the code and
the specifications, not the reports. It found 1 high, 4 medium, 7 low and 4 informational issues.
Each was checked in the code and fixed, except I3, which is recorded (D-0108).

| Finding | Fix | Test or check |
| --- | --- | --- |
| High: a supervised child could turn "anyone may send" on and be reached without a request | The policy closes the account; opening it answers 403 `supervised` | the parental gate |
| Medium: later policies could push the unlink date out without limit | The date only moves earlier (409 `date`) | the parental gate |
| Medium: `PUT /v1/supervision` told who is a supervised child | One answer (403 `account`) for another account's policy | the parental gate |
| Medium: nudges sent as ordinary ephemerals escaped budgets and blocks | Lane classes marked by the server; attention in its own frame `0x84` | the nudge gate; frame proptests |
| Medium: linking a second child wiped the first child's key | A link in force is never replaced | `start_link`; the screen says to unlink first |
| Low: later policies named the parent to the server | `PUT /v1/supervision/update`, unsigned, per-IP budget | the parental gate |
| Low: the order of the group-add checks revealed supervision | Contacts check before approvals | the P05 gate |
| Low: the six digits could be ground by someone relaying the codes | Commit then reveal; install only after the digits are compared | `a_child_accepts_only_the_first_policy_meant_for_it`; `the_commitment_binds_the_key_and_the_secret` |
| Low: the lock's wait could be skipped by moving the clock | Time left counted on the monotonic clock; "lock after" checks both clocks | `closing_the_app_does_not_reset_the_wait` |
| Low: storage budgets counted requests, not records | A budget per record written | `ci fast`; config validation |
| Low: client rules showed how many were on | Padded to 64 bytes | `client_rules_open_only_for_their_child_and_version` |
| Low: linking failed on accounts with a PIN | The new device asks for the PIN | built; not run against a server with a PIN (see below) |
| Info: a device that never scanned the parent's code showed rules unchecked | It says it can't check them | — |
| Info: an age giving no end date started supervision ending at once | Linking stops | — |
| Info: presence answered 401 or 204 by which devices exist | Always 204 | the presence gate |
| Info: secrets in plain app storage | Recorded: the A0 mock, keystore with the host projects | — |

## Not verified

- **Between two real phones:**
  - device linking (the new device and the main phone, the PIN step included);
  - parental linking (parent and child, three codes and the six digits).
  
  The flows are built, and their checks are unit tested against what each phone scans. They have
  never run end to end on two registered devices with cameras. The camera's own device checks are
  open in `CAM-gate.md` (a physical iPhone, the Android scan).
- **Presence and nudges from the app** send nothing yet. The payloads must be sealed for each
  contact's device, which needs app-core's sessions (A2). The server side and the rules are tested.
- **A removed device and the storage key:** while other devices stay linked, a removed device keeps
  the key until A2 can send a new one end to end. The key is rotated when the main phone is left
  alone (D-0106, PROTOCOL §10.1).
- **The lock's biometrics** (Face ID, fingerprints) come with the native host projects.
- **Screens on a running app:** M5 and M6 were checked headless and by reading against the tokens.
  The motion inventory lines (MOTION_settings.md) were not frame-captured.

## Threat model

Awaiting the owner:
- THREAT_MODEL §1: the rows for the record store, settings, profiles, presence and supervision.
- §3.26: every row, including the M5 and M6 rows and those D-0108 changed.
- §4: the completed table of server-enforced settings.
- §5: the GDPR Article 8 table. The range, the default of 16 and seven countries were confirmed on
  2026-11-18; the rest must be confirmed with counsel before release.

## For the owner

1. Approve the gate, with the threat-model rows above.
2. Device and parental linking need two real phones: one session with a physical iPhone and an
   Android phone, after the camera's own device checks.
3. Nothing is merged. PR #67 carries the camera module from PR #68. Merging #68 first keeps #67's
   diff to Prompt 9's own work.
