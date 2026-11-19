# Runbook: abuse controls, moderation and appeals

Owner: trust and safety on-call. Prompt 11, M5 (D-0126 §7–§8, D-0131). Protocol:
`docs/PROTOCOL.md` §14.7. **Nothing here reads content**: signals are metadata, and the only
content a moderator ever sees is what a recipient chose to report (franked, sealed to the
offline moderation key).

## Layers

| Layer | Where | Default |
| --- | --- | --- |
| Registration budgets per IP range and deployment | `api` `[api.registration.throttle]` | Prompt 3 (D-0048) |
| **Escalating proof of work** | `api` `[api.registration.escalation]` | +1 bit (twice the work) at 3, 10 and 30 registrations from one range in the past hour; +1 for everyone at 300 across the deployment, +2 at 1,200; at most +4 |
| Message requests per sender, pair and recipient | the gate (`[…requests.limits]`) | 20 an hour (burst 10) per sender; 10 (5) per pair; 100 (30) per recipient |
| **New accounts** (their first 30 days) | the gate | 5 requests an hour per sender (burst 10: a new user's first ten conversations go through) |
| **Limited accounts** | the gate; `api` | 1 request an hour (burst 2); no new group invite links |
| Reports per reporter | `api` `[api.reports]` | Prompt 4 |
| **Suspended accounts** | the send path (delivery, `api`), `api` | no sends (reject 15 `Suspended`), no sender certificate, no new calls or call links; receiving, export, deletion and appeals work |

## Signals and thresholds (automatic, limit only)

| Signal | Counted | Threshold | Effect |
| --- | --- | --- | --- |
| A verified report of a **direct** message the account sent (franking proves receipt; one report per message) | per keyed tag of the sender per day, 30 days | **5** distinct messages in 30 days | limited 7 days (reason `reports`) |
| A block by someone the account sent a **message request** in the last week | per keyed tag per day, 7 days | **5** such blocks in 7 days **and** at least **20 %** of its requests in those days | limited 7 days (reason `blocks`) |

- Group messages reported go to moderators only: a group of brigaders cannot trigger anything.
- Blocks by people the account never sent a request to count for nothing: a brigade of
  strangers cannot trigger anything.
- A new signal while limited extends the limit; quiet for a week, it lifts by itself.
- An automatic limit never overrides or shortens a moderator's decision.

The thresholds are constants in `services/api/src/abuse.rs`; change them there with a test, and
record the change in `docs/DECISIONS.md`.

## Moderating

The moderation key is offline (`songbird-admin reports keygen`). On the moderation machine:

```bash
songbird-admin reports list --addr <registry> --namespace songbird --database songbird
songbird-admin reports open --key moderation.key --addr <registry> ...
songbird-admin moderation decide --key moderation.key --report <id> --action suspend --reason abuse --days 30 --confirm songbird/songbird --addr <registry> ...
```

- Decisions: `dismiss`, `limit --days N`, `suspend [--days N]` (without `--days`, until lifted).
- Reasons are categories (`spam`, `abuse`, `fraud`, `impersonation`, `illegal`): the account
  sees the category, never a moderator's words.
- A report whose sender the server could not attest (a sealed send) can only be dismissed.
- A decision deletes the report. Undecided reports go after `retention_days` (30).
- Every decision is in the audit log with the report, the account, the action and the reason.

## Appeals

A suspended or limited account appeals through Help (a support ticket of kind `appeal` with the
account attached, Prompt 11 M6). The moderator reviews it with the decision's audit entry, then:

```bash
songbird-admin moderation show --account <hex> --addr <registry> ...
songbird-admin moderation lift --account <hex> --confirm songbird/songbird --addr <registry> ...
```

## Failures

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Many new users report "Too many requests" | A deployment-wide registration surge also slows nothing in messaging; check `young_sender_*` in `[…requests.limits]` | Raise the young budget; record why |
| Registrations slow for everyone | The deployment step (300 an hour) is reached | Expected during a flood; raise `global_step` if it is legitimate growth |
| Standings not applied on a node | The node's snapshot follower failing (logs: "entitlements reload failed") | Check the registry connection; standings apply within a second of a reload |
