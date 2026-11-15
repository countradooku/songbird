# P02 — Realtime delivery core: final gate (definition of done)

- Date: 2026-11-15
- Prompt: [02-realtime.md](../prompts/02-realtime.md), "Definition of done" in
  [02a-realtime-master.md](../prompts/02a-realtime-master.md) §9.
- Status: **for the owner's decision.** This report adds no new build or measurement. It checks each
  definition-of-done item against the milestone reports, the tests on `main` (`c377d4d`) and the
  runbooks, and lists what is still open.
- State of `main`:
  - `ci` passed on `c377d4d`. CodeQL passed on #46, whose tree is identical.
  - The scheduled nightly passed all 13 jobs on 2026-11-15 (run 43699416351, `83cf2b9`): fuzz on
    8 targets, ASan, TSan, Miri, benchmarks, and the clean-cache fast checks.
- Owner decision of 2026-11-15: the 24-hour soak (D-0043) runs once, after every prompt phase is
  finished. It does not block Prompt 3.

## Summary

| Definition of done | Verdict |
| --- | --- |
| Every milestone gate passed and its report written | **Met for M2–M7 and the send library.** M1: approval not written down (below). M0 is Prompt 1, whose gate is still open. |
| Every invariant has a named, passing test; the checker passes in every load, chaos and restore scenario | **Met.** |
| A timed DR drill met the RTO; every failure in the matrix has a tested runbook | **Partly.** The restore drill under load passed (software path). The 2-hour whole-environment RTO is not drilled. Every matrix row has a runbook; three rows have no test or drill. |
| One command reproduces the benchmark suite and compares against the baseline and Sockudo | **Met against the stored baseline.** Sockudo was replaced by the sockudo-ws baseline at M1 (owner-accepted, D-0022), and the suite does not run it. |

## 1. Milestone gates and reports

| Gate | Report | Approval |
| --- | --- | --- |
| M0: workspace, CI, compose, telemetry, decisions | [P01-foundations](P01-foundations.md) | Prompt 1's report still reads "stopped at the gate, waiting for the owner". Of its open items, CI on GitHub is now green on every pull request. The timed rebuild at a second provider is not run (§3). |
| M1: proto, server, session, client, loadgen | [P02-M1](P02-M1.md) | **Not recorded.** The report's status still reads "waiting for the owner's approval of the gate". The owner merged PR #21 on 2026-11-11, settled its three decisions (D-0024), accepted the sockudo-ws baseline (D-0022) and started M2. |
| M2: mailbox, send path, ACK deletes | [P02-M2](P02-M2.md), [deletion](P02-M2-deletion.md) | Approved 2026-11-12 |
| M3: thread-per-core runtime | [P02-M3](P02-M3.md) | Approved 2026-11-12 |
| M4: Valkey routing, takeover, chaos | [P02-M4](P02-M4.md) | Approved 2026-11-12 |
| M5: jobs, push, worker, api | [P02-M5](P02-M5.md) | Approved 2026-11-13. Two threat-model rows are still **awaiting approval** (§5). |
| M6: backups, store generation, restore | [P02-M6](P02-M6.md) | Approved 2026-11-13 (delegated, D-0041) |
| M7: tuning, load suite, soak, threat model | [P02-M7](P02-M7.md) | Approved 2026-11-13, with the soak moved |
| Send library, `PUT /v1/messages`, system frames | [P02-send](P02-send.md) | Approved 2026-11-14 (D-0044) |

## 2. Invariants and the checker

The constitution's nine invariants each have a named end-to-end test in
`tests/e2e/tests/invariants.rs`. The tests run in CI on Linux on every pull request, and nightly
under ASan and TSan.

| Invariant (constitution) | Test |
| --- | --- |
| 1. Store before acknowledge | `inv1_store_before_acknowledge` |
| 2. Per-device ordering | `inv2_per_device_order_without_gaps_or_duplicates` |
| 3. Delete on ACK, 30 days at most | `inv3_delete_on_ack_and_expiry` |
| 4. One live connection per device | `inv4_one_live_connection_per_device` |
| 5. No slow client slows anyone else | `inv5_slow_client_never_slows_anyone_else` |
| 6. No identifiers in logs or metrics | `inv6_no_identifiers_in_logs_or_metrics` |
| 7. Bounded, validated input | `inv7_bounded_and_validated_input` (plus 8 fuzz targets nightly) |
| 8. Explicit degraded modes | `inv8_store_unavailable_rejects_retryably_and_keeps_sockets` (other modes: §3) |
| 9. Server-side authorization | `inv9_server_side_authorization` |

The master prompt's two extra invariants are shown by the checker runs below rather than by one
test: "the mailbox is the only source of truth" and "nothing important lives only in one
process's memory".

The delivery checker (nothing lost, nothing duplicated, order kept) passed in every scenario run:

- **Load:** every M7 run at the beta's peak (30,000 devices, 1,000 sends/s, 20 group sends/s), and
  the reconnect storm of all 30,000 connections (59,980 of 59,980 delivered).
- **Chaos (M4):** partition owner `kill -9`, Valkey restart without persistence, owner SIGTERM, two
  nodes killed at once, and a rolling restart of all three.
- **Restore (M6):** `bench/m6/restore-drill.sh`: delivery killed under 5,000 msg/s, the registry
  restored, and the store generation raised.

Locally on macOS, `inv7` fails with ConnectionClosed, on `main` too. It passes on Linux in CI and
under both sanitizers, so it is a platform difference, not a regression.

## 3. Disaster recovery and the failure matrix

**The timed drill.** The M6 restore drill passed for the software path: the registry was restored
under load, and the checker passed. The software restore takes about one minute per million
accounts. The **2-hour RTO** covers a whole-environment rebuild at the second provider plus the
restore, and is **not drilled**. Its one command (`deploy/bin/env-up`) is built and validated
offline. Running it is Prompt 1's open gate item and needs the owner's provider accounts.

**The failure matrix** (master prompt §6). Every row has a runbook:

| Failure | Runbook | Tested by |
| --- | --- | --- |
| `delivery` process crash | [delivery.md](../RUNBOOKS/delivery.md) (several nodes) | M4 chaos (`kill -9`); restart policy `unless-stopped` |
| Delivery node lost | [delivery.md](../RUNBOOKS/delivery.md) | M4 chaos (two nodes at once, rolling restart) |
| `valkey-hot` lost or restarted | [delivery.md](../RUNBOOKS/delivery.md), [jobs-push-api-worker.md](../RUNBOOKS/jobs-push-api-worker.md) | M4 chaos (Valkey restart without persistence) |
| `valkey-jobs` lost | [jobs-push-api-worker.md](../RUNBOOKS/jobs-push-api-worker.md) (outbox, dead letters) | `the_relay_empties_the_outbox_and_the_consumer_runs_every_job`; no loss drill |
| Store unavailable | [delivery.md](../RUNBOOKS/delivery.md) | `inv8_…` |
| Store data loss or corruption | [backup-and-restore.md](../RUNBOOKS/backup-and-restore.md) | M6 restore drill |
| RustFS lost | [jobs-push-api-worker.md](../RUNBOOKS/jobs-push-api-worker.md) | **No outage test.** Uploads are covered by live tests only. |
| APNs or FCM outage | [jobs-push-api-worker.md](../RUNBOOKS/jobs-push-api-worker.md) | `breaker_opens_and_answers_without_the_network` and breaker unit tests |
| Whole server or provider lost | [provider-switch.md](../RUNBOOKS/provider-switch.md) | **Not drilled** (above) |
| Bad deploy | [deploy-and-rollback.md](../RUNBOOKS/deploy-and-rollback.md) | **Not drilled**: needs a first release |
| Operator error | [backup-and-restore.md](../RUNBOOKS/backup-and-restore.md) (restore from before the mistake) | `a_missing_or_wrong_confirmation_is_refused_and_logs_nothing` (admin tool). There is no point-in-time restore: the registry is restored to the last export, at most 5 minutes old (D-0040). |
| Compromise or ransomware | [backup-and-restore.md](../RUNBOOKS/backup-and-restore.md), [secrets-rotation.md](../RUNBOOKS/secrets-rotation.md) | Off-site copies are write-once with separate credentials (D-0042). No drill. |

## 4. The benchmark suite

`bench/m7/suite.sh <work dir> [baseline.json]` builds the node and runs every scenario. It prints
the comparison against the stored baseline (`bench/m7/baseline-vmpal-arm64.json`), and fails on a
tracked figure more than 10% worse or on a missed target.

The "against Sockudo" half was settled at M1. The owner accepted the sockudo-ws library's own
echo server as the baseline instead of a Sockudo server (D-0022). That comparison is in P02-M1
and is not part of the suite. CI keeps only the deterministic gates: the allocation budget and
the checker.

## 5. Open items

For the owner to decide now:

1. **Approve the two M5 threat-model rows** (THREAT_MODEL §1, D-0036): jobs in `valkey-jobs` as
   sealed IDs, and the hash of a request's (device, nonce) in `valkey-hot` for 2 minutes. Both are
   sealed or hashed forms of data already approved.
2. **Record the M1 gate as approved**, given PR #21's merge and M2's start.
3. **Accept the sockudo-ws baseline as meeting the "against Sockudo" item**, or ask for a Sockudo
   server run to be added to the suite.
4. **Accept the untested matrix rows as known gaps**, each with its plan: RustFS outage (a
   compose test can stop RustFS mid-upload), bad deploy (the first release), and compromise (a
   game day).

Deferred by the owner's decision, run once at the end of all phases or at go-live:

5. The 24-hour soak (`bench/m7/soak.sh` on the beta server).
6. Durable latency and x86: `bench/m7/suite.sh` on the `ccx33`, with Iggy on its disk.
7. The 2-hour RTO drill: the provider rebuild and restore. This is also Prompt 1's gate.

Not blocking, already tracked in DECISIONS: Iggy pre-1.0 and its seccomp needs (D-0029), the
supply-chain audit backlog, the RustFS digest pin (D-0035), and the owner's GitHub and Actions
settings (D-0045, D-0046).

## Recommendation

Approve Prompt 2 as done, with items 1–4 decided as above and items 5–7 as the recorded go-live
checks. None of the open items changes code that Prompt 3 builds on.
