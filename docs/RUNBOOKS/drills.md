# Drills

Monthly restore drills and quarterly game days (master prompt §6). Each entry: what was destroyed,
how long the recovery took against the target, and the delivery checker's verdict.

| Date | Drill | Where | Measured | Target | Checker | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-13 | Registry and mailbox lost under load, restored from an encrypted backup (`bench/m6/restore-drill.sh`, 3,000 devices, 5,000 msg/s for 60 s, disaster at 25 s, 300 recipients offline throughout) | Compose stack on the agent's laptop (Apple M5 Pro): SurrealDB 4.0.1, Iggy 0.10.0, one delivery node | Outage 1.23 s from the kill to delivery ready (restore 1.16 s of it) | RTO 2 h | **PASS**: 294,125 accepted, 294,125 delivered, 0 lost, 0 duplicates, 0 order violations | Negative control (`NO_RESEND=1`, clients keep no send log): FAIL, 11,581 lost: what the resend recovered. Backup taken just before the run, so RPO not exercised. The restore came from a local directory, not the off-site bucket, and the host was not rebuilt: this measures the software path, not the 2-hour whole-environment target. |
| 2026-11-13 | Restore time at scale (100,000 accounts and devices) | Same | Backup 0.3 s (34 MB encrypted); restore with checks 5.3 s | RTO 2 h | n/a | About 1 minute per million accounts, linear. |

## Not drilled yet

- The off-site path end to end at Hetzner (Object Lock enforcement, put-only keys):
  `deploy/bin/backups-up <env> apply`, then `check`, once the backup projects exist.
- A whole-environment rebuild at the second provider plus restore, timed against the 2-hour RTO
  (provider-switch.md; Prompt 1's drill did not include a restore).
- The daily verification on a real verification host.
