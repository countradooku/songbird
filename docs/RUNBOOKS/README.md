# Runbooks

Every degraded mode is explicit, tested and has a runbook (constitution, invariant 8).

## Index

| Failure | Runbook | Last drilled |
| --- | --- | --- |
| Failed deployment, rollback | [deploy-and-rollback.md](deploy-and-rollback.md) | not yet (needs first release) |
| Internal certificate expiry or compromise | [mtls-rotation.md](mtls-rotation.md) | leaf issue/renew: tests only |
| Secret exposure, rotation, people changes | [secrets-rotation.md](secrets-rotation.md) | not yet |
| Provider loss, rebuild at the second provider | [provider-switch.md](provider-switch.md) | not yet (Prompt 1 gate drill) |
| Delivery: overload, slow consumers, store unavailable, auth failures, deploy drain | [delivery.md](delivery.md) | load-generator runs and e2e tests (P02-M1) |
| Jobs, push, attachments, account deletion, registry busy | [jobs-push-api-worker.md](jobs-push-api-worker.md) | live tests and M5 gate tests only |
| Media: GIF provider outage, uploads failing, storage growth, download abuse | [media.md](media.md) | live tests only (`media_live`, `gate_p06`) |
| Calls: a LiveKit node or its Valkey down, TURN over TLS failing, webhooks failing, rotating the LiveKit secret | [calls.md](calls.md) | live tests (`gate_p07`), the E2EE harness (`tools/calls-harness`) |
| Registry loss or corruption, mailbox loss, backups or verification failing, compromise | [backup-and-restore.md](backup-and-restore.md) | 2026-11-13: restore under load on compose ([drills.md](drills.md)); off-site path not yet (needs the Scaleway project) |
| Billing: provider outages, notifications failing, refunds, the token secret | [billing.md](billing.md) | live tests only (`billing_live`) |
| Abuse: floods, spam, standings, moderation, appeals | [abuse.md](abuse.md) | live tests only (`gate_p11`) |
| Legal requests, transparency reports, support tickets | [legal-requests.md](legal-requests.md) | live tests only (`support_live`, `plans_live`); the process awaits counsel |

## Runbook template

```
# <Failure>

- Detection: alert, dashboard, symptom
- Impact: what users see; what is guaranteed not to be lost
- Immediate actions: numbered steps
- Recovery: numbered steps, with expected duration
- Verification: how to prove recovery (delivery checker, metrics)
- Follow-up: report, regression test
```

## Drills

Results of monthly restores and quarterly game days go in [drills.md](drills.md).
