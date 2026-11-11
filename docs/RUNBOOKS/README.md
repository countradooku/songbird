# Runbooks

Every degraded mode is explicit, tested and has a runbook (constitution, invariant 8).

## Index

| Failure | Runbook | Last drilled |
| --- | --- | --- |
| Failed deployment, rollback | [deploy-and-rollback.md](deploy-and-rollback.md) | not yet (needs first release) |
| Internal certificate expiry or compromise | [mtls-rotation.md](mtls-rotation.md) | leaf issue/renew: tests only |
| Secret exposure, rotation, people changes | [secrets-rotation.md](secrets-rotation.md) | not yet |
| Provider loss, rebuild at the second provider | [provider-switch.md](provider-switch.md) | not yet (Prompt 1 gate drill) |

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

Results of monthly restores and quarterly game days go in `drills.md` (Prompt 13).
