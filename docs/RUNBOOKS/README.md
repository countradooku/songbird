# Runbooks

Every degraded mode is explicit, tested and has a runbook (constitution, invariant 8).

## Index

| Failure | Runbook | Last drilled |
| --- | --- | --- |
| | | |

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
