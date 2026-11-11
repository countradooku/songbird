# Failed deployment and rollback

- Detection: `deploy` workflow fails at "staged rollout"; Ansible prints which host failed and the
  version it was rolled back to. Alerts on `/readyz` failures (Prompt 13 dashboards).
- Impact: at most the canary host (first batch) or one batch ran the bad version, and only until
  its health check failed. Durable data is untouched: services store before acknowledging and the
  database is the only truth (invariant 1); a restarted service resumes from it.
- Immediate actions:
  1. Do nothing to the remaining hosts: the rollout stopped itself (`max_fail_percentage: 0`,
     `any_errors_fatal`).
  2. Confirm the failed host is back on the previous version:
     `ssh -J root@<bastion> root@<host> cat /etc/songbird/version` and its `/readyz` returns 200.
  3. If the automatic rollback itself failed (no previous version on a fresh host, or the old
     version also unhealthy), deploy the last known good version explicitly:
     `deploy/bin/rollout <env> <good-version>`.
- Recovery: fix forward with a new release; never re-run a failed version.
  Expected duration: rollback is automatic within one health-check window (≤ 60 s per host).
- Verification: every host's `/etc/songbird/version` matches; every `/readyz` 200;
  `songbird_telemetry_refused_callsites_total` is 0 everywhere; from Prompt 2, the end-to-end
  delivery checker passes.
- Follow-up: report in `docs/reports/`, regression test for the cause.

## Normal deployment

1. Tag a release (`vX.Y.Z`, signed tag). `release.yml` builds twice, compares, signs, attests and
   publishes images.
2. Run the `deploy` workflow: environment `staging`, version `X.Y.Z`. Reviewers approve.
   It verifies signatures (`deploy/bin/verify-release`), then rolls out: canary, 25 %, rest.
3. Watch staging for the soak period, then the same for `production`.

Manual equivalent from the owner's machine: `deploy/bin/verify-release X.Y.Z && deploy/bin/rollout <env> X.Y.Z`.
