# CI runner host (D-0039)

Self-hosted GitHub Actions runners for this repository, on a Linux host shared with other
workloads. CI runs as an unprivileged `ci` user with its own rootless Docker and CPU and memory
caps, so it cannot touch the host's other containers or starve them.

```bash
# Prepare the host (idempotent):
ssh root@HOST 'sh -s' < deploy/ci-runner/provision.sh

# Add a runner (the token is valid for an hour and is not stored):
TOKEN=$(gh api -X POST repos/countradooku/songbird/actions/runners/registration-token -q .token)
ssh root@HOST "RUNNER_TOKEN=$TOKEN sh -s -- songbird-1 songbird,songbird-stack" < deploy/ci-runner/add-runner.sh
```

Labels: `songbird` on every runner; `songbird-stack` on exactly one, for the jobs that start the
compose stack or bind fixed ports.

Remove a runner: `systemctl disable --now songbird-runner-NAME`, then
`runuser -u ci -- ~ci/runners/NAME/config.sh remove --token $(gh api -X POST repos/countradooku/songbird/actions/runners/remove-token -q .token)`.
