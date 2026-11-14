# CI runner host (D-0039)

Self-hosted GitHub Actions runners for this repository, on a Linux host shared with other
workloads. CI runs as an unprivileged `ci` user with its own rootless Docker and CPU and memory
caps, so it cannot touch the host's other containers or starve them.

```bash
# Prepare the host (idempotent):
ssh root@HOST 'sh -s' < deploy/ci-runner/provision.sh

# Add a runner (the token is valid for an hour and is not stored):
TOKEN=$(gh api -X POST repos/songbirdchat/songbird/actions/runners/registration-token -q .token)
ssh root@HOST "RUNNER_TOKEN=$TOKEN sh -s -- songbird-1 songbird,songbird-stack" < deploy/ci-runner/add-runner.sh
```

Labels: `songbird` on every runner; `songbird-stack` on exactly one, for the jobs that start the
compose stack or bind fixed ports.

Remove a runner: `systemctl disable --now songbird-runner-NAME`, then
`runuser -u ci -- ~ci/runners/NAME/config.sh remove --token $(gh api -X POST repos/songbirdchat/songbird/actions/runners/remove-token -q .token)`.

If GitHub no longer lists a runner (Settings, Actions, Runners) but its service still exists on the
host, its local registration is stale: stop the service, delete `~ci/runners/NAME/.runner`,
`.credentials` and `.credentials_rsaparams`, then run `add-runner.sh` again with a fresh token.

Every workflow except `release.yml` and `deploy.yml` runs only on these runners (D-0045); `cargo
xtask workflows`, part of `cargo xtask ci fast`, fails on a job that names a GitHub-hosted runner.
