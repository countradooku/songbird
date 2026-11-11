# Provider loss: rebuild the environment at the second provider

Hetzner is primary, Scaleway secondary (D-0009). The same OpenTofu topology and Ansible code build
either; only `deploy/tofu/providers/<cloud>.tfvars` differs. State for each provider is kept at the
other provider, so losing one never loses the state needed to rebuild at the other.

- Detection: provider status page, all hosts unreachable, or a decision to leave the provider.
- Impact: service down until the rebuild completes and data is restored. Data written since the
  last backup is lost unless the database is reachable for a final export (Prompt 10 defines
  backups, restore and their verification; until then this runbook rebuilds infrastructure only).

## Rebuild (one command, timed)

```bash
deploy/bin/env-up <env> scaleway [version]
```

It decrypts the environment secrets, creates network, firewalls and servers, generates the
inventory, waits for SSH, then runs `site.yml`: hardening, nftables, Docker, certificates,
SurrealDB, Valkey, Garage, LiveKit and the Songbird services, ending with health checks. Timings
are appended to `deploy/drill-timings.tsv`.

Then: restore data (Prompt 10 runbook), switch DNS to the new edge addresses, and set
`active_cloud` in the SOPS file so `deploy/bin/rollout` targets the new provider.

## Drill (gate for Prompt 1, then quarterly)

1. `time deploy/bin/env-up staging hetzner`
2. `deploy/bin/env-down staging hetzner --yes-destroy-staging`
3. `time deploy/bin/env-up staging scaleway`
4. Record both timings, failures and fixes in the drill report; tear down when done.

- Verification: every `/readyz` 200; `cargo xtask smoke`-equivalent checks in `site.yml` pass;
  from Prompt 2, the end-to-end delivery checker passes against the new environment.
