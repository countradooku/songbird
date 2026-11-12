# Deployment

Everything needed to build, run and operate Songbird environments. No secrets live here in plain
text: they are in `secrets/*.sops.yaml` (SOPS + age).

| Path | What |
| --- | --- |
| `compose/` | Local development and CI: SurrealDB, valkey-hot, valkey-jobs, RustFS, LiveKit (`cargo xtask compose up`) |
| `docker/` | Service images: from source (`Dockerfile`) and from verified release binaries (`runtime.Dockerfile`) |
| `tofu/` | OpenTofu: `modules/topology` (provider-independent), `modules/{hetzner,scaleway}`, roots in `envs/`, shared `environments/*.tfvars`, `providers/*.tfvars` |
| `ansible/` | Host configuration: hardening, nftables, Docker, mTLS certificates, data services, LiveKit, Songbird services; `rollout.yml`, `rotate-certs.yml` |
| `secrets/` | Encrypted secrets per environment and the age recipients that may read them |
| `proxy/` | Operator kit for the censorship-resistant proxy |
| `bin/` | The commands below |

## Commands

```bash
deploy/bin/secrets-init <env>                    # once per environment (owner)
deploy/bin/env-up <env> <hetzner|scaleway> [ver] # build or converge a full environment, timed
deploy/bin/env-down <env> <cloud> --yes-destroy-<env>
deploy/bin/verify-release <version>              # signatures before deploying
deploy/bin/rollout <env> <version>               # staged rollout, automatic rollback
deploy/bin/validate-iac                          # offline checks (CI)
```

Topologies: `beta` is one server running every role (Prompt 2a: sized for 20,000 accounts);
`staging` has the production shape at minimum size. Decisions: D-0009 (IaC), D-0010 (secrets),
D-0012 (mTLS), D-0013 (releases), D-0014 (host networking and access). Runbooks:
`docs/RUNBOOKS/`.

Prerequisites on the operator machine: `tofu` 1.13.9, `sops` 3.13.3, `age` 1.3.2, Python 3.12+
with `pip install --require-hashes -r deploy/ansible/requirements.txt`, and `songbird-admin`
(`cargo install --path tools/admin --locked`).
