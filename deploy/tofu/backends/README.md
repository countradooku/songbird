# Remote state backends

One file per environment and provider, `<env>-<cloud>.s3.tfbackend`, holding only non-secret
settings (bucket, key, region, endpoint). Access keys come from SOPS (`deploy/secrets/<env>.sops.yaml`,
keys `state_access_key` and `state_secret_key`) and are exported by `deploy/bin/env-up`.

State is also encrypted client-side by OpenTofu (`encryption` block, passphrase in SOPS), so the
storage provider cannot read it.

Keep state for an environment at a *different* provider from the one it describes, so losing a
provider never loses the state needed to rebuild elsewhere.
