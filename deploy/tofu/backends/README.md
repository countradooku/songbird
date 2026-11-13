# Remote state backends

One file per environment and provider, `<env>-<cloud>.s3.tfbackend`, holding only non-secret
settings (bucket, key, region, endpoint). Access keys come from SOPS (`deploy/secrets/<env>.sops.yaml`,
keys `state_access_key` and `state_secret_key`) and are exported by `deploy/bin/env-up`.

State is also encrypted client-side by OpenTofu (`encryption` block, passphrase in SOPS), so the
storage provider cannot read it.

All state is at Hetzner Object Storage in Helsinki (`hel1`), in a Hetzner project that holds
nothing but OpenTofu state, so its keys reach nothing else and a server project's keys cannot
reach it (D-0042: Hetzner only for now). Servers run in other locations, so losing a location
never loses the state needed to rebuild in another.
