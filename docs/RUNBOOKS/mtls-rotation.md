# Internal certificates: rotation and expiry

Hierarchy (D-0012): root CA (10 years, owner-only SOPS file) → intermediate (1 year,
name-constrained to `songbird.internal` and private ranges, deploy SOPS file) → leaf per component
per host (30 days).

- Detection: `songbird-admin ca check --cert <file> --renew-within 10` exits 1; TLS handshake
  errors between services; Prompt 13 adds an expiry alert at 10 days.
- Impact if a leaf expires: that component's internal connections fail; clients of Songbird are
  affected only through the failing component. No data is lost.

## Routine leaf renewal (automatic window: 10 days before expiry)

```bash
# From the owner's machine or CI, with the environment's SOPS key and the deploy SSH key loaded:
cd deploy/ansible && ansible-playbook -i inventory/generated/<env>.yml rotate-certs.yml
```

Renews only leaves inside the window and restarts only the components whose certificate changed
(25 % of hosts at a time). Schedule it weekly. Force every leaf (for example after a suspected key
exposure): add `-e force_rotate=true`.

## Leaf key compromised

1. Force-rotate that host: `ansible-playbook … rotate-certs.yml -e force_rotate=true --limit <host>`.
2. Until certificate revocation lists are added (open risk, report P01), the old leaf stays valid
   for at most 30 days: if the exposure is serious, rotate the intermediate (below), which
   invalidates every old leaf at once.

## Intermediate renewal (yearly, or on compromise) — owner task

1. Decrypt the root key into a private temporary directory:
   `sops -d --extract '["pki_root_key"]' deploy/secrets/<env>.root-ca.sops.yaml > $TMP/root.key`
   and `pki_root_crt` to `$TMP/root.crt`.
2. `songbird-admin ca init-intermediate --root $TMP --out $TMP/ca --env <env>`
3. `sops edit deploy/secrets/<env>.sops.yaml`: replace `pki_intermediate_crt` and `pki_intermediate_key`.
4. `rm -rf $TMP`, then `rotate-certs.yml -e force_rotate=true` for the whole environment.
- Verification: every component restarted; `songbird-admin ca check` on a sample of leaves shows
  ~30 days; services healthy.

## Root renewal (every ~9 years, or on compromise)

Create a new root and intermediate with `deploy/bin/secrets-init` logic in a temporary
environment name, distribute both roots in `ca.crt` for one leaf period (trust overlap), then
remove the old root. Drill this before it is needed (Prompt 13).
