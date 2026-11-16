# Secrets: rotation and suspected exposure

Secrets live only in `deploy/secrets/<env>.sops.yaml` (SOPS + age, D-0010) and in memory on the
hosts that need them. Nothing secret is in config files, logs or images.

- Detection: a secret appears where it must not (log, ticket, chat, a commit — `p/secrets` Semgrep
  rules and GitHub secret scanning catch the obvious cases); a team member with access leaves; an
  age key is lost or exposed.
- Impact: depends on the secret; none of them gives access to message content (end-to-end
  encryption), but they protect availability, metadata and the integrity of the deployment.

## Rotate one value

1. `sops edit deploy/secrets/<env>.sops.yaml`, replace the value (`python3 -c 'import secrets; print(secrets.token_hex(32))'`).
2. Apply it:
   - Valkey, SurrealDB, RustFS, LiveKit credentials: a `site.yml` run (converges; recreates only
     containers whose settings changed). SurrealDB's root password is set
     only when the database is created: change it with `DEFINE USER … PASSWORD` first, then update SOPS.
   - Provider tokens, state bucket keys: revoke the old one in the provider console after the new one works.
   - `tofu_state_passphrase`: OpenTofu re-encrypts on the next apply when both old and new keys are
     configured (`fallback` key provider); follow OpenTofu's key-rotation procedure, then remove the old one.
   - Deploy SSH key: add the new public key with `site.yml`, verify access, then remove the old one.
   - **The router's `cluster_secret`: do not rotate it while MLS groups exist** (D-0075). `api`
     derives the delivery service's external-sender key from it, and every group's context
     names that key: with another key, every commit to every existing group is refused
     (`400 proposal`) and departed devices are no longer proposed for removal. Rotating it needs
     the key-rotation step D-0075 records as not built (each group commits a context change to
     the new key while the old one is still accepted). If it is exposed, treat it as an
     incident: the key can only propose removals of departed devices (apps refuse the rest),
     but fan-out keys and Valkey channel names also derive from it.
3. Commit the re-encrypted file.

## Rotate the SOPS data key (all values re-encrypted)

`sops rotate -i deploy/secrets/<env>.sops.yaml` — do this after any recipient is removed.

## Add or remove a person or CI key

1. Edit `deploy/secrets/recipients/<env>.txt` (or `owner.txt` for root CA files).
2. `deploy/bin/sops-config`
3. `sops updatekeys -y deploy/secrets/<env>.sops.yaml`, then `sops rotate -i …` when removing.
4. Removing a person: also rotate every value they could read (above).

## Lost age key

Recovery needs another recipient's key. Keep the owner's age key backed up offline in two places;
CI keys live in GitHub environment secrets (`SOPS_AGE_KEY`) and can be re-created by the owner.

- Verification: `sops -d` works for every remaining recipient and fails for a removed one;
  environment healthy after `site.yml`.
