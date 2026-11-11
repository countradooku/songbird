# P01 — Foundations and platform: gate report

- Date: 2026-11-11
- Prompt: [01-foundations.md](../prompts/01-foundations.md)
- Status: **stopped at the gate, waiting for the owner.** Two gate items need the owner's provider
  accounts and GitHub settings (see "Gate status").
- Measurement machine for every number below: Apple M5 Pro, 18 cores, 48 GiB, macOS 27.2
  (Darwin 27.2.0), Docker 29.8.2 (linux/aarch64 VM), Rust 1.99.1. Not the reference hardware;
  no performance claims are made in this prompt.

## Skills and tools

Skills available in this session: `security-review`, `code-review`, `simplify`, Postman API skills
and document/office skills. None is specific to Rust, fuzzing or benchmarking, and no Songbird
project skill exists yet, so none was loaded while building; the API skills do not apply (no API
yet). Recommended before merging: run `/code-review` and `/security-review` on this change.
**Proposed skill:** `.claude/skills/songbird-invariants/` — a review checklist that walks a diff
through the nine invariants (store-before-ack, ordering, delete-on-ACK, one connection, slow
clients, no PII in logs or metrics, bounded input, degraded modes with runbooks, server-side
authorization) and the constitution's working rules, citing the test that proves each.

## What was built

| Area | Where | Notes |
| --- | --- | --- |
| Workspace | `Cargo.toml`, `rust-toolchain.toml` (1.99.1), `clippy.toml`, `deny.toml`, `.config/nextest.toml` | D-0001 |
| `crates/types` | IDs (16 random bytes, typed, redacted `Debug`), errors, config loader with validation, secret references | D-0003, D-0006 |
| `crates/telemetry` | Non-blocking lossy tracing, redaction layer, Prometheus metrics, admin endpoint | D-0005 |
| `crates/service` | Shared bootstrap: CLI, config, telemetry, admin endpoint, SIGTERM drain | D-0002 |
| Services | `delivery`, `api`, `push`, `worker`, `calls`: empty, healthy, measurable | mimalloc global allocator |
| Proxy | `services/proxy`, `deploy/proxy/` | D-0011, PROTOCOL §1.1 |
| Tools | `tools/admin` (mTLS CA), `tools/loadgen` (placeholder for Prompt 2) | D-0012 |
| `xtask` | `ci [fast\|deep]`, `smoke`, `bench`, `fuzz`, `sanitize`, `miri`, `release [--verify]`, `dev-env`, `compose` | |
| Fuzzing | `fuzz/` (4 targets) | |
| Compose | `deploy/compose/` | D-0007 |
| CI | `.github/workflows/{ci,nightly,codeql,release,deploy}.yml`, `.semgrep/` | D-0008, D-0013 |
| IaC | `deploy/tofu/` (topology + Hetzner + Scaleway), `deploy/ansible/` | D-0009, D-0014 |
| Secrets | SOPS + age, `deploy/bin/secrets-init`, `sops-config` | D-0010 |
| Docs | DECISIONS (D-0001…D-0014), THREAT_MODEL §1, §3.1–3.4, §6, PROTOCOL §1.1, four runbooks | |

## Tests and evidence

| Check | Result |
| --- | --- |
| `cargo xtask ci fast` (fmt, clippy pedantic + restriction `-D warnings`, nextest, doctests, rustdoc `-D warnings`, deny, audit, vet, smoke) | **pass**, 47 tests |
| Smoke: each of the 5 services starts, `/readyz` 200, `/metrics` has `build_info`, no sensitive names, `refused_callsites_total 0`, exits 0 on SIGTERM | **pass** (5/5) |
| Proxy end to end: client → outer TLS (proxy) → inner TLS (upstream) → echo, 200 KB both ways | **pass** (`services/proxy/tests/relay.rs`) |
| Proxy refuses unknown inner SNI; closes silent clients at the handshake timeout; plain HTTP probes get no HTTP/upstream bytes | **pass** |
| Proxy container: user `nonroot`, `--cap-drop ALL`, read-only; TLS 1.3, ALPN `h2`; `docker logs` = **0 bytes**; SIGTERM exit 0 | **pass** (manual run, image built from `deploy/docker/Dockerfile`) |
| mTLS CA: issued certificates complete a rustls TLS 1.3 mutual handshake; a foreign CA's client is refused; renewal window check exits 1 | **pass** (`tools/admin/tests/mtls.rs`) |
| Redaction: events and spans with `device_id`, `client_ip`, `remote_addr` never reach the writer; panic mode fails loudly | **pass** |
| Custom Semgrep rules fire on a sensitive log field and on `to_hex_unredacted()` in a log macro | **pass** (2/2 on a planted sample); repository scan with `p/rust`, `p/secrets`, Songbird rules: **0 findings** |
| Fuzzing, 20 s per target (smoke run; nightly runs 10 min): `client_hello` 588,660 runs, `config_toml` 1,559,127, `id_parse` 32,980,491, `proxy_link` 607,830 | **no crash** |
| Reproducible release: `cargo xtask release --verify` (two LTO builds in separate directories) | **7/7 binaries bit-identical** (aarch64-apple-darwin; Linux in CI on first tag) |
| SBOM: CycloneDX per release binary | written to `target/dist/…/*.cdx.json` |
| docker compose: all 5 containers healthy from empty volumes (images cached) | **7 s**; auth enforced on SurrealDB (403 without credentials), Valkey (`WRONGPASS`), Garage S3 (403); `valkey-jobs` `appendfsync everysec` |
| OpenTofu: topology rules (6 runs) and full plans at Hetzner and Scaleway against mocked providers, beta and staging shapes | **pass** (`deploy/bin/validate-iac tofu`) |
| Ansible: syntax checks of `site.yml`, `rollout.yml`, `rotate-certs.yml`; `ansible-lint` production profile | **pass** |
| Secrets: `secrets-init` on a scratch age key: 25 values encrypted (27 since the GHCR token fields were added; not re-run); intermediate CA decrypts and checks 364 days | **pass** (scratch copy, nothing committed) |

## Gate status

| Gate item | Status |
| --- | --- |
| CI green on an empty service of each kind | **Green locally** with the exact commands CI runs (`cargo xtask ci fast`, smoke covers all 5 services, image build verified for the proxy). **Not yet run on GitHub**: nothing is pushed. The `compose`, `images`, `semgrep`, `iac` and CodeQL jobs and the nightly tier have not executed on a runner yet. |
| Full environment from scratch with one command; torn down and rebuilt at the second provider in a timed run | **Built, not run.** `deploy/bin/env-up <env> <cloud>` is the one command and records timings; validated offline (mocked plans, lint). The timed drill needs: owner's Hetzner and Scaleway accounts and API tokens, two state buckets, `deploy/bin/secrets-init staging`, the admin source range, and confirmation of the second provider (D-0009). Runbook: `docs/RUNBOOKS/provider-switch.md`. |
| Every pinned dependency verified and recorded | **Partly.** Recorded: every direct crate (D-0004), image digest (D-0007), action SHA and tool version (D-0008, D-0009); Python packages hash-pinned; OpenTofu providers locked with hashes. Verified: APIs read in the pinned sources; deny/audit clean. **Gap:** `cargo vet` has 110 crates vetted (imported audit sets, plus publishers trusted by two or more imported organizations, D-0016) and **57 exempted**. |

## Code review fixes (same session)

A `/code-review` pass found ten issues, all fixed before this report was finalised:
host addresses now come from a fixed per-host `index` (adding a host used to re-address and
replace existing servers, data hosts included; regression test in `topology.tftest.hcl`); the
songbird role records `/etc/songbird/version` after health checks, so the first rollout can roll
back; `rotate-certs.yml` no longer runs controller steps with sudo and creates its working
directories; the data role applies Garage's single-node layout; hosts log in to GHCR with a
read-only token from SOPS (`ghcr_read_token`, or `public`); proxy and admin endpoint back off
50 ms after accept errors instead of spinning; Miri skips file-system tests and caps proptest
cases (local run: 16 passed, 3 ignored, 17 s); the nightly fuzz input is validated instead of
expanded into the shell; DNS-name and internal-IP checks live once in `songbird-types` and are
shared by the proxy and the CA.

## Open risks and follow-ups

1. **cargo-vet exemptions (57, down from 129 by D-0016).** Burn down with human audits or new
   imported audit sets, starting with those in the TLS and allocation paths.
2. **First CI run.** Some steps can only be proven on GitHub runners: `rustup toolchain install`
   from `rust-toolchain.toml`, `attest-build-provenance` with `subject-checksums`, the release
   build inside the builder image, GHCR pushes. Expect a short fix-up round on the first push and
   the first tag.
3. **Ansible never ran against real hosts.** Validated by lint and syntax only. Riskiest parts:
   `rotate-certs.yml` (per-component file plumbing between controller and hosts) and the
   community.docker container options. The drill will exercise them.
4. **SurrealDB has no client-certificate authentication**; it gets server TLS and a password.
   Garage's S3/admin APIs rely on ghostunnel tunnels.
5. **No internal certificate revocation**; 30-day leaves and intermediate rotation instead.
6. **LiveKit public signalling TLS and TURN/TLS** are deferred to Prompt 7 (firewall rules exist).
7. **Root SSH through the bastion** (owner decision, D-0014).
8. Not yet written: iai-callgrind and criterion benchmarks (`xtask bench` runs whatever exists;
   nothing hot exists yet), Kani proofs, Tamarin/ProVerif models, AFL++ (cargo-fuzz only so far),
   loom/shuttle tests. They arrive with the code they check (Prompts 2, 12, 13).
9. The proxy's upstream names are placeholders until the owner picks Songbird's public domains.

## What the owner needs to do

1. Review and approve D-0009 (Scaleway as second provider), D-0011 (proxy link format; pick the
   web domain), D-0014 (access model); pick the public domains.
2. Push to GitHub and check the first CI run; create the `staging` and `production` environments
   with required reviewers.
3. Run `deploy/bin/secrets-init staging`, fill the `CHANGE_ME` values (`sops edit`), then the timed
   drill in `docs/RUNBOOKS/provider-switch.md`, and add the timings to this report.
