# Decisions

Every "X versus Y" choice, new dependency, `unsafe` exception and owner decision is recorded here,
newest first. Performance decisions cite the benchmark run (hardware, kernel, configuration, numbers).

## Template

```
## D-NNNN — <title>

- Date: YYYY-MM-DD
- Status: proposed | accepted | superseded by D-NNNN
- Decided by: owner | agent (with owner approval)
- Context: what forced the decision
- Options considered: X, Y, ...
- Evidence: benchmark runs, tests, proofs (with links)
- Decision: what was chosen
- Consequences: what this rules in or out; what to revisit and when
```

## Open owner decisions

- Group read receipts follow the read-receipt setting or not (Prompt 4).
- Public channels: build or not (Prompt 5).
- Inactivity deletion period (Prompt 3).
- WhatsApp interop legal gate (Prompt 14).
- Second EU provider: Scaleway proposed (D-0009). Confirm, or name another.
- Public domains: Songbird's client endpoints and the web domain for proxy links (D-0011). The
  upstream names in `deploy/proxy/proxy.example.toml` are placeholders until then.
- Licence for the repository (README says all rights reserved until chosen).
- Deployment access model: SSH as root with a key, through one bastion restricted to admin ranges
  (D-0014). Alternatives: WireGuard-only access, a non-root deploy user with sudo.
- GitHub environments `staging` and `production` with required reviewers, and their secrets
  (`SOPS_AGE_KEY`, `DEPLOY_SSH_KEY`), must be created by the owner before `deploy.yml` can run.

## Decisions

## D-0016 — cargo-vet: trust publishers that two or more imported organizations trust

- Date: 2026-11-11
- Status: proposed (owner to accept the remaining exemptions as a risk)
- Decided by: agent
- Context: P01 gate item "every pinned dependency verified": `cargo vet` had 38 crates fully
  audited and 129 exempted. The six imported audit sets were current; `cargo vet prune` removed
  nothing.
- Options considered: import the three remaining registry sets (actix, ariel-os, fermyon); trust
  publishers; audit crates ourselves; leave the exemptions.
- Evidence: the three extra sets vetted no additional crate, so they are not imported. `cargo vet
  suggest` showed 70 exempted crates published by people that two or more of Mozilla, ISRG,
  Bytecode Alliance, Google and Zcash trust outright.
- Decision: `supply-chain/audits.toml` trusts, for `safe-to-deploy` until 2027-11-11, the crates
  in our graph published by dtolnay, Kenny Kerr (kennykerr), epage, cuviper, seanmonstar, Amanieu,
  BurntSushi, rust-lang-owner, sunfishcode, alexcrichton, Darksonn, Thomasdezeeuw and the
  `taiki-e/pin-project-lite` GitHub team. A trust entry covers only versions that publisher
  released. Publishers trusted by one organization only (ctz, djc, Manishearth) are not trusted.
  No audits were certified: an audit entry claims a person read the code.
  Result: 110 crates vetted, 57 exempted.
- Consequences: trust entries expire on 2027-11-11 and must be renewed (`cargo vet trust`) or
  replaced. A new version from a different publisher fails `cargo vet` until audited or exempted.
  The 57 remaining exemptions include the TLS stack (rustls, rustls-webpki, ring, aws-lc-rs,
  aws-lc-sys, tokio-rustls, rcgen), the x509/asn1 parsers used by `tools/admin`, tracing, time,
  libc, getrandom, mimalloc and prometheus-client. Burning them down needs human audits or new
  imported audit sets; start with the TLS and allocation paths.

## D-0015 — CodeQL gates on its own SARIF; no code scanning upload

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: both CodeQL jobs failed on PR 17. The job token lacked `actions: read`, which
  codeql-action needs on a private repository, and code scanning is not enabled on this private
  repository (the code scanning API answers 403), so an upload could not succeed either.
- Options considered: enable GitHub Code Security (paid; owner action); drop CodeQL; run CodeQL
  with `upload: never` and gate on the SARIF.
- Decision: `codeql.yml` grants `actions: read` and `contents: read` only, runs analysis with
  `upload: never`, fails the job when the SARIF holds any result (each shown as an annotation), and
  keeps the SARIF as a 30-day artifact.
- Consequences: no Security tab alerts or dismissal workflow; a false positive is fixed in code or
  excluded in the workflow. If code scanning is enabled later, switch back to uploading and grant
  `security-events: write`.

## D-0014 — Hosts: containers on host networking, nftables authoritative, bastion-only SSH

- Date: 2026-11-11
- Status: proposed
- Decided by: agent (awaiting owner approval)
- Context: Prompt 1 security: private network for every internal service, firewall allowing only
  client ports. Docker's default bridge publishes ports through its own NAT rules, which bypass a
  host INPUT policy.
- Options considered: Docker bridge plus `DOCKER-USER` rules; host networking with Docker's iptables
  management off; podman with quadlets; bare systemd units.
- Evidence: `deploy/ansible/roles/firewall/templates/nftables.conf.j2` (default drop, per-role
  public ports, internal ports from the private range only), validated by `nft -c` at deploy time;
  `deploy/tofu/modules/topology/tests/topology.tftest.hcl` proves edge exposes only 443, data
  hosts expose nothing, SSH only from admin ranges, never 0.0.0.0/0.
- Decision: every container uses host networking and binds to the private address (internal
  services) or the public one (client ports); Docker runs with `bridge: none`, `iptables: false`.
  Two firewall layers: the provider firewall (OpenTofu) and nftables (Ansible). SSH: only the
  bastion, only from `admin_cidrs` (held in SOPS); other hosts accept SSH only from the bastion's
  private address. Ansible connects as root with the deploy key (cloud-init disables passwords).
- Consequences: no container-to-container isolation by network namespace; isolation comes from
  users, read-only root filesystems, dropped capabilities and mTLS. Revisit root SSH (owner
  decision above).

## D-0013 — Release pipeline: reproducible, signed, attested; staged rollout with rollback

- Date: 2026-11-11
- Status: accepted (pending first tagged release in CI)
- Decided by: agent
- Context: Prompt 1: reproducible builds, signed artifacts, SBOM per release, staged rollout with
  automatic rollback on failed health checks.
- Options considered: Nix for hermetic builds; a pinned builder container plus path remapping and
  `--locked`; signing with a long-lived key versus Sigstore keyless.
- Evidence: `cargo xtask release --verify` builds every release binary twice in different target
  directories and fails unless all are bit-identical; local run on the development machine is in
  `docs/reports/P01-foundations.md`. `.github/workflows/release.yml` runs the same command inside
  `rust:1.99.1-trixie@sha256:8a4e90c7…` with `cargo-cyclonedx 0.5.10`.
- Decision: release binaries are built in the pinned builder image (`SOURCE_DATE_EPOCH` from the
  commit, `--remap-path-prefix` for the workspace and Cargo home, `-C strip=symbols`, `--locked`,
  toolchain from `rust-toolchain.toml`), verified twice, summed in `SHA256SUMS`, signed with cosign
  keyless (GitHub OIDC), and attested (SLSA provenance; CycloneDX SBOM per binary). Images are
  distroless (`gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222…`), pushed to GHCR, signed and
  attested. `deploy.yml` verifies signatures (`deploy/bin/verify-release`) before a staged
  rollout: one canary host, then 25 %, then the rest; any failed `/readyz` or a non-zero
  `songbird_telemetry_refused_callsites_total` rolls that host back and stops the rollout
  (`deploy/ansible/rollout.yml`).
- Consequences: reproducibility is proven per build, not assumed. Independent rebuilds by a third
  party are possible with the same image digest and commit. Nix remains an option if the
  container approach ever drifts.

## D-0012 — Internal mutual TLS certificate authority

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: mutual TLS CA for service-to-service traffic, rotation scripted from day one.
- Options considered: step-ca (online CA), OpenBao PKI, an offline CA in our own admin tool.
- Evidence: `tools/admin/tests/mtls.rs` completes a real TLS 1.3 mutual handshake with rustls
  (aws-lc-rs) using issued certificates and refuses a certificate from another CA;
  `tools/admin/src/ca.rs` tests check key modes 0600, chain layout, and that public names or
  addresses are refused.
- Decision: `songbird-admin ca` (rcgen 0.14.10 with aws-lc-rs). ECDSA P-256. Root CA 10 years,
  key only in `deploy/secrets/<env>.root-ca.sops.yaml` (owner recipient only). Intermediate 1 year,
  path length 0, name-constrained to `songbird.internal` and private/loopback ranges, in the deploy
  secrets. Leaves 30 days (at most 90), one per component per host, `serverAuth`+`clientAuth`.
  `deploy/ansible/rotate-certs.yml` renews leaves inside a 10-day window (or all with
  `force_rotate=true`) and restarts the affected components; site.yml runs it on every build.
  Valkey uses native TLS with required client certificates (TLS 1.3 only); Garage (single-node
  layout applied idempotently by the data role) has its S3 and admin
  APIs sit behind ghostunnel 1.11.5 mTLS tunnels; SurrealDB gets server TLS with password auth (it
  has no client-certificate authentication); Songbird services load their certificates when their
  internal listeners arrive (Prompt 2+).
- Consequences: no online CA to attack or keep available. Revisit if certificate volume grows
  (step-ca or OpenBao). Intermediate renewal is an owner task (runbook `mtls-rotation.md`).

## D-0011 — Censorship-resistant proxy

- Date: 2026-11-11
- Status: accepted (link domain open)
- Decided by: agent
- Context: Prompt 1 WhatsApp-parity item: a separately deployable TLS proxy anyone can run,
  forwarding encrypted bytes only, logging nothing, configured by a proxy link.
- Options considered: nginx `stream` with `ssl_preread` (Signal's design); HAProxy (WhatsApp's);
  a small Rust relay.
- Evidence: `services/proxy/tests/relay.rs` (client → outer TLS to the proxy → inner TLS to an
  upstream echo server, 200 KB round trip; unknown SNI refused; silent clients closed at the
  handshake timeout; plain HTTP probes get no HTTP or upstream data); `services/proxy/src/sni.rs`
  property tests and the `client_hello` fuzz target; `services/proxy/src/link.rs` tests and the
  `proxy_link` fuzz target.
- Decision: `songbird-proxy`, Rust with rustls (aws-lc-rs) and Tokio. Outer TLS with the
  operator's certificate (ALPN `h2`, `http/1.1` so it resembles a web server), then route by the
  inner `ClientHello` SNI to an allowlist of Songbird upstreams, then copy bytes both ways with an
  idle timeout. No logging code at all; Docker logging disabled in the operator compose file. The
  SNI scanner is bounded and allocation-free (scratch sized by `max_client_hello_bytes`). Multi-
  thread Tokio runtime (not on the Songbird hot path; operators run it on small VPSes). Links:
  `songbird://proxy#host[:port]` and `https://<web-domain>/proxy#host[:port]`, host in the
  fragment so the web server never learns it.
- Consequences: a single binary and image, no nginx config for operators to get wrong. A client
  using Encrypted Client Hello would expose only the public name to the proxy; the allowlist must
  then list that name. Proxy operators see client IPs (stated in the operator README and threat
  model).

## D-0010 — Secrets: SOPS with age

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: secrets never in plain files, documented rotation.
- Options considered: SOPS + age; OpenBao.
- Evidence: `deploy/bin/secrets-init` run end to end against a scratch key (report P01): 25 values
  encrypted, CA material decrypts and validates. `crates/types/src/secret.rs` tests: literal
  secrets in config files are rejected at parse time; world-readable secret files are refused;
  oversized ones are rejected before reading.
- Decision: SOPS 3.13.3 with age 1.3.2. Per environment, `deploy/secrets/<env>.sops.yaml`
  (recipients: owner + that environment's CI key) and `<env>.root-ca.sops.yaml` (owner only).
  `.sops.yaml` is generated from `deploy/secrets/recipients/*.txt`. Services never read secrets
  from config files: `SecretRef` is `{ file = … }` or `{ env = … }` only. Local development uses a
  generated, git-ignored `.env` with throwaway values (`cargo xtask dev-env`).
- Consequences: no secret server to run. OpenBao stays an option if dynamic secrets are needed.
  Rotation: `docs/RUNBOOKS/secrets-rotation.md`.

## D-0009 — Infrastructure as code: OpenTofu + Ansible; Hetzner and Scaleway

- Date: 2026-11-11
- Status: proposed (second provider needs owner confirmation)
- Decided by: agent
- Context: Prompt 1: a complete environment at Hetzner and, unchanged apart from provider
  variables, at a second EU provider.
- Options considered: NixOS (needs custom images or nixos-infect on both providers) versus Ansible
  on stock Debian 13; second provider Scaleway, OVHcloud, UpCloud.
- Evidence: `deploy/bin/validate-iac`: `tofu test` plans the beta (one host) and staging (six
  hosts) topologies at both providers against mocked APIs; topology rules tested; `ansible-lint`
  (production profile) and syntax checks pass.
- Decision: OpenTofu 1.13.9 (hcloud provider 1.70.2, scaleway 2.91.0, lock files with hashes for
  linux/darwin amd64/arm64). One provider-independent `topology` module (hosts, roles, private
  addresses from a fixed per-host `index` so adding a host never re-addresses or replaces another,
  public firewall rules) feeds two thin provider modules; environment files
  (`environments/*.tfvars`) are shared and provider files (`providers/*.tfvars`) hold only region
  and machine types. State: S3 backend at the *other* provider, with OpenTofu client-side state
  and plan encryption (passphrase in SOPS). Ansible core 2.21.6 (newest on the CI runner's Python
  3.12), ansible-lint 26.11.0, all Python packages hash-pinned; collections community.docker 5.4.0,
  ansible.posix 2.2.2, community.sops 2.5.1. Scaleway (France) as second provider: mature OpenTofu
  provider with VPC, IPAM and security groups, EU regions only.
  Tool downloads in CI are checksum-verified (`deploy/bin/install-tools`).
- Consequences: one command per provider (`deploy/bin/env-up <env> <cloud>`). The timed rebuild
  at the second provider is the gate drill; it needs the owner's provider accounts.

## D-0008 — Continuous integration: fast and deep tiers, everything pinned

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: CI running the constitution's quality bar, split into fast and deep checks.
- Decision: CI calls `cargo xtask` so local and CI runs are identical.
  Fast (`ci.yml`, every push and PR): rustfmt; clippy pedantic plus selected restriction lints with
  `-D warnings`; nextest; doctests; rustdoc `-D warnings`; cargo-deny; cargo-audit; cargo-vet;
  service smoke test (every service starts, `/readyz`, `/metrics` audited for sensitive names and
  refused callsites, clean exit on SIGTERM); docker compose environment health; distroless image
  build per service; Semgrep (`p/rust`, `p/secrets`, `.semgrep/songbird.yml`); IaC validation.
  CodeQL (`codeql.yml`, Rust and Actions, security-extended).
  Deep (`nightly.yml`): each fuzz target 10 minutes; ASan and TSan (nightly, `-Zbuild-std`); Miri
  on `songbird-types`; criterion benchmarks; the fast tier on a cold cache.
  Pins: actions by commit SHA (checkout v7.0.1 `3d3c42e5…`, upload-artifact v7.0.2 `cf430e03…`,
  download-artifact v8.0.2 `9000827c…`, rust-cache v2.9.3 `d1527c8f…`, install-action v2.90.3
  `cfdb7ed4…`, codeql-action v4.39.3 `33d7b85d…`, setup-buildx v4.4.1 `f87e5991…`, build-push
  v7.4.0 `c3c9e263…`, login v4.8.0 `8aa5831f…`, cosign-installer v4.1.3 `756fe2d2…`,
  attest-build-provenance v4.2.2 `4d101475…`, attest-sbom v4.1.0 `c6043329…`, setup-opentofu
  v2.0.2 `a1320f89…`). Tools: cargo-nextest 0.9.151, cargo-deny 0.20.2, cargo-audit 0.22.2,
  cargo-vet 0.10.2, cargo-fuzz 0.13.2, cargo-cyclonedx 0.5.10, Semgrep 1.185.0 by digest.
- Consequences: shared runners make nightly benchmark numbers trend-only; decisions use the
  reference hardware (Prompt 13).

## D-0007 — Local and CI environment: docker compose, images pinned by digest

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: compose for SurrealDB, `valkey-hot`, `valkey-jobs`, Garage, LiveKit, with
  health checks.
- Evidence: `cargo xtask compose up` on the development machine: all five containers healthy;
  SurrealDB refuses unauthenticated queries (403) and accepts the generated root credentials;
  Valkey refuses commands without the password; `valkey-jobs` reports `appendfsync everysec`;
  Garage reports "fully operational" after the single-node layout step; anonymous S3 is refused
  (403); LiveKit answers `OK`.
- Decision: `deploy/compose/compose.yaml`, every image by digest:
  SurrealDB v4.0.1 `sha256:408eb8e5c9436670525e2bc2634b1e50ba74ce1b447eaf0094c35f73b67f9cb6`;
  Valkey 9.1.3-alpine3.24 `sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b`;
  Garage v2.5.0 `sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5`;
  LiveKit v1.13.11 `sha256:25cd902de7cacbd5f1f779f6a6ac1eae20ba8f56b0935934ce6b0ab80d1e3d20`;
  ghostunnel v1.11.5 `sha256:65c4e34ec0ee0f30ea1f72b7411ec70a91c32fc50f067a8466ad2adb1e7420f2`
  (deployments). Both Valkeys use `noeviction`: silently evicting registry or rate-limit keys
  would break invariants 4 and 5, so a full Valkey must fail loudly instead. `valkey-hot` has no
  persistence; `valkey-jobs` AOF `everysec`. Host ports 47xxx on 127.0.0.1 (overridable with
  `SB_PORT_*`) to avoid clashing with other local stacks. Credentials are random per machine.
- Consequences: Prompt 2's integration tests start from `cargo xtask compose up`.

## D-0006 — Configuration: TOML plus environment overrides, strict and validated

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: configuration loading with validation; invariant 7 (bounded input).
- Options considered: `figment`, `config`, a small loader on `toml` + `serde`.
- Evidence: `crates/types/src/config.rs` tests: file then environment precedence; unknown fields
  and unknown override keys are errors; all violations reported at once with dotted paths;
  bounds on file size (checked before reading), override count, value length, key depth;
  multi-line override values rejected; error messages do not echo values. `config_toml` fuzz
  target.
- Decision: own loader (one dependency, `toml` 1.2.1, instead of a framework). Overrides are
  `SONGBIRD__SECTION__KEY=value`; values parse as TOML, else string. Staging and production refuse
  a non-private admin address and non-JSON logs.
- Consequences: no hot reload yet; `arc-swap` reload arrives with the first hot setting.

## D-0005 — Telemetry: non-blocking tracing, callsite redaction, prometheus-client

- Date: 2026-11-11
- Status: accepted for Prompt 1; per-core hot-path counters to be benchmarked in Prompt 2
- Decided by: agent
- Context: Prompt 1: tracing with a non-blocking writer, Prometheus metrics, a redaction layer that
  refuses known sensitive field names (invariant 6).
- Options considered: metrics facade + `metrics-exporter-prometheus` versus `prometheus-client`;
  redaction by rewriting values versus refusing callsites.
- Evidence: `crates/telemetry/tests/redaction.rs` (sensitive events and spans never reach the
  writer; panic mode fails loudly); `metrics.rs` tests (sensitive metric names rejected; exposition
  audit); `admin.rs` test (endpoints, 405, 404, oversized headers rejected). The smoke test checks
  every running service exposes `songbird_telemetry_refused_callsites_total 0`.
- Decision: `tracing-appender` non-blocking writer in **lossy** mode (a full buffer drops lines and
  counts them; logging never blocks a task). The redaction layer decides once per callsite from
  static field names (no per-event cost) and disables the callsite globally. `prometheus-client`
  0.26 (official OpenMetrics client, no exporter framework); admin endpoint on hyper 1.12 HTTP/1
  with header timeout, 8 KiB buffer, 32 headers, 64 connections. Semgrep rules
  (`.semgrep/songbird.yml`) catch sensitive log fields and unredacted IDs at review time.
- Consequences: field names matter; values formatted into the message text are not inspected,
  which is why IDs and secrets redact themselves in `Debug`.

## D-0004 — Dependencies of Prompt 1

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Constitution: no new dependency without a recorded reason; read the exact pinned
  version's source before use.
- Evidence: APIs used were read in the registry sources of these exact versions before writing
  code (getrandom `fill`, tracing-appender `NonBlockingBuilder`/`ErrorCounter`, prometheus-client
  `Collector`/`DescriptorEncoder`, toml `Table::try_into`, hyper `http1::Builder`, rustls
  `ServerConfig::builder_with_provider`, pki-types `PemObject`, rcgen `Issuer`/`CertifiedIssuer`,
  x509-parser `parse_x509_pem`). `cargo deny` (advisories, licences, bans incl. no OpenSSL,
  sources) and `cargo audit` clean; `cargo vet`: 38 crates fully audited through imported audit
  sets (Mozilla, Google, Bytecode Alliance, ISRG, Zcash, Embark), 129 exempted and listed in
  `supply-chain/config.toml` (burn-down is an open risk, report P01). Reduced to 57 by D-0016.
- Decision (version, reason): tokio 1.54.1 (runtime, locked stack); rustls 0.23.46 + aws-lc-rs
  1.19.0 / aws-lc-sys 0.47.0, tokio-rustls 0.26.6, rustls-pki-types 1.16.0 (TLS, locked stack);
  mimalloc 0.1.52 (allocator, locked stack); tracing 0.1.44, tracing-subscriber 0.3.23,
  tracing-appender 0.2.5 (logging); prometheus-client 0.26.0 (metrics); hyper 1.12.0, hyper-util
  0.1.21, http-body-util 0.1.5, bytes 1.12.1 (admin endpoint); serde 1.0.229, toml 1.2.1
  (configuration); thiserror 2.0.21 (error types); getrandom 0.4.3 (ID randomness straight from
  the OS); hex 0.4.3 (ID text form off the hot path); zeroize 1.9.1 (secrets wiped on drop);
  rcgen 0.14.10, x509-parser 0.18.1, time 0.3.55 (CA tool); clap 4.6.7, anyhow 1.0.104 (CLI only);
  proptest 1.12.0, tempfile 3.27.0 (tests); libfuzzer-sys 0.4 (fuzz crate, outside the workspace).
- Consequences: the server stack takes no OpenSSL (enforced by `deny.toml`).

## D-0003 — Identifiers: 16 random bytes, typed, redacted

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: Prompt 1: IDs as 16-byte random values; invariant 6.
- Options considered: UUIDv4/v7 crates; ULIDs; plain random bytes.
- Evidence: `crates/types/src/id.rs` tests (round trips, wrong lengths rejected without
  allocation, `Debug` prints only the kind); `id_parse` fuzz target.
- Decision: `Id<K>` over `[u8; 16]` from `getrandom::fill`; kinds via `define_id!`; no timestamp
  or host data inside (v7-style IDs would leak creation time); `Debug` redacted, no `Display`;
  hex only through `to_hex_unredacted()`, which Semgrep forbids in log and format macros.
- Consequences: IDs are not time-sortable; ordering uses `seq`, never IDs.

## D-0002 — `crates/service`: one bootstrap for every service

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Context: five services need identical startup, health, metrics and shutdown; Prompt 1 lists
  only `types` and `telemetry`.
- Decision: `crates/service` provides `Service` and `main::<S>()`: CLI (`--config`,
  `--check-config`, `--version`), config load and validation, tracing, metrics, admin endpoint,
  SIGTERM/SIGINT drain with a configured grace period. It runs one current-thread Tokio runtime
  until `crates/runtime` (thread-per-core, Prompt 2) replaces it for the hot path.
- Consequences: Prompt 2 swaps the runtime under `run_service` without touching services.

## D-0001 — Workspace, toolchain and lints

- Date: 2026-11-11
- Status: accepted
- Decided by: agent
- Decision: Cargo workspace (resolver 3, edition 2024, `rust-version = 1.88`); toolchain pinned
  to 1.99.1 in `rust-toolchain.toml` (reproducible builds; bump deliberately and record);
  layout `crates/`, `services/` (delivery, api, push, worker, calls, proxy), `tools/` (loadgen,
  admin), `xtask/`, `deploy/`, `docs/`, `tests/`, `fuzz/` (outside the workspace, nightly).
  Workspace lints: `unsafe_code = "forbid"`; clippy pedantic plus restriction lints
  (`unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `as_conversions`, `print_*`,
  `dbg_macro`, `todo`, `unimplemented`, `allow_attributes_without_reason`, …); CI denies warnings.
  Release profile: fat LTO, one codegen unit, `panic = "abort"`, stripped; `profiling` profile for
  flamegraphs. The proxy lives in `services/proxy` because it is a deployable binary, though third
  parties run it.
- Consequences: tests may unwrap and index (`clippy.toml`); production code may not.
