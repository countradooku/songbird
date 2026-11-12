# Prompt 1 — Foundations and platform

*File: `docs/prompts/01-foundations.md` · Skills: Rust workspace and CI, infrastructure as code, security review.*

**Goal:** a repository, pipeline and environment where every later prompt can build, test, benchmark and deploy safely.

**Build:**

- Cargo workspace with the layout `crates/` (shared libraries), `services/` (`delivery`, `api`, `push`, `worker`, `calls`), `tools/` (`loadgen`, `admin`), `deploy/`, `docs/`, `tests/`, plus an `xtask` crate for repeatable commands (`cargo xtask ci`, `bench`, `fuzz`, `release`).
- `crates/types` (IDs as 16-byte random values, errors, configuration loading with validation) and `crates/telemetry` (tracing with a non-blocking writer, Prometheus metrics, a redaction layer that refuses known sensitive field names).
- Docker compose for local and CI: SurrealDB, `valkey-hot`, `valkey-jobs`, RustFS, LiveKit, with health checks.
- CI running the full quality bar from the constitution, split into fast checks (every push) and deep checks (nightly: sanitizers, long fuzz runs, full benchmarks).
- Infrastructure as code in `deploy/` (OpenTofu plus NixOS or Ansible) able to build a complete environment at Hetzner and, unchanged apart from provider variables, at a second EU provider.
- Secrets with SOPS and age (or OpenBao), never in plain files; documented rotation.
- Release pipeline: reproducible builds, signed artifacts, SBOM per release, staged rollout with automatic rollback on failed health checks.
- `docs/DECISIONS.md`, `docs/THREAT_MODEL.md` skeleton, `docs/RUNBOOKS/`, `docs/PROTOCOL.md` skeleton.

**Also build (WhatsApp parity): censorship-resistant proxy.** A small, separately deployable TLS proxy (in the style of Signal's and WhatsApp's proxy support) that anyone can run to relay Songbird traffic in countries that block it. It forwards encrypted bytes only, logs nothing, and is configured in the app by a proxy link. Ship it as a container image with documentation.

**Security:** private network for every internal service; firewall allowing only client ports; mutual TLS certificate authority for service-to-service traffic, with rotation scripted from day one.

**Gate:** CI green on an empty service of each kind; a full environment builds from scratch with one command, and is torn down and rebuilt at the second provider in a timed run; every pinned dependency verified and recorded.
