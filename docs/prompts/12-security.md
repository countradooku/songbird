# Prompt 12 — Security hardening and verification

*File: `docs/prompts/12-security.md` · Skills: security review, threat modelling, fuzzing, formal methods, applied cryptography. Run early, then before every release.*

**Goal:** turn "virtually unbreakable" into evidence: a complete threat model, proofs where they matter, continuous fuzzing, and an external audit with nothing serious left open.

**Build and run:**

- **Threat model** (`docs/THREAT_MODEL.md`): per component, STRIDE analysis against these attackers: network attacker, malicious client, malicious group member, compromised server or operator, legally compelled provider, insider, supply-chain attacker. Each threat names its mitigation and the test or proof that covers it.
- **Formal models** (Tamarin or ProVerif) for Songbird-specific protocol glue: device linking and provisioning, sealed-sender certificates, the store-generation resend rule, the call key schedule, backup key derivation and vault access. Where practical, use hax to extract verifiable models from the Rust code; use Kani for bounded proofs of decoders and the `seq` and deduplication logic.
- **Continuous fuzzing:** every decoder and state machine, in CI (ClusterFuzzLite or equivalent) with stored corpora and coverage targets; AFL++ campaigns before releases.
- **Memory and concurrency safety:** Miri for any `unsafe`; ASan and TSan nightly; `loom` and `shuttle` for every lock-free component; a `cargo-geiger` report of unsafe code in the whole dependency tree.
- **Constant-time checks** for secret comparisons (statistical timing tests in the style of dudect).
- **Supply chain:** `cargo-vet` audits for every cryptographic and networking dependency, `cargo-deny` policy, SBOM per release, and an independent rebuild proving builds are reproducible.
- **Key management:** server signing keys (sender certificates, key-transparency log) in hardware-backed storage where the provider offers it, with documented, rehearsed rotation and compromise procedures.
- **Network hardening:** provider-level DDoS protection plus application-level limits; TLS configuration verified with `testssl.sh`; no unnecessary ports, headers or banners.
- **Audit readiness:** a package for an external firm (architecture, threat model, protocol spec, test and proof inventory); a bug-bounty policy and safe-harbour text; every vulnerability ever found becomes a permanent regression test.

**Gate:** threat model has no uncovered threat; formal models verified; fuzzing clean for the agreed CPU-hours; an independent audit completed with no unresolved high or critical findings.
