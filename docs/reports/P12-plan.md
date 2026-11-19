# P12 — Security hardening and verification: plan, milestones and gates

- Date: 2026-11-19
- Prompt: [12-security.md](../prompts/12-security.md)
- Status: **proposed, waiting for the owner** (D-0135).
- Base: branch `claude/p12-security-f5d816`, cut from `main` after Prompt 11's merge (PR #70,
  `7df7474`).
- Way of working (as Prompts 7 to 11): one branch and one PR. Each milestone gets its own
  commit, tests, report `docs/reports/P12-Mn.md`, decision record (D-0136 onward) and
  threat-model rows marked "awaiting the owner's approval". Then `cargo xtask ci fast`, the live
  suites (one heavy job at a time, `-j 1`, or `-j 2` for stores and e2e, with the environment of
  `ci.yml`'s compose job, without Iggy locally), an independent read-only security review of the
  whole diff by a separate agent given the code and not my conclusions, and
  `docs/reports/P12-gate.md`. Nothing is merged without the owner.
- Skills: `security-review` for the independent review (M8). No skill covers Tamarin, ProVerif,
  Kani, hax, loom, shuttle, AFL++, dudect, cargo-vet auditing or testssl.sh; I read each tool's
  manual and the exact pinned versions' sources instead. `nsh` and `nsh-design-guides` are not
  needed: no milestone changes `apps/ui` screens (the delegated-key check of M6 lives in
  `crates/client`, which the app already uses). A `songbird-invariants` review checklist under
  `.claude/skills/` (constitution) is proposed again: M7's findings register and threat-model
  checker are most of its content.

## What Prompt 12 starts from

| The prompt asks for | Already there | Missing |
| --- | --- | --- |
| A complete threat model: per component, STRIDE against seven attackers, each threat with its mitigation and the test or proof covering it | `docs/THREAT_MODEL.md` (939 lines): §1 what the server may see, §2 the seven attackers, §3.1–§3.28 one STRIDE table per component as each prompt built it, §4 server-enforced settings, §5 compliance, §6 open risks. Its header still says "Skeleton. Completed in Prompt 12" | A per-component check that **every attacker** was considered; a mechanical check that every "test or proof" cell names something that exists; rows whose cell says only "code review", "residual risk" or a decision number (about 20) get a test or move to §6 as an accepted risk; components never tabled on their own (`songbird-admin` and staff access, observability, `deploy/`'s hosts as a whole) |
| Formal models (Tamarin or ProVerif) of device linking, sealed-sender certificates, the store-generation resend rule, the call key schedule, backup key derivation and vault access; hax where practical; Kani for decoders and the `seq` and dedupe logic | Test vectors cross-checked with independent implementations (OpenSSL, Python, libsignal and OpenMLS scratch tools); property tests (`proptest`) of `seq` ordering and decoders | **No formal model, no Kani harness, no hax.** None of Tamarin, ProVerif, Maude, Kani or hax is installed locally or in CI |
| Continuous fuzzing of every decoder and state machine in CI (ClusterFuzzLite or equivalent), stored corpora, coverage targets; AFL++ before releases | 37 libFuzzer targets (`fuzz/`), 35 run nightly for 10 minutes each (`nightly.yml`); committed seeds for 9 targets; crashes and new corpus entries uploaded as 14-day artifacts | Corpora that persist between runs; coverage measured and held; fuzzing on pull requests; **stateful** targets for the state machines (delivery session, mailbox ACK window, vault write session, call lobby, entitlement snapshot); AFL++; `storage` and `backup_format` missing from the nightly matrix; an agreed CPU-hour budget |
| Miri for any `unsafe`; ASan and TSan nightly; loom and shuttle for every lock-free component; `cargo-geiger` over the whole tree | Miri on `songbird-types` and the one `unsafe` crate (`alloc-count`, D-0033); ASan and TSan nightly over the whole workspace (`cargo xtask sanitize`). `unsafe` also lives in `apps/camera`'s platform modules (D-0110) | **No loom or shuttle.** Lock-free components to cover: `arc-swap` snapshots (`send/directory.rs`, `entitlements`), sharded atomics (`telemetry/sharded.rs`, `metrics.rs`), the router's subscription table, the runtime's per-core state, the proxy's connection counters, the mailbox's in-flight window. No geiger report; Miri runs on 2 of 26 crates |
| Constant-time checks of secret comparisons (dudect-style statistical tests) | 34 call sites compare secrets with `ct_eq`, `verify_slices_are_equal` or `subtle`, several hand-written (`send/src/lib.rs:814`) | Any timing measurement; one shared helper; a check that no secret is compared with `==` |
| `cargo-vet` audits for every cryptographic and networking dependency; `cargo-deny`; an SBOM per release; an independent rebuild proving reproducibility | cargo-deny (advisories, licences, bans, sources), cargo-audit, cargo-vet with six imported audit sets; `cargo xtask release` builds twice and compares, writes `SHA256SUMS` and a CycloneDX SBOM, cosign and SLSA provenance (D-0013) | **0 audits of our own; 411 exemptions, about 125 of them cryptographic or networking crates** (`aws-lc-rs`, `rustls`, the `dalek` crates, `libcrux-*`, `openmls*`, `ml-kem`, `ml-dsa`, `hpke-rs*`, `sockudo-ws`, `redis`, `reqwest`, `tower-http` …). Both reproducibility builds run on one runner: not independent |
| Server signing keys in hardware-backed storage where the provider offers it; rehearsed rotation and compromise procedures | Signing keys are `SecretRef`s decrypted from SOPS: the sender-certificate key (`[api.profiles] certificate_key`), the system-notice key (`system_key`), the key-transparency log's head key, the token secret shared by billing and `api`; runbooks for mTLS and secrets rotation | Hetzner (D-0042) offers **no HSM or KMS**. No offline root, no delegation, no rotation drill for these keys; the token key list is not in the transparency log (proposed in D-0128) |
| Provider DDoS protection and application limits; TLS verified with `testssl.sh`; no unnecessary ports, headers or banners | GCRA budgets everywhere, connection caps and accept-rate limits (§3.5, §3.5.1); two firewall layers (§3.2); rustls with aws-lc-rs | No `testssl.sh` run; no test of response headers or banners; no listening-port inventory checked against the firewall; Hetzner's DDoS protection undocumented |
| Audit readiness: a package for an external firm, a bug-bounty policy and safe harbour, every vulnerability a permanent regression test | `SECURITY.md` (private reporting; bounty "before the public beta (Prompt 12)"); `docs/PROTOCOL.md`; nine "security review's fixes" decisions (D-0074 to D-0134) and earlier reviews' fixes inside milestone decisions, each with tests | The package; the policy and safe-harbour text; **one register of every finding** with its regression test, checked mechanically |
| Carried to Prompt 12 by earlier prompts | — | Sealed sender verified before it is switched on (D-0054, P03); least-privilege SurrealDB users instead of root (D-0025); a least-privilege Iggy user (§6); the token key list in the transparency log (D-0128) |

## Findings that shape the plan

1. **"No uncovered threat" can be checked by a program, so it should be.** A prose review of
   939 lines will drift the next time a prompt adds a table. Recommended: `cargo xtask
   threat-model` parses every §3 table and fails when a row's "test or proof" cell names no test
   function, fuzz target, Kani harness, formal lemma, loom or shuttle model or file that exists in
   the tree; when a cell says only "residual risk" or "code review" without a §6 entry; and when
   a component's **attacker matrix** (a new table at the head of each §3 subsection: the seven
   attackers, each with its rows or a one-line "not applicable because …") has a gap. It runs in
   `ci fast`, so every later prompt keeps the model complete.

2. **Tamarin for the stateful protocols, ProVerif for the two privacy properties.** Four of the
   five named protocols are about state over time (a provisioning code used once, a
   `store_generation` that only moves forward, a vault generation, a call key that ratchets on
   membership changes); Tamarin's multiset rewriting and its lemmas over traces fit them, and it
   is what the MLS and Apple PQ3 analyses used. Two properties are **unlinkability**: a sealed
   sender's anonymity towards the server, and Prompt 11's token issuance against redemption.
   Those are observational equivalence, which ProVerif proves far more automatically
   (`diff`/`choice`). Every model gets:
   - **sanity lemmas** (an honest run can complete; `exists-trace`), so a model that proves
     everything because nothing can happen fails;
   - a **mutant**: the same model with the defence removed (the code not burnt, the generation
     check dropped, the delegation not checked), which must **fail** in CI;
   - a **correspondence table** from each rule to the Rust function it models, checked by the
     threat-model tool (finding 1) so a renamed function breaks the build.
   Models are of the protocol as specified in `PROTOCOL.md` and implemented; cryptographic
   primitives are ideal (Dolev–Yao), as usual. Pinned versions: Tamarin 1.10 with Maude 3.4,
   ProVerif 2.05, both installed in CI from checksum-verified release archives.

3. **hax is not practical for this code yet; Kani is.** hax extracts F\* and (experimentally)
   ProVerif from a restricted Rust subset; our protocol code uses async, traits over stores and
   `curve25519-dalek` types it cannot take. Recommended: one measured experiment (backup key
   derivation, a pure function, to F\*), recorded either way, and no dependency on it. **Kani**
   (bounded model checking, runs on the real code) gives proofs where the prompt asks for them:
   every hand-written decoder never panics, never reads out of bounds and never allocates more
   than its declared bound for inputs up to a stated size; the per-device `seq` assignment is
   strictly increasing without gaps; the client's dedupe window never delivers one `seq` twice
   and never drops a new one; the idempotency fingerprint scoping. Harnesses sit under
   `#[cfg(kani)]` in each crate (no `unsafe`, no new runtime dependency).

4. **Lock-free components need models, not more stress tests.** Recommended: **shuttle**
   (randomised and PCT schedules, works through `shuttle::sync` shims behind `cfg(shuttle)`) for
   the composite components (snapshot reload with readers, the router table, the in-flight
   window), and **loom** (exhaustive, small state) for the primitives (sharded counters, the
   reload's version check, connection counters). Both are dev-dependencies only, behind a
   `cfg`, recorded as new dependencies. Miri extends to every crate whose tests run without
   sockets (about 14 of 26). `cargo-geiger` gives the tree's `unsafe` report, attached to the
   gate and regenerated per release.

5. **Corpora must outlive a run, without giving CI a write secret.** ClusterFuzzLite stores
   corpora in a git repository through a token with write access. D-0045 keeps secrets out of
   every workflow but `release.yml` and `deploy.yml`; a fuzzing workflow holding a write token
   that runs fuzzed code is exactly what it forbids. Recommended, as the "equivalent" the prompt
   allows:
   - nightly campaigns restore and save each target's corpus with `actions/cache` (saved on
     `main` only, as every cache), minimised weekly (`cargo fuzz cmin`);
   - **pull requests** fuzz, for 5 minutes each, the targets whose crates the PR changes (the
     same file-to-target map the README keeps, made machine-readable);
   - `cargo xtask fuzz --coverage` measures each target's line coverage of its own decoder
     module (`cargo fuzz coverage` and `llvm-cov`); a per-target floor, recorded from the first
     measurement, fails the nightly when coverage drops more than 2 points; targets under 70 %
     get seeds or a better harness in M4;
   - **stateful targets** for every state machine (M4's list), each driving the real code
     with a sequence of operations decoded from the input and checking it against a small
     reference model;
   - **AFL++** through `cargo afl` on the same harnesses (one macro, two engines), run in a Linux
     container before each release (`cargo xtask fuzz --engine afl`).

6. **Constant time is measured, not assumed.** A small dudect-style harness (Welch's t-test on
   two input classes, 10⁶ measurements, cropped percentiles, `|t| < 4.5`) as a test-only tool,
   about 200 lines and no dependency, run nightly on every secret comparison and on the token,
   MAC and franking verifications. Shared runners are noisy, so a nightly failure is re-run
   before it is believed; the gate's numbers come from this Mac with nothing else running. All
   34 call sites move to one `songbird_types::ct::eq` helper, and a Semgrep rule refuses `==` on
   the secret types (`Secret*`, MAC tags, nullifiers, proof keys).

7. **Supply-chain audits: import first, then audit what is left, honestly labelled.** About 125
   exempted crates are cryptographic or networking. Recommended order:
   1. import more audit sets already trusted by the Rust ecosystem (the cargo-vet registry:
      for example Ariel OS, Fermyon, ISRG's other repositories, the Rust project's own), which
      may cover many versions we exempt;
   2. bump to an audited version where a bump is free;
   3. **our own audits** for the rest, by the agent, reading each crate's diff from its nearest
      audited version (or the whole crate), with `safe-to-deploy` criteria and notes that say
      who looked and how ("agent review, D-01xx; owner sign-off pending") — never presented as
      a third-party audit. `aws-lc-rs` and `aws-lc-sys` (C and assembly) are not read line by
      line: their audit notes rely on AWS-LC's FIPS 140-3 validation, its own fuzzing and
      formal verification of parts of it, and imported audits, and say so.
   The exemptions that remain afterwards are only non-cryptographic, non-networking crates, and
   a CI check fails if a new cryptographic or networking crate arrives as an exemption.
   `cargo-deny` gains: `multiple-versions = "deny"` for cryptographic crates (two versions of a
   primitive is how a fix gets missed), and a ban on `git` dependencies already holds.

8. **An independent rebuild means another machine, not a second build.** `cargo xtask release
   --verify` builds twice on one runner. Recommended: a `rebuild` job in `release.yml` on a
   fresh runner, from a clean checkout of the tag, inside the same toolchain image pinned by
   digest, that compares its hashes with the published `SHA256SUMS`; and `deploy/bin/rebuild`,
   which anyone can run with podman. For the gate I run it on this Mac (x86-64 container under
   Rosetta) against the CI's build of a test tag: a different machine, operating system and
   CPU.

9. **Hetzner has no HSM, so the root goes offline and the online keys become short-lived.**
   Options for the sender-certificate key, the system-notice key and the transparency log's
   head key:
   - **(recommended) an offline root on the owner's security key, delegating to online keys.**
     One Ed25519 root per purpose, generated on and never leaving a hardware token the owner
     holds (a YubiKey 5 with firmware 5.7 or later, or a Nitrokey 3: both sign Ed25519 on the
     device). Apps pin the roots. Each online key (in SOPS, as now) carries a **delegation**
     signed by its root: purpose, public key, not-before, not-after (90 days), serial. Apps and
     `crates/client` check certificate → delegation → pinned root. The owner signs a new
     delegation every 60 days (`songbird-admin keys delegate`, a few minutes with the token
     plugged in); alerts fire 21 days before expiry. A stolen online key is useful for at most
     its delegation's life, and a published **revocation list** (signed by the root, fetched
     with the key list) ends it early.
   - a dedicated server with a YubiHSM 2: Hetzner Cloud cannot attach it and Hetzner dedicated
     servers take no customer hardware outside colocation.
   - keys in SOPS only, as now, with rehearsed rotation: a stolen key is good until the owner
     notices.
   The **token secret** (D-0128) stays symmetric and online (a VOPRF key must be online to
   evaluate); its exposure is bounded by the key per (level, month) and by publishing the key
   list in the transparency log (finding 11). Rotation and compromise of every key get one
   runbook (`docs/RUNBOOKS/signing-keys.md`) and a **live drill test**: rotate under traffic,
   old certificates verify until they expire, new ones verify at once, a revoked delegation is
   refused everywhere.

10. **Least privilege in the stores, carried since Prompt 2.** Every service signs in to
    SurrealDB as root (D-0025). Recommended: one database user per service and database
    (`DEFINE USER … ON DATABASE … ROLES EDITOR`, or `VIEWER` where a service only reads), so a
    compromised `api` cannot touch billing's or push's databases, define namespaces or read
    other databases; root kept for migrations, run by `songbird-admin` only. Valkey ACL users
    per service with only the key prefixes and commands each uses. An Iggy user for `delivery`
    with rights on its own stream only (tested in CI's compose job, which has Iggy; not
    locally).

11. **The token key list belongs in the transparency log.** Each month's public keys (per
    level) are inserted under a reserved label in the existing log; apps check inclusion and
    consistency before redeeming. A server that serves one user a key of its own (D-0128's
    tagging risk) must then also fork the log, which monitors detect.

12. **Sealed sender is ready to be verified, then switched on.** M2's two models (certificate
    authenticity in Tamarin; sender anonymity towards the server in ProVerif), the live suite
    with the delegated certificate key, and the stated residual risk (IP address and timing,
    §6). Recommended: switched on in staging after M6 and on by default once the owner approves
    the gate.

13. **Network hardening is mostly evidence.** `testssl.sh` (pinned, checksum-verified) in CI's
    compose job against every TLS listener (delivery, api, billing, calls signalling, proxy):
    TLS 1.3 only on client endpoints, TLS 1.2 kept only where a provider requires it (webhooks
    from Apple, Google and Mollie reach billing behind the edge); no compression,
    renegotiation, or weak groups; the results stored per release. A test sends one request to
    every HTTP route and fails on a `Server`, `X-Powered-By` or version banner, a missing
    `Strict-Transport-Security`, `X-Content-Type-Options: nosniff` or `Cache-Control: no-store`
    on authenticated answers. A port inventory (compose, Ansible's nftables rules, each
    service's listeners from its configuration) checked against one allowlist. DDoS: Hetzner's
    included protection, its limits documented in a runbook (to confirm with Hetzner), with the
    application's limits behind it.

14. **Every vulnerability ever found, in one register, checked.** Nine decisions record a
    security review's fixes (D-0074 to D-0134); earlier prompts record theirs inside milestone
    decisions. Recommended: `docs/security/findings.md`, one row per finding back to Prompt 1
    (ID, date, component, severity, the decision, its regression test), and `cargo xtask
    findings` fails if a listed test no longer exists. New findings, including the external
    audit's and the bounty's, are added the same way.

15. **The external audit is the owner's to commission.** I prepare the package
    (`docs/audit/`: architecture, threat model, `PROTOCOL.md`, the formal models and what they
    prove and assume, the test, fuzzing, Kani and model inventory generated by xtask, how to
    build, run and attack a local stack). The gate's audit item stays open until a firm's report
    exists with no unresolved high or critical finding, as Prompt 11's sandbox item waited for
    the owner's accounts.

## Milestones and gates

| | Builds | Gate |
| --- | --- | --- |
| **M1** | **The threat model completed and checked:** `cargo xtask threat-model` (finding 1) in `ci fast`; an attacker matrix per §3 subsection; new subsections for `songbird-admin` and staff access, observability (logs, metrics, alerts), and the hosts as a whole; every row whose cell names nothing real gets a test, or a §6 entry; the header's "skeleton" removed; THREAT_MODEL §2 defines each attacker's capabilities (what they hold, what they cannot do). | The checker passes on the tree and fails on a mutated copy (a renamed test, a removed row, an empty matrix cell): tests for each. Every §3 subsection has its matrix. Rows changed are listed in the report. |
| **M2** | **Formal models** (`formal/`): Tamarin — device linking and provisioning; sealed-sender certificates (with M6's delegation); the `store_generation` resend rule; the call key schedule; backup key derivation and vault access (Prompt 11's token sessions included). ProVerif — sealed sender's anonymity towards the server; token issuance and redemption unlinkability. Sanity lemmas, mutants, correspondence tables (finding 2). `cargo xtask formal` and a CI job (nightly, and on PRs that touch `formal/` or a modelled file). The hax experiment (finding 3). | Every lemma verified, every sanity lemma has a trace, every mutant fails, with run times on this Mac; the correspondence tables resolve; assumptions stated per model in `formal/README.md`. |
| **M3** | **Proofs and models on the code:** Kani harnesses (finding 3) for the hand-written decoders (`proto` frames, the CBOR subset, Iggy records, the system frame, attachments, the backup format, tokens) and for `seq` and dedupe; shuttle and loom models (finding 4); Miri over every socket-free crate; the `cargo-geiger` report. `cargo xtask kani` and `cargo xtask concurrency`; nightly jobs. | Every harness verified with its bound stated; each concurrency model run (shuttle: 10,000 schedules per test; loom: exhaustive within its bound) and a seeded bug caught by each; Miri clean; the geiger report in the milestone's report with every `unsafe`-using dependency named. |
| **M4** | **Continuous fuzzing** (finding 5): persistent corpora, PR fuzzing, coverage floors, stateful targets for the delivery session, mailbox ACK window, vault write session, call lobby, entitlement snapshot and moderation decisions; the two missing nightly targets; AFL++ through `cargo afl`. Then the **campaign**. | Every decoder and state machine in the inventory has a target (a test compares the inventory with `fuzz/fuzz_targets`); coverage per target recorded; **the agreed CPU-hours** (question 3) run clean on this Mac, libFuzzer and AFL++, every crash fixed with a regression test first. |
| **M5** | **Constant time and the supply chain:** the dudect harness and one `ct::eq` (finding 6) with the Semgrep rule; cargo-vet: imports, bumps, our own audits, the CI check on new crypto exemptions (finding 7); `cargo-deny` tightened; the independent rebuild job and `deploy/bin/rebuild` (finding 8). | Every secret comparison measured, `|t| < 4.5`, with a deliberately leaky comparison caught by the same harness; no cryptographic or networking crate left as an exemption; the rebuild on this Mac matches the CI build's hashes bit for bit. |
| **M6** | **Keys and least privilege:** offline roots and delegations (finding 9) in `crates/keys` and `crates/client`, `songbird-admin keys` (generate on the token, delegate, revoke), the signing-keys runbook and the live rotation drill; the token key list in the transparency log (finding 11); SurrealDB, Valkey and Iggy users per service (finding 10); sealed sender verified (finding 12). PROTOCOL updated. | The drill test: rotation under traffic with no failed send; expired and revoked delegations refused by `crates/client`; a key not in the log refused before redemption; each service's live suite passes under its own user, and the same user is refused on another service's database, key prefix or stream (tests); sealed sender's live suite with delegated certificates. |
| **M7** | **Network hardening and audit readiness:** `testssl.sh`, header and banner tests, the port inventory, the DDoS runbook (finding 13); `docs/security/findings.md` and `cargo xtask findings` (finding 14); `docs/audit/` and the generated inventory (finding 15); `SECURITY.md` with the bounty policy, safe harbour and reward table (question 8); `cargo xtask security`, one command for every check of this prompt, for each release. | `testssl.sh` clean on every listener; header tests pass on every route; inventory matches the firewall; every finding since Prompt 1 has a test that exists; the audit package builds; `cargo xtask security` passes from a clean checkout. |
| **M8** | **The gate:** the independent security review of the whole diff; fixes with tests; `P12-gate.md`. | The prompt's gate item by item. **Open until the owner acts:** the independent external audit (question 9). |

Order: M1 first (it lists what the others must cover). M2, M3 and M5 need only M1. M4 needs M3's
decoder inventory. M6 needs M2's sealed-sender and delegation models. M7 needs M1 and M5. M8
needs everything. M2 and M3 could run in parallel sessions; recommended sequentially (one PR,
shared files in `xtask` and CI).

## Threat-model rows this plan will propose

- **§1:** nothing new the server sees. Changed: the signing keys' delegations and revocation list
  (public); the token key list in the transparency log (public); per-service database, Valkey
  and Iggy users (credentials, not data).
- **§2:** each attacker's capabilities spelled out.
- **§3:** an attacker matrix per subsection; new subsections §3.29 (staff and `songbird-admin`),
  §3.30 (observability), §3.31 (hosts and network edge), §3.32 (signing keys and their
  delegation); rows re-pointed at the models, harnesses and fuzz targets that now cover them.
- **§6:** what the formal models assume (ideal primitives, no side channels, the bounded sizes of
  each Kani proof); a stolen online signing key is valid until its delegation expires or is
  revoked; Hetzner's DDoS limits; the external audit still to come.

## For the owner

The recommended answer comes first. One word ("approve all") takes every recommendation, as in
Prompts 4 to 11.

1. **Scope.** Recommended: the milestones above. The alternative: M1, M3, M4, M5 and M7 now, the
   formal models (M2) and keys (M6) in a second pass before release.
2. **Formal tools.** Recommended: Tamarin for the five stateful protocols, ProVerif for the two
   unlinkability properties, mutants that must fail, hax as an experiment only (findings 2, 3).
   The alternative: one tool (Tamarin, with its weaker automation for equivalence).
3. **Fuzzing budget ("the agreed CPU-hours").** Recommended for this gate: **2 CPU-hours per
   target with libFuzzer and 1 with AFL++**, about 130 CPU-hours for the 43 targets M4 will have
   (about 8 hours on this Mac's 18 cores); each release campaign the same; coverage floors per
   target; corpora kept with `actions/cache`, fuzzing on PRs, no write secret in CI (finding 5).
   The alternatives: a larger budget on rented Hetzner machines (an owner cost), or
   ClusterFuzzLite with a corpus repository and a write token in a fuzzing workflow (changes
   D-0045).
4. **Server signing keys.** Recommended: offline Ed25519 roots on your hardware token, 90-day
   delegations renewed every 60 days, a signed revocation list (finding 9). **Which token do you
   have or prefer** (YubiKey 5 with firmware ≥ 5.7, or Nitrokey 3)? Two are recommended: one in
   use, one as a sealed backup in another place. Until you have it, M6 is built and tested with a
   software stand-in for the token, and production keeps today's SOPS keys. The alternatives:
   SOPS keys with rehearsed rotation only; a YubiHSM 2 in colocation.
5. **Supply-chain audits.** Recommended: import further audit sets, bump where free, then
   agent-written `safe-to-deploy` audits labelled as such, for you to sign off; `aws-lc-rs`
   audited on its FIPS validation and its own verification, not line by line (finding 7).
6. **Least privilege and sealed sender.** Recommended: per-service SurrealDB, Valkey and Iggy
   users, root only for migrations through `songbird-admin` (finding 10); sealed sender on by
   default once this gate is approved (finding 12).
7. **The token key list in the transparency log.** Recommended: yes (finding 11).
8. **Bug bounty.** Recommended: publish the policy and safe-harbour text now (based on the
   disclose.io core terms), reports through GitHub's private reporting, rewards paid by you;
   move to an EU platform (Intigriti, Belgium, or YesWeHack, France) at the public launch.
   **Reward table:** recommended critical €5,000–10,000, high €1,500–5,000, medium €300–1,500,
   low a thank-you; or name your own.
9. **External audit.** Yours to commission, after this gate and Prompt 13's, before the public
   beta. Recommended: an EU application and backend firm (Cure53, Berlin; X41 D-Sec, Aachen;
   Radically Open Security, Amsterdam; or Quarkslab, Paris) for the services, plus a
   cryptography-focused review (NCC Group's cryptography services or Trail of Bits) of the
   protocol glue, the tokens and the backup format. The package (finding 15) is written for
   either.
10. **Agent decisions, recorded unless you object:**
    - `cargo xtask threat-model` in `ci fast`, so every later prompt keeps the model complete;
    - Tamarin 1.10 with Maude 3.4 and ProVerif 2.05, installed in CI from checksum-verified
      archives; a nightly job and PR runs on changes;
    - Kani, shuttle and loom as dev-only tools behind `cfg`, recorded as dependencies;
    - Miri on every socket-free crate;
    - our own dudect harness (no dependency) and one `ct::eq` helper with a Semgrep rule;
    - PR fuzzing of changed targets for 5 minutes each; coverage floors that fail on a drop of
      more than 2 points;
    - `multiple-versions = "deny"` for cryptographic crates; a CI check against new cryptographic
      or networking exemptions;
    - the rebuild job on a separate runner and `deploy/bin/rebuild`;
    - one register of every security finding since Prompt 1, checked by `cargo xtask findings`;
    - `cargo xtask security` as the release's one command for this prompt;
    - one branch and one PR for every milestone.
