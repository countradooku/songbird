# Threat model

Skeleton. Completed in Prompt 12; every prompt adds the threats for what it builds.

## 1. What the server may see

The exhaustive list of data the server may hold in plaintext. Anything not listed must not reach the
server in plaintext. Adding to this list requires the owner's approval.

| Data | Why the server needs it | Retention | Introduced by |
| --- | --- | --- | --- |
| _Nothing yet: Prompt 1 services handle no user data._ | | | |

Prompt 1 adds two operational views, neither of which is user data on the server:

- **Aggregate metrics** on the private admin endpoint: counts and build information only. Metric
  and label names are checked against the redaction rules (D-0005); no per-device or
  per-connection labels.
- **Proxy operators** (third parties running `songbird-proxy`) see the IP addresses of people who
  connect to their proxy and when, but no content and no Songbird identifiers. This is outside
  Songbird's servers and is stated plainly in `deploy/proxy/README.md`.

## 2. Attackers

- Network attacker
- Malicious client
- Malicious group member
- Compromised server or operator
- Legally compelled provider
- Insider
- Supply-chain attacker

## 3. Components (STRIDE)

One subsection per component. Each threat names its mitigation and the test or proof that covers it.

### 3.1 Build, CI and supply chain (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Malicious or compromised crate | T, E | Supply chain | `Cargo.lock` + `--locked`; cargo-deny (advisories, licences, crates.io only, no OpenSSL), cargo-audit, cargo-vet (imported audits; exemptions listed) | `cargo xtask ci fast`; D-0004 |
| Retagged action or image | T | Supply chain | Actions pinned by commit SHA; images by digest; tool downloads checksum-verified | `.github/workflows/*`, `deploy/bin/install-tools`; D-0007, D-0008 |
| Tampered release artifact | T, S | Supply chain, insider | Reproducible build checked twice; cosign keyless signature on `SHA256SUMS`; SLSA provenance and SBOM attestations; signed images; deploy verifies before rollout | `cargo xtask release --verify`; `deploy/bin/verify-release`; D-0013 |
| Workflow token abuse | E | Malicious PR | Default `contents: read`; write scopes only on release/deploy jobs; `persist-credentials: false`; deploy needs environment approval | workflow files; CodeQL `actions` analysis |
| Secret committed to the repo | I | Insider (accident) | SOPS-only secrets; config files reject literal secrets; `.gitignore`; Semgrep `p/secrets` | `crates/types/src/secret.rs` tests; CI semgrep job |

### 3.2 Secrets and infrastructure (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Stolen OpenTofu state reveals infrastructure secrets | I | Provider, network | Client-side state and plan encryption; state stored at the other provider | `envs/*/main.tf` `encryption` block (enforced) |
| Exposed internal service | I, T, E | Network | Two firewall layers (provider + nftables default drop); internal ports only from the private range; host networking keeps nftables authoritative | `modules/topology/tests/topology.tftest.hcl`; `nft -c` validation at deploy |
| SSH brute force or key theft | S, E | Network | SSH only on the bastion, only from admin ranges (never 0.0.0.0/0, enforced by validation); keys only, no passwords | topology tests; cloud-init `sshd_config` |
| Lateral movement between services | S, E | Compromised host or component | Mutual TLS with per-component leaves from a name-constrained intermediate; Valkey requires client certificates; Garage behind mTLS tunnels; containers non-root, read-only, no capabilities | `tools/admin/tests/mtls.rs`; D-0012 |
| CA key theft | S | Insider, compromised CI | Root key owner-only and offline; intermediate in deploy secrets, decrypted only into a temporary directory during rotation; leaves ≤ 30 days | `deploy/ansible/rotate-certs.yml`; runbook `mtls-rotation.md` |

### 3.3 Service runtime common to every service (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Personal data in logs (invariant 6) | I | Insider, compromised log store | Redaction layer refuses sensitive field names per callsite; IDs and secrets redact themselves in `Debug`; Semgrep rules; smoke test and rollout fail if any callsite was refused | `crates/telemetry/tests/redaction.rs`; `id.rs`, `secret.rs` tests; `cargo xtask smoke` |
| Logging stalls request handling | D | Load | Non-blocking, lossy writer; drops counted | `songbird_telemetry_log_lines_dropped_total` |
| Admin endpoint abuse | I, D | Network (private) | Private address enforced in staging/production; header timeout, 8 KiB buffer, 32 headers, 64 connections, GET/HEAD only | `admin.rs` tests; `config.rs` tests |
| Malformed configuration or overrides | T, D | Operator error, compromised env | Size bounds before reading; unknown fields rejected; validation of every field; single-line overrides | `config.rs` tests; `config_toml` fuzz target |

### 3.4 Censorship-resistant proxy (Prompt 1)

| Threat | STRIDE | Attacker | Mitigation | Test or proof |
| --- | --- | --- | --- | --- |
| Proxy reads or alters traffic | I, T | Malicious proxy operator | Inner TLS is end to end between app and Songbird server; the proxy only sees ciphertext and the inner SNI | `services/proxy/tests/relay.rs` (nested TLS) |
| Proxy used as an open relay | E | Abuser | Inner-SNI allowlist of Songbird upstreams; anything else closed silently | `refuses_unknown_sni` test |
| Malformed ClientHello crashes or exhausts the proxy | D | Network | Bounded, allocation-free parser; scratch sized by configuration; handshake timeout; connection cap; idle timeout | `sni.rs` property tests; `client_hello` fuzz target; relay tests |
| Proxy identified by probing | I | Censor | Looks like an HTTPS server on the operator's domain (real certificate, ALPN h2/http1.1); non-TLS probes get nothing | `non_tls_probes_get_nothing` test. Residual risk: traffic analysis |
| Users' IPs logged by operator | I | Proxy operator | No logging code; operator compose disables Docker logs; documented honestly | `deploy/proxy/README.md` |
| Malicious proxy link | S, T | Phisher | Strict, bounded link parser; host in the URL fragment; app shows the proxy host before use (Prompt 9 UI requirement) | `link.rs` tests; `proxy_link` fuzz target |

## 4. Server-enforced settings

## 5. Compliance notes (GDPR, age of digital consent per EU country)

## 6. Open risks

- No certificate revocation for internal leaves yet; mitigated by 30-day lifetimes and intermediate
  rotation (runbook `mtls-rotation.md`).
- SurrealDB has server TLS and password authentication but no client-certificate authentication.
- cargo-vet: 129 of 167 crates are exempted rather than audited (report P01).
- Root SSH through the bastion (owner decision open, D-0014).
- The proxy is identifiable by traffic analysis; it is a reachability tool, not an anonymity tool.
