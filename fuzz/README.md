# Fuzzing

Every decoder that touches untrusted input has a libFuzzer target here (constitution: cargo-fuzz on
every decoder). The crate is outside the main workspace because it needs nightly.

| Target | Decoder | Crate |
| --- | --- | --- |
| `client_hello` | inner TLS ClientHello SNI scanner | `songbird-proxy` |
| `proxy_link` | proxy link parser | `songbird-proxy` |
| `config_toml` | configuration file + environment overrides | `songbird-types` |
| `id_parse` | 16-byte IDs from bytes and hex | `songbird-types` |
| `registration_request` | registration request and invite codes (Prompt 3) | `songbird-proto` |
| `pow_challenge` | proof-of-work challenge and its MAC (Prompt 3) | `songbird-pow` |
| `ed25519_key` | Ed25519 public-key check (Prompt 3) | `songbird-keys` |
| `username` | username proof verification and parser (Prompt 3) | `songbird-keys` |
| `keypackages` | MLS KeyPackage checks; KeyPackage upload and fetch decoders (Prompt 3) | `songbird-keys`, `songbird-proto` |
| `prekeys` | key directory upload and bundle decoders; XEdDSA, X25519 and ML-KEM-1024 checks (Prompt 3) | `songbird-proto`, `songbird-keys` |
| `devices` | signed device list, link request and provisioning decoders; provisioning envelopes; WebAuthn checks (Prompt 3) | `songbird-proto`, `songbird-keys` |
| `profile` | profile upload and sender-certificate decoders (Prompt 3) | `songbird-proto` |
| `kt` | akd lookup, history and audit proof decoders and verification; signed heads (Prompt 3) | `songbird-akd` |
| `content` | padded plaintext and encrypted content decoders and validation (Prompt 4) | `songbird-content` |
| `franking` | franking stamps in front of envelopes; report bodies from M5 (Prompt 4) | `songbird-proto` |
| `mls_wire` | `PrivateMessage` prefix, commit bundle, `GroupInfo` signer (Prompt 5) | `songbird-groups` |
| `mls_commit` | commit bundles against a real post-quantum group; stored group records (Prompt 5) | `songbird-groups` |
| `attachment_decrypt` | the attachment format: header, commitment, chunks, padding; tampered ciphertexts (Prompt 6) | `songbird-content` |
| `upload_grant` | upload grant requests; parts covering an upload (Prompt 6) | `songbird-api` |
| `s3_multipart_xml` | the object store's multipart answers (Prompt 6) | `songbird-s3` |
| `media_url` | signed media URL queries; `Range` headers (Prompt 6) | `songbird-api` |
| `pack_manifest` | pack manifests: length prefix, padding, bounds (Prompt 6) | `songbird-content` |
| `gif_proxy` | GIF requests, the provider's answers, media tokens (Prompt 6) | `songbird-api` |

```bash
cargo xtask fuzz --secs 60            # every target, 60 s each (CI fast checks do not fuzz)
cargo xtask fuzz --secs 600 client_hello
```

Nightly CI runs each target for 10 minutes and uploads new corpus entries and any crash as
artifacts. Corpora live in `fuzz/corpus/<target>/`; seeds worth keeping are committed. Every crash
becomes a regression test in the owning crate before the fix lands (SECURITY.md).
