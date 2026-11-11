# Fuzzing

Every decoder that touches untrusted input has a libFuzzer target here (constitution: cargo-fuzz on
every decoder). The crate is outside the main workspace because it needs nightly.

| Target | Decoder | Crate |
| --- | --- | --- |
| `client_hello` | inner TLS ClientHello SNI scanner | `songbird-proxy` |
| `proxy_link` | proxy link parser | `songbird-proxy` |
| `config_toml` | configuration file + environment overrides | `songbird-types` |
| `id_parse` | 16-byte IDs from bytes and hex | `songbird-types` |

```bash
cargo xtask fuzz --secs 60            # every target, 60 s each (CI fast checks do not fuzz)
cargo xtask fuzz --secs 600 client_hello
```

Nightly CI runs each target for 10 minutes and uploads new corpus entries and any crash as
artifacts. Corpora live in `fuzz/corpus/<target>/`; seeds worth keeping are committed. Every crash
becomes a regression test in the owning crate before the fix lands (SECURITY.md).
