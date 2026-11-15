# OpenMLS reference KeyPackages

The server checks MLS KeyPackages with its own focused parser (`crates/keys/src/mls.rs`); the
owner chose that over running OpenMLS on the server (D-0051). This tool makes KeyPackages with
OpenMLS 0.9.2 so the parser is tested against the reference Rust implementation. It is not in
the workspace and CI never builds it.

```bash
cd tools/openmls-vectors
cargo run --release > ../../crates/keys/tests/openmls_keypackages.txt
```

Output: a `now` line (Unix seconds), then one line per package: label, ciphersuite, the
TLS-serialized KeyPackage and its `KeyPackageRef`, in hex. Every basic credential's identity is
16 × `d1`. The packages expire after OpenMLS's default lifetime; the tests check them at `now`.
