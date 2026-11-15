# libsignal reference vectors

Songbird implements Signal's protocols on permissive crates instead of linking libsignal, which
is AGPL-3.0-only (owner's decision, D-0047). This tool is how the implementations are proven
byte-compatible. It is **not** in the workspace, CI never builds it, and nothing it links ships.

```bash
git clone https://github.com/signalapp/libsignal.git ../libsignal   # next to this repository
cd tools/libsignal-vectors
cargo run --release                     # SHO sequence; libsignal username hashes and proofs
cargo run --release --bin songbird -- <generator> <hash> <proof>   # poksho checks Songbird's
```

The username crate's `build.rs` needs `protoc` for an unrelated protobuf (username links);
without it, replace `rust/usernames/build.rs` with `fn main() {}` and write the two-field
`UsernameData` message by hand in `rust/usernames/src/proto/username.rs` in your scratch copy.

Used at libsignal commit `8be00c2` (2026-11-13). Outputs are checked in as test data:
`crates/keys/tests/username_vectors.rs` and `username_vector.txt`.
