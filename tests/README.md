# Integration and chaos tests

- `tests/e2e`: the real `songbird-client` against an in-process `songbird-delivery` on loopback,
  one named test per invariant (`tests/e2e/tests/invariants.rs`: `inv1_…` to `inv9_…`) plus
  drain, overload, ephemeral and TLS tests. It is the only crate that depends on both server and
  client crates. Runs in `cargo xtask ci fast` (nextest).
- Load, chaos and reconnect-storm runs use `tools/loadgen` and its checker
  (`tools/loadgen/bench/m1.sh` reproduces the milestone 1 numbers).
- WebSocket conformance: `cargo xtask autobahn`.

Suites against the docker compose environment (`cargo xtask compose up`: SurrealDB, Valkey,
Garage) arrive with the SurrealDB mailbox (milestone 2) and Valkey routing (milestone 4).
Unit, property and per-crate integration tests live next to the code they test.
