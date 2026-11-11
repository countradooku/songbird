# Integration and chaos tests

Cross-service suites that run against the docker compose environment
(`cargo xtask compose up`). Prompt 2 adds one named test per invariant, the end-to-end delivery
checker and the chaos suite here. Unit, property and per-crate integration tests live next to the
code they test (`crates/*/tests`, `services/*/tests`, `tools/*/tests`).
