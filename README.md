# Songbird

Songbird is a European end-to-end encrypted messenger: 1:1 and group chats, channels, voice and
video calls, and a few Yahoo Messenger-style touches. The server never sees message content; it
stores and relays opaque, client-encrypted bytes, and it runs on EU hosting only.

This repository holds the **backend only** for now: the Rust services and the shared crates that
define the backend's contract with future apps (wire protocol, encrypted content schemas, backup
format, and a Rust test client). The mobile and desktop apps come later.

## Where to start

- [Constitution](docs/prompts/00-constitution.md): privacy model, invariants, locked stack and quality bar. Read it before any task.
- [Decisions](docs/DECISIONS.md): every recorded decision, with benchmark numbers.
- [Prompt set](docs/prompts/README.md): the build plan, one prompt per area, each ending at a gate.
- [Threat model](docs/THREAT_MODEL.md), [protocol](docs/PROTOCOL.md) and [runbooks](docs/RUNBOOKS/README.md).
- [Security policy](SECURITY.md): how to report a vulnerability.

## Status

Prompt 1 (foundations and platform) is built and waiting at its gate: see
[the report](docs/reports/P01-foundations.md). Services are empty shells that start, report health
and metrics, and drain; Prompt 2 builds the realtime delivery core.

```bash
cargo xtask ci            # the full fast quality bar, as CI runs it
cargo xtask compose up    # SurrealDB, valkey-hot, valkey-jobs, RustFS, LiveKit on localhost
cargo xtask smoke         # start every service, check health and metrics, stop cleanly
cargo xtask help          # everything else (fuzz, bench, release, sanitize, miri)
```

Infrastructure and operations: [deploy/](deploy/README.md). Running a censorship-resistant proxy:
[deploy/proxy](deploy/proxy/README.md).

## Licence

No licence has been chosen yet, so all rights are reserved for now. A licence will be chosen
before the code goes public.
