# Prompt 13 — Performance, reliability and disaster-recovery certification

*File: `docs/prompts/13-certification.md` · Skills: performance engineering, benchmarking, reliability and chaos engineering, infrastructure as code. Run before every release.*

**Goal:** prove, with reproducible numbers and timed drills, that the whole backend is as fast and as resilient as claimed, and keep it that way.

**Build and run:**

- **Service-level objectives** for every user-visible path (send-to-deliver, connect, group commit, attachment upload and download, call join, push wake-up, backup and restore), each with a p99 target agreed with the owner and a dashboard.
- **Benchmark suite** (`cargo xtask bench`): every service and path, on fixed reference hardware, with flamegraphs and allocation profiles, compared against the stored baseline and against Sockudo for the WebSocket path. CI fails on a regression of more than 10%; `iai-callgrind` instruction counts guard hot functions deterministically.
- **Load scenarios** with the delivery checker: idle connections at scale, steady 1:1 traffic, 1,024-member groups, large private channels, call rooms at capacity, a reconnect storm of every connection, and a 24-hour soak with memory and latency drift reported.
- **Chaos:** kill nodes of every service under load; restart Valkey; pause and fail over the database; break Garage; simulate APNs, FCM and LiveKit outages; add latency and packet loss between nodes. The checker must pass and recovery times must meet the objectives.
- **Disaster recovery** exactly as specified in section 6 of the [Realtime Master Build Prompt](02a-realtime-master.md), extended to every service: failure matrix with runbooks, encrypted immutable off-site backups, daily automated restore verification, `store_generation` resend, and a full rebuild at the second EU provider.
- **Drills:** monthly timed restore; quarterly game day covering the failure matrix; results recorded in `docs/RUNBOOKS/drills.md`.
- **Capacity planning:** a sizing table (connections, messages per second, call participants, storage) per server type, derived from the benchmarks, used to decide when to add nodes or move SurrealDB to TiKV.
- **Release checklist:** all prompt gates still green, benchmark and chaos results attached, SBOM and reproducible-build proof, audit findings closed.

**Gate (and definition of done for the whole set):** every objective met or formally accepted by the owner; a timed DR drill met the recovery targets with zero lost messages; the release checklist passes from a clean checkout with one command.
