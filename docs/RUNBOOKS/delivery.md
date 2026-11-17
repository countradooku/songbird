# Delivery service degraded modes (Prompt 2, milestone 1)

Metrics are on the private admin endpoint (`/metrics`, prefix `songbird_delivery_`). They are
aggregate counters only; nothing in them or in the logs identifies a device (invariant 6).

## Cores and threads (thread-per-core, D-0032)

- `delivery` runs one worker thread per core (`[delivery.runtime] workers`, 0 = every CPU the
  process may use), each pinned to its own CPU with its own listener on the same port
  (`SO_REUSEPORT`: the kernel spreads connections), plus the mailbox's threads
  (`storage_threads`, default one per Iggy partition) and the main control thread.
- On a single server, confine it so Iggy and the other stores keep their own cores: run it with a
  cgroup cpuset (the container's `cpuset`, systemd `AllowedCPUs=`) or `taskset`; pinning follows the
  allowed CPUs, in order.
  Give `workers` fewer CPUs than allowed so the mailbox threads have room.
- Logs at start: `websocket listeners bound cores=N pinned=true` and `mailbox runtime started
  storage_threads=M`. `cannot pin worker` means the CPU set changed under it: it runs unpinned
  (slower, still correct).
- Memory: about 26 KiB per idle connection (report P02-M3): size the host for the connection cap.
- Kernel settings (open files, `somaxconn`, `tcp_max_syn_backlog`, ephemeral ports) are in
  `deploy/`; with per-core listeners `backlog` applies to each core's listener.

## Several nodes (cluster mode, D-0034)

- Each mailbox partition has one owner node (it runs the writer) and two standbys (each holds a
  copy of its key store; the second in another `zone` when there is one). Leases live in the
  router's Valkey (`songbird:<stream>:<topic>:lease:<p>`), renewed every third of
  `lease_ttl_ms` (default 3 s); members in `songbird:<stream>:<topic>:members` (expiry on
  Valkey's clock). Nodes reach each other's partitions over node links (`[delivery.cluster]
  link_listen`, mutual TLS with the `delivery` leaf certificates). Give the topic several
  partitions per node (`partitions`, fixed when the topic is created): partitions are the unit
  of failover and of balance.
- **A node dies** (crash, host loss): its devices reconnect elsewhere at once; its partitions
  move to their first live standby about one lease period later. Sends to devices on those
  partitions are rejected as retryable (reason 6) meanwhile; nothing is lost. Logs on the
  standby: `mailbox partition taken over`. Two nodes may die at once: every partition still has
  a copy. The returning node takes its share back (below).
- **A node stops gracefully** (deploy): it writes and copies its key stores and releases its
  leases on SIGTERM; standbys take over within a renewal tick. Rolling deploys need no
  draining: one node at a time.
- **A node joins or returns**: once it has been up two lease periods and holds a full copy, each
  owner hands it the partitions it ranks first for, one per renewal tick (`mailbox partition
  handed to its preferred node`; each move pauses that partition's sends for well under a
  second, retried by clients).
- **Valkey restarts or fails over**: routing re-subscribes by itself (sessions drain their
  mailboxes once); leases are taken back by their owners without restarting anything. Expect
  `mailbox key store not replicated to a standby` only if a node cannot reach another.
- **`mailbox key store not replicated to a standby`** (warning): a standby is unreachable (link
  port, certificates, firewall). A new key window is used only once at least one standby holds
  it, so with every standby unreachable, sends to that partition are refused (retryable) until
  one is back or drops out of the members (a lease period). Fix the link; the full store is
  copied again once it is back.
- **`mailbox key store copy deleted (no longer a standby)`** (info): placement changed; copies a
  node no longer needs are deleted after three lease periods (deleted keys must not linger).
- **`mailbox partition lease lost; writer stopped`**: another node took the partition (this node
  was cut off from Valkey longer than a lease). Normal after a network partition; check that the
  partition is running somewhere (`/metrics`, logs on the other nodes).
- Every node needs the same `master_key`, `idempotency_secret`, `cluster_secret` and Iggy
  topic; certificates `delivery.<host>.songbird.internal` from the internal CA (D-0012).

## Overload: connections refused (close 4101)

- Detection: `connections_refused_total` rising; clients report 4101 with a retry hint.
- Impact: new connections wait and retry with backoff; connected devices are unaffected; nothing
  is lost (mailboxes hold everything).
- Immediate actions:
  1. Check `connections_open` against `[delivery.session] max_connections` and the accept rate
     against `accepts_per_sec`.
  2. After an outage, a reconnect storm is expected: let the token bucket pace it. Do not raise
     the limits during the storm.
  3. If the cap is reached in steady state, add capacity (milestone 3: more cores; milestone 4:
     more nodes) rather than raising the cap past what the host can hold.
- Verification: `connections_refused_total` flat; load-generator `reconnect` scenario passes the
  checker against the same configuration.

## Slow consumers (close 4100) and lag

- Detection: `slow_consumers_total` (a socket made no write progress for `write_timeout_ms`,
  default 30 s); `window_full_total` (a device has `max_unacked`, default 256, envelopes in flight
  and delivery to it paused until it acknowledges); `routes_lagged_total` and `drains_total` (a
  session's inbox overflowed and it caught up from the mailbox).
- Impact: the slow device reconnects and drains its mailbox; nobody else waits (invariant 5).
- Immediate actions: none for isolated cases. A fleet-wide rise points at the network path or at
  the server's own write capacity: check CPU and `delivered_*` rates.
- Verification: `inv5_slow_client_never_slows_anyone_else` reproduces the mode.

## Store unavailable (sends rejected with reason 6, close 4104)

- Detection: `mailbox_errors_total` and `sends_rejected_total` rising.
- Impact: sends are rejected as retryable; clients keep their messages and retry with the same
  idempotency key; sockets stay open; delivery of already-stored envelopes resumes when the store
  returns (failed drains retry every second).
- Logs: `mailbox append failed; resending` and `mailbox read failed`, each with Iggy's numeric
  error code. A writer resends the same batch (same producer sequence, so it is written once)
  until Iggy confirms; sends wait up to `timeout_ms` (5 s) and are then rejected as retryable;
  clients retry with the same idempotency key.
- Immediate actions: check Iggy (`songbird-iggy` container logs, disk space on the data host,
  `/var/lib/songbird/iggy`). A full disk stops Iggy's affected shards (they refuse to commit and
  shut the server down rather than lose data): free space, restart the container; the mailbox
  replays and continues.
- Verification: `mailbox_errors_total` and `sends_rejected_total` flat again; the load-generator
  checker passes.
- Verification: `inv8_store_unavailable_rejects_retryably_and_keeps_sockets`; rejected sends stop
  and the load-generator checker passes afterwards.

## `valkey-hot` unreachable: channel posts at the per-node rate (D-0077)

- Detection: `delivery_channel_rate_local_only_total` and `api_channel_rate_local_only_total`
  rising; the message-request gate refuses requests and broadcasts as unavailable at the same
  time (it fails closed).
- Impact: posts to private channels are no longer held to one budget across the cluster. Each
  node admits a channel's posts at the class's rate (1 a second, burst 10, by default), so a
  channel posting through N nodes gets up to N times its class. Each post waits at most
  `CHANNEL_GATE_WAIT` (250 ms) for Valkey before the node decides alone. Group messages and
  ordinary sends are unaffected. This is chosen over refusing every channel post: channel
  admins are authorized posters, each also under their device's own budget.
- Immediate actions: restore `valkey-hot` (container status, memory, TLS certificates). The
  connections heal on the next command; nothing needs a restart.
- Verification: the counters stop rising; `without_valkey_the_per_node_budget_decides_alone`
  (unit) and `a_channels_rate_class_is_shared_by_the_websocket_and_http` (live) describe both
  modes.

## Mailbox writer fenced (node not ready)

- Detection: `/readyz` fails on a delivery node; log `mailbox writer fenced by another writer;
  stopping` with code 93 (`ProducerEpochFenced`) or 92.
- Cause: another delivery process started on the same Iggy topic and took the partitions over
  (one node per topic until M4).
- Immediate actions: make sure only one delivery node points at the topic; restart the node that
  should own it (it replays and takes a new producer epoch). Nothing is lost: the fenced writer
  wrote nothing after the takeover.

## Mailbox key store (what it is, where it lives)

- Every mailbox record is sealed under keys in a key store (D-0031): one directory per partition
  under `[delivery.mailbox.iggy] key_dir` (`p<partition>-<hash>`: `head`, pages `w*.p*.e*.g*`,
  `lock`), sealed with `master_key` (64 hex characters, from the secrets store, mode 0600).
- `key_dir` must be on the node's persistent disk, owned by the service user, mode 0700. Not
  tmpfs (a reboot would lose every pending message), and **never in a backup or snapshot**: a
  copy keeps keys that acknowledgements destroyed. The data volume must use full-disk
  encryption.
- The master key is the same on a replacement host; rotating it is not supported yet (stop,
  re-seal: follow-up work).
- `key_interval_ms` (default 1000): how soon an acknowledged message's key leaves the disk.
  Shorter means more writes (the store writes only the pages that changed).

## Mailbox key store unusable (delivery does not start, or stops)

- Detection: delivery exits at start with `mailbox key store of partition P unusable`, or a
  running node logs `mailbox key store write failed` (sends then fail as retryable when a new key
  window cannot be written) or `mailbox key store owned by a newer writer; stopping` (node not
  ready).
- Causes and actions:
  - **Wrong `master_key`** (a rotated or mistyped secret): restore the right secret.
  - **A missing, altered or misplaced page** (disk fault, a file deleted by hand, a partial
    copy): the store is refused because the pending messages under that page would otherwise look
    acknowledged and vanish. Restore the directory from the same host if a copy exists (there
    should be none: see above); otherwise the pending messages of that partition are lost:
    move the partition's directory away, start on a new stream (`[delivery.mailbox.iggy] stream`)
    and raise `store_generation` so clients reset their resume points (PROTOCOL §3.6). Never
    edit the files.
  - **Write failures**: disk full or read-only, permissions on `key_dir`. Fix and the next write
    (every `key_interval_ms`) catches up; nothing acknowledged is lost (the log's ACK records are
    the authority).
  - **Owned by a newer writer**: another delivery process took the partition over, as in
    "Mailbox writer fenced" below.
- Verification: `/readyz` succeeds; the live test `start_up_refuses_a_lost_key_page` describes the
  refusal.

## Mailbox log unreadable (delivery does not start)

- Detection: delivery exits at start with `mailbox log unreadable: partition P, offset O, record
  version V`; `/readyz` never succeeds.
- Cause: the Iggy topic holds a record this build cannot read: written by an incompatible
  version (V differs from the build's record version) or corrupted. Replaying past it would lose
  counters and reuse `seq`s, which clients would drop as duplicates, so delivery refuses to
  start.
- Immediate actions: run the build that wrote the log (roll back), or restore the topic from a
  backup (next section). Never delete the record to get past it: that is the `seq` reuse the
  check prevents.

## Restoring the mailbox from a backup

- Restore the Iggy data directory, then raise `[delivery.mailbox] store_generation` by one
  before starting delivery: clients see the new generation in `Hello` and reset their resume
  points (PROTOCOL §3.6).
- Records are sealed (D-0031): a backup of the Iggy data is readable only with the key store it
  was written with, and key stores are never backed up (a copy would keep the keys of
  acknowledged messages). So an Iggy backup does not bring pending messages back; it fails to
  start ("Mailbox log unreadable"). After losing a node's disk, start on a new stream and raise
  `store_generation`: pending messages of that node are lost. Protection against losing a disk
  is replication with partition ownership (M4), not backups.
- Upgrading Iggy across a storage-format change (0.9 to 0.10 was one): stop delivery, let devices
  drain if possible, follow Iggy's upgrade notes; a fresh data directory loses pending envelopes,
  so treat it as a restore (raise `store_generation`).

## Authentication failures (close 4000) or timeouts (4102)

- Detection: `auth_failures_total`, `auth_timeouts_total`.
- Impact: affected devices stop reconnecting (4000) and must re-register; timeouts back off and
  retry.
- Immediate actions: a sudden fleet-wide rise of 4000 after a deploy means a server-name or
  directory mismatch: roll back (`deploy-and-rollback.md`). A rise from few sources is probing:
  rate limits handle it; firewall at the edge if it persists.

## Deploy drain (close 4200)

- Detection: expected during rollouts; `connections_open` falls on the draining node.
- Impact: clients reconnect within ~0.5 s, to any node; nothing is lost.
- Procedure: SIGTERM; the server stops accepting, closes every session with 4200 at random times
  within `drain_window_ms` (default 2 s, must be below `shutdown_grace_secs`) and exits 0.
- Verification: `graceful_drain_closes_with_4200`; the smoke test's SIGTERM check.
