# P02 — Between M2 and M3: deletion on acknowledgement (D-0031)

- Date: 2026-11-12
- Prompt: [02-realtime.md](../prompts/02-realtime.md); issue countradooku/songbird#2. Not a
  milestone gate: a security change to the M2 mailbox, done before M3 at the owner's request
  ("cant we delete on acknowledgement too?", "we need deleted after delivery too somehow",
  "I don't want to be behind anybody in security"), under the owner's standing delegation for
  security and privacy calls.
- Measurement machine: as in [P02-M2](P02-M2.md) (Ryzen 9 7950X, 30 GiB, Linux 7.3.1, NVMe with
  btrfs zstd), Iggy 0.10.0 natively (auto mode refused relaxing the container's seccomp locally),
  CPUs 4–7; `delivery` one thread on CPU 0; load generator on CPUs 8–15. Not the reference
  hardware.

## What changed

| | M2 (D-0029) | Now (D-0031) |
| --- | --- | --- |
| What the log holds | The client's ciphertext, recipient device and `seq` in the clear | Every entry sealed under its own puncturable key; metadata under a per-window key |
| An acknowledged message | Leaves the index; bytes readable on disk until the segment goes | Unopenable within about 1 s (`key_interval`), by anyone holding everything on the node |
| Delivered bytes on disk | Up to about 14 hours (6 h idempotency + 8 h segment expiry) | About 25 minutes after delivery plus the time to fill a 16 MiB segment |
| Idempotency records | In the mailbox log (held the log for 6 hours) | Own topic, keyed hashes and offsets only, 7 hours |
| Retry of a delivered send | Answered from the record | A replay: acknowledged entries answer `seq` 0, nothing re-routed |

How it works, in short: each 10-minute window has a GGM key tree (16.7 M leaves, AES-256 as PRG)
and a metadata key. An ACK is written to the log, then the entry's leaf is punctured; the
partition's key store (a head plus 1,024-slot pages, sealed with the node's master key, written
copy-on-write) follows within a second. Compaction re-seals entries pending for 15 minutes into
the current window, so old windows empty, are destroyed, and Iggy deletes their segments. Details
and trade-offs: D-0031.

Compared with others (public documentation): Signal deletes a delivered message from its
database (FoundationDB), WhatsApp and Threema delete on delivery; in each, the bytes stay in the
storage engine and the SSD until compaction and garbage collection. None describes making queued
messages cryptographically unopenable at delivery.

## Evidence

| Check | Result |
| --- | --- |
| Acknowledged messages unopenable with every key on the node | `acknowledged_messages_cannot_be_decrypted_even_with_every_key`: a forensic scan opens every record of every partition with the key stores and master key; the markers of acknowledged messages are in no plaintext (and in no raw record before that) |
| Windows destroyed, idempotency outlives them | `compaction_destroys_old_windows` |
| A lost key page refuses the start | `start_up_refuses_a_lost_key_page` (and unit tests: missing, misplaced, altered pages; crash between pages and head) |
| No key ever used twice | `a_restart_never_reuses_key_slots` (fails without the fix, below) |
| Iggy mailbox live tests | 15/15, three consecutive runs |
| End-to-end invariant tests on Iggy | 16/16 |
| Fuzzing | `iggy_record` (records, sealed records, key-store head and pages): 4.9 M runs in 60 s, no crash |
| End to end through `delivery` | Below |

### Cost of sealing (`bench/stores`, `STORE=iggyprod`, random envelopes, base = main `819d07e`)

| | Base | Sealed |
| --- | --- | --- |
| This disk, 128 senders | 3,382–17,400 sends/s | 7,863–9,902 sends/s |
| This disk, 1,024 senders | 1,216–5,563 sends/s | 1,476–7,518 sends/s |
| tmpfs, 128 senders | 431,386–433,577 sends/s | 340,946–341,004 (0.79×) |
| tmpfs, 1,024 senders | 858,025–867,920 sends/s | 426,314–430,880 (0.50×) |

On disk both versions are bound by fsync and indistinguishable run to run; tmpfs shows the CPU
ceiling. Writer time at 1,024 senders on tmpfs: append 67 %, sealing 14 %, applying 10 %,
planning 4 %; one GGM expansion 136 ns, sealing a 256-byte entry 181 ns. Pipelining the writer
(seal the next batch while one appends) belongs to M3.

### Key store (release build, this disk)

| Pending entries | Store size | Write after 100 scattered ACKs | State lock held |
| --- | --- | --- | --- |
| 10,000 | 0.36 MB | 10 pages, 8 ms | 0.04 ms |
| 100,000 | 3.5 MB | 75 pages, 57 ms | 1.0 ms |
| 1,000,000 | 36 MB | 100 pages, 80 ms | 1.8 ms |

The first design rewrote the whole file on every write (every 50 ms): 36 MB and a 25 ms lock
hold per write at 1 M pending, about 720 MB/s of writes. Caught by measurement before merging;
now writes follow the changes.

### End to end through `delivery` (load generator and checker)

1,000 devices, 1:1 random traffic, 256-byte random envelopes, every append fsynced, the same
scenario for the sealed mailbox and for main `819d07e` (base), run back to back. Achieved
messages/s, latency p50 / p99 in ms, checker.

| Phase (offered) | Sealed | Base |
| --- | --- | --- |
| Steady 1,000/s | 997, 2 / 163, pass | 1,000, 2 / 321, pass |
| Steady 5,000/s | 3,244, 35 / 1,598, pass | 2,346, 39 / 1,794, pass |
| Steady 10,000/s | 9,965, 34 / 80, pass | 2,014, 602 / 2,095, pass |
| Steady 20,000/s | 3,914, 39 / 1,529, pass | 2,377, 405 / 2,095, pass |
| Steady 40,000/s | 15,698, 46 / 664, pass | 8,693, 69 / 1,530, pass |
| Steady 80,000/s | 7,885, 47 / 1,438, pass | 2,625, 407 / 1,767, pass |
| Reconnect storm at 10,000/s (a drop every 20 ms) | 3,352, 35 / 2,191, pass | 1,939, 553 / 2,012, pass |
| Iggy frozen (SIGSTOP) 8 s at 2,000/s | 1,177, 11 / 8,331, pass | 1,264, 14 / 8,443, pass |
| `delivery` restart, then 5,000/s | ready in 0.83 s; 4,772, 7 / 672, pass | ready in 0.42 s; 4,156, 10 / 1,173, pass |

Every phase: nothing lost, duplicated or reordered; no rejected sends, no mailbox errors. With
incompressible envelopes this disk bounds both versions and varies widely between phases (an
earlier sealed run reached 24,700/s at 40,000 offered); the sealed mailbox is not slower end to
end. The restart takes longer because the key store is loaded and a new window written first.

## Bugs found and fixed

- **Key reuse after a restart (critical, found by the end-to-end restart run).** The key store
  lags the log by up to a second; replay did not mark the slots of records appended after the
  last key-store write as used, so a restarted writer gave new messages the leaf keys (and the
  constant AES-GCM nonce) of old ones. Acknowledging an old message destroyed the new one: the
  checker reported 174 messages lost and `delivery` 1,131 mailbox errors. Fixed twice over:
  replay marks every record's slots used, and a new writer always seals in a fresh random
  window. Regression test `a_restart_never_reuses_key_slots`.
- **A newer writer could be refused by its own key store.** The first key-store write after
  replay used epoch 0, so after a crash with unwritten punctures a restart would fail as fenced.
  The new writer now sets its epoch and writes the store before anything else.
- **Key-store writes could land out of order** (the periodic write and a new window's write,
  concurrently): an older snapshot could overwrite a newer one and drop a window. Writes are
  serialised.
- **Whole-file key store** rewrote O(pending) bytes every 50 ms (above); replaced by the paged,
  copy-on-write store with a 1-second interval.
- **Benchmarks flattered by compression.** `bench/stores` and the load generator sent
  constant-byte envelopes; this disk's btrfs zstd compressed them away, so plaintext stores
  looked several times faster than with real ciphertext (base 100,000–130,000 sends/s at 1,024
  senders with constant bytes, 1,200–5,600 with random ones, same session). Both now send random
  bytes. **M2's disk numbers ([P02-M2](P02-M2.md)) are optimistic for that reason**; its tmpfs
  numbers and every correctness result stand.
- **Local test hygiene:** the live tests leave their Iggy streams behind; after hours of runs the
  local Iggy 0.10 server refused logins ("metadata prepare queue is full") until restarted with
  a fresh data directory. CI starts a fresh server per job. Follow-up below.

## Open risks and follow-ups

1. **The key store is part of the mailbox**: losing `key_dir` or the master key loses the node's
   pending messages, and Iggy backups no longer restore them (owner decision 1).
2. **SSD remnants**: deleted key-store files and segments can survive in flash until garbage
   collection; data volumes need full-disk encryption with the key off the disk (issue filed for
   P13/P12).
3. **CPU cost**: sealing halves a partition writer's CPU ceiling (still 430,000 sends/s per node
   on tmpfs with 4 partitions); M3 pipelines the writer.
4. **Visible until segment deletion**: Iggy's message headers (record size, time, partition).
5. **M4**: window ids should carry the writer epoch; partition handover must fence the old
   writer before the new one replays.
6. Live tests should delete their Iggy streams.

## What the owner needs to decide

1. **Backups and pending messages.** With deletion by key destruction, a backup of the key store
   would keep the keys of acknowledged messages, so key stores are never backed up, and an Iggy
   backup alone cannot be read. A node that loses its disk loses its undelivered messages (the
   senders saw them accepted) until M4 replicates partitions. Recommended: accept (forward
   deletion over restorable queues), with M4 replication as the durability answer. The alternative is an escrowed
   key-store backup, which weakens deletion to "after the backup expires".
2. The M2 owner items stand (D-0029 Iggy pre-1.0 and seccomp, D-0030 locked-stack wording,
   D-0028 runtime); the 14-hour retention item is answered by D-0031.
