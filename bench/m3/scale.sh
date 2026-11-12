#!/usr/bin/env bash
# M3 scaling curve (report P02-M3): delivery on 1..N pinned cores, the load generator on other
# physical cores, the checker after every run.
#
#   bench/m3/scale.sh <workdir> <out.txt> <rate>...
#
# <workdir> holds keys/ (songbird-loadgen keys --devices 10000 --out <workdir>/keys) and the
# delivery configuration template named by CFG (default delivery-mem.toml), in which WORKERS and
# STREAM are replaced per run. Environment: WORKERS_LIST (default "1 2 4 8"), DEVICES (2000),
# LGCPUS (load generator CPUs, default 8-15,24-31), IGGY_FRESH (a script that restarts Iggy with
# an empty data directory before each run; see iggy-fresh.sh).
set -u
B=$1; OUT=$2; shift 2; RATES="$@"
: > "$OUT"
for w in ${WORKERS_LIST:-1 2 4 8}; do
  [ -n "${IGGY_FRESH:-}" ] && "$IGGY_FRESH"
  sed "s/WORKERS/$w/; s/STREAM/m3s$w$RANDOM/" "$B/${CFG:-delivery-mem.toml}" > "$B/d.toml"
  taskset -c 0-7 target/release/songbird-delivery --config "$B/d.toml" > "$B/server.log" 2>&1 &
  PID=$!
  for i in $(seq 1 300); do curl -sf http://127.0.0.1:9191/readyz >/dev/null && break; sleep 0.1; done
  for rate in $RATES; do
    echo "== workers=$w rate=$rate" >> "$OUT"
    taskset -c "${LGCPUS:-8-15,24-31}" target/release/songbird-loadgen run --addr 127.0.0.1:9291 \
      --seeds "$B/keys/seeds.txt" --devices "${DEVICES:-2000}" --secs 8 --rate "$rate" --size 256 \
      --threads 16 --connect-rate 20000 2>&1 | grep -E "sends:|latency|checker" >> "$OUT"
  done
  kill $PID; wait $PID 2>/dev/null
done
echo DONE >> "$OUT"
