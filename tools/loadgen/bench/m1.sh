#!/usr/bin/env bash
# Milestone 1 gate numbers (docs/reports/P02-M1.md), reproducible on one Linux machine.
#
#   tools/loadgen/bench/m1.sh <path-to-sockudo-ws-3.1.1-source> [out-dir]
#
# Server under test pinned to CPU 0 (one thread: milestone 1 runs one current-thread runtime);
# load generator pinned to CPUs 8-15. Prints every result; nothing is uploaded anywhere.
set -euo pipefail
SOCKUDO_SRC=${1:?path to the sockudo-ws 3.1.1 source (cargo registry copy)}
OUT=${2:-target/bench-m1}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"
mkdir -p "$OUT"
SERVER_CPU=${SERVER_CPU:-0}
LOAD_CPUS=${LOAD_CPUS:-8-15}
LG="taskset -c $LOAD_CPUS target/release/songbird-loadgen"

echo "== machine"
lscpu | grep 'Model name' | sed 's/^ *//'
echo "kernel: $(uname -r)"
rustc --version

cargo build --release --locked -p songbird-delivery -p songbird-loadgen >/dev/null 2>&1
(cd "$SOCKUDO_SRC" && cargo build --release --example simple_echo >/dev/null 2>&1)

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }
rss_kib() { awk '/VmRSS/ {print $2}' "/proc/$1/status"; }

echo
echo "== echo baseline: sockudo-ws simple_echo vs songbird delivery WebSocket layer (1 thread each)"
TOKIO_WORKER_THREADS=1 taskset -c "$SERVER_CPU" "$SOCKUDO_SRC/target/release/examples/simple_echo" >/dev/null 2>&1 &
pids+=($!); sleep 0.5
AUTOBAHN_LISTEN=127.0.0.1:9003 taskset -c "$SERVER_CPU" target/release/songbird-delivery-autobahn >/dev/null 2>&1 &
pids+=($!); sleep 0.5
for spec in "100 1" "1000 4"; do
  set -- $spec
  for target in "sockudo-ws:127.0.0.1:9001" "songbird:127.0.0.1:9003"; do
    name=${target%%:*}; addr=${target#*:}
    echo "-- $name connections=$1 inflight=$2 size=256"
    $LG echo --addr "$addr" --connections "$1" --inflight "$2" --size 256 --secs 10 --threads 8 | tail -2
  done
done
cleanup; pids=()

echo
echo "== delivery end to end (store in memory, route, deliver, ACK), 1 thread"
$LG keys --devices 10000 --out "$OUT" >/dev/null
cat > "$OUT/delivery.toml" <<TOML
[common]
environment = "dev"
admin_listen = "127.0.0.1:9191"
shutdown_grace_secs = 10
[common.log]
format = "pretty"
filter = "warn"
[delivery]
listen = "127.0.0.1:9291"
server_name = "localhost"
[delivery.directory]
file = "$OUT/devices.toml"
[delivery.session]
sends_per_sec = 10000
send_burst = 20000
frames_per_sec = 50000
frame_burst = 100000
accepts_per_sec = 5000
accept_burst = 10000
TOML
start_delivery() {
  taskset -c "$SERVER_CPU" target/release/songbird-delivery --config "$OUT/delivery.toml" >"$OUT/server.log" 2>&1 &
  DPID=$!; pids+=($DPID)
  for _ in $(seq 50); do curl -sf 127.0.0.1:9191/readyz >/dev/null && break; sleep 0.1; done
}
start_delivery
for rate in 10000 30000 60000 100000; do
  t0=$(cpu_ticks "$DPID")
  echo "-- steady devices=1000 rate=$rate size=256"
  $LG run --addr 127.0.0.1:9291 --seeds "$OUT/seeds.txt" --devices 1000 --secs 10 --rate "$rate" --size 256 --threads 8 | tail -4
  t1=$(cpu_ticks "$DPID")
  echo "server cpu: $(( (t1 - t0) * 10 )) ms ($(getconf CLK_TCK) ticks/s)"
done
echo "-- reconnect chaos devices=1000 rate=10000, one drop every 20 ms plus one storm of all"
$LG run --addr 127.0.0.1:9291 --seeds "$OUT/seeds.txt" --devices 1000 --secs 20 --rate 10000 --size 256 --threads 8 --scenario reconnect --chaos-every-ms 20 | tail -4
kill "$DPID"; wait "$DPID" 2>/dev/null || true

echo
echo "== idle connection memory (fresh server, 10000 authenticated devices)"
start_delivery
r0=$(rss_kib "$DPID")
$LG run --addr 127.0.0.1:9291 --seeds "$OUT/seeds.txt" --devices 10000 --secs 15 --rate 100 --size 64 --threads 8 --connect-rate 5000 >"$OUT/idle.txt" &
LGPID=$!
sleep 12
r1=$(rss_kib "$DPID")
wait "$LGPID" || true
tail -3 "$OUT/idle.txt"
echo "server RSS: before=${r0} KiB with 10000 connections=${r1} KiB per connection=$(( (r1 - r0) * 1024 / 10000 )) bytes"
