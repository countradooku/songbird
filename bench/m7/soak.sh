#!/usr/bin/env bash
# M7's 24-hour soak (master prompt §8), on the node bench/m7/suite.sh sets up.
#
#   bench/m7/soak.sh <suite work dir> [hours]
#
# Every beta device (the suite's devices) connected for the whole run, the beta's peak 1:1
# traffic, one random connection dropped every second and one storm of every connection halfway
# through (loadgen --scenario reconnect). Every minute a sampler records delivery's resident
# memory, descriptors, CPU and store-latency counts, and Iggy's memory, to <work>/soak/samples.csv,
# so a leak or a slow drift shows as a slope. The checker must pass over the whole run.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=$(realpath "$1"); HOURS=${2:-24}
SECS=${SOAK_SECS:-$(( HOURS * 3600 ))}; PEAK_RATE=${PEAK_RATE:-1000}
DELIVERY_CPUS=${DELIVERY_CPUS:-0-5}; LOADGEN_CPUS=${LOADGEN_CPUS:-8-11}
B=target/release; NAME=delivery.bench.songbird.internal
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"
mkdir -p "$W/soak"; S="$W/soak"
[ -f "$W/delivery.toml" ] || { echo "run bench/m7/suite.sh $W first"; exit 1; }
STREAM="m7soak$RANDOM"
sed -E "s/^stream = .*/stream = \"$STREAM\"/; s#^key_dir = .*#key_dir = \"$W/keystore-$STREAM\"#" \
  "$W/delivery.toml" > "$S/delivery.toml"
mkdir -p "$W/keystore-$STREAM"
taskset -c "$DELIVERY_CPUS" "$B/songbird-delivery" --config "$S/delivery.toml" > "$S/delivery.log" 2>&1 &
P=$!
SAMPLER=""
trap 'kill $P ${SAMPLER:-} 2>/dev/null || true' EXIT
for _ in $(seq 1 600); do curl -sf http://127.0.0.1:9191/readyz >/dev/null && break; sleep 0.1; done

IGGY=$(docker compose -f deploy/compose/compose.yaml --env-file .env ps -q iggy)
echo "unix_secs,rss_bytes,open_fds,cpu_secs,stores,stores_le_2ms,iggy_mem" > "$S/samples.csv"
( while kill -0 "$P" 2>/dev/null; do
    m=$(curl -sf http://127.0.0.1:9191/metrics || true)
    v() { printf '%s\n' "$m" | awk -v n="$1" '$1==n {print $2; exit}'; }
    le2=$(printf '%s\n' "$m" | awk '$1=="songbird_delivery_store_seconds_bucket{le=\"0.002\"}" {print $2; exit}')
    mem=$(docker stats --no-stream --format '{{.MemUsage}}' "$IGGY" 2>/dev/null | cut -d/ -f1 | tr -d ' ')
    echo "$(date +%s),$(v songbird_process_resident_memory_bytes),$(v songbird_process_open_fds),$(v songbird_process_cpu_seconds_total),$(v songbird_delivery_store_seconds_count),${le2:-},${mem:-}" >> "$S/samples.csv"
    sleep 60
  done ) &
SAMPLER=$!

echo "soak: $HOURS h, $PEAK_RATE/s, stream $STREAM, started $(date -u +%FT%TZ)" | tee "$S/summary.txt"
taskset -c "$LOADGEN_CPUS" "$B/songbird-loadgen" run --addr 127.0.0.1:9291 --server-name "$NAME" \
  --tls-ca "$W/pki/leaf/ca.crt" --admin 127.0.0.1:9191 --seeds "$W/keys/seeds.txt" \
  --scenario reconnect --chaos-every-ms 1000 --secs "$SECS" --rate "$PEAK_RATE" --size 256 \
  --threads 4 --connect-rate 4000 --settle-secs 120 --json-out "$S/result.json" > "$S/load.log" 2>&1 \
  && RC=0 || RC=$?
grep -E "connect:|sends:|server|latency|checker:|songbird-loadgen:" "$S/load.log" | tee -a "$S/summary.txt"
python3 - "$S/samples.csv" <<'PY' | tee -a "$S/summary.txt"
import csv, sys
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["rss_bytes"]]
if len(rows) < 3:
    sys.exit("too few samples")
f = lambda r, k: float(r[k] or 0)
first, mid, last = rows[1], rows[len(rows) // 2], rows[-1]   # rows[0]: before devices connected
hours = (f(last, "unix_secs") - f(first, "unix_secs")) / 3600
grow = (f(last, "rss_bytes") - f(mid, "rss_bytes")) / max(hours / 2, 1e-9) / 1048576
print(f"samples: {len(rows)} over {hours:.1f} h")
print(f"delivery rss: {f(first,'rss_bytes')/1048576:.0f} MiB -> {f(mid,'rss_bytes')/1048576:.0f} MiB (middle) -> {f(last,'rss_bytes')/1048576:.0f} MiB; second-half slope {grow:+.1f} MiB/h")
print(f"open fds: {f(first,'open_fds'):.0f} -> {f(last,'open_fds'):.0f}")
stores = f(last, "stores") - f(first, "stores")
fast = f(last, "stores_le_2ms") - f(first, "stores_le_2ms")
print(f"stores: {stores:.0f}, within 2 ms: {100 * fast / max(stores, 1):.3f} %")
print(f"iggy memory: {first['iggy_mem']} -> {last['iggy_mem']}")
PY
exit "$RC"
