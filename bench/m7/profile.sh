#!/usr/bin/env bash
# Profiles delivery under load (master prompt §8: flamegraphs with every milestone report).
#
#   bench/m7/profile.sh <suite work dir> <out prefix> [loadgen run args...]
#
# Uses the node bench/m7/suite.sh set up in <suite work dir> (certificates, devices, its last
# delivery.toml, Iggy still running). Builds delivery with the `profiling` profile (release with
# symbols), runs the given load (default: steady at 1,000/s for 40 s), records perf with call
# stacks for 15 s from second 12, and writes <out prefix>.folded (stacks with counts) and
# <out prefix>.svg (inferno's flamegraph, when `inferno-flamegraph` is on the PATH).
set -euo pipefail
cd "$(dirname "$0")/../.."
W=$(realpath "$1"); OUT=$2; shift 2
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"
DELIVERY_CPUS=${DELIVERY_CPUS:-0-5}; LOADGEN_CPUS=${LOADGEN_CPUS:-8-11}
cargo build --profile profiling --locked -p songbird-delivery 2>&1 | tail -1
[ $# -gt 0 ] || set -- --scenario steady --secs 40 --rate 1000
taskset -c "$DELIVERY_CPUS" target/profiling/songbird-delivery --config "$W/delivery.toml" > "$W/profile-delivery.log" 2>&1 &
P=$!
trap 'kill $P 2>/dev/null || true' EXIT
for _ in $(seq 1 600); do curl -sf http://127.0.0.1:9191/readyz >/dev/null && break; sleep 0.1; done
taskset -c "$LOADGEN_CPUS" target/release/songbird-loadgen run --addr 127.0.0.1:9291 \
  --server-name delivery.bench.songbird.internal --tls-ca "$W/pki/leaf/ca.crt" \
  --seeds "$W/keys/seeds.txt" --threads 4 --connect-rate 4000 --admin 127.0.0.1:9191 "$@" \
  > "$OUT.load.txt" 2>&1 &
L=$!
sleep 12
sudo -n perf record -F 499 --call-graph dwarf,32768 -p "$P" -o "$OUT.perf" -- sleep 15 2>&1 | tail -1
wait "$L" || true
grep -E "connect:|sends:|server:|latency|checker:" "$OUT.load.txt"
sudo -n perf script -i "$OUT.perf" 2>/dev/null > "$OUT.script"
python3 - "$OUT.script" "$OUT.folded" <<'PY'
import collections, re, sys
# perf script: a header line per sample, then one frame per line (innermost first), blank line.
stacks = collections.Counter(); frames = []; thread = ""
def flush():
    if frames:
        stacks[";".join([thread] + frames[::-1])] += 1
for line in open(sys.argv[1], errors="replace"):
    if not line.strip():
        flush(); frames = []; continue
    if not line.startswith((" ", "\t")):
        thread = line.split()[0]; continue
    parts = line.strip().split(None, 1)
    if len(parts) < 2:
        continue
    sym = re.sub(r"\+0x[0-9a-f]+$", "", parts[1].split(" (")[0])
    sym = re.sub(r"::h[0-9a-f]{16}$", "", sym)
    frames.append(sym.replace(";", ":"))
flush()
with open(sys.argv[2], "w") as f:
    for k, v in stacks.most_common():
        f.write(f"{k} {v}\n")
total = sum(stacks.values())
leaf = collections.Counter()
for k, v in stacks.items():
    leaf[k.rsplit(";", 1)[-1]] += v
print(f"samples: {total}")
for s, v in leaf.most_common(25):
    print(f"{100*v/total:5.1f}%  {s[:140]}")
PY
if command -v inferno-flamegraph >/dev/null; then
  inferno-flamegraph --title "delivery: $*" < "$OUT.folded" > "$OUT.svg"
fi
