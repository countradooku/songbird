#!/usr/bin/env bash
# M7 load suite (master prompt §8): one command, on a Linux host, reproduces every scenario on a
# production-shaped node and compares the results with a stored baseline.
#
#   bench/m7/suite.sh <work dir> [baseline.json]
#
# The node: one delivery process with TLS 1.3 (certificates from songbird-admin's CA), the Iggy
# mailbox (compose's pinned image, a fresh stream per scenario), production session limits
# (accept-rate limits included). Cores are split three ways (DELIVERY_CPUS, IGGY_CPUS,
# LOADGEN_CPUS) so the load generator does not take the server's CPU.
#
# Scenarios, at the beta's size (D-0043; DEVICES, PEAK_RATE, GROUP_RATE override):
#   idle    every device connected, no traffic: memory per idle connection
#   steady  1:1 traffic at the beta's peak send rate: p99 send-to-deliver (target < 2 ms)
#   group   256-member groups at the peak group rate: fan-out p99
#   storm   peak traffic, then every connection dropped at once: recovery (target < 60 s)
#   max     the highest steady rate the node sustains with the checker passing
# Every scenario must pass the delivery checker. Results: <work dir>/results/*.json and a summary
# (<work dir>/results/summary.json). With a baseline, any tracked figure more than 10 % worse
# fails the run (exit 1); so does a missed target.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=$(realpath -m "$1"); BASELINE=${2:-}
DEVICES=${DEVICES:-30000}; PEAK_RATE=${PEAK_RATE:-1000}; GROUP_RATE=${GROUP_RATE:-20}
SECS=${SECS:-60}; MAX_RATE=${MAX_RATE:-40000}; MAX_DEVICES=${MAX_DEVICES:-5000}
DELIVERY_CPUS=${DELIVERY_CPUS:-0-5}; IGGY_CPUS=${IGGY_CPUS:-6-7}; LOADGEN_CPUS=${LOADGEN_CPUS:-8-11}
WORKERS=$(( $(echo "$DELIVERY_CPUS" | awk -F- '{print $2-$1+1}') ))
B=target/release; NAME=delivery.bench.songbird.internal
# Where the mailbox key stores go (production: the host's persistent disk). KEY_DIR=/dev/shm/...
# separates the key persister's flushes from the measurement on hosts with slow disk flushes.
KEY_DIR=${KEY_DIR:-$W}
mkdir -p "$W/results"; chmod 700 "$W"
# One descriptor per connection on both sides: well above the default 1024.
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"

[ -f .env ] || cargo xtask dev-env >/dev/null
set -a; . ./.env; set +a
umask 077
printf %s "$IGGY_ROOT_PASSWORD" > "$W/iggy-pass"
[ -f "$W/master-key" ] || openssl rand -hex 32 > "$W/master-key"
[ -f "$W/idem-secret" ] || openssl rand -hex 32 > "$W/idem-secret"

echo "== build"
cargo build --release --locked -p songbird-delivery -p songbird-loadgen -p songbird-admin 2>&1 | tail -1

echo "== certificates (internal CA, as deployments issue them)"
if [ ! -f "$W/pki/leaf/ca.crt" ]; then
  "$B/songbird-admin" ca init-root --out "$W/pki/root" --env bench >/dev/null
  "$B/songbird-admin" ca init-intermediate --root "$W/pki/root" --out "$W/pki/ca" --env bench >/dev/null
  "$B/songbird-admin" ca issue --ca "$W/pki/ca" --name "$NAME" --san "$NAME" --san 127.0.0.1 \
    --out "$W/pki/leaf" >/dev/null
fi

# IGGY_TMPFS=1 keeps Iggy's data in memory: the software path alone, as P02-M3 measured it, for
# hosts whose disk flushes are not production's (a VM's virtual disk). Without it Iggy's data is
# on this host's disk, fsync and all, as in production.
COMPOSE=(docker compose -f deploy/compose/compose.yaml --env-file .env)
if [ -n "${IGGY_TMPFS:-}" ]; then
  cat > "$W/iggy-tmpfs.yaml" <<'Y'
services:
  iggy:
    volumes: !reset []
    tmpfs: ["/data:size=8g"]
Y
  COMPOSE+=(-f "$W/iggy-tmpfs.yaml")
fi
# Host networking, as Ansible runs Iggy in production (compose publishes the port through
# Docker's userland proxy, an extra copy each way). Default on; IGGY_HOST_NET=0 for compose's.
if [ "${IGGY_HOST_NET:-1}" = 1 ]; then
  cat > "$W/iggy-hostnet.yaml" <<Y
services:
  iggy:
    network_mode: host
    networks: !reset null
    ports: !reset []
    environment:
      IGGY_TCP_ADDRESS: "127.0.0.1:${SB_PORT_IGGY:-47890}"
Y
  COMPOSE+=(-f "$W/iggy-hostnet.yaml")
fi
echo "== Iggy (compose's pinned image) on CPUs $IGGY_CPUS${IGGY_TMPFS:+, data in memory}"
"${COMPOSE[@]}" up -d --force-recreate iggy >/dev/null
docker update --cpuset-cpus "$IGGY_CPUS" "$("${COMPOSE[@]}" ps -q iggy)" >/dev/null
for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/${SB_PORT_IGGY:-47890}) 2>/dev/null && break; sleep 1; done

echo "== devices: $DEVICES"
[ -f "$W/keys/seeds.txt" ] && [ "$(wc -l < "$W/keys/seeds.txt")" -eq "$DEVICES" ] \
  || "$B/songbird-loadgen" keys --devices "$DEVICES" --out "$W/keys" >/dev/null

PID=""
start() { # <stream>
  mkdir -p "$KEY_DIR/keystore-$1"
  cat > "$W/delivery.toml" <<CONF
[common]
environment = "dev"
admin_listen = "127.0.0.1:9191"
shutdown_grace_secs = 15
[common.log]
format = "json"
filter = "warn"
[delivery]
listen = "127.0.0.1:9291"
server_name = "$NAME"
[delivery.tls]
cert_chain = "$W/pki/leaf/$NAME.crt"
key = { file = "$W/pki/leaf/$NAME.key" }
[delivery.directory]
file = "$W/keys/devices.toml"
[delivery.runtime]
workers = $WORKERS
storage_threads = 4
[delivery.mailbox]
backend = "iggy"
max_per_device = 100000
[delivery.mailbox.iggy]
addr = "127.0.0.1:${SB_PORT_IGGY:-47890}"
user = "$IGGY_ROOT_USERNAME"
pass = { file = "$W/iggy-pass" }
stream = "$1"
partitions = 8
idempotency_secret = { file = "$W/idem-secret" }
key_dir = "$KEY_DIR/keystore-$1"
master_key = { file = "$W/master-key" }
CONF
  taskset -c "$DELIVERY_CPUS" "$B/songbird-delivery" --config "$W/delivery.toml" >> "$W/delivery.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 600); do curl -sf http://127.0.0.1:9191/readyz >/dev/null && return 0; sleep 0.1; done
  echo "delivery not ready"; tail -5 "$W/delivery.log"; exit 1
}
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null; PID=""; }
trap stop EXIT
SCENARIOS=${SCENARIOS:-idle steady group storm max}
run() { # <name> <loadgen args...>
  local name=$1; shift
  case " $SCENARIOS " in *" $name "*) ;; *) return 0 ;; esac
  echo "== $name"
  start "m7$name$RANDOM"
  taskset -c "$LOADGEN_CPUS" "$B/songbird-loadgen" run --addr 127.0.0.1:9291 --server-name "$NAME" \
    --tls-ca "$W/pki/leaf/ca.crt" --admin 127.0.0.1:9191 --threads 4 --connect-rate 4000 \
    --size 256 --settle-secs 60 --json-out "$W/results/$name.json" "$@" > "$W/results/$name.log" 2>&1 || true
  grep -E "connect:|sends:|storm:|server:|latency|checker:|songbird-loadgen:" "$W/results/$name.log" || true
  stop
}

run idle   --seeds "$W/keys/seeds.txt" --scenario idle --secs 30
run steady --seeds "$W/keys/seeds.txt" --scenario steady --secs "$SECS" --rate "$PEAK_RATE"
run group  --seeds "$W/keys/seeds.txt" --scenario group --secs "$SECS" --rate "$GROUP_RATE" --group-size 256
run storm  --seeds "$W/keys/seeds.txt" --scenario storm --secs "$SECS" --rate "$PEAK_RATE"
run max    --seeds "$W/keys/seeds.txt" --devices "$MAX_DEVICES" --scenario steady --secs 30 --rate "$MAX_RATE"

python3 - "$W/results" "$BASELINE" <<'PY'
import json, os, platform, sys
res, baseline = sys.argv[1], sys.argv[2]
r = {n: json.load(open(os.path.join(res, n + ".json")))
     for n in ("idle", "steady", "group", "storm", "max")
     if os.path.exists(os.path.join(res, n + ".json"))}
for n in ("idle", "steady", "group", "storm", "max"):
    r.setdefault(n, {"checker": {"passed": True}, "server": None, "latency_us": {"p99": None, "p999": None},
                     "delivery_rate": None, "storm_recovery_secs": None})
s = {
    "host": platform.node(), "machine": platform.machine(), "kernel": platform.release(),
    "cpus": os.cpu_count(),
    "checker_passed": all(x["checker"]["passed"] for x in r.values()),
    "idle_bytes_per_connection": (r["idle"]["server"] or {}).get("bytes_per_connection"),
    "steady_p99_us": r["steady"]["latency_us"]["p99"],
    "steady_p999_us": r["steady"]["latency_us"]["p999"],
    "steady_cpu_per_10k_secs": (r["steady"]["server"] or {}).get("cpu_per_10k_deliveries_secs"),
    "steady_store_p99_le_secs": (r["steady"]["server"] or {}).get("store_p99_le_secs"),
    "group_p99_us": r["group"]["latency_us"]["p99"],
    "group_delivery_rate": r["group"]["delivery_rate"],
    "storm_recovery_secs": r["storm"]["storm_recovery_secs"],
    "max_delivery_rate": r["max"]["delivery_rate"],
    "max_p99_us": r["max"]["latency_us"]["p99"],
}
json.dump(s, open(os.path.join(res, "summary.json"), "w"), indent=2)
fail = []
if not s["checker_passed"]:
    fail.append("the delivery checker failed in at least one scenario")
# The 2 ms target is server-side (store, group commit included); the client-observed p99 adds
# the client's own work and, on one host, the load generator's share of the CPU.
store99 = s["steady_store_p99_le_secs"]
if store99 is None or store99 > 0.002:
    fail.append(f"steady server store p99 <= {store99} s: target < 2 ms")
if s["storm_recovery_secs"] is not None and s["storm_recovery_secs"] >= 60:
    fail.append(f"storm recovery {s['storm_recovery_secs']} s: target < 60 s")
# Tracked figures: lower is better unless listed in HIGHER.
HIGHER = {"group_delivery_rate", "max_delivery_rate"}
rows = []
if baseline:
    b = json.load(open(baseline))
    for k, v in s.items():
        if not isinstance(v, (int, float)) or isinstance(v, bool) or not isinstance(b.get(k), (int, float)):
            continue
        base = b[k]
        change = (v - base) / base if base else 0.0
        worse = -change if k in HIGHER else change
        rows.append((k, base, v, change))
        if worse > 0.10:
            fail.append(f"{k}: {v:.4g} against baseline {base:.4g} ({change:+.1%})")
print("\n== summary" + (f" (baseline {baseline})" if baseline else ""))
for k, v in s.items():
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        base = next((f"{row[1]:.4g} ({row[3]:+.1%})" for row in rows if row[0] == k), "")
        print(f"  {k:30} {v:>14.4g}  {base}")
print("FAIL:\n  " + "\n  ".join(fail) if fail else "PASS")
sys.exit(1 if fail else 0)
PY
