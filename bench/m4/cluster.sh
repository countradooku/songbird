#!/usr/bin/env bash
# M4: three delivery nodes sharing an Iggy topic (cluster mode, D-0034) behind Valkey routing,
# twelve mailbox partitions, the load generator spread over all three, the checker after every
# phase: steady load, the partition owner killed (-9) and restarted, Valkey restarted, the owner
# stopped gracefully, two nodes killed at once, a rolling restart; partition leases per node
# after the start and at the end (rebalancing).
#
#   bench/m4/cluster.sh <workdir> <out.txt>
#
# <workdir>: keys/ (songbird-loadgen keys), pki/<n>/ (songbird-admin ca issue for
# delivery.<n>.songbird.internal, n = a b c), iggy-pass, valkey-pass, master-key, idem-secret,
# cluster-secret. Environment: IGGY_FRESH (restarts Iggy clean), VALKEY_CONTAINER (podman name),
# VALKEY_ADDR (127.0.0.1:47379), IGGY_ADDR (127.0.0.1:47990).
set -u
W=$1; OUT=$2
cd "$(dirname "$0")/../.."
: > "$OUT"
STREAM="m4c$RANDOM"
NODES="a b c"
declare -A CPU=([a]=0-1 [b]=2-3 [c]=4-5) IDX=([a]=1 [b]=2 [c]=3) PID=()
conf() {
  local n=$1 i=${IDX[$1]}
  mkdir -p "$W/keystore-$n"; chmod 700 "$W/keystore-$n"
  cat > "$W/node-$n.toml" <<CONF
[common]
environment = "dev"
admin_listen = "127.0.0.1:919$i"
shutdown_grace_secs = 15
[common.log]
format = "pretty"
filter = "warn,songbird_mailbox=info"
[delivery]
listen = "127.0.0.1:929$i"
server_name = "localhost"
[delivery.directory]
file = "$W/keys/devices.toml"
[delivery.session]
sends_per_sec = 100000
send_burst = 200000
frames_per_sec = 500000
frame_burst = 1000000
accepts_per_sec = 50000
accept_burst = 100000
[delivery.runtime]
workers = 2
storage_threads = 4
[delivery.mailbox]
backend = "iggy"
max_per_device = 100000
[delivery.mailbox.iggy]
addr = "${IGGY_ADDR:-127.0.0.1:47990}"
user = "iggy"
pass = { file = "$W/iggy-pass" }
stream = "$STREAM"
partitions = 12
idempotency_secret = { file = "$W/idem-secret" }
key_dir = "$W/keystore-$n"
master_key = { file = "$W/master-key" }
[delivery.router]
backend = "valkey"
[delivery.router.valkey]
addr = "${VALKEY_ADDR:-127.0.0.1:47379}"
pass = { file = "$W/valkey-pass" }
cluster_secret = { file = "$W/cluster-secret" }
[delivery.cluster]
node_name = "delivery.$n.songbird.internal"
link_listen = "127.0.0.1:940$i"
link_advertise = "127.0.0.1:940$i"
cert_chain = "$W/pki/$n/delivery.$n.songbird.internal.crt"
key = { file = "$W/pki/$n/delivery.$n.songbird.internal.key" }
ca = "$W/pki/$n/ca.crt"
lease_ttl_ms = 3000
CONF
}
start() {
  local n=$1 i=${IDX[$1]}
  taskset -c "${CPU[$n]}" target/release/songbird-delivery --config "$W/node-$n.toml" >> "$W/node-$n.log" 2>&1 &
  PID[$n]=$!
  for _ in $(seq 1 300); do curl -sf "http://127.0.0.1:919$i/readyz" >/dev/null && return 0; sleep 0.1; done
  echo "node $n not ready" >> "$OUT"
}
# The node holding partition 0's lease now (read from Valkey).
owner() {
  podman exec "${VALKEY_CONTAINER:-songbird-valkey-m4}" valkey-cli --no-auth-warning -a "$(cat "$W/valkey-pass")" \
    GET "songbird:$STREAM:mailbox:lease:0" | sed -E 's/.*delivery\.([a-z]+)\.songbird.*/\1/'
}
# Partition leases per node.
leases() {
  local keys=""; for p in $(seq 0 11); do keys="$keys songbird:$STREAM:mailbox:lease:$p"; done
  # shellcheck disable=SC2086
  podman exec "${VALKEY_CONTAINER:-songbird-valkey-m4}" valkey-cli --no-auth-warning -a "$(cat "$W/valkey-pass")" \
    MGET $keys | sed -E 's/.*delivery\.([a-z]+)\.songbird.*/\1/; s/^$/(none)/' | sort | uniq -c | tr '\n' ' '
  echo
}
load() { # secs rate
  taskset -c 12-15,28-31 target/release/songbird-loadgen run --addr 127.0.0.1:9291,127.0.0.1:9292,127.0.0.1:9293 \
    --seeds "$W/keys/seeds.txt" --devices 3000 --secs "$1" --rate "$2" --size 256 --threads 16 --connect-rate 20000 2>&1 \
    | grep -E "sends:|latency|checker"
}
[ -n "${IGGY_FRESH:-}" ] && "$IGGY_FRESH"
for n in $NODES; do : > "$W/node-$n.log"; conf "$n"; done
for n in $NODES; do start "$n"; done
sleep 15; echo "leases per node after the start: $(leases)" >> "$OUT"
for rate in 5000 20000 50000; do
  echo "== steady rate=$rate (3 nodes)" >> "$OUT"; load 8 "$rate" >> "$OUT"
done
K=$(owner)
echo "== partition owner ($K) killed (-9) at 6 s, restarted at 14 s, 25 s at 10000/s" >> "$OUT"
load 25 10000 > "$W/phase.txt" & L=$!
sleep 6; kill -9 "${PID[$K]}"; echo "killed $K at $(date +%T)" >> "$OUT"
sleep 8; start "$K"; echo "restarted $K at $(date +%T)" >> "$OUT"
wait $L; cat "$W/phase.txt" >> "$OUT"
echo "== Valkey restarted at 6 s (no persistence: leases and subscriptions lost), 20 s at 10000/s" >> "$OUT"
load 20 10000 > "$W/phase.txt" & L=$!
sleep 6; podman restart -t 0 "${VALKEY_CONTAINER:-songbird-valkey-m4}" > /dev/null; echo "valkey restarted at $(date +%T)" >> "$OUT"
wait $L; cat "$W/phase.txt" >> "$OUT"
G=$(owner)
echo "== partition owner ($G) stopped gracefully (SIGTERM) at 6 s, restarted at 14 s, 25 s at 10000/s" >> "$OUT"
load 25 10000 > "$W/phase.txt" & L=$!
sleep 6; kill -TERM "${PID[$G]}"; echo "stopped $G at $(date +%T)" >> "$OUT"
# Its devices reconnect when it is back (a load balancer would send them elsewhere at once).
sleep 8; wait "${PID[$G]}" 2>/dev/null; start "$G"; echo "restarted $G at $(date +%T)" >> "$OUT"
wait $L; cat "$W/phase.txt" >> "$OUT"
sleep 10
K=$(owner); for n in $NODES; do [ "$n" != "$K" ] && O=$n && break; done
echo "== two nodes killed at once (-9): partition owner ($K) and $O at 6 s, restarted at 14 s, 25 s at 10000/s" >> "$OUT"
load 25 10000 > "$W/phase.txt" & L=$!
sleep 6; kill -9 "${PID[$K]}" "${PID[$O]}"; echo "killed $K and $O at $(date +%T)" >> "$OUT"
sleep 8; start "$K"; start "$O"; echo "restarted $K and $O at $(date +%T)" >> "$OUT"
wait $L; cat "$W/phase.txt" >> "$OUT"
sleep 10
echo "== rolling restart: each node stopped (SIGTERM) and restarted in turn, 12 s apart, 45 s at 10000/s" >> "$OUT"
load 45 10000 > "$W/phase.txt" & L=$!
sleep 5
for n in $NODES; do
  kill -TERM "${PID[$n]}"; wait "${PID[$n]}" 2>/dev/null; start "$n"; echo "restarted $n at $(date +%T)" >> "$OUT"
  sleep 12
done
wait $L; cat "$W/phase.txt" >> "$OUT"
sleep 15; echo "leases per node at the end: $(leases)" >> "$OUT"
for n in $NODES; do kill "${PID[$n]}" 2>/dev/null; done; wait 2>/dev/null
echo DONE >> "$OUT"
