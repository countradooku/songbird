#!/usr/bin/env bash
# M6 gate: timed restore drill under load (D-0040). One delivery node on the registry
# (SurrealDB) and the Iggy mailbox of the compose stack; steady load with end-to-end delivery
# receipts (`songbird-loadgen run --scenario restore`); mid-run the data host is "lost":
#
#   1. delivery killed (-9);
#   2. the registry database removed;
#   3. the mailbox lost: delivery comes back on a new, empty stream with a new key directory
#      (from delivery's side indistinguishable from a wiped Iggy volume, without wiping the
#      shared dev stack);
#
# then the restore runbook: `songbird-admin backup restore` from the newest encrypted backup
# (which bumps the store generation), delivery restarted. RTO is measured from the kill to
# delivery ready again. The load generator's checker must PASS: no accepted message lost,
# numbering restarting at the restore allowed, repeats after it dropped by message ID.
#
# A tenth of the devices (OFFLINE, default) only receive and come online after sending stops:
# their whole mailbox is lost in the disaster, so everything they get from before it reaches
# them only because senders resend what has no delivery receipt.
#
#   bench/m6/restore-drill.sh <work dir> [age dir] [devices] [rate] [secs] [disaster at, s]
#
# Needs the compose stack up (`cargo xtask dev-up`) and release binaries
# (cargo build --release -p songbird-delivery -p songbird-loadgen -p songbird-admin).
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a; . ./.env; set +a
# The deletion journal key (D-0041): restores refuse to run without it.
DELETION_JOURNAL_KEY=$(openssl rand -hex 32); export DELETION_JOURNAL_KEY
W=$1; AGEDIR=${2:-}; DEVICES=${3:-1000}; RATE=${4:-2000}; SECS=${5:-60}; AT=${6:-20}
OFFLINE=${OFFLINE:-$((DEVICES / 10))}
# NO_RESEND=1: negative control (clients keep no send log); the checker must FAIL with losses.
EXTRA=(); [ -n "${NO_RESEND:-}" ] && EXTRA=(--no-resend)
AGE=${AGEDIR:+$AGEDIR/}age; KEYGEN=${AGEDIR:+$AGEDIR/}age-keygen
B=target/release
NS=drill; DB=registry; SURREAL=127.0.0.1:47800; IGGY=127.0.0.1:${SB_PORT_IGGY:-47890}
now() { perl -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
sql() { curl -s -u "$SURREAL_USER:$SURREAL_PASS" -H "Surreal-NS: $NS" -H "Surreal-DB: $DB" -H "Accept: application/json" "http://$SURREAL/sql" -d "$1"; }
C=(--addr "$SURREAL" --user "$SURREAL_USER" --namespace "$NS" --database "$DB")
G=(--confirm "$NS/$DB" --audit-log "$W/admin-audit.jsonl")

rm -rf "$W"; mkdir -p "$W"; chmod 700 "$W"
umask 077
printf %s "$IGGY_ROOT_PASSWORD" > "$W/iggy-pass"
printf %s "$SURREAL_PASS" > "$W/surreal-pass"
openssl rand -hex 32 > "$W/master-key"; openssl rand -hex 32 > "$W/idem-secret"
"$KEYGEN" -o "$W/owner.key" 2>/dev/null
OWNER=$(grep -o 'age1[0-9a-z]*' "$W/owner.key")

conf() { # stream key_dir
  mkdir -p "$2"
  cat > "$W/delivery.toml" <<CONF
[common]
environment = "dev"
admin_listen = "127.0.0.1:9191"
shutdown_grace_secs = 5
[common.log]
format = "pretty"
filter = "warn"
[delivery]
listen = "127.0.0.1:9291"
server_name = "localhost"
[delivery.registry]
poll_ms = 500
[delivery.registry.surrealdb]
addr = "$SURREAL"
host = "127.0.0.1"
user = "$SURREAL_USER"
pass = { file = "$W/surreal-pass" }
namespace = "$NS"
database = "$DB"
[delivery.session]
sends_per_sec = 100000
send_burst = 200000
frames_per_sec = 500000
frame_burst = 1000000
accepts_per_sec = 50000
accept_burst = 100000
[delivery.mailbox]
backend = "iggy"
max_per_device = 100000
[delivery.mailbox.iggy]
addr = "$IGGY"
user = "$IGGY_ROOT_USERNAME"
pass = { file = "$W/iggy-pass" }
stream = "$1"
partitions = 4
idempotency_secret = { file = "$W/idem-secret" }
key_dir = "$2"
master_key = { file = "$W/master-key" }
CONF
}
start() {
  "$B/songbird-delivery" --config "$W/delivery.toml" >> "$W/delivery.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 600); do curl -sf http://127.0.0.1:9191/readyz >/dev/null && return 0; sleep 0.05; done
  echo "delivery not ready"; exit 1
}

echo "== registry: $DEVICES devices, one account each"
sql "REMOVE DATABASE IF EXISTS $DB; DEFINE DATABASE $DB;" >/dev/null
"$B/songbird-loadgen" keys --devices "$DEVICES" --out "$W/keys" >/dev/null
SURREAL_PASS=$SURREAL_PASS "$B/songbird-admin" accounts import "${C[@]}" "${G[@]}" --directory "$W/keys/devices.toml"
echo "store generation before: $("$B/songbird-admin" generation show "${C[@]}")"
echo "== backup (the timer's job)"
"$B/songbird-admin" backup run "${C[@]}" --dir "$W/store" --recipient "$OWNER" --age "$AGE" --state "$W/state"

STREAM1="m6a$RANDOM"; STREAM2="m6b$RANDOM"
conf "$STREAM1" "$W/keystore-1"; start
echo "== load: $RATE/s for $SECS s over $DEVICES devices ($OFFLINE offline until sending stops); disaster at $AT s"
"$B/songbird-loadgen" run --addr 127.0.0.1:9291 --seeds "$W/keys/seeds.txt" --scenario restore \
  --secs "$SECS" --rate "$RATE" --size 256 --threads 8 --connect-rate 5000 --settle-secs 60 --offline-recipients "$OFFLINE" ${EXTRA[@]+"${EXTRA[@]}"} \
  > "$W/load.txt" 2>&1 & L=$!
# The load generator connects every device before its clock starts (well under 2 s here).
sleep $((AT + 2))

T0=$(now)
kill -9 "$PID"; wait "$PID" 2>/dev/null || true
sql "REMOVE DATABASE $DB;" >/dev/null
echo "disaster at $(date +%T): delivery killed, registry removed, mailbox lost"
echo "== restore runbook"
T1=$(now)
"$B/songbird-admin" backup restore "${C[@]}" "${G[@]}" --dir "$W/store" --identity "$W/owner.key" --age "$AGE" --max-age-hours 24
conf "$STREAM2" "$W/keystore-2"; start
T2=$(now)
echo "restore took $(perl -e "printf '%.2f', $T2-$T1") s; outage (RTO measured) $(perl -e "printf '%.2f', $T2-$T0") s"

RC=0; wait "$L" || RC=$?
cat "$W/load.txt"
echo "== audit log"; cat "$W/admin-audit.jsonl"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null || true
sql "REMOVE DATABASE IF EXISTS $DB;" >/dev/null
exit "$RC"
