#!/usr/bin/env bash
# Restarts a native Iggy server with an empty data directory on tmpfs (each benchmark run starts
# clean; streams of earlier runs would fill the tmpfs quota). Environment: IGGY_BIN (iggy-server
# 0.10.0), IGGY_DATA (default /dev/shm/songbird-iggy-m3), IGGY_PASS_FILE, WORKDIR (pid, log and
# the key store live there), IGGY_CPUS (default 8..12).
set -u
W=${WORKDIR:?}; DATA=${IGGY_DATA:-/dev/shm/songbird-iggy-m3}
P=$(cat "$W/iggy.pid" 2>/dev/null); [ -n "$P" ] && kill "$P" 2>/dev/null
for i in $(seq 1 50); do kill -0 "$P" 2>/dev/null || break; sleep 0.2; done
rm -rf "$DATA" "$W/keystore"; mkdir -p "$DATA" "$W/keystore"
env IGGY_PATH="$DATA" IGGY_TCP_ADDRESS=127.0.0.1:47990 IGGY_HTTP_ADDRESS=127.0.0.1:47991 \
  IGGY_QUIC_ENABLED=false IGGY_WEBSOCKET_ENABLED=false IGGY_SHARDING_CPU_ALLOCATION="${IGGY_CPUS:-8..12}" \
  IGGY_ROOT_USERNAME=iggy IGGY_ROOT_PASSWORD="$(cat "${IGGY_PASS_FILE:?}")" \
  nohup "${IGGY_BIN:?}" > "$W/iggy.log" 2>&1 &
echo $! > "$W/iggy.pid"
for i in $(seq 1 100); do ss -ltn | grep -q 47990 && break; sleep 0.2; done
sleep 1
