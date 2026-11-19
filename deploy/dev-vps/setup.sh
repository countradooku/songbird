#!/usr/bin/env bash
# Runs ON the server (deploy.sh copies and calls it). Idempotent: secrets are made once and kept;
# configs and routes are rewritten every run.
#   setup.sh <domain> <public-ipv4>
# Layout:
#   /opt/songbird/secrets  root:65532 0750; hex keys 0640 (services run as 65532); env files 0600
#   /opt/songbird/config   service configs (no secrets: they reference /run/songbird or env)
#   /opt/songbird/tls      ws/ and turn/ certificates exported from Coolify's Traefik (certs.py)
set -euo pipefail
domain=${1:?domain}; ip=${2:?public ipv4}
base=/opt/songbird
sec=$base/secrets; cfg=$base/config
install -d -m 0755 "$base" "$cfg" "$base/tls"
install -d -m 0750 -o root -g 65532 "$sec"
install -d -m 0700 -o 65532 -g 65532 "$base/admin" # songbird-admin's audit log

hexfile() { # a 32-byte hex key, made once
  local f="$sec/$1.hex"
  [ -s "$f" ] || { (umask 077; openssl rand -hex 32 > "$f"); }
  chown root:65532 "$f"; chmod 0640 "$f"
}
for k in push-index jobs registration usernames keys calls livekit-secret; do hexfile "$k"; done

if [ ! -s "$sec/env" ]; then
  (umask 077; cat > "$sec/env" <<EOF
SURREAL_USER=root
SURREAL_PASS=$(openssl rand -hex 24)
VALKEY_HOT_PASSWORD=$(openssl rand -hex 24)
VALKEY_JOBS_PASSWORD=$(openssl rand -hex 24)
RUSTFS_ACCESS_KEY=$(openssl rand -hex 12)
RUSTFS_SECRET_KEY=$(openssl rand -hex 24)
EOF
  )
fi
(umask 077; printf 'LIVEKIT_KEYS=songbird: %s\n' "$(cat "$sec/livekit-secret.hex")" > "$sec/livekit.env")
[ -s "$sec/push-public.hex" ] || openssl rand -hex 32 > "$sec/push-public.hex" # push is off here

surreal='addr = "surrealdb:8000"
host = "surrealdb"
user = "root"
pass = { env = "SURREAL_PASS" }'
common() { cat <<EOF
[common]
environment = "dev"
admin_listen = "0.0.0.0:$1"
shutdown_grace_secs = 10
[common.log]
format = "json"
filter = "info"
EOF
}
livekit_settings="secret = { file = \"/run/songbird/calls.hex\" }
livekit_url = \"wss://livekit.$domain\"
api_url = \"http://songbird-livekit:7880\"
api_key = \"songbird\"
api_secret = { file = \"/run/songbird/livekit-secret.hex\" }"

{ common 9102; cat <<EOF

[api]
listen = "0.0.0.0:8443"
server_name = "api.$domain"
push_public_key = "$(cat "$sec/push-public.hex")"
push_index_secret = { file = "/run/songbird/push-index.hex" }
[api.surrealdb]
$surreal
[api.valkey_hot]
addr = "valkey-hot:6379"
pass = { env = "VALKEY_HOT_PASSWORD" }
[api.jobs]
secret = { file = "/run/songbird/jobs.hex" }
[api.jobs.valkey]
addr = "valkey-jobs:6379"
pass = { env = "VALKEY_JOBS_PASSWORD" }
[api.s3]
addr = "rustfs:9000"
bucket = "songbird-attachments"
access_key = { env = "RUSTFS_ACCESS_KEY" }
secret_key = { env = "RUSTFS_SECRET_KEY" }
[api.registration]
secret = { file = "/run/songbird/registration.hex" }
invite_only = true
allowance = 5
[api.usernames]
secret = { file = "/run/songbird/usernames.hex" }
[api.keys]
secret = { file = "/run/songbird/keys.hex" }
[api.calls]
$livekit_settings
EOF
} > "$cfg/api.toml"

{ common 9101; cat <<EOF

[delivery]
listen = "0.0.0.0:9201"
server_name = "ws.$domain"
[delivery.tls]
cert_chain = "/etc/songbird/tls/tls.crt"
key = { file = "/etc/songbird/tls/tls.key" }
[delivery.registry]
poll_ms = 1000
[delivery.registry.surrealdb]
$surreal
EOF
} > "$cfg/delivery.toml"

{ common 9105; cat <<EOF

[calls]
webhook_listen = "0.0.0.0:9106"
[calls.valkey_hot]
addr = "valkey-hot:6379"
pass = { env = "VALKEY_HOT_PASSWORD" }
[calls.livekit]
$livekit_settings
EOF
} > "$cfg/calls.toml"

cat > "$cfg/livekit.yaml" <<EOF
# Single node, no Valkey (one SFU). As deploy/ansible/roles/calls/templates/livekit.yaml.j2
# otherwise: rooms only as api creates them (D-0088), TURN relays only to the public internet.
port: 7880
bind_addresses: ["0.0.0.0"]
rtc:
  tcp_port: 7881
  udp_port: 7882
  use_external_ip: false
  node_ip: "$ip"
  congestion_control: { enabled: true, allow_pause: true }
turn:
  enabled: true
  domain: "turn.$domain"
  tls_port: 5349
  udp_port: 3478
  external_tls: false
  cert_file: /tls/turn/tls.crt
  key_file: /tls/turn/tls.key
  deny_peer_cidrs: [0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, "::1/128", fc00::/7, fe80::/10]
room:
  auto_create: false
  empty_timeout: 180
  departure_timeout: 20
  max_participants: 128
webhook:
  api_key: songbird
  urls: ["http://songbird-calls:9106/livekit"]
logging: { json: true, level: info, pion_level: error }
EOF

# Routes in Coolify's Traefik (file provider, watched). Songbird's routers keep no access log:
# no client IPs from Songbird traffic in Traefik's log (invariant 6).
cat > /data/coolify/proxy/dynamic/songbird.yaml <<EOF
http:
  routers:
    songbird-api:
      rule: Host(\`api.$domain\`)
      entryPoints: [https]
      service: songbird-api
      tls: { certResolver: letsencrypt }
      observability: { accessLogs: false }
    songbird-livekit:
      rule: Host(\`livekit.$domain\`)
      entryPoints: [https]
      service: songbird-livekit
      tls: { certResolver: letsencrypt }
      observability: { accessLogs: false }
    # Only so Traefik obtains (and renews) certificates for ws. and turn. (its domains list);
    # certs.py exports them. It must not match ws.: an HTTP router for ws. answers it itself
    # instead of the TCP passthrough below (measured: 418 from noop). turn. is LiveKit's on 5349.
    songbird-certs:
      rule: Host(\`turn.$domain\`)
      entryPoints: [https]
      service: noop@internal
      tls:
        certResolver: letsencrypt
        domains: [{ main: "ws.$domain" }, { main: "turn.$domain" }]
      observability: { accessLogs: false }
    songbird-http:
      rule: Host(\`api.$domain\`) || Host(\`livekit.$domain\`)
      entryPoints: [http]
      middlewares: [songbird-https]
      service: noop@internal
      observability: { accessLogs: false }
  middlewares:
    songbird-https:
      redirectScheme: { scheme: https, permanent: true }
  services:
    songbird-api:
      loadBalancer: { servers: [{ url: "http://songbird-api:8443" }] }
    songbird-livekit:
      loadBalancer: { servers: [{ url: "http://songbird-livekit:7880" }] }
tcp:
  routers:
    # Delivery terminates TLS itself: the device signs the TLS exporter (D-0018).
    songbird-ws:
      rule: HostSNI(\`ws.$domain\`)
      entryPoints: [https]
      service: songbird-delivery
      tls: { passthrough: true }
  services:
    songbird-delivery:
      loadBalancer: { servers: [{ address: "songbird-delivery:9201" }] }
EOF

install -m 0755 "$(dirname "$0")/certs.py" /usr/local/sbin/songbird-certs
cat > /etc/systemd/system/songbird-certs.service <<EOF
[Unit]
Description=Export Songbird's ws./turn. certificates from Coolify's Traefik
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/songbird-certs $domain
EOF
cat > /etc/systemd/system/songbird-certs.timer <<'EOF'
[Unit]
Description=Daily export of Songbird's certificates (Traefik renews 30 days before expiry)
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now songbird-certs.timer >/dev/null
echo "setup: configs, routes and certificate timer in place for $domain"
