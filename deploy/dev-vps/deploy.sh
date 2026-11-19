#!/usr/bin/env bash
# Deploys the test stack (compose.yaml) to one server running Coolify. From the repository root:
#   deploy/dev-vps/deploy.sh <ssh-target> <domain> <public-ipv4>     # build, configure, start
#   deploy/dev-vps/deploy.sh <ssh-target> <domain> <ip> invite       # mint one invite code
#   deploy/dev-vps/deploy.sh <ssh-target> <domain> <ip> status       # containers and readiness
# Images are built on the server from this checkout (no registry). Secrets never leave it.
set -euo pipefail
cd "$(dirname "$0")/../.."
target=${1:?ssh target}; domain=${2:?domain}; ip=${3:?ipv4}; cmd=${4:-up}
remote=/opt/songbird
r() { ssh -o BatchMode=yes "$target" "$@"; }
compose="docker compose -f $remote/deploy/compose.yaml --project-directory $remote/deploy"

case "$cmd" in
invite)
  r "set -a; . $remote/secrets/env; set +a; $compose run --rm -e SURREAL_PASS admin \
     invites create --addr surrealdb:8000 --host surrealdb --count 1 \
     --confirm songbird/songbird --audit-log /var/lib/songbird-admin/audit.jsonl"
  exit 0 ;;
status)
  r "$compose ps --format 'table {{.Name}}\t{{.Status}}'"
  exit 0 ;;
up) ;;
*) echo "unknown command $cmd" >&2; exit 1 ;;
esac

echo "== source"
r "install -d -m 0755 $remote/src $remote/deploy"
# Only what the server workspace builds from (apps/ is its own workspace; .claude holds agent state).
rsync -az --delete --exclude target --exclude .git --exclude '.env*' --exclude /.claude \
  --exclude /apps --exclude 'fuzz/corpus' --exclude 'fuzz/artifacts' --exclude '*.key' --exclude '*.pem' \
  ./ "$target:$remote/src/"
rsync -az deploy/dev-vps/ "$target:$remote/deploy/"

echo "== images (built on the server)"
for bin in songbird-api songbird-delivery songbird-calls songbird-admin; do
  r "cd $remote/src && DOCKER_BUILDKIT=1 docker build -q -f deploy/docker/Dockerfile \
     --build-arg BIN=$bin -t ${bin}:dev ." >/dev/null
  echo "  $bin:dev"
done

echo "== configuration and routes"
r "bash $remote/deploy/setup.sh $domain $ip"

echo "== certificates for ws.$domain and turn.$domain (Traefik, HTTP-01)"
for _ in $(seq 1 40); do
  if r "/usr/local/sbin/songbird-certs $domain"; then break; fi
  sleep 6
done
r "test -s $remote/tls/ws/tls.crt && test -s $remote/tls/turn/tls.crt" \
  || { echo "certificates not issued: check DNS and Traefik's log" >&2; exit 1; }

echo "== start"
r "$compose up -d --remove-orphans"
r "$compose ps --format 'table {{.Name}}\t{{.Status}}'"
