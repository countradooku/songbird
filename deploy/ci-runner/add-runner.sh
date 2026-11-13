#!/bin/sh
# Installs and starts one GitHub Actions runner as the `ci` user (D-0039). Run as root after
# provision.sh. The registration token is short-lived (one hour) and is not stored:
#   TOKEN=$(gh api -X POST repos/countradooku/songbird/actions/runners/registration-token -q .token)
#   ssh root@host "RUNNER_TOKEN=$TOKEN sh -s -- songbird-1 songbird,songbird-stack" < deploy/ci-runner/add-runner.sh
#
# Labels: every runner has `songbird`; the one runner with `songbird-stack` runs the jobs that
# start the compose stack or bind fixed ports (one at a time).
set -eu

NAME=$1
LABELS=$2
: "${RUNNER_TOKEN:?RUNNER_TOKEN is required}"
REPO_URL=https://github.com/countradooku/songbird
VERSION=2.338.2
SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
CI_USER=ci
uid=$(id -u "$CI_USER")
home=$(getent passwd "$CI_USER" | cut -d: -f6)
dir="$home/runners/$NAME"

if [ ! -x "$dir/run.sh" ]; then
  tarball="$home/runners/actions-runner-linux-x64-$VERSION.tar.gz"
  runuser -u "$CI_USER" -- mkdir -p "$dir"
  if [ ! -f "$tarball" ]; then
    runuser -u "$CI_USER" -- curl -fsSL -o "$tarball" \
      "https://github.com/actions/runner/releases/download/v$VERSION/actions-runner-linux-x64-$VERSION.tar.gz"
  fi
  echo "$SHA256  $tarball" | sha256sum -c -
  runuser -u "$CI_USER" -- tar -xzf "$tarball" -C "$dir"
fi

# The runner and the docker CLI it calls use the ci user's rootless daemon.
cat > "$dir/.env" <<ENV
DOCKER_HOST=unix:///run/user/$uid/docker.sock
XDG_RUNTIME_DIR=/run/user/$uid
LANG=C.UTF-8
PATH=$home/.cargo/bin:/usr/local/bin:/usr/bin:/bin
SONGBIRD_AUTOBAHN_HOST=10.0.2.2
ENV
chown "$CI_USER:$CI_USER" "$dir/.env"
# Pick up a changed environment on a runner that already exists.
systemctl try-restart "songbird-runner-$NAME.service" 2>/dev/null || true

if [ ! -f "$dir/.runner" ]; then
  runuser -u "$CI_USER" -- "$dir/config.sh" --unattended --replace \
    --url "$REPO_URL" --token "$RUNNER_TOKEN" --name "$NAME" \
    --labels "$LABELS" --work _work
fi

cat > "/etc/systemd/system/songbird-runner-$NAME.service" <<UNIT
[Unit]
Description=Songbird CI runner $NAME
After=network-online.target user@$uid.service
Wants=network-online.target

[Service]
User=$CI_USER
WorkingDirectory=$dir
EnvironmentFile=$dir/.env
ExecStart=$dir/run.sh
Restart=always
RestartSec=5
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=5min
Slice=ci-runners.slice
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now "songbird-runner-$NAME.service"
systemctl is-active "songbird-runner-$NAME.service"
