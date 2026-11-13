#!/bin/sh
# Prepares a Linux host to run Songbird's CI (D-0039). Idempotent; run as root:
#   ssh root@host 'sh -s' < deploy/ci-runner/provision.sh
#
# - A `ci` user with no sudo. CI jobs run as it and use their own rootless Docker daemon, which
#   cannot see or touch the host's other containers (Coolify and its apps).
# - Resource caps: the runners and the rootless Docker daemon each get a systemd slice with a
#   CPU and memory ceiling, so CI cannot starve the host's services.
# - Tools the workflows expect on a runner: C build tools, pkg-config, Python venv, rustup.
set -eu

CI_USER=ci
# Ceilings (the host has 8 cores and 16 GB; leave room for what else runs there).
RUNNERS_CPU=600%
RUNNERS_MEM=7G
DOCKER_CPU=400%
DOCKER_MEM=5G

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q uidmap dbus-user-session build-essential pkg-config python3-venv \
  git curl jq unzip docker-ce-rootless-extras

id "$CI_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$CI_USER"
uid=$(id -u "$CI_USER")
loginctl enable-linger "$CI_USER"

# Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor; rootless Docker's
# rootlesskit needs this profile (Docker's documented fix).
cat > /etc/apparmor.d/usr.bin.rootlesskit <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

/usr/bin/rootlesskit flags=(unconfined) {
  userns,

  include if exists <local/usr.bin.rootlesskit>
}
PROFILE
apparmor_parser -r /etc/apparmor.d/usr.bin.rootlesskit

# Caps: the runners (compiles, tests) and the user's systemd instance (rootless Docker and every
# container it starts).
cat > /etc/systemd/system/ci-runners.slice <<SLICE
[Unit]
Description=Songbird CI runners

[Slice]
CPUQuota=$RUNNERS_CPU
MemoryMax=$RUNNERS_MEM
TasksMax=8192
SLICE
mkdir -p "/etc/systemd/system/user-$uid.slice.d"
cat > "/etc/systemd/system/user-$uid.slice.d/50-ci-limits.conf" <<SLICE
[Slice]
CPUQuota=$DOCKER_CPU
MemoryMax=$DOCKER_MEM
TasksMax=8192
SLICE
systemctl daemon-reload

# Rootless Docker for the ci user (its own daemon, socket under /run/user/<uid>).
until [ -S "/run/user/$uid/bus" ]; do sleep 1; done
as_ci() {
  runuser -l "$CI_USER" -c "export XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus; $1"
}
as_ci 'systemctl --user is-active -q docker || dockerd-rootless-setuptool.sh install --skip-iptables'
# Containers may reach the host's loopback through 10.0.2.2 (Autobahn's echo server, D-0039).
as_ci 'mkdir -p ~/.config/systemd/user/docker.service.d && printf "[Service]\nEnvironment=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=false\n" > ~/.config/systemd/user/docker.service.d/host-loopback.conf && systemctl --user daemon-reload'
as_ci 'systemctl --user enable -q docker && systemctl --user restart docker'
# rustup from upstream, pinned and checksum-verified (Ubuntu's 1.26 cannot install the toolchain
# named by rust-toolchain.toml without arguments, which the workflows rely on).
RUSTUP_VERSION=1.29.3
RUSTUP_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
if dpkg -s rustup >/dev/null 2>&1; then apt-get remove -y -q rustup; fi
as_ci 'test -x ~/.cargo/bin/rustup && ~/.cargo/bin/rustup --version 2>/dev/null | grep -q " '"$RUSTUP_VERSION"' " || {
  curl -fsSL -o /tmp/rustup-init https://static.rust-lang.org/rustup/archive/'"$RUSTUP_VERSION"'/x86_64-unknown-linux-gnu/rustup-init &&
  echo "'"$RUSTUP_SHA256"'  /tmp/rustup-init" | sha256sum -c - &&
  chmod +x /tmp/rustup-init && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none &&
  rm -f /tmp/rustup-init; }'
as_ci '~/.cargo/bin/rustup --version'
as_ci 'DOCKER_HOST=unix:///run/user/'"$uid"'/docker.sock docker info --format "rootless docker {{.ServerVersion}} ({{.SecurityOptions}})"'
echo "provisioned: user $CI_USER (uid $uid)"
