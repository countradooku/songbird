# Shared helpers for deploy/bin scripts. Sourced, not executed.
set -euo pipefail

DEPLOY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_DIR=$(cd "$DEPLOY_DIR/.." && pwd)
TOFU_DIR="$DEPLOY_DIR/tofu"
ANSIBLE_DIR="$DEPLOY_DIR/ansible"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

need() { for t in "$@"; do command -v "$t" >/dev/null || die "$t is required (deploy/bin/install-tools in CI)"; done; }

check_env() {
  [[ "$1" =~ ^[a-z][a-z0-9-]{1,20}$ ]] || die "bad environment name: $1"
  [ -f "$TOFU_DIR/environments/$1.tfvars" ] || die "no deploy/tofu/environments/$1.tfvars"
  [ -f "$DEPLOY_DIR/secrets/$1.sops.yaml" ] || die "no deploy/secrets/$1.sops.yaml (run deploy/bin/secrets-init $1)"
}

check_cloud() {
  case "$1" in hetzner|scaleway) ;; *) die "cloud must be hetzner or scaleway, not $1" ;; esac
}

# secret <env> <key>: one decrypted value, never echoed.
secret() { sops -d --extract "[\"$2\"]" "$DEPLOY_DIR/secrets/$1.sops.yaml"; }

# Exports the credentials OpenTofu needs for <env> at <cloud>. Values stay in this process.
export_cloud_env() {
  local env=$1 cloud=$2
  TF_VAR_state_passphrase=$(secret "$env" tofu_state_passphrase); export TF_VAR_state_passphrase
  TF_VAR_ssh_public_key=$(secret "$env" deploy_ssh_public_key); export TF_VAR_ssh_public_key
  TF_VAR_admin_cidrs=$(secret "$env" admin_cidrs_json); export TF_VAR_admin_cidrs
  AWS_ACCESS_KEY_ID=$(secret "$env" "state_access_key_${cloud}"); export AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY=$(secret "$env" "state_secret_key_${cloud}"); export AWS_SECRET_ACCESS_KEY
  case "$cloud" in
    hetzner) HCLOUD_TOKEN=$(secret "$env" hcloud_token); export HCLOUD_TOKEN ;;
    scaleway)
      SCW_ACCESS_KEY=$(secret "$env" scw_access_key); export SCW_ACCESS_KEY
      SCW_SECRET_KEY=$(secret "$env" scw_secret_key); export SCW_SECRET_KEY
      SCW_DEFAULT_PROJECT_ID=$(secret "$env" scw_project_id); export SCW_DEFAULT_PROJECT_ID ;;
  esac
}

tofu_init() { # env cloud
  tofu -chdir="$TOFU_DIR/envs/$2" init -input=false -reconfigure \
    -backend-config="$TOFU_DIR/backends/$1-$2.s3.tfbackend" >/dev/null
}

tofu_vars() { # env cloud
  echo "-var-file=$TOFU_DIR/environments/$1.tfvars -var-file=$TOFU_DIR/providers/$2.tfvars"
}

# Starts an ssh-agent holding the deploy key (from DEPLOY_SSH_KEY or SOPS) for Ansible.
start_agent() {
  eval "$(ssh-agent -s)" >/dev/null
  trap 'ssh-agent -k >/dev/null 2>&1 || true' EXIT
  if [ -n "${DEPLOY_SSH_KEY:-}" ]; then
    printf '%s\n' "$DEPLOY_SSH_KEY" | ssh-add - >/dev/null 2>&1
  else
    secret "$1" deploy_ssh_private_key | ssh-add - >/dev/null 2>&1
  fi
}

ansible_prepare() {
  ( cd "$ANSIBLE_DIR" && ansible-galaxy collection install -r collections/requirements.yml -p .collections >/dev/null )
}
