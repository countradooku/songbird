# Root module for a Songbird environment at scaleway. Identical to envs/hetzner apart from the
# provider block and provider variables. Use deploy/bin/env-up, not tofu directly.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.89"
    }
  }

  # Remote state in S3-compatible storage; bucket and endpoint come from
  # deploy/tofu/backends/<env>-scaleway.s3.tfbackend, credentials from SOPS.
  backend "s3" {}

  # Client-side state and plan encryption (OpenTofu). The passphrase lives only in SOPS.
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }
    state {
      method   = method.aes_gcm.state
      enforced = true
    }
    plan {
      method   = method.aes_gcm.state
      enforced = true
    }
  }
}

# Credentials from SCW_ACCESS_KEY, SCW_SECRET_KEY and SCW_DEFAULT_PROJECT_ID (decrypted from SOPS
# by deploy/bin/env-up).
provider "scaleway" {
  region = var.region
  zone   = var.zone
}

variable "state_passphrase" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.state_passphrase) >= 32
    error_message = "state_passphrase must be at least 32 characters."
  }
}

variable "environment" {
  type = string
}

variable "hosts" {
  type = map(object({
    roles = list(string)
    class = string
    index = number
  }))
}

variable "admin_cidrs" {
  type = list(string)
}

variable "ssh_public_key" {
  type = string
}

variable "region" {
  type = string
}

variable "zone" {
  type = string
}

variable "server_types" {
  type = map(string)
}

module "topology" {
  source      = "../../modules/topology"
  environment = var.environment
  hosts       = var.hosts
  admin_cidrs = var.admin_cidrs
}

locals {
  topology = {
    environment  = module.topology.environment
    private_cidr = module.topology.private_cidr
    subnet_cidr  = module.topology.subnet_cidr
    cloud_init   = module.topology.cloud_init
    hosts        = module.topology.hosts
  }
}

module "cloud" {
  source         = "../../modules/scaleway"
  topology       = local.topology
  region         = var.region
  zone           = var.zone
  server_types   = var.server_types
  ssh_public_key = var.ssh_public_key
}

output "inventory" {
  value = module.cloud.inventory
}
