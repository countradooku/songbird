# Off-site, write-once registry backups for one Songbird environment (D-0040), at Scaleway Object
# Storage (EU). A root of its own, applied by the owner with an Organization-level key kept in
# deploy/secrets/backups.sops.yaml: the environments' deploy credentials can neither change nor
# destroy it. Use deploy/bin/backups-up, not tofu directly.
#
#   project   a dedicated Scaleway project: IAM rules scoped to it reach nothing else
#   bucket    versioned, Object Lock in compliance mode (default 1 day; `songbird-admin backup
#             run --lock` sets each object's retention by tier), expiry per tier prefix
#   writer    the data host's key: PutObject and PutObjectRetention on this bucket only. It
#             cannot read, list, delete, change ACLs or the lock configuration, so a compromised
#             server can neither read old backups (which hold deleted accounts until retention
#             ends) nor destroy them
#   verifier  the verification host's key: GetObject and ListBucket only

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.89"
    }
  }

  # State at Hetzner Object Storage (the other provider): deploy/tofu/backends/<env>-backups.s3.tfbackend.
  backend "s3" {}

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

# Credentials from SCW_ACCESS_KEY, SCW_SECRET_KEY and SCW_DEFAULT_ORGANIZATION_ID (the owner's
# Organization-level key, decrypted from deploy/secrets/backups.sops.yaml by deploy/bin/backups-up).
provider "scaleway" {
  region = var.region
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
  type        = string
  description = "The environment whose registry is backed up, e.g. beta."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.environment))
    error_message = "environment must be 2-21 chars of [a-z0-9-], starting with a letter."
  }
}

variable "region" {
  type        = string
  default     = "fr-par"
  description = "Scaleway region, EU only."
  validation {
    condition     = contains(["fr-par", "nl-ams", "pl-waw"], var.region)
    error_message = "EU regions only: fr-par, nl-ams, pl-waw."
  }
}

variable "bucket_name" {
  type        = string
  description = "Globally unique bucket name, e.g. songbird-beta-backups-<random>."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,62}$", var.bucket_name))
    error_message = "bucket_name must be 3-63 chars of [a-z0-9-]."
  }
}

variable "admin_principal" {
  type        = string
  description = <<-EOT
    The owner's IAM principal, which keeps full access to the bucket through its policy, e.g.
    "user_id:<uuid>". Without it the policy would lock everyone else out of administration.
  EOT
  validation {
    condition     = can(regex("^(user_id|application_id):[0-9a-f-]{36}$", var.admin_principal))
    error_message = "admin_principal must be user_id:<uuid> or application_id:<uuid>."
  }
}

locals {
  # Days after creation each tier is expired; one day longer than the retention `songbird-admin
  # backup run --lock` sets (tools/admin/src/backup.rs TIERS), so expiry never meets a lock.
  tiers = {
    frequent = 2
    daily    = 9
    weekly   = 30
    monthly  = 94
  }
}

resource "scaleway_account_project" "backups" {
  name        = "songbird-${var.environment}-backups"
  description = "Write-once registry backups of ${var.environment} (D-0040). Nothing else."
}

resource "scaleway_object_bucket" "backups" {
  name                = var.bucket_name
  project_id          = scaleway_account_project.backups.id
  object_lock_enabled = true
  force_destroy       = false

  versioning {
    enabled = true
  }

  dynamic "lifecycle_rule" {
    for_each = local.tiers
    content {
      id      = "registry-${lifecycle_rule.key}"
      prefix  = "registry/${lifecycle_rule.key}/"
      enabled = true
      expiration {
        days = lifecycle_rule.value
      }
      # The expired version becomes noncurrent behind a delete marker; remove it the day after.
      noncurrent_version_expiration {
        noncurrent_days = 1
      }
    }
  }

  lifecycle_rule {
    id                                     = "abort-incomplete-uploads"
    enabled                                = true
    abort_incomplete_multipart_upload_days = 1
  }

  tags = {
    songbird    = "backups"
    environment = var.environment
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "scaleway_object_bucket_lock_configuration" "backups" {
  bucket     = scaleway_object_bucket.backups.name
  project_id = scaleway_account_project.backups.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 1
    }
  }
}

resource "scaleway_iam_application" "writer" {
  name        = "songbird-${var.environment}-backup-writer"
  description = "Data host: puts registry backups. Cannot read, list or delete them."
}

resource "scaleway_iam_application" "verifier" {
  name        = "songbird-${var.environment}-backup-verifier"
  description = "Verification host: reads registry backups. Cannot write or delete them."
}

# IAM grants the coarse permission sets, scoped to the dedicated project; the bucket policy below
# narrows them to the exact actions (both must allow a request).
resource "scaleway_iam_policy" "writer" {
  name           = "songbird-${var.environment}-backup-writer"
  application_id = scaleway_iam_application.writer.id
  rule {
    project_ids          = [scaleway_account_project.backups.id]
    permission_set_names = ["ObjectStorageObjectsWrite"]
  }
}

resource "scaleway_iam_policy" "verifier" {
  name           = "songbird-${var.environment}-backup-verifier"
  application_id = scaleway_iam_application.verifier.id
  rule {
    project_ids          = [scaleway_account_project.backups.id]
    permission_set_names = ["ObjectStorageObjectsRead"]
  }
}

resource "scaleway_object_bucket_policy" "backups" {
  bucket     = scaleway_object_bucket.backups.name
  project_id = scaleway_account_project.backups.id
  policy = jsonencode({
    Version = "2023-04-17"
    Id      = "songbird-backups"
    Statement = [
      {
        Sid       = "Owner"
        Effect    = "Allow"
        Principal = { SCW = var.admin_principal }
        Action    = ["s3:*"]
        Resource  = [scaleway_object_bucket.backups.name, "${scaleway_object_bucket.backups.name}/*"]
      },
      {
        Sid       = "WriterPutsOnly"
        Effect    = "Allow"
        Principal = { SCW = "application_id:${scaleway_iam_application.writer.id}" }
        Action    = ["s3:PutObject", "s3:PutObjectRetention"]
        Resource  = ["${scaleway_object_bucket.backups.name}/registry/*"]
      },
      {
        Sid       = "VerifierReadsOnly"
        Effect    = "Allow"
        Principal = { SCW = "application_id:${scaleway_iam_application.verifier.id}" }
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource  = [scaleway_object_bucket.backups.name, "${scaleway_object_bucket.backups.name}/*"]
      },
    ]
  })
}

# The keys go into the environment's SOPS file (backup_s3_* on the data host, backup_verify_s3_*
# on the verification host); the state holding them is encrypted client-side.
resource "scaleway_iam_api_key" "writer" {
  application_id     = scaleway_iam_application.writer.id
  default_project_id = scaleway_account_project.backups.id
  description        = "songbird-${var.environment} data host"
}

resource "scaleway_iam_api_key" "verifier" {
  application_id     = scaleway_iam_application.verifier.id
  default_project_id = scaleway_account_project.backups.id
  description        = "songbird-${var.environment} backup verification"
}

output "bucket" {
  value = scaleway_object_bucket.backups.name
}

output "endpoint" {
  value = "s3.${var.region}.scw.cloud:443"
}

output "writer_access_key" {
  value = scaleway_iam_api_key.writer.access_key
}

output "writer_secret_key" {
  value     = scaleway_iam_api_key.writer.secret_key
  sensitive = true
}

output "verifier_access_key" {
  value = scaleway_iam_api_key.verifier.access_key
}

output "verifier_secret_key" {
  value     = scaleway_iam_api_key.verifier.secret_key
  sensitive = true
}
