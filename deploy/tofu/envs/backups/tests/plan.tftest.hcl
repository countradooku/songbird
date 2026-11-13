# tofu test: the backups root plans with a mocked provider (no credentials, nothing created) and
# its security properties hold: compliance-mode lock, every tier expired after its retention, a
# writer that can only put, a verifier that can only read.

mock_provider "scaleway" {
  mock_resource "scaleway_iam_application" {
    defaults = { id = "11111111-1111-1111-1111-111111111111" }
  }
  mock_resource "scaleway_account_project" {
    defaults = { id = "33333333-3333-3333-3333-333333333333" }
  }
}

variables {
  state_passphrase = "test-passphrase-not-used-for-anything-real"
  environment      = "beta"
  bucket_name      = "songbird-beta-backups-test"
  admin_principal  = "user_id:22222222-2222-2222-2222-222222222222"
}

run "write_once_and_least_privilege" {
  command = plan

  assert {
    condition     = scaleway_object_bucket.backups.object_lock_enabled && !scaleway_object_bucket.backups.force_destroy
    error_message = "Object Lock on, no force_destroy"
  }
  assert {
    condition     = one(one(scaleway_object_bucket_lock_configuration.backups.rule).default_retention).mode == "COMPLIANCE"
    error_message = "compliance mode: nobody can shorten a retention, the owner included"
  }
  assert {
    condition     = length([for r in scaleway_object_bucket.backups.lifecycle_rule : r if startswith(r.prefix == null ? "" : r.prefix, "registry/")]) == 4
    error_message = "one expiry rule per tier"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(scaleway_object_bucket_policy.backups.policy).Statement :
      toset(s.Action) == toset(["s3:PutObject", "s3:PutObjectRetention"]) if s.Sid == "WriterPutsOnly"
    ])
    error_message = "the writer can only put objects and set their retention"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(scaleway_object_bucket_policy.backups.policy).Statement :
      toset(s.Action) == toset(["s3:PutObject", "s3:PutObjectRetention"]) && toset(s.Resource) == toset(["songbird-beta-backups-test/deletions/*"]) if s.Sid == "JournalPutsOnly"
    ])
    error_message = "the deletion journal can only put tombstones under deletions/"
  }
  assert {
    condition     = length([for r in scaleway_object_bucket.backups.lifecycle_rule : r if r.prefix == "deletions/"]) == 1
    error_message = "tombstones expire after their lock"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(scaleway_object_bucket_policy.backups.policy).Statement :
      toset(s.Action) == toset(["s3:GetObject", "s3:ListBucket"]) if s.Sid == "VerifierReadsOnly"
    ])
    error_message = "the verifier can only read"
  }
  assert {
    condition     = one(scaleway_iam_policy.writer.rule).permission_set_names == toset(["ObjectStorageObjectsWrite"])
    error_message = "the writer's IAM grant has no read or delete"
  }
}

run "rejects_a_region_outside_the_eu" {
  command = plan
  variables {
    region = "us-east-1"
  }
  expect_failures = [var.region]
}
