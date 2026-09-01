# Mirrors examples/complete: every input is set explicitly, including the
# public access block flags, which are turned off there.
mock_provider "aws" {
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::secure-bucket"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:eu-central-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  bucket_name = "secure-bucket"

  bucket_lifecycle_configuration_rule_noncurrent_version_expiration_noncurrent_days           = 45
  bucket_lifecycle_configuration_rule_noncurrent_version_first_transition_noncurrent_days     = 15
  bucket_lifecycle_configuration_rule_noncurrent_version_first_transition_storage_class       = "ONEZONE_IA"
  bucket_lifecycle_configuration_rule_noncurrent_version_second_transition_noncurrent_days    = 30
  bucket_lifecycle_configuration_rule_noncurrent_version_second_transition_storage_class      = "GLACIER_IR"
  bucket_lifecycle_configuration_rule_abort_incomplete_multipart_upload_days_after_initiation = 14

  aws_kms_key_enable_key_rotation = false
  aws_kms_key_multi_region        = true

  aws_s3_bucket_public_access_block_block_public_acls       = false
  aws_s3_bucket_public_access_block_block_public_policy     = false
  aws_s3_bucket_public_access_block_ignore_public_acls      = false
  aws_s3_bucket_public_access_block_restrict_public_buckets = false
}

run "all_inputs_configured" {
  command = plan

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "Bucket must be encrypted with KMS regardless of the other inputs"
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.this.versioning_configuration).status == "Enabled"
    error_message = "Bucket versioning must be enabled regardless of the other inputs"
  }

  assert {
    condition     = aws_kms_key.this.multi_region && !aws_kms_key.this.enable_key_rotation
    error_message = "KMS key must honour the configured rotation and multi-region inputs"
  }

  assert {
    condition = alltrue([
      for flag in [
        aws_s3_bucket_public_access_block.this.block_public_acls,
        aws_s3_bucket_public_access_block.this.block_public_policy,
        aws_s3_bucket_public_access_block.this.ignore_public_acls,
        aws_s3_bucket_public_access_block.this.restrict_public_buckets,
      ] : flag == false
    ])
    error_message = "Public access block flags must honour the configured inputs"
  }

  assert {
    condition = alltrue([
      for transition in one(aws_s3_bucket_lifecycle_configuration.this.rule).noncurrent_version_transition :
      contains(["ONEZONE_IA", "GLACIER_IR"], transition.storage_class)
    ])
    error_message = "Lifecycle transitions must honour the configured storage classes"
  }
}
