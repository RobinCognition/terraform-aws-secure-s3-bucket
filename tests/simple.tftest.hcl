# Mirrors examples/simple: only bucket_name is provided, everything else is a
# secure default. The AWS provider is mocked so the plan needs no credentials.
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
}

run "secure_defaults" {
  command = plan

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "Bucket must be encrypted with KMS by default"
  }

  assert {
    condition     = aws_kms_key.this.enable_key_rotation
    error_message = "KMS key rotation must be enabled by default"
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.this.versioning_configuration).status == "Enabled"
    error_message = "Bucket versioning must be enabled"
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.this.block_public_acls,
      aws_s3_bucket_public_access_block.this.block_public_policy,
      aws_s3_bucket_public_access_block.this.ignore_public_acls,
      aws_s3_bucket_public_access_block.this.restrict_public_buckets,
    ])
    error_message = "All four public access block flags must be enabled by default"
  }

}

# The bucket policy and the KMS key reference attributes that are only known
# once the (mocked) resources exist, so these assertions run against a mocked
# apply instead of a plan. No AWS API is contacted.
run "https_only_policy_and_kms_key" {
  command = apply

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.this.policy).Statement :
      statement.Sid == "HTTPSOnly" &&
      statement.Effect == "Deny" &&
      statement.Condition.Bool["aws:SecureTransport"] == "false"
    ])
    error_message = "Bucket policy must deny non-HTTPS requests"
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).kms_master_key_id == aws_kms_key.this.arn
    error_message = "Bucket must be encrypted with the KMS key managed by this module"
  }
}
