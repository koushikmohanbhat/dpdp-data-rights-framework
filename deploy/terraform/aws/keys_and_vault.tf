# KMS keys, vault tables and the certificate bucket.

resource "aws_kms_key" "vault" {
  description             = "${local.name}: vault key-encryption key (wraps per-principal DEKs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "vault" {
  name          = "alias/${local.name}-vault"
  target_key_id = aws_kms_key.vault.key_id
}

# Sealed KEK: the app may only Encrypt with it; Decrypt is reserved for the break-glass role.
resource "aws_kms_key" "sealed" {
  description             = "${local.name}: sealed-data KEK (legal hold / statutory escrow)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
          "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]
        Resource = "*"
      },
      {
        Sid       = "AppEncryptOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.task.arn }
        Action    = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        Sid       = "BreakGlassDecrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.break_glass.arn }
        Action    = ["kms:Decrypt", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        Sid       = "DenyAppDecrypt"
        Effect    = "Deny"
        Principal = { AWS = aws_iam_role.task.arn }
        Action    = ["kms:Decrypt"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "sealed" {
  name          = "alias/${local.name}-sealed"
  target_key_id = aws_kms_key.sealed.key_id
}

resource "aws_kms_key" "cert_signing" {
  description              = "${local.name}: signs erasure certificates"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
}

resource "aws_kms_alias" "cert_signing" {
  name          = "alias/${local.name}-cert-signing"
  target_key_id = aws_kms_key.cert_signing.key_id
}

# ---- vault tables (consider a separate account in production) ---------------------------
locals {
  vault_prefix = replace("${local.name}_vault", "-", "_")
  vault_tables = {
    keys    = { hash = "principal_id", gsi = false }
    values  = { hash = "token", gsi = true }
    lookups = { hash = "lookup_hash", gsi = true }
  }
}

resource "aws_dynamodb_table" "vault" {
  for_each     = local.vault_tables
  name         = "${local.vault_prefix}_${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value.hash

  attribute {
    name = each.value.hash
    type = "S"
  }

  dynamic "attribute" {
    for_each = each.value.gsi ? [1] : []
    content {
      name = "principal_id"
      type = "S"
    }
  }

  dynamic "global_secondary_index" {
    for_each = each.value.gsi ? [1] : []
    content {
      name            = "principal_id-index"
      hash_key        = "principal_id"
      projection_type = "ALL"
    }
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.vault.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ---- certificate archive (S3 Object Lock) --------------------------------------------------
resource "aws_s3_bucket" "certificates" {
  bucket_prefix       = "${local.name}-certs-"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "certificates" {
  bucket = aws_s3_bucket.certificates.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "certificates" {
  bucket = aws_s3_bucket.certificates.id
  rule {
    default_retention {
      mode = var.certificate_lock_mode
      days = var.certificate_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.certificates]
}

resource "aws_s3_bucket_public_access_block" "certificates" {
  bucket                  = aws_s3_bucket.certificates.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "certificates" {
  bucket = aws_s3_bucket.certificates.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# ---- config in SSM Parameter Store (not in the repo or image) ---------------------------------
resource "aws_ssm_parameter" "config" {
  name  = "${local.ssm_prefix}/config"
  type  = "String"
  tier  = "Advanced"
  value = file(var.dpdp_config_file)
}
