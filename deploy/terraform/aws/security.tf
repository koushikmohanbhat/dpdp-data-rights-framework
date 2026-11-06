# Production hardening resources (v0.2):
#  - separate KMS key for sealed (legal-hold / escrow) DEKs: app can Encrypt, only break-glass role can Decrypt
#  - asymmetric KMS key for signing erasure certificates
#  - S3 bucket with Object Lock (COMPLIANCE) for immutable certificate copies
#  - break-glass IAM role (assumable only with MFA by named principals)
#  - extra orchestrator permissions: X-Ray, SES/SNS for verification codes, Cognito sign-out

variable "app_role_arn" {
  description = "IAM role ARN of the framework's API / worker (ECS task role, Lambda role, AgentCore runtime role)"
  type        = string
}
variable "break_glass_principals" {
  description = "IAM principal ARNs (users/roles of DPOs) allowed to assume the break-glass role"
  type        = list(string)
}
variable "certificate_retention_days" { default = 3650 }
variable "cognito_user_pool_arn" { default = "" }

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "break_glass" {
  name                 = "dpdp-break-glass"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.break_glass_principals }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

resource "aws_kms_key" "sealed" {
  description         = "DPDP sealed-data KEK (legal hold / statutory escrow). Decrypt only via break-glass."
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Admin", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
      Action = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:TagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"], Resource = "*" },
      { Sid = "AppEncryptOnly", Effect = "Allow", Principal = { AWS = var.app_role_arn },
      Action = ["kms:Encrypt", "kms:GenerateDataKey"], Resource = "*" },
      { Sid = "BreakGlassDecrypt", Effect = "Allow", Principal = { AWS = aws_iam_role.break_glass.arn },
      Action = ["kms:Decrypt"], Resource = "*" },
      { Sid = "DenyAppDecrypt", Effect = "Deny", Principal = { AWS = var.app_role_arn },
      Action = ["kms:Decrypt"], Resource = "*" }
    ]
  })
}

resource "aws_iam_role_policy" "app_assume_break_glass" {
  # The app process assumes the role only inside an approved grant window (see BreakGlass);
  # remove this policy to require DPOs to run sealed reads from their own MFA session instead.
  name = "dpdp-app-assume-break-glass"
  role = element(split("/", var.app_role_arn), length(split("/", var.app_role_arn)) - 1)
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.break_glass.arn }] })
}

resource "aws_kms_key" "cert_signing" {
  description              = "Signs DPDP erasure certificates"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_s3_bucket" "certificates" {
  bucket_prefix       = "dpdp-erasure-certificates-"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "certificates" {
  bucket = aws_s3_bucket.certificates.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "certificates" {
  bucket = aws_s3_bucket.certificates.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.certificate_retention_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "certificates" {
  bucket                  = aws_s3_bucket.certificates.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "hardening" {
  statement {
    sid       = "SignCertificates"
    actions   = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"]
    resources = [aws_kms_key.cert_signing.arn]
  }
  statement {
    sid       = "ArchiveCertificates"
    actions   = ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject"]
    resources = ["${aws_s3_bucket.certificates.arn}/*"]
  }
  statement {
    sid       = "XRayDiscovery"
    actions   = ["xray:GetTraceSummaries", "xray:BatchGetTraces"]
    resources = ["*"]
  }
  statement {
    sid       = "VerificationCodes"
    actions   = ["ses:SendEmail", "sns:Publish"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = var.cognito_user_pool_arn == "" ? [] : [1]
    content {
      sid       = "RevokeAgentCoreIdentityTokens"
      actions   = ["cognito-idp:AdminUserGlobalSignOut"]
      resources = [var.cognito_user_pool_arn]
    }
  }
}

resource "aws_iam_policy" "hardening" {
  name   = "dpdp-rights-hardening"
  policy = data.aws_iam_policy_document.hardening.json
}

output "sealed_kms_key_arn" { value = aws_kms_key.sealed.arn }
output "break_glass_role_arn" { value = aws_iam_role.break_glass.arn }
output "cert_signing_key_arn" { value = aws_kms_key.cert_signing.arn }
output "certificate_bucket" { value = aws_s3_bucket.certificates.bucket }
