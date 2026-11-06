# Live integration-test stack for the AWS connectors.
#
# Creates low-cost test resources in a NON-PRODUCTION account, a GitHub OIDC role for the
# integration workflow (optional), and publishes every resource ID to SSM Parameter Store
# under var.ssm_prefix so the tests need no hard-coded settings. See docs/testing.md.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "dpdp-data-rights-framework", Purpose = "integration-tests" }
  }
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type    = string
  default = "dpdp-it"
}

variable "ssm_prefix" {
  type    = string
  default = "/dpdp-it"
}

variable "github_repository" {
  description = "owner/repo of YOUR fork or copy that runs the integration workflow. Empty = no GitHub role (run tests locally)."
  type        = string
  default     = ""
}

variable "github_environment" {
  description = "GitHub environment allowed to assume the test role"
  type        = string
  default     = "aws-integration"
}

variable "github_owner_id" {
  description = "Numeric ID of the repository owner. Set it (with github_repository_id) when GitHub issues immutable subject claims: repositories created, renamed or transferred after 15 July 2026, or opted in. Get it with: gh api repos/OWNER/REPO --jq .owner.id"
  type        = number
  default     = null
}

variable "github_repository_id" {
  description = "Numeric ID of the repository (gh api repos/OWNER/REPO --jq .id)"
  type        = number
  default     = null
}

variable "create_github_oidc_provider" {
  description = "Create the token.actions.githubusercontent.com OIDC provider (false if the account already has one)"
  type        = bool
  default     = true
}

variable "local_test_principals" {
  description = "IAM principal ARNs allowed to assume the test role for local runs (optional)"
  type        = list(string)
  default     = []
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  vault      = replace("${var.name_prefix}_vault", "-", "_")

  # GitHub OIDC subject: immutable format (owner@id/repo@id) when IDs are given, else the legacy name-only format
  gh_parts = split("/", var.github_repository)
  gh_subject = (var.github_owner_id != null && var.github_repository_id != null
    ? "repo:${local.gh_parts[0]}@${var.github_owner_id}/${try(local.gh_parts[1], "")}@${var.github_repository_id}:environment:${var.github_environment}"
  : "repo:${var.github_repository}:environment:${var.github_environment}")
}

# ---- keys -----------------------------------------------------------------------------------
resource "aws_kms_key" "vault" {
  description             = "${var.name_prefix} vault KEK"
  deletion_window_in_days = 7
}

resource "aws_kms_key" "sealed" {
  description             = "${var.name_prefix} sealed KEK"
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Admin", Effect = "Allow", Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }, Action = "kms:*", Resource = "*" },
      { Sid = "TestRoleEncryptOnly", Effect = "Allow", Principal = { AWS = aws_iam_role.test.arn }, Action = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = "*" },
      { Sid = "BreakGlassDecrypt", Effect = "Allow", Principal = { AWS = aws_iam_role.break_glass.arn }, Action = ["kms:Decrypt", "kms:DescribeKey"], Resource = "*" },
      { Sid = "DenyTestRoleDecrypt", Effect = "Deny", Principal = { AWS = aws_iam_role.test.arn }, Action = ["kms:Decrypt"], Resource = "*" }
    ]
  })
}

resource "aws_kms_key" "signing" {
  description              = "${var.name_prefix} certificate signing"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
}

# ---- data stores ------------------------------------------------------------------------------
resource "aws_dynamodb_table" "vault" {
  for_each     = { keys = "principal_id", values = "token", lookups = "lookup_hash" }
  name         = "${local.vault}_${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value
  attribute {
    name = each.value
    type = "S"
  }
  dynamic "attribute" {
    for_each = each.key == "keys" ? [] : [1]
    content {
      name = "principal_id"
      type = "S"
    }
  }
  dynamic "global_secondary_index" {
    for_each = each.key == "keys" ? [] : [1]
    content {
      name            = "principal_id-index"
      hash_key        = "principal_id"
      projection_type = "ALL"
    }
  }
}

resource "aws_dynamodb_table" "chat_history" {
  name         = "${var.name_prefix}-chat-history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"
  range_key    = "ts"
  attribute {
    name = "principal_id"
    type = "S"
  }
  attribute {
    name = "ts"
    type = "S"
  }
}

resource "aws_s3_bucket" "data" {
  bucket_prefix = "${var.name_prefix}-data-"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "certs" {
  bucket_prefix       = "${var.name_prefix}-certs-"
  object_lock_enabled = true
  force_destroy       = true
}

resource "aws_s3_bucket_versioning" "certs" {
  bucket = aws_s3_bucket.certs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "certs" {
  bucket = aws_s3_bucket.certs.id
  rule {
    default_retention {
      mode = "GOVERNANCE" # test account: deletable with s3:BypassGovernanceRetention
      days = 1
    }
  }
  depends_on = [aws_s3_bucket_versioning.certs]
}

resource "aws_s3_bucket_public_access_block" "all" {
  for_each                = { data = aws_s3_bucket.data.id, certs = aws_s3_bucket.certs.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.name_prefix}/app"
  retention_in_days = 7
}

resource "aws_cognito_user_pool" "test" {
  name = "${var.name_prefix}-identity"
}

# ---- roles ---------------------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.github_repository != "" && var.create_github_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "test_trust" {
  dynamic "statement" {
    for_each = var.github_repository == "" ? [] : [1]
    content {
      sid     = "GitHubEnvironment"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = ["arn:${local.partition}:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values   = ["sts.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:sub"
        values   = [local.gh_subject]
      }
    }
  }
  dynamic "statement" {
    for_each = length(var.local_test_principals) == 0 ? [] : [1]
    content {
      sid     = "LocalRuns"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.local_test_principals
      }
    }
  }
}

resource "aws_iam_role" "test" {
  name                 = "${var.name_prefix}-test-runner"
  assume_role_policy   = data.aws_iam_policy_document.test_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role" "break_glass" {
  name = "${var.name_prefix}-break-glass"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = aws_iam_role.test.arn }, Action = "sts:AssumeRole" }]
  })
}

data "aws_iam_policy_document" "test" {
  statement {
    sid       = "ReadParams"
    actions   = ["ssm:GetParametersByPath", "ssm:GetParameter"]
    resources = ["arn:${local.partition}:ssm:${var.region}:${local.account_id}:parameter${var.ssm_prefix}*"]
  }
  statement {
    sid       = "VaultKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.vault.arn]
  }
  statement {
    sid       = "Signing"
    actions   = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"]
    resources = [aws_kms_key.signing.arn]
  }
  statement {
    sid       = "AssumeBreakGlass"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.break_glass.arn]
  }
  statement {
    sid       = "Tables"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
    resources = flatten([aws_dynamodb_table.chat_history.arn, [for t in aws_dynamodb_table.vault : [t.arn, "${t.arn}/index/*"]]])
  }
  statement {
    sid = "Buckets"
    actions = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ListBucket",
      "s3:ListBucketVersions", "s3:PutObjectRetention", "s3:GetObjectRetention", "s3:BypassGovernanceRetention",
    "s3:GetObjectVersion"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*", aws_s3_bucket.certs.arn, "${aws_s3_bucket.certs.arn}/*"]
  }
  statement {
    sid = "LogsAndTraces"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:StartQuery", "logs:GetQueryResults", "logs:DescribeLogGroups",
    "xray:PutTraceSegments", "xray:GetTraceSummaries", "xray:BatchGetTraces"]
    resources = ["*"]
  }
  statement {
    sid       = "ModelsAndPii"
    actions   = ["bedrock:InvokeModel", "bedrock:Converse", "comprehend:DetectPiiEntities"]
    resources = ["*"]
  }
  statement {
    sid = "AgentCoreMemory"
    actions = ["bedrock-agentcore:CreateMemory", "bedrock-agentcore:GetMemory", "bedrock-agentcore:DeleteMemory",
      "bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents", "bedrock-agentcore:DeleteEvent",
      "bedrock-agentcore:ListSessions", "bedrock-agentcore:ListMemoryRecords", "bedrock-agentcore:DeleteMemoryRecord",
    "bedrock-agentcore:ListActors"]
    resources = ["*"]
  }
  statement {
    sid       = "Cognito"
    actions   = ["cognito-idp:AdminCreateUser", "cognito-idp:AdminDeleteUser", "cognito-idp:AdminUserGlobalSignOut"]
    resources = [aws_cognito_user_pool.test.arn]
  }
}

resource "aws_iam_role_policy" "test" {
  name   = "integration-tests"
  role   = aws_iam_role.test.id
  policy = data.aws_iam_policy_document.test.json
}

# ---- publish IDs for the tests ----------------------------------------------------------------------
locals {
  params = {
    region             = var.region
    vault_kms_key_arn  = aws_kms_key.vault.arn
    sealed_kms_key_arn = aws_kms_key.sealed.arn
    signing_key_arn    = aws_kms_key.signing.arn
    break_glass_role   = aws_iam_role.break_glass.arn
    vault_table_prefix = local.vault
    chat_history_table = aws_dynamodb_table.chat_history.name
    data_bucket        = aws_s3_bucket.data.bucket
    cert_bucket        = aws_s3_bucket.certs.bucket
    log_group          = aws_cloudwatch_log_group.app.name
    cognito_user_pool  = aws_cognito_user_pool.test.id
  }
}

resource "aws_ssm_parameter" "p" {
  for_each = local.params
  name     = "${var.ssm_prefix}/${each.key}"
  type     = "String"
  value    = each.value
}

output "test_role_arn" {
  description = "Set as AWS_ROLE_ARN in your GitHub environment, or assume it for local runs"
  value       = aws_iam_role.test.arn
}

output "github_oidc_subject" {
  description = "The sub claim the test role trusts; must match what GitHub issues for your repository"
  value       = var.github_repository == "" ? null : local.gh_subject
}

output "ssm_prefix" {
  value = var.ssm_prefix
}
