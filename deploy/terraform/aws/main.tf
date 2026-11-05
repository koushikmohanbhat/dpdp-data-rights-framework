# AWS infrastructure for the DPDP Data Rights Framework:
# KMS key for the vault, DynamoDB vault tables, IAM policy for the orchestrator,
# CloudWatch Logs data-protection policies (masking as defence in depth),
# and a daily EventBridge schedule for escrow purges.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.60" }
  }
}

provider "aws" { region = var.region }

variable "region" { default = "ap-south-1" }
variable "prefix" { default = "dpdp_vault" }
variable "log_group_names" {
  type    = list(string)
  default = ["aws/spans", "/aws/bedrock/modelinvocations"]
}
variable "agentcore_memory_arn" { default = "*" }
variable "purge_task_target_arn" {
  description = "Lambda / ECS task that runs `dpdp-erasure purge-escrows`"
  default     = ""
}

resource "aws_kms_key" "vault" {
  description             = "DPDP vault key-encryption key (wraps per-principal DEKs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "vault" {
  name          = "alias/dpdp-vault"
  target_key_id = aws_kms_key.vault.key_id
}

locals {
  tables = {
    keys    = { hash = "principal_id", gsi = false }
    values  = { hash = "token", gsi = true }
    lookups = { hash = "lookup_hash", gsi = true }
  }
}

resource "aws_dynamodb_table" "vault" {
  for_each     = local.tables
  name         = "${var.prefix}_${each.key}"
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

  # PITR backups would retain shredded wrapped keys for 35 days; ciphertext stays unreadable
  # once the KMS-wrapped DEK is gone from the live table, but document the window.
  point_in_time_recovery { enabled = true }
}

data "aws_iam_policy_document" "orchestrator" {
  statement {
    sid       = "VaultKms"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.vault.arn]
  }
  statement {
    sid       = "VaultTables"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
    resources = flatten([for t in aws_dynamodb_table.vault : [t.arn, "${t.arn}/index/*"]])
  }
  statement {
    sid = "CloudWatchDiscovery"
    actions = ["logs:StartQuery", "logs:GetQueryResults", "logs:DescribeLogGroups",
    "logs:PutRetentionPolicy", "logs:DeleteLogStream"]
    resources = ["*"]
  }
  statement {
    sid = "AgentCoreMemory"
    actions = ["bedrock-agentcore:ListSessions", "bedrock-agentcore:ListEvents", "bedrock-agentcore:DeleteEvent",
      "bedrock-agentcore:ListMemoryRecords", "bedrock-agentcore:DeleteMemoryRecord",
    "bedrock-agentcore:BatchDeleteMemoryRecords", "bedrock-agentcore:CreateEvent"]
    resources = [var.agentcore_memory_arn]
  }
  statement {
    sid       = "BedrockKb"
    actions   = ["bedrock:DeleteKnowledgeBaseDocuments", "bedrock:StartIngestionJob", "bedrock:GetKnowledgeBaseDocuments"]
    resources = ["*"]
  }
  statement {
    sid       = "PiiDetection"
    actions   = ["comprehend:DetectPiiEntities", "bedrock:ApplyGuardrail", "bedrock:InvokeModel", "bedrock:Converse"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "orchestrator" {
  name   = "dpdp-erasure-orchestrator"
  policy = data.aws_iam_policy_document.orchestrator.json
}

# Defence in depth: mask any PII that slips past tokenisation in these log groups.
resource "aws_cloudwatch_log_data_protection_policy" "mask" {
  for_each       = toset(var.log_group_names)
  log_group_name = each.value
  policy_document = jsonencode({
    Name    = "dpdp-mask"
    Version = "2021-06-01"
    Statement = [
      {
        Sid            = "Audit"
        DataIdentifier = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress", "arn:aws:dataprotection::aws:data-identifier/CreditCardNumber"]
        Operation      = { Audit = { FindingsDestination = {} } }
      },
      {
        Sid            = "Mask"
        DataIdentifier = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress", "arn:aws:dataprotection::aws:data-identifier/CreditCardNumber"]
        Operation      = { Deidentify = { MaskConfig = {} } }
      }
    ]
  })
}

resource "aws_iam_role" "scheduler" {
  count = var.purge_task_target_arn == "" ? 0 : 1
  name  = "dpdp-purge-scheduler"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "scheduler.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_scheduler_schedule" "purge_escrows" {
  count               = var.purge_task_target_arn == "" ? 0 : 1
  name                = "dpdp-purge-escrows"
  schedule_expression = "cron(30 20 * * ? *)" # 02:00 IST daily
  flexible_time_window { mode = "OFF" }
  target {
    arn      = var.purge_task_target_arn
    role_arn = aws_iam_role.scheduler[0].arn
    input    = jsonencode({ command = "purge-escrows" })
  }
}

output "kms_key_arn" { value = aws_kms_key.vault.arn }
output "orchestrator_policy_arn" { value = aws_iam_policy.orchestrator.arn }
