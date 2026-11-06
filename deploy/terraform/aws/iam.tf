# Roles: ECS execution role, task role (the framework), break-glass role.

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "db-secret"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_db_instance.this.master_user_secret[0].secret_arn }]
  })
}

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

locals {
  cognito_pool_arn = var.create_cognito ? aws_cognito_user_pool.this[0].arn : (
    var.existing_cognito_user_pool_id == "" ? "" :
    "arn:${local.partition}:cognito-idp:${var.region}:${local.account_id}:userpool/${var.existing_cognito_user_pool_id}"
  )
}

data "aws_iam_policy_document" "task" {
  statement {
    sid       = "ReadConfig"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.config.arn]
  }
  statement {
    sid       = "VaultKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.vault.arn]
  }
  statement {
    sid       = "VaultTables"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
    resources = flatten([for t in aws_dynamodb_table.vault : [t.arn, "${t.arn}/index/*"]])
  }
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
    sid       = "PiiDetectionAndModels"
    actions   = ["comprehend:DetectPiiEntities", "bedrock:InvokeModel", "bedrock:Converse", "bedrock:ApplyGuardrail"]
    resources = ["*"]
  }
  statement {
    sid       = "OwnLogsAndTraces"
    actions   = ["logs:StartQuery", "logs:GetQueryResults", "logs:DescribeLogGroups", "xray:GetTraceSummaries", "xray:BatchGetTraces"]
    resources = ["*"]
  }
  statement {
    sid       = "AdotExport"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup", "logs:DescribeLogStreams", "cloudwatch:PutMetricData"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = var.allow_app_break_glass ? [1] : []
    content {
      sid       = "AssumeBreakGlass"
      actions   = ["sts:AssumeRole"]
      resources = [aws_iam_role.break_glass.arn]
    }
  }
  dynamic "statement" {
    for_each = local.cognito_pool_arn == "" ? [] : [1]
    content {
      sid       = "RevokeIdentityTokens"
      actions   = ["cognito-idp:AdminUserGlobalSignOut"]
      resources = [local.cognito_pool_arn]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "dpdp-rights"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_iam_role_policy_attachment" "task_extra" {
  for_each   = toset(var.extra_task_policy_arns)
  role       = aws_iam_role.task.name
  policy_arn = each.value
}

# ---- break-glass -------------------------------------------------------------------------
data "aws_iam_policy_document" "break_glass_trust" {
  statement {
    sid     = "HumansWithMfa"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.break_glass_principals
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
  dynamic "statement" {
    for_each = var.allow_app_break_glass ? [1] : []
    content {
      sid     = "AppWithinApprovedGrant"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = [aws_iam_role.task.arn]
      }
    }
  }
}

resource "aws_iam_role" "break_glass" {
  name                 = "${local.name}-break-glass"
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.break_glass_trust.json
}

# ---- policy for agent runtimes that embed the SDK (protect / track_artifact / generate) -------------
data "aws_iam_policy_document" "agent" {
  statement {
    sid       = "ReadConfig"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.config.arn]
  }
  statement {
    sid       = "ReadDbSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.this.master_user_secret[0].secret_arn]
  }
  statement {
    sid       = "VaultKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.vault.arn]
  }
  statement {
    sid       = "VaultTables"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
    resources = flatten([for t in aws_dynamodb_table.vault : [t.arn, "${t.arn}/index/*"]])
  }
  statement {
    sid       = "PiiDetectionAndModels"
    actions   = ["comprehend:DetectPiiEntities", "bedrock:InvokeModel", "bedrock:Converse", "bedrock:ApplyGuardrail"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "agent" {
  name        = "${local.name}-agent-sdk"
  description = "Attach to agent runtime roles that embed the DPDP Data Rights Framework SDK"
  policy      = data.aws_iam_policy_document.agent.json
}
