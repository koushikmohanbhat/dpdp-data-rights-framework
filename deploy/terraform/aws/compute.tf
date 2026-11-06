# ECR, ECS Fargate (API + worker, each with an ADOT sidecar), internal ALB, logs, schedules.

resource "aws_ecr_repository" "this" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
  }
}

resource "aws_ecs_cluster" "this" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${local.name}/api"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${local.name}/worker"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "adot" { # collector diagnostics only; no processing records
  name              = "/ecs/${local.name}/adot"
  retention_in_days = 30
}

# Defence in depth: mask PII that slips past tokenisation in the framework's own logs.
resource "aws_cloudwatch_log_data_protection_policy" "mask" {
  for_each       = { api = aws_cloudwatch_log_group.api.name, worker = aws_cloudwatch_log_group.worker.name }
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

resource "aws_ssm_parameter" "adot_config" {
  name  = "${local.ssm_prefix}/adot-config"
  type  = "String"
  tier  = "Advanced"
  value = file("${path.module}/../../otel/collector-aws.yaml")
}

locals {
  image = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"

  base_env = merge({
    DPDP_CONFIG                 = "ssm://${aws_ssm_parameter.config.name}"
    AWS_REGION                  = var.region
    TENANT                      = var.tenant
    BEDROCK_MODEL_ID            = var.bedrock_model_id
    BEDROCK_EMBEDDING_MODEL_ID  = var.bedrock_embedding_model_id
    DPDP_KMS_KEY_ARN            = aws_kms_key.vault.arn
    DPDP_SEALED_KMS_KEY_ARN     = aws_kms_key.sealed.arn
    DPDP_BREAK_GLASS_ROLE_ARN   = aws_iam_role.break_glass.arn
    DPDP_VAULT_TABLE_PREFIX     = local.vault_prefix
    DPDP_CERT_SIGNING_KEY_ARN   = aws_kms_key.cert_signing.arn
    DPDP_CERT_BUCKET            = aws_s3_bucket.certificates.bucket
    DPDP_CERT_LOCK_MODE         = var.certificate_lock_mode
    DPDP_CERT_RETAIN_DAYS       = tostring(var.certificate_retention_days)
    DPDP_DB_HOST                = aws_db_instance.this.address
    DPDP_DB_PORT                = tostring(aws_db_instance.this.port)
    DPDP_DB_NAME                = aws_db_instance.this.db_name
    DPDP_DB_USER                = aws_db_instance.this.username
    DPDP_SERVICE_KEY_SHA256     = var.service_api_key_sha256
    DPDP_AUTH_MODE              = var.auth_mode
    COGNITO_USER_POOL_ID        = local.cognito_user_pool_id
    COGNITO_APP_CLIENT_ID       = local.cognito_app_client_id
    DPDP_API_LOG_GROUP          = aws_cloudwatch_log_group.api.name
    DPDP_WORKER_LOG_GROUP       = aws_cloudwatch_log_group.worker.name
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318"
  }, var.extra_environment)

  env_list = [for k, v in local.base_env : { name = k, value = v }]

  db_password_secret = [{
    name      = "DPDP_DB_PASSWORD"
    valueFrom = "${aws_db_instance.this.master_user_secret[0].secret_arn}:password::"
  }]

  adot_container = {
    name        = "adot"
    image       = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
    essential   = false
    environment = [{ name = "AWS_REGION", value = var.region }]
    secrets     = [{ name = "AOT_CONFIG_CONTENT", valueFrom = aws_ssm_parameter.adot_config.arn }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { awslogs-group = aws_cloudwatch_log_group.adot.name, awslogs-region = var.region, awslogs-stream-prefix = "adot" }
    }
  }

  app_container = {
    image                  = local.image
    essential              = true
    environment            = local.env_list
    secrets                = local.db_password_secret
    readonlyRootFilesystem = false
    user                   = "10001"
  }
}

resource "aws_iam_role_policy" "execution_ssm" {
  name = "adot-config"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:GetParameters", "ssm:GetParameter"], Resource = aws_ssm_parameter.adot_config.arn }]
  })
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${local.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([
    merge(local.app_container, {
      name         = "api"
      command      = ["serve", "--port", "8080"]
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      healthCheck  = { command = ["CMD-SHELL", "python -c \"import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')\""], interval = 30, timeout = 5, retries = 3, startPeriod = 30 }
      logConfiguration = {
        logDriver = "awslogs"
        options   = { awslogs-group = aws_cloudwatch_log_group.api.name, awslogs-region = var.region, awslogs-stream-prefix = "api" }
      }
    }),
    local.adot_container
  ])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([
    merge(local.app_container, {
      name    = "worker"
      command = ["worker"]
      logConfiguration = {
        logDriver = "awslogs"
        options   = { awslogs-group = aws_cloudwatch_log_group.worker.name, awslogs-region = var.region, awslogs-stream-prefix = "worker" }
      }
    }),
    local.adot_container
  ])
}

# ---- networking ------------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Internal ALB for the Rights API"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_in" {
  for_each          = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = var.certificate_arn == "" ? 80 : 443
  to_port           = var.certificate_arn == "" ? 80 : 443
}

resource "aws_vpc_security_group_egress_rule" "alb_out" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.tasks.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_security_group" "tasks" {
  name        = "${local.name}-tasks"
  description = "API and worker tasks"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_alb" {
  security_group_id            = aws_security_group.tasks.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_egress_rule" "tasks_out" {
  security_group_id = aws_security_group.tasks.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_lb" "api" {
  name                       = substr("${local.name}-api", 0, 32)
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.private_subnet_ids
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "api" {
  name        = substr("${local.name}-api", 0, 32)
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    path    = "/healthz"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http" {
  count             = var.certificate_arn == "" ? 1 : 0
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_ecs_service" "api" {
  name            = "${local.name}-api"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8080
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  depends_on = [aws_lb_listener.https, aws_lb_listener.http]
}

resource "aws_ecs_service" "worker" {
  name            = "${local.name}-worker"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}

# ---- daily purge of expired retention escrows -----------------------------------------------------
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name = "run-task"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecs:RunTask"], Resource = aws_ecs_task_definition.worker.arn },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.task.arn, aws_iam_role.execution.arn] }
    ]
  })
}

resource "aws_scheduler_schedule" "purge_escrows" {
  name                         = "${local.name}-purge-escrows"
  schedule_expression          = var.purge_escrows_schedule
  schedule_expression_timezone = "UTC"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = aws_ecs_cluster.this.arn
    role_arn = aws_iam_role.scheduler.arn
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.worker.arn
      launch_type         = "FARGATE"
      network_configuration {
        subnets          = var.private_subnet_ids
        security_groups  = [aws_security_group.tasks.id]
        assign_public_ip = false
      }
    }
    input = jsonencode({ containerOverrides = [{ name = "worker", command = ["purge-escrows"] }] })
  }
}
