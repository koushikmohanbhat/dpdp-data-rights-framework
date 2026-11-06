output "api_url" {
  description = "Internal URL of the Rights API"
  value       = "${var.certificate_arn == "" ? "http" : "https"}://${aws_lb.api.dns_name}"
}

output "ecr_repository_url" {
  description = "Push the container image here (see docs/deploy-aws.md)"
  value       = aws_ecr_repository.this.repository_url
}

output "ecs_cluster" {
  value = aws_ecs_cluster.this.name
}

output "api_service" {
  value = aws_ecs_service.api.name
}

output "worker_service" {
  value = aws_ecs_service.worker.name
}

output "worker_task_definition" {
  value = aws_ecs_task_definition.worker.arn
}

output "task_role_arn" {
  description = "Grant this role access to your agent's stores (or use var.extra_task_policy_arns)"
  value       = aws_iam_role.task.arn
}

output "break_glass_role_arn" {
  value = aws_iam_role.break_glass.arn
}

output "vault_kms_key_arn" {
  value = aws_kms_key.vault.arn
}

output "sealed_kms_key_arn" {
  value = aws_kms_key.sealed.arn
}

output "cert_signing_key_arn" {
  value = aws_kms_key.cert_signing.arn
}

output "certificate_bucket" {
  value = aws_s3_bucket.certificates.bucket
}

output "db_endpoint" {
  value = aws_db_instance.this.address
}

output "db_secret_arn" {
  value = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "config_parameter" {
  description = "Update the config with: terraform apply (after editing your config file)"
  value       = aws_ssm_parameter.config.name
}

output "cognito_user_pool_id" {
  value = local.cognito_user_pool_id
}

output "cognito_app_client_id" {
  value = local.cognito_app_client_id
}

output "private_subnet_ids" {
  value = var.private_subnet_ids
}

output "tasks_security_group_id" {
  value = aws_security_group.tasks.id
}

output "agent_policy_arn" {
  description = "Attach to your agent runtime role(s) so the SDK can tokenise, record lineage and call models"
  value       = aws_iam_policy.agent.arn
}

output "db_security_group_id" {
  value = aws_security_group.db.id
}
