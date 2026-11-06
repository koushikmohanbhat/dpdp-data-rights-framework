# ---- basics -------------------------------------------------------------------
variable "region" {
  description = "AWS region, e.g. ap-south-1"
  type        = string
}

variable "environment" {
  description = "Environment name used in resource names (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "dpdp-rights"
}

variable "tenant" {
  description = "Tenant / customer label written into the config (TENANT)"
  type        = string
  default     = "default"
}

variable "tags" {
  description = "Extra tags for all resources"
  type        = map(string)
  default     = {}
}

# ---- network (bring your own VPC) ---------------------------------------------------
variable "vpc_id" {
  description = "Existing VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "At least two private subnets (different AZs) with egress to AWS APIs (NAT gateway or VPC endpoints)"
  type        = list(string)
}

variable "allowed_cidrs" {
  description = "CIDRs allowed to reach the internal API load balancer (your API gateway, backend, VPN)"
  type        = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate ARN for an HTTPS listener on the internal ALB. Empty = HTTP only (not for production)."
  type        = string
  default     = ""
}

# ---- application -------------------------------------------------------------------------
variable "dpdp_config_file" {
  description = "Path to YOUR edited copy of config/dpdp.production.aws.yaml (keep it outside the repo or git-ignored)"
  type        = string
}

variable "image_tag" {
  description = "Container image tag pushed to the ECR repository created by this stack (tags are immutable, so use a version or git SHA)"
  type        = string
}

variable "bedrock_model_id" {
  description = "Bedrock model or inference profile ID enabled in your account (BEDROCK_MODEL_ID)"
  type        = string
}

variable "bedrock_embedding_model_id" {
  description = "Bedrock embedding model ID (BEDROCK_EMBEDDING_MODEL_ID)"
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "service_api_key_sha256" {
  description = "SHA-256 hex of the API key your backend will use (dpdp-rights hash-api-key <key>). Never pass the raw key."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.service_api_key_sha256))
    error_message = "Must be a 64-character lowercase hex SHA-256 digest."
  }
}

variable "auth_mode" {
  description = "API auth mode written to DPDP_AUTH_MODE: both | api_key | oidc"
  type        = string
  default     = "both"
}

variable "extra_environment" {
  description = "Extra environment variables for the containers, for connector placeholders in your config (AGENTCORE_MEMORY_ID, KB_ID...)"
  type        = map(string)
  default     = {}
}

variable "extra_task_policy_arns" {
  description = "Extra IAM policy ARNs for the task role, granting access to your agent's stores (buckets, tables, memories, KBs)"
  type        = list(string)
  default     = []
}

variable "api_desired_count" {
  type    = number
  default = 2
}

variable "worker_desired_count" {
  type    = number
  default = 1
}

variable "task_cpu" {
  type    = number
  default = 512
}

variable "task_memory" {
  type    = number
  default = 1024
}

# ---- database ------------------------------------------------------------------------------
variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "db_multi_az" {
  type    = bool
  default = true
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

# ---- identity --------------------------------------------------------------------------------
variable "create_cognito" {
  description = "Create a Cognito user pool with groups principal, dpo, approver for OIDC login"
  type        = bool
  default     = true
}

variable "existing_cognito_user_pool_id" {
  description = "Use an existing user pool instead (create_cognito = false)"
  type        = string
  default     = ""
}

variable "existing_cognito_app_client_id" {
  type    = string
  default = ""
}

# ---- break-glass ------------------------------------------------------------------------------
variable "break_glass_principals" {
  description = "IAM principal ARNs (DPO users/roles) allowed to assume the break-glass role with MFA"
  type        = list(string)
}

variable "allow_app_break_glass" {
  description = "Let the API task assume the break-glass role inside an approved grant (needed for POST /v1/break-glass/grants/{id}/read)"
  type        = bool
  default     = true
}

# ---- certificates ------------------------------------------------------------------------------
variable "certificate_retention_days" {
  type    = number
  default = 3650
}

variable "certificate_lock_mode" {
  description = "S3 Object Lock mode for certificates: COMPLIANCE (production) or GOVERNANCE (test accounts)"
  type        = string
  default     = "COMPLIANCE"
}

# ---- schedules ----------------------------------------------------------------------------------
variable "purge_escrows_schedule" {
  description = "EventBridge Scheduler expression for purge-escrows"
  type        = string
  default     = "cron(30 20 * * ? *)" # 02:00 IST
}

variable "log_retention_days" {
  description = "Retention of the API and worker log groups. DPDP Rules 2025 r.8(3) asks for processing logs to be kept at least one year: keep this at 365 or more unless counsel advises otherwise. Must be a CloudWatch-supported value (365, 400, 545, 731...)"
  type        = number
  default     = 400
}

# ---- agents that use the SDK ----------------------------------------------------------------------
variable "agent_security_group_ids" {
  description = "Security groups of agent runtimes (ECS, Lambda, AgentCore Runtime in VPC mode, EKS) that use the SDK and need the control-plane database"
  type        = list(string)
  default     = []
}
