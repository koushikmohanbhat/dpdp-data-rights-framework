# Optional Cognito user pool for OIDC login (DPOs, approvers, self-service principals).

resource "aws_cognito_user_pool" "this" {
  count                    = var.create_cognito ? 1 : 0
  name                     = local.name
  mfa_configuration        = "ON"
  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }
}

resource "aws_cognito_user_pool_client" "this" {
  count                         = var.create_cognito ? 1 : 0
  name                          = "${local.name}-api"
  user_pool_id                  = aws_cognito_user_pool.this[0].id
  generate_secret               = false
  explicit_auth_flows           = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"
  access_token_validity         = 60
  id_token_validity             = 60
  token_validity_units {
    access_token = "minutes"
    id_token     = "minutes"
  }
}

resource "aws_cognito_user_group" "roles" {
  for_each     = var.create_cognito ? toset(["principal", "dpo", "approver"]) : toset([])
  name         = each.value
  user_pool_id = aws_cognito_user_pool.this[0].id
}

locals {
  cognito_user_pool_id  = var.create_cognito ? aws_cognito_user_pool.this[0].id : var.existing_cognito_user_pool_id
  cognito_app_client_id = var.create_cognito ? aws_cognito_user_pool_client.this[0].id : var.existing_cognito_app_client_id
}
