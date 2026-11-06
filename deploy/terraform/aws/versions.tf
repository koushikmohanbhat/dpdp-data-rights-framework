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
    tags = merge({ Project = "dpdp-data-rights-framework", Environment = var.environment }, var.tags)
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name       = "${var.name_prefix}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  ssm_prefix = "/${var.name_prefix}/${var.environment}"
}
