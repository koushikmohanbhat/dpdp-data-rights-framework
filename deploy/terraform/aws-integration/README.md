# AWS integration-test stack

Creates the resources the live test suite (`tests/integration/test_aws_live.py`) needs in a
**non-production** account, and writes their IDs to SSM Parameter Store under `/dpdp-it`:
KMS keys, DynamoDB vault and chat-history tables, S3 buckets (one with GOVERNANCE Object Lock),
a log group, a Cognito pool, and a test role that GitHub Actions assumes through OIDC.

**Full guide: [docs/testing.md](../../../docs/testing.md#live-aws-integration-tests).**

```bash
cp terraform.tfvars.example ~/my-dpdp-deployment/it.tfvars    # set github_repository to your fork
terraform init
terraform apply -var-file ~/my-dpdp-deployment/it.tfvars
terraform output test_role_arn    # -> AWS_ROLE_ARN in your GitHub environment "aws-integration"
```

Tear down with `terraform destroy` when you no longer need it.
