# AWS deployment stack

Deploys the DPDP Data Rights Framework into your AWS account: ECS Fargate API and worker with an ADOT
sidecar, internal ALB, RDS PostgreSQL, KMS keys (vault, sealed, certificate signing), DynamoDB vault,
S3 Object Lock certificate archive, Cognito, EventBridge schedule and IAM.

**Full guide: [docs/deploy-aws.md](../../../docs/deploy-aws.md).**

```bash
cp terraform.tfvars.example ~/my-dpdp-deployment/terraform.tfvars   # edit outside the repo
terraform init
terraform apply -var-file ~/my-dpdp-deployment/terraform.tfvars -target aws_ecr_repository.app
# build and push the image with the tag in image_tag, then:
terraform apply -var-file ~/my-dpdp-deployment/terraform.tfvars
```

| File | Contents |
|---|---|
| `versions.tf` | Providers, default tags, naming |
| `variables.tf` | All inputs, with descriptions and defaults |
| `keys_and_vault.tf` | KMS keys, DynamoDB vault tables, Object Lock bucket, config in SSM |
| `database.tf` | RDS PostgreSQL 16 and its security group |
| `iam.tf` | Execution, task, break-glass roles; policy for agent runtimes |
| `identity.tf` | Optional Cognito user pool, app client and groups |
| `compute.tf` | ECR, ECS cluster, task definitions, services, ALB, ADOT config, schedule |
| `outputs.tf` | API URL, ECR URL, key ARNs, agent policy, Cognito IDs |

No account values are committed. `*.tfvars` is git-ignored; keep your copy and your framework config
in a private location. Use a remote state backend for anything beyond a trial.
