# Deploy on AWS

This guide deploys the framework into **your own AWS account** with the Terraform stack in
[`deploy/terraform/aws`](../deploy/terraform/aws). Nothing account-specific lives in this repository:
you supply a `terraform.tfvars` and a framework config file, both kept outside version control.

Allow half a day for a first deployment, plus whatever time your organisation needs for network,
security and privacy reviews.

## What gets deployed

```
                   your callers (backend, DPO console, agent)          your agents (ECS / Lambda /
                                   │ HTTPS, internal only                AgentCore Runtime / EKS)
                                   ▼                                          │ SDK: protect(),
  ┌─────────────── your VPC, private subnets ─────────────────────────────┐  │ track_artifact()
  │  internal ALB ──► ECS Fargate: API (dpdp-rights serve) + ADOT sidecar │  │
  │                   ECS Fargate: worker (dpdp-rights worker) + ADOT     │◄─┘
  │                   EventBridge Scheduler ─► worker task: purge-escrows │
  │                   RDS PostgreSQL 16 (lineage, consent, job queue)     │
  └───────────────────────────────────────────────────────────────────────┘
     KMS: vault key · sealed key (break-glass decrypt only) · certificate signing key (ECC P-256)
     DynamoDB: vault tables (wrapped per-principal keys, token values, lookups)
     S3: certificate archive with Object Lock · SSM: your config + ADOT config
     ECR: image repository (immutable tags) · Cognito: user pool with principal / dpo / approver groups
     IAM: task, execution, break-glass and scheduler roles · a policy to attach to your agents
```

| Component | Resource | Notes |
|---|---|---|
| Rights API | ECS Fargate service behind an **internal** ALB | `api_desired_count` tasks (default 2); health check `GET /healthz` |
| Worker | ECS Fargate service | Processes the durable job queue; `worker_desired_count` (default 1) |
| Escrow purge | EventBridge Scheduler → worker task with command `purge-escrows` | Daily at 02:00 IST by default |
| Control plane DB | RDS PostgreSQL 16, encrypted, `rds.force_ssl=1`, Multi-AZ by default | Master password managed by RDS in Secrets Manager |
| Vault | DynamoDB (3 tables, PITR, KMS-encrypted) + KMS vault key | Per-principal data keys, wrapped by KMS |
| Sealed escrow | Separate KMS key | The app can only **encrypt**; decrypt requires the break-glass role with MFA |
| Certificates | KMS asymmetric signing key + S3 bucket with Object Lock | `COMPLIANCE` mode, 3650 days by default |
| Config | SSM Parameter (Advanced tier) | Uploaded from your `dpdp_config_file`; tasks read it at start via `DPDP_CONFIG=ssm://...`. It holds placeholders, not secrets |
| Telemetry | ADOT collector sidecar | Masks PII patterns, exports traces to X-Ray and metrics to CloudWatch (EMF, namespace `DPDPRights`) |
| Identity | Cognito user pool (optional) | MFA required, admin-created users only, groups `principal`, `dpo`, `approver` |

## Prerequisites

**Tools on the machine that runs the deployment**

- Terraform ≥ 1.6
- AWS CLI v2, signed in to the target account with permission to create the resources above
- Docker (or another OCI builder) to build the image
- Python 3.10+ with the framework installed (`pip install -e .`), for `hash-api-key` and `check-config`

**In the AWS account**

- A **VPC with at least two private subnets** in different AZs. Tasks need outbound access to AWS
  APIs: either a NAT gateway, or VPC interface endpoints for `ecr.api`, `ecr.dkr`, `logs`, `ssm`,
  `secretsmanager`, `kms`, `sts`, `xray`, `monitoring`, `comprehend`, `bedrock-runtime` (plus
  `bedrock-agentcore` and others your connectors call) and gateway endpoints for `s3` and `dynamodb`.
  OpenAI or Anthropic API calls need internet egress through NAT or a proxy.
- **Bedrock model access** granted for the chat and embedding models you choose, in your region.
  Many newer models are invoked through a cross-region inference profile ID rather than a model ID.
- An **ACM certificate** for the internal ALB (strongly recommended; without one the ALB listens on
  plain HTTP inside the VPC and `check-config` will warn).
- The IAM principals (roles or users) of the people who may use **break-glass** access. They must
  sign in with MFA to assume the break-glass role.

**Region:** any region with ECS Fargate, RDS, KMS and Bedrock. For India data residency use
`ap-south-1` (Mumbai) or `ap-south-2` (Hyderabad), and check that the AWS services and models your
connectors use are available there.

## Step 1: Prepare a private working folder

Keep your settings in a folder **outside** your clone of this repository (or in a separate private
repository your team controls):

```
my-dpdp-deployment/
  dpdp.yaml            # your framework config (copied from the template)
  terraform.tfvars     # your Terraform values
  backend.tf           # optional: your Terraform state backend
```

```bash
mkdir -p ~/my-dpdp-deployment
cp config/dpdp.production.aws.yaml       ~/my-dpdp-deployment/dpdp.yaml
cp deploy/terraform/aws/terraform.tfvars.example ~/my-dpdp-deployment/terraform.tfvars
```

`.gitignore` in this repository already ignores `*.tfvars` and `config/*.local.yaml`, as a safety net
if you do work inside the clone.

## Step 2: Edit the framework config

Open `~/my-dpdp-deployment/dpdp.yaml`. The template already uses `${VAR}` placeholders for every
value Terraform knows (keys, tables, database, buckets, Cognito). You only edit what is specific to
your agent:

1. **`tenant`** if you run more than one business unit.
2. **`purposes`**: the purposes your agent processes personal data for, and which are legitimate
   uses with a legal hold (for example KYC record keeping). See the
   [integration guide](integration-guide.md#1-model-your-purposes).
3. **`connectors`**: one entry per store your agent writes personal data to. The template enables
   only the framework's own CloudWatch log groups and X-Ray; uncomment and adapt the AgentCore,
   S3, DynamoDB, Bedrock Knowledge Base or OpenAI examples, and add your own. Any value you reference
   as `${SOMETHING}` must be provided through `extra_environment` in Step 3.
4. **`policy`**: erasure rules per artifact kind (keep `aggregate_k_threshold` ≥ 10 in production).

Every key is documented in [configuration.md](configuration.md). Then check it, with dummy values for
the Terraform-supplied variables:

```bash
env $(grep -o '\${[A-Z_]*' ~/my-dpdp-deployment/dpdp.yaml | tr -d '${' | sort -u | sed 's/$/=x/') \
  dpdp-rights -c ~/my-dpdp-deployment/dpdp.yaml check-config
```

`check-config` must report no errors. Warnings explain what to fix before go-live.

## Step 3: Fill in `terraform.tfvars`

The example file lists every value you must supply. The important ones:

| Variable | What to put |
|---|---|
| `region`, `environment`, `tenant` | Your choice. `environment` becomes part of every resource name (`dpdp-rights-<environment>-…`) |
| `vpc_id`, `private_subnet_ids` | From your network team |
| `allowed_cidrs` | CIDRs allowed to call the internal API (your backend, agents, DPO tooling) |
| `certificate_arn` | ACM certificate ARN for the ALB |
| `dpdp_config_file` | Path to the config you edited in Step 2 |
| `image_tag` | The tag you will push in Step 5 (ECR tags are immutable, so use a version, never `latest`) |
| `bedrock_model_id`, `bedrock_embedding_model_id` | Models or inference profiles enabled in your account |
| `service_api_key_sha256` | SHA-256 of the API key your backend will use (see below) |
| `break_glass_principals` | IAM ARNs of the DPO staff allowed to assume the break-glass role |
| `extra_environment` | Values for any extra `${VAR}` placeholders in your config (memory IDs, bucket names, table names) |
| `extra_task_policy_arns` | IAM policies giving the framework access to **your** stores, so it can find and delete data there |

Generate the service API key and its hash. Store the key itself in your secrets manager, never in a
file in this repository:

```bash
KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
dpdp-rights hash-api-key "$KEY"          # paste the output into service_api_key_sha256
aws secretsmanager create-secret --name dpdp/backend-api-key --secret-string "$KEY"
```

Optional settings and their defaults are in [`variables.tf`](../deploy/terraform/aws/variables.tf):
task sizing, database class and Multi-AZ, Cognito (create a pool or bring an existing one),
certificate retention and lock mode, purge schedule and log retention.

### Permissions for your stores

The task role only has access to resources this stack creates. For every connector you enable, write
an IAM policy for the actions that connector needs (listed per connector in
[connectors.md](connectors.md)) and pass its ARN in `extra_task_policy_arns`. For example, for an
AgentCore Memory and an S3 bucket of uploaded documents:

```hcl
extra_environment = {
  AGENTCORE_MEMORY_ID = "<your memory id>"
  DOCS_BUCKET         = "<your bucket>"
}
extra_task_policy_arns = ["arn:aws:iam::<account>:policy/dpdp-erasure-agent-stores"]
```

## Step 4: Create the infrastructure

Use a remote state backend (S3 with locking) for anything beyond a trial. Put a `backend.tf` in your
working folder, or pass `-backend-config` options to `terraform init`.

The ECR repository is created by this stack, so create it first, then push the image, then apply the
rest:

```bash
cd deploy/terraform/aws
terraform init
terraform apply -var-file ~/my-dpdp-deployment/terraform.tfvars -target aws_ecr_repository.app
```

## Step 5: Build and push the image

```bash
REPO=$(terraform output -raw ecr_repository_url)
TAG=0.2.0                                          # must equal image_tag in terraform.tfvars
aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin "${REPO%/*}"
docker build --platform linux/amd64 -t "$REPO:$TAG" ../../..
docker push "$REPO:$TAG"
```

The image contains no configuration. At start, each task reads its config from SSM (the `DPDP_CONFIG`
environment variable that Terraform sets) and runs as a non-root user (uid 10001).

If your organisation builds images in its own pipeline, build from the repository's `Dockerfile` and
push to the ECR repository Terraform created.

## Step 6: Apply the full stack

```bash
terraform apply -var-file ~/my-dpdp-deployment/terraform.tfvars
```

This creates the KMS keys, DynamoDB vault, RDS database, certificate bucket, Cognito pool, ECS services,
ALB and schedule, and uploads your config to SSM. RDS takes 10–20 minutes. The framework creates its
database tables on first start, so there are no migrations to run.

Useful outputs:

```bash
terraform output api_url               # internal URL of the Rights API
terraform output agent_policy_arn      # attach to your agent runtime role (Step 9)
terraform output cognito_user_pool_id
terraform output break_glass_role_arn
```

## Step 7: Create users

API keys are for systems. People (DPO, approvers, and optionally Data Principals themselves) sign in
through Cognito. Users are admin-created only and must set up MFA:

```bash
POOL=$(terraform output -raw cognito_user_pool_id)
aws cognito-idp admin-create-user --user-pool-id "$POOL" --username dpo@yourcompany.in \
  --user-attributes Name=email,Value=dpo@yourcompany.in Name=email_verified,Value=true
aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" --username dpo@yourcompany.in --group-name dpo
```

| Group / key | Role | Can |
|---|---|---|
| service API key | `service` | Submit consents, withdrawals and erasure requests your backend has already verified |
| `principal` | `principal` | Submit requests and see status for **their own** data only |
| `dpo` | `dpo` | See all requests, certificates, lineage and SLA; request break-glass access |
| `approver` | `approver` | Approve or revoke break-glass grants (must be a different person from the requester) |

Using your existing identity provider instead of Cognito: set `create_cognito = false`, configure
`api.auth.oidc` in your config with your issuer, audience and roles claim, and map your groups to the
role names above.

## Step 8: Smoke test

The API is internal. Run these from a host inside an allowed CIDR (a bastion, Cloud9, or an SSM
session on an instance in the VPC):

```bash
API=$(terraform output -raw api_url)
KEY=$(aws secretsmanager get-secret-value --secret-id dpdp/backend-api-key --query SecretString --output text)

curl -s "$API/healthz"

curl -s -XPOST "$API/v1/consents" -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"external_id":"smoke-test-001","purpose_id":"<one of your purposes>","notice_version":"v1"}'

curl -s -XPOST "$API/v1/erasure-requests" -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -H 'Idempotency-Key: smoke-001' \
  -d '{"external_id":"smoke-test-001","dry_run":true,"verified_by":"smoke-test","verification_ref":"n/a"}'

curl -s "$API/v1/erasure-requests/<request_id>" -H "x-api-key: $KEY"
```

Check the worker picked the request up (`aws logs tail /ecs/dpdp-rights-<environment>/worker --follow`),
and that traces appear in X-Ray under the service name `dpdp-rights`. A dry run shows the plan: every
store, artifact and action, without changing anything.

Then run the live test suite against a non-production copy of the stack: [testing.md](testing.md).

## Step 9: Connect your agents

Agents use the framework as a library (`protect()`, `track_artifact()`, `generate()`) and must reach
the same control-plane database and vault as the API.

1. Install the framework in the agent image: `pip install "dpdp-data-rights-framework[aws,postgres]"`
   (or from your fork).
2. Attach the **`agent_policy_arn`** output to the agent's IAM role. It grants config read, the DB
   secret, the vault key and tables, Comprehend and Bedrock.
3. Add the agent's security group to **`agent_security_group_ids`** and apply again, so it can reach
   PostgreSQL.
4. Give the agent the same environment as the tasks. `DPDP_CONFIG` points at the SSM parameter
   (`terraform output -raw config_parameter`), and `DPDP_DB_PASSWORD` comes from the RDS secret
   (`terraform output -raw db_secret_arn`, JSON key `password`). The full list is in
   [configuration.md](configuration.md#environment-variables-used-by-the-aws-template).
5. Follow the [integration guide](integration-guide.md) to instrument the agent code.

For AgentCore Runtime, run the agent in VPC mode in the same private subnets.

## Updating

| Change | How |
|---|---|
| Framework config (purposes, connectors, policy) | Edit your `dpdp.yaml`, `terraform apply`. Terraform updates the SSM parameter. Then restart tasks: `aws ecs update-service --cluster <cluster> --service <svc> --force-new-deployment` for API and worker |
| New framework version | Build and push a new tag, set `image_tag`, `terraform apply` (rolling deployment with circuit breaker and rollback) |
| Infrastructure settings | Edit `terraform.tfvars`, `terraform plan`, `terraform apply` |
| Rotate the service API key | Generate a new key and hash, add both hashes to `api.auth.api_keys` in your config during the change-over, apply, update the backend, then remove the old one |

Read the release notes before upgrading. The framework adds new tables and columns on start but never
drops data.

## Observability and alerts

The ADOT sidecar masks email, phone, Aadhaar and PAN patterns as a second line of defence, then
exports:

- **Traces** to X-Ray, with `dpdp.principal` (pseudonymous ID), `dpdp.purpose` and `dpdp.request_id`
  indexed so you can find every span for one request.
- **Metrics** to CloudWatch namespace `DPDPRights`: `dpdp.erasure.requests` (by status),
  `dpdp.erasure.actions` (by action, store and outcome), `dpdp.erasure.open` (open requests by SLA
  bucket), `dpdp.erasure.duration`, `dpdp.consent.withdrawals`, `dpdp.processing.blocked` and
  `dpdp.pii.tokenized`.

Recommended CloudWatch alarms: erasure requests with status `failed` or `completed_with_exceptions`,
actions with a failed outcome, `dpdp.erasure.open` with `sla=overdue` above zero, ECS running count below
desired, and RDS CPU and free storage. Details in
[observability.md](observability.md) and the [operations runbook](operations.md).

## Costs

The main fixed costs are RDS (Multi-AZ doubles the instance cost), the ALB, Fargate tasks (two API
tasks and one worker, each with a sidecar), three KMS keys and the Advanced-tier SSM parameter.
DynamoDB, S3, Comprehend and Bedrock are usage based. For a test environment set
`db_multi_az = false`, `api_desired_count = 1` and a smaller `db_instance_class`.

## Tearing down

Production stacks are protected on purpose:

- RDS has deletion protection (`db_deletion_protection = true`) and takes a final snapshot.
- Certificates under `COMPLIANCE` Object Lock **cannot be deleted by anyone**, including the root
  user, until their retention ends. The bucket cannot be removed while they exist.
- KMS keys are scheduled for deletion with a waiting period, not deleted at once. Destroying the
  vault key makes every token unreadable; destroying the sealed key ends statutory retention early.

For test environments, set `certificate_lock_mode = "GOVERNANCE"`, `certificate_retention_days = 1`,
`db_deletion_protection = false` and `db_multi_az = false` **before** creating the stack. Then
`terraform destroy` works once the retention day has passed.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Tasks stop with `CannotPullContainerError` | Image tag not pushed, or no route to ECR (NAT or ECR/S3 endpoints) |
| Tasks exit at start with a config error | A `${VAR}` in your config has no value; add it to `extra_environment` |
| `check-config` errors in the logs | `environment: production` refuses unsafe settings; fix the config and apply |
| `AccessDenied` from a connector | Missing permission in `extra_task_policy_arns` for that store |
| `AccessDeniedException` from Bedrock | Model access not granted, or a model that needs an inference profile ID |
| Worker never picks up jobs | Worker service not running, or it cannot reach RDS (security groups) |
| 401 with a valid key | Hash mismatch: re-run `hash-api-key` on the exact key; check for trailing newlines |
| No traces in X-Ray | ADOT sidecar not healthy, or no route to X-Ray (NAT or `xray` endpoint) |

More in the [operations runbook](operations.md#troubleshooting).
