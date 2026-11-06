# Testing

Two test suites:

| Suite | Where | Needs | Runs |
|---|---|---|---|
| Unit and component tests | `tests/` | Nothing (offline: echo model, local vault, SQLite) | On every push and pull request in CI |
| Live AWS integration tests | `tests/integration/` | A non-production AWS account you own | On demand, from your own GitHub environment or your machine |

Run the live suite in your own account before go-live, after upgrading the framework, and after
changing the connectors you use. Cloud APIs change; the live suite is how you confirm the connectors
behave as expected with your account, region and service versions.

## Unit tests

```bash
pip install -e ".[dev]"
pytest -q                       # live tests are skipped automatically

# the same suite against PostgreSQL (what production uses for the control plane)
DPDP_TEST_PG_URL=postgresql+psycopg://postgres:postgres@localhost:5432/postgres pytest -q
ruff check src tests            # lint, as in CI
```

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs the suite on SQLite (three Python
versions) and on PostgreSQL 16, plus `pip-audit`, the offline demo, and `terraform validate` on every
stack in `deploy/terraform/`.

## Connector conformance kit

`dpdp_rights.testing.conformance` is the suite every connector must pass, built-in or plug-in: erasing a
registered record, finding an unregistered one, redacting a mention in someone else's record, catching a
leaked raw value, dry runs, re-runs and unsupported actions. The built-in SQL, JSONL, log file, Redis, S3
and DynamoDB connectors run it on every push (`tests/test_conformance_builtin.py`, with fakeredis and
moto). How to run it for your own connector: [plugins.md](plugins.md#conformance-kit).

## Live AWS integration tests

### What they cover

| Test | Checks |
|---|---|
| KMS + DynamoDB vault, sealed key, break-glass | Tokenise and detokenise with KMS-wrapped keys; crypto-shred; the app role **cannot** decrypt the sealed key, the break-glass role can |
| Comprehend | PII detection finds names and emails |
| Bedrock Converse and embeddings | Model calls with tokenised prompts (only if model IDs are set) |
| AgentCore Memory | Creates a memory, writes turns as the pseudonymous `actorId`, discovers the events, erases them, confirms they are gone, deletes the memory |
| AgentCore Identity | Cognito `AdminUserGlobalSignOut` for a test user |
| CloudWatch Logs | Logs Insights discovery of tokens, and detection of a deliberately leaked raw value |
| X-Ray | Trace discovery by the `dpdp_principal` annotation |
| S3 | Every version of a versioned object is purged |
| DynamoDB | Chat-history items found by partition key and deleted |
| JSONL eval set on S3 | Row discovery and deletion in an S3-hosted dataset |
| End to end | API → durable queue → worker → erasure → KMS-signed certificate stored under Object Lock, signature verified |
| OpenAI (optional) | A stored response is found through lineage and deleted |
| Anthropic (optional) | An uploaded file is found through lineage and deleted |

Each run uses a random run ID in every resource name and cleans up what it creates. CloudWatch Logs
Insights can take several minutes to index new events, so a full run takes 10–20 minutes.

### Cost and safety

- Use a **separate, non-production account** (or at least a sandbox). The tests create and delete
  data.
- The test stack uses on-demand DynamoDB, small S3 buckets, three KMS keys (about USD 1 a month each,
  plus a 7-day deletion window after destroy), a Cognito pool and one log group. A run costs cents in
  API calls, plus model calls if enabled.
- The certificate bucket uses `GOVERNANCE` Object Lock with 1-day retention so test certificates can
  be removed. Production uses `COMPLIANCE`.

### Step 1: Create the test stack

The stack in [`deploy/terraform/aws-integration`](../deploy/terraform/aws-integration) creates the
resources the tests need and writes their IDs to SSM Parameter Store under `/dpdp-it`. The tests read
everything from there, so no IDs are needed in the repository or in GitHub.

```bash
cp deploy/terraform/aws-integration/terraform.tfvars.example ~/my-dpdp-deployment/it.tfvars
# edit: region, github_repository (your fork, owner/repo), local_test_principals
cd deploy/terraform/aws-integration
terraform init
terraform apply -var-file ~/my-dpdp-deployment/it.tfvars
terraform output test_role_arn
```

| Variable | Meaning |
|---|---|
| `github_repository` | `owner/repo` of **your** fork that will run the workflow. The test role trusts only this repository's `aws-integration` environment. Leave empty for local runs only |
| `github_owner_id`, `github_repository_id` | Numeric IDs of your account and fork. **Required if your repository was created, renamed or transferred after 15 July 2026** (or opted in to immutable subject claims): GitHub then sends `repo:owner@<id>/repo@<id>:…`. Get them with `gh api repos/<owner>/<repo> --jq '.owner.id, .id'`, or from `https://api.github.com/repos/<owner>/<repo>` (`owner.id` and `id`) |
| `create_github_oidc_provider` | `false` if the account already has the `token.actions.githubusercontent.com` provider |
| `local_test_principals` | IAM ARNs (yours) allowed to assume the test role from a laptop |
| `name_prefix`, `ssm_prefix` | Change only if `dpdp-it` and `/dpdp-it` clash with something |

There are no long-lived AWS keys anywhere: GitHub gets short-lived credentials through OIDC.

If the workflow fails with `Not authorized to perform sts:AssumeRoleWithWebIdentity`, the subject
does not match. Compare `terraform output github_oidc_subject` with your repository's format (see the
ID variables above), and check that the environment is named exactly `aws-integration`.

### Step 2a: Run from GitHub Actions

In **your fork**, go to *Settings → Environments → New environment*, name it `aws-integration`,
and add:

| Kind | Name | Value | Required |
|---|---|---|---|
| Variable | `AWS_ROLE_ARN` | `test_role_arn` output | yes |
| Variable | `AWS_REGION` | Region of the test stack | yes |
| Variable | `BEDROCK_CHAT_MODEL_ID` | A chat model or inference profile ID enabled in the account | no |
| Variable | `BEDROCK_EMBEDDING_MODEL_ID` | For example `amazon.titan-embed-text-v2:0` | no |
| Variable | `OPENAI_TEST_MODEL` | An OpenAI model name | no |
| Secret | `OPENAI_API_KEY` | A key from a test OpenAI project | no |
| Secret | `ANTHROPIC_API_KEY` | A key from a test Anthropic workspace | no |

Optionally add **required reviewers** to the environment so every run needs approval, and restrict
it to the `main` branch.

Then *Actions → integration-aws → Run workflow* (the `ssm_prefix` input defaults to `/dpdp-it`). Results are uploaded as a JUnit artifact
(`integration-results`). Tests for optional providers are skipped when their variables are empty.

Never paste API keys into issues, chats or commit messages. If one is exposed, revoke it at the
provider straight away.

### Step 2b: Run from your machine

```bash
pip install -e ".[dev,aws,postgres,api,openai,anthropic]"

# credentials for a principal listed in local_test_principals, then assume the test role
eval $(aws sts assume-role --role-arn <test_role_arn> --role-session-name dpdp-it \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text |
  awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')

export DPDP_IT_AWS=1 AWS_REGION=<region>
export BEDROCK_CHAT_MODEL_ID=<optional> BEDROCK_EMBEDDING_MODEL_ID=<optional>
# optional: a local PostgreSQL for the control plane, otherwise SQLite in a temp dir
# export DPDP_IT_LINEAGE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/dpdp_it

pytest tests/integration -m integration -v -rA
```

Run the tests as the test role, not as an administrator. The break-glass test checks that the
application role is denied decrypt on the sealed key, which an administrator would not be.

### Step 3: Tear down

```bash
cd deploy/terraform/aws-integration
terraform destroy -var-file ~/my-dpdp-deployment/it.tfvars
```

If a certificate written in the last day is still under retention, wait for it to expire or delete it
with `s3:BypassGovernanceRetention`, then destroy again.

## Testing your own deployment

The live suite tests the framework's connectors. Also test **your** integration:

1. **Dry-run an erasure** for a test principal that has used every feature of your agent:
   `POST /v1/erasure-requests` with `"dry_run": true`, or `dpdp-rights erase --external-id ... --dry-run`.
   Check the plan lists every store your agent writes to. A store missing from the plan is a store
   with no connector or no `track_artifact()` call.
2. **Run the real erasure** in a staging environment and check the certificate: every artifact
   actioned, verification passed for every connector, legal holds listed with their basis.
3. **Seed a leak**: write the test principal's raw phone number into a log the framework watches,
   and confirm verification fails and the request ends as `completed_with_exceptions`.
4. **Withdraw one purpose** and confirm processing for that purpose is refused while other purposes
   continue.
5. **Exercise break-glass** end to end with two different people (request, approve, read, revoke)
   and review the audit trail.

Add these as automated tests in your own pipeline, using a dedicated test principal.

## Testing on Google Cloud

To validate the GCP connectors against your project, follow the same pattern as the AWS suite: a non-production project, resources created by Terraform, IDs passed through
environment variables, and a principal with only the roles in
[`deploy/terraform/gcp`](../deploy/terraform/gcp). A packaged GCP suite is on the [roadmap](roadmap.md).
