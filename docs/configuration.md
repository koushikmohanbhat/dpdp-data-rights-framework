# Configuration reference

The framework reads one YAML file. It can live anywhere you choose:

| `-c` / `DPDP_CONFIG` value | Source |
|---|---|
| `config/my.yaml` | Local file or mounted volume |
| `ssm:///dpdp-rights/prod/config` | AWS SSM Parameter Store (what the AWS Terraform stack uses) |
| `s3://bucket/path/dpdp.yaml` | Amazon S3 |

Keep your real config **outside this repository** (or in a git-ignored path such as `config/private/`).
Start from one of the templates in `config/`.

## Placeholders

Any string value may contain environment-variable placeholders, resolved when the config loads:

| Syntax | Meaning |
|---|---|
| `${VAR}` | Value of `VAR` (empty if unset) |
| `${VAR:-default}` | Value of `VAR`, or `default` if unset |
| `${VAR!url}` | URL-encoded value, for passwords inside database URLs |

Secrets (database passwords, API keys for providers) should come from your platform's secret store as
environment variables, never written into the file.

## Templates

| File | Use |
|---|---|
| `config/dpdp.local.yaml` | Offline demo and tests: echo model, local vault, SQLite |
| `config/dpdp.production.aws.yaml` | Production on AWS with the Terraform stack in `deploy/terraform/aws` |
| `config/dpdp.production.gcp.yaml` | Production on Google Cloud |
| `config/dpdp.aws.yaml`, `config/dpdp.gcp.yaml` | Non-production references with more connector examples |
| `config/dpdp.openai.yaml`, `config/dpdp.anthropic.yaml` | OpenAI direct / Anthropic direct |

Check any config with `dpdp-rights -c <config> check-config` (production guardrails).

## Top level

| Key | Type | Default | Description |
|---|---|---|---|
| `environment` | `dev` \| `staging` \| `production` | `dev` | `production` turns on guardrails that refuse unsafe settings |
| `tenant` | string | none | Label recorded in the context envelope |
| `enforce_consent` | bool | `true` | `protect()` raises `ConsentDenied` without consent for the purpose |
| `purposes` | list | `[]` | Purposes of processing (below) |
| `connectors` | list | `[]` | Stores the framework can discover / erase / verify (below) |
| `tenants` | map | `{}` | Multi-tenant API: `{tenant_name: {config: <path or ssm:// or s3://>}}` |

## `provider`: model calls

| Key | Default | Description |
|---|---|---|
| `type` | `echo` | `openai`, `anthropic`, `bedrock`, `vertex`, or `echo` (offline test model) |
| `model` | `echo` | Model ID, Bedrock model / inference profile ID, or Vertex model |
| `platform` | `anthropic` | For `type: anthropic`: `anthropic` (direct), `bedrock` or `vertex` |
| `embedding_model` | provider default | Embedding model ID |
| `embedding_provider` | none | Required for `anthropic` (Claude has no embeddings API): `openai`, `bedrock`, `vertex`, `echo` |
| `region` | none | Bedrock region / Vertex location |
| `project` | none | Vertex project |
| `store` | `false` | OpenAI: keep responses on the platform (they are then registered and deleted on erasure) |
| `options` | `{}` | Provider extras, e.g. Bedrock `guardrail_id`, `guardrail_version`; Anthropic `max_tokens` |

## `pii`: detection

| Key | Default | Description |
|---|---|---|
| `detectors` | `[regex]` | Any of `regex`, `aws_comprehend`, `bedrock_guardrail`, `gcp_dlp`, `presidio`, `transformers_ner`, `llm`; results are merged and de-overlapped. Choosing: [pii-detection.md](pii-detection.md) |
| `region` | none | For AWS detectors and Textract |
| `project` | none | For `gcp_dlp` |
| `guardrail_id`, `guardrail_version` | none, `DRAFT` | For `bedrock_guardrail` |
| `min_score` | `0.8` | Minimum confidence for Comprehend findings |
| `detect_names` | `true` | Name cues in English, Hinglish and Indian languages ("my name is", "mera naam ... hai", "मेरा नाम") |
| `presidio` | `{}` | Options for `presidio`: `language`, `spacy_model` (default `en_core_web_lg`), `entities`, `min_score`, `nlp_configuration` |
| `transformers_ner` | `{}` | Options for `transformers_ner`: `model` (default `ai4bharat/IndicNER`, or a local path), `include_locations`, `min_score`, `device` |
| `llm` | none | A provider block (same keys as `provider`) for the `llm` detector. **Raw text is sent to it**: use a separate in-region model with prompt logging off |
| `llm_options` | `{}` | `max_chars` per call (default 6000), `score` |
| `surrogates` | `[]` | Element types stored as format-preserving surrogates instead of `<TYPE_xxxx>` tokens: `PHONE_IN`, `PHONE`, `AADHAAR`, `CARD_NUMBER`, `PAN`, `EMAIL`, `BANK_ACCOUNT` |
| `documents` | `{}` | For `protect_document`: `ocr` (`none`, `textract`, `document_ai`), `region`, `processor` (Document AI resource name) |
| `allow_regex_only` | `false` | Production refuses regex-only detection unless this is set after review |

## `vault`: keys and tokens

| Key | Default | Description |
|---|---|---|
| `key_wrapper` | `local` | `aws_kms`, `gcp_kms`, or `local` (development only) |
| `kms_key_id` | none | AWS KMS key ARN / alias, or GCP `projects/.../cryptoKeys/...` |
| `storage` | `sql` | `dynamodb`, `firestore`, or `sql` |
| `sql_url` | lineage URL | Separate database for the vault when `storage: sql` |
| `dynamodb_table_prefix` | `dpdp_vault` | Tables `<prefix>_keys`, `_values`, `_lookups` |
| `firestore_collection_prefix` | `dpdp_vault` | Firestore collections |
| `firestore_database` | `(default)` | Named Firestore database (`deploy/terraform/gcp` creates `dpdp-vault`) |
| `region`, `project` | none | For AWS / GCP storage and keys |
| `local_master_key_path` | `.dpdp/master.key` | Development only |
| `cache_ttl_seconds` | `300` | How long unwrapped data keys stay in memory |
| `cache_max_entries` | `10000` | Cache size |
| `sealed_key_wrapper` | none | Separate KEK for legal-hold / escrow keys: `aws_kms`, `gcp_kms`, `local` |
| `sealed_kms_key_id` | none | Sealed KEK |
| `sealed_role_arn` | none | AWS: role assumed only to decrypt sealed keys (break-glass) |
| `sealed_local_master_key_path` | `.dpdp/sealed.key` | Development only |

## `lineage`: control-plane database

| Key | Default | Description |
|---|---|---|
| `url` | `sqlite:///.dpdp/lineage.db` | Any SQLAlchemy URL. Production: `postgresql+psycopg://user:${PASSWORD!url}@host:5432/db?sslmode=require` |

Tables are created automatically on first start. See [lineage-data-model.md](lineage-data-model.md).

## `purposes`

```yaml
purposes:
  - id: policy_issuance              # referenced by dpdp.context(purpose=...)
    description: Issue the policy
    legal_basis: consent             # consent | legitimate_use (no consent check)
    retention_days: 365              # informational today; purpose-end erasure is on the roadmap
    legal_hold_basis: null           # set to retain (sealed) instead of erasing, e.g. "KYC record keeping"
```

## `connectors`

```yaml
connectors:
  - name: agentcore_memory          # the "store" name used in track_artifact(...)
    type: aws_agentcore_memory      # see docs/connectors.md for all types and options
    options: {memory_id: "${AGENTCORE_MEMORY_ID}", region: "${AWS_REGION}"}
```

## `policy`: erasure decisions

| Key | Default | Description |
|---|---|---|
| `default_action` | `delete` | Action when no rule or built-in default applies |
| `aggregate_k_threshold` | `10` | Aggregates with at least this many *other* principals are retained (tokens redacted) |
| `sla_days` | `30` | Due date for requests (`due_by`) |
| `rules` | `[]` | Ordered overrides: match on `kind`, `edge_type`, `store`, `purpose`, `min_principals`; set `action` and `reason` |
| `statutory_retention.enabled` | `true` | Seal an escrow copy on erasure (DPDP Rules 8(3)) |
| `statutory_retention.days` | `365` | Escrow window, counted from last processing |
| `statutory_retention.basis` | Rule 8(3) text | Recorded in certificates |

Actions: `delete`, `redact`, `regenerate`, `crypto_shred`, `retain_aggregate`, `retain_legal_hold`, `flag_retrain`, `skip`.

## `api`: Rights API authentication

| Key | Default | Description |
|---|---|---|
| `auth.mode` | `none` | `api_key`, `oidc`, `both`; `none` is rejected in production |
| `auth.api_keys[]` | `[]` | `{name, sha256, roles, tenant}`; `sha256` from `dpdp-rights hash-api-key <key>` |
| `auth.oidc.issuer` | required for oidc | e.g. `https://cognito-idp.<region>.amazonaws.com/<pool-id>` |
| `auth.oidc.audience` | required for oidc | App client ID / audience |
| `auth.oidc.jwks_url` | `<issuer>/.well-known/jwks.json` | Override for non-standard issuers |
| `auth.oidc.algorithms` | `[RS256, ES256]` | |
| `auth.oidc.roles_claim` | `roles` | Cognito: `cognito:groups` |
| `auth.oidc.tenant_claim` | `tenant` | For multi-tenant deployments |
| `auth.oidc.subject_claim` | `sub` | Mapped to `external_id` for self-service principals |

Roles: `principal`, `service`, `dpo`, `approver`, `admin`. See [security.md](security.md).

## `queue`: durable jobs

| Key | Default | Description |
|---|---|---|
| `lease_seconds` | `300` | A job is re-claimable if its worker stops renewing it |
| `max_attempts` | `5` | Then the job and its request are marked failed |
| `backoff_seconds` | `60` | Exponential backoff base |

## `certificates`

| Key | Default | Description |
|---|---|---|
| `signer` | `none` | `aws_kms`, `gcp_kms`, `local` (development), `none` |
| `key_id` | none | KMS asymmetric key ARN (ECC_NIST_P256) or GCP key version |
| `local_key_path` | `.dpdp/cert_signing.key` | Development only |
| `archive` | `none` | `s3`, `gcs`, `local`, `none` |
| `archive_uri` | none | `s3://bucket/prefix`, `gs://bucket/prefix`, or a local directory |
| `archive_mode` | `COMPLIANCE` | S3 Object Lock mode; `GOVERNANCE` only for test accounts |
| `retain_days` | `3650` | Object Lock retention |
| `region` | none | |

## `break_glass`

| Key | Default | Description |
|---|---|---|
| `require_second_approver` | `true` | Two-person rule |
| `max_grant_minutes` | `60` | Grant lifetime after approval |

## `observability`

| Key | Default | Description |
|---|---|---|
| `otel` | `false` | Install OpenTelemetry for `serve` / `worker` (needs the `otel` extra) |
| `service_name` | `dpdp-rights` | |
| `otlp_endpoint` | `http://localhost:4318` | ADOT / OTel Collector |
| `tokenize_spans` | `true` | Tokenise / mask personal data in spans before export |

## Environment variables used by the AWS template

`config/dpdp.production.aws.yaml` reads these. The Terraform stack in `deploy/terraform/aws` sets all
of them on the ECS tasks except the ones marked *you*, which you pass through `extra_environment`.

| Variable | Set by | Source |
|---|---|---|
| `DPDP_CONFIG` | Terraform | `ssm://` path of the uploaded config |
| `AWS_REGION` | Terraform | `var.region` |
| `TENANT` | Terraform | `var.tenant` |
| `BEDROCK_MODEL_ID`, `BEDROCK_EMBEDDING_MODEL_ID` | Terraform | `var.bedrock_model_id`, `var.bedrock_embedding_model_id` |
| `BEDROCK_GUARDRAIL_ID` | you | optional |
| `DPDP_KMS_KEY_ARN` | Terraform | vault KMS key |
| `DPDP_SEALED_KMS_KEY_ARN` | Terraform | sealed KMS key |
| `DPDP_BREAK_GLASS_ROLE_ARN` | Terraform | break-glass role |
| `DPDP_VAULT_TABLE_PREFIX` | Terraform | DynamoDB vault tables |
| `DPDP_DB_HOST`, `DPDP_DB_PORT`, `DPDP_DB_NAME`, `DPDP_DB_USER` | Terraform | RDS instance |
| `DPDP_DB_PASSWORD` | Terraform (ECS secret) | RDS-managed secret in Secrets Manager |
| `DPDP_SERVICE_KEY_SHA256` | Terraform | `var.service_api_key_sha256` |
| `DPDP_AUTH_MODE` | Terraform | `var.auth_mode` |
| `COGNITO_USER_POOL_ID`, `COGNITO_APP_CLIENT_ID` | Terraform | created pool or `existing_cognito_*` |
| `DPDP_CERT_SIGNING_KEY_ARN`, `DPDP_CERT_BUCKET`, `DPDP_CERT_LOCK_MODE`, `DPDP_CERT_RETAIN_DAYS` | Terraform | signing key, Object Lock bucket |
| `DPDP_API_LOG_GROUP`, `DPDP_WORKER_LOG_GROUP` | Terraform | the framework's own log groups |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Terraform | ADOT sidecar `http://localhost:4318` |
| `AGENTCORE_MEMORY_ID`, `AGENT_RUNTIME_ID`, `KB_ID`, `KB_DATA_SOURCE_ID`, `TRANSCRIPT_BUCKET`, `APP_DB_URL`, ... | you | only if you enable those connectors |
