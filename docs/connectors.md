# Connectors

What each connector can find, do and verify, and its limits: [capability matrix](capabilities.md)
(generated from each connector's `capabilities` declaration). To see which of a client's systems are
covered, list them in an inventory and run `dpdp-rights coverage` ([partner pack](../partner-pack/README.md)).

| Type | Store | Discover | Actions | Verify |
|---|---|---|---|---|
| `sql_table` | Any SQLAlchemy DB: app tables, pgvector, summaries, Aurora, Cloud SQL, AlloyDB | principal column + token `LIKE` | delete, redact, regenerate | tokens + raw values absent |
| `jsonl_dataset` | Eval / fine-tune / batch JSONL on disk, `s3://`, `gs://` | token scan | delete row, redact | tokens + raw absent |
| `log_file` | Local log files | token scan | crypto_shred | raw values absent |
| `redis_cache` | Redis semantic / response caches | principal key index | delete | index empty |
| `aws_cloudwatch_logs` | CloudWatch Logs: app logs, Bedrock invocation logs, AgentCore Runtime logs, AgentCore Observability spans (`aws/spans`) | Logs Insights query | crypto_shred, or delete stream | raw-value Insights query + retention check |
| `aws_agentcore_memory` | AgentCore Memory short-term events + long-term records | ListSessions/ListEvents by actorId; ListMemoryRecords by namespace | DeleteEvent, DeleteMemoryRecord | re-discovery empty |
| `aws_bedrock_kb` | Bedrock Knowledge Bases | via lineage | DeleteKnowledgeBaseDocuments or S3 delete + StartIngestionJob | action status |
| `aws_s3_objects` | S3 objects (purges **all versions**) | prefix template | delete | re-discovery empty |
| `aws_dynamodb` | DynamoDB items keyed by principal | Query on partition key | delete | re-discovery empty |
| `gcp_cloud_logging` | Cloud Logging | entries.list text search | crypto_shred | raw-value search |
| `gcp_bigquery` | BigQuery tables | principal column + `STRPOS` | DELETE, UPDATE ... REPLACE | re-discovery empty |
| `gcp_vertex_vector_search` | Vertex AI Vector Search | via lineage | remove_datapoints | - |
| `gcp_vertex_memory_bank` | Agent Engine Memory Bank (v1beta1) | memories:retrieve by scope | delete memory | re-discovery empty |
| `openai_platform` | Stored responses, conversations, files, vector-store files | via lineage | delete | API confirmation |
| `anthropic_platform` | Anthropic Files API uploads (Messages API is stateless) | via lineage | delete | API confirmation |
| `aws_xray` | AWS X-Ray traces | `GetTraceSummaries` on the `dpdp_principal` annotation | crypto_shred (traces are immutable) | scans segments for raw values |
| `gcp_cloud_trace` | Google Cloud Trace | `list_traces` on the `dpdp.principal` label | crypto_shred (spans are immutable) | scans span labels for raw values |
| `langfuse` | Langfuse LLM traces | traces by `userId` | delete | re-discovery empty |
| `gcp_agent_engine_sessions` | Vertex AI Agent Engine Sessions (v1beta1) | sessions by `user_id` | delete session | re-discovery empty |
| `aws_agentcore_identity` | AgentCore Identity token vault (per-user OAuth tokens) | one per principal | revoke at IdP: Cognito `AdminUserGlobalSignOut` or webhook (no per-user delete API exists) | IdP confirmation |

## Agent platforms: AgentCore and Vertex AI Agent Engine

| Capability | Amazon Bedrock AgentCore | Vertex AI Agent Engine | Connector coverage |
|---|---|---|---|
| Short-term memory / sessions | Memory events | Sessions | `aws_agentcore_memory`, `gcp_agent_engine_sessions` |
| Long-term memory | Memory records | Memory Bank | `aws_agentcore_memory`, `gcp_vertex_memory_bank` |
| Traces and logs | Observability (`aws/spans`, runtime logs) | Cloud Trace, Cloud Logging | `aws_cloudwatch_logs`, `aws_xray`, `gcp_cloud_trace`, `gcp_cloud_logging` |
| Per-user credentials | Identity token vault | (your IdP) | `aws_agentcore_identity` |
| Runtime | Runtime helper (`envelope_from_agentcore_payload`) | context via headers / payload | `integrations.agentcore` |

Use the pseudonymous principal id as AgentCore `actorId` / Identity `userId` and as Agent Engine
`user_id`, so platform data is findable per person but never keyed by a real identifier.

## AgentCore conventions

- Use the framework's pseudonymous `principal_id` as the AgentCore Memory **actorId**. The
  `integrations.agentcore.AgentCoreMemory` helper does this and tokenises every turn.
- Namespace templates in config (`/users/{actorId}/facts`) must match your memory strategies.
- Pass the context envelope into AgentCore Runtime as W3C `baggage`, or in the payload under `dpdp`.
  `envelope_from_agentcore_payload()` rebuilds it inside the entrypoint.
- Observability spans and runtime logs land in CloudWatch. Add `aws/spans` and
  `/aws/bedrock-agentcore/runtimes/<id>-<endpoint>` to the `aws_cloudwatch_logs` connector.

## IAM permissions for AWS connectors

The framework's task role (and the role you run integration tests with) needs these actions on
**your** resources. Write a policy scoped to the specific ARNs and pass it in
`extra_task_policy_arns` (see [deploy-aws.md](deploy-aws.md#permissions-for-your-stores)).

| Connector | Actions |
|---|---|
| `aws_cloudwatch_logs` | `logs:StartQuery`, `logs:GetQueryResults`; `logs:PutRetentionPolicy` if `apply_retention` is set; `logs:DeleteLogStream` if streams may be deleted |
| `aws_xray` | `xray:GetTraceSummaries`, `xray:BatchGetTraces` |
| `aws_agentcore_memory` | `bedrock-agentcore:ListSessions`, `ListEvents`, `ListMemoryRecords`, `DeleteEvent`, `DeleteMemoryRecord` on the memory ARN |
| `aws_agentcore_identity` | `cognito-idp:AdminUserGlobalSignOut` on the user pool (or none, if you use the webhook) |
| `aws_bedrock_kb` | `bedrock:DeleteKnowledgeBaseDocuments` (direct mode), or `bedrock:StartIngestionJob` plus `s3:DeleteObject` on the data source bucket (S3 mode) |
| `aws_s3_objects` | `s3:ListBucket`, `s3:ListBucketVersions`, `s3:DeleteObject`, `s3:DeleteObjectVersion` |
| `aws_dynamodb` | `dynamodb:Query`, `dynamodb:DeleteItem` (plus `dynamodb:Query` on the index, if you use one) |
| `sql_table` on RDS / Aurora | none in IAM; a database user with `SELECT`, `UPDATE`, `DELETE` on the tables |
| `jsonl_dataset` on S3 | `s3:GetObject`, `s3:PutObject` on the dataset object |

KMS: if any of these stores are encrypted with a customer-managed key, also allow `kms:Decrypt`
(and `kms:GenerateDataKey` where the connector rewrites objects) on that key.

## Writing a connector

Write it as a plug-in in your own package, declare its capabilities, and run the conformance kit against
a sandbox: [plugins.md](plugins.md#writing-a-connector). No fork of this repository is needed.
