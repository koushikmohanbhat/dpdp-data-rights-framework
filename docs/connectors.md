# Connectors

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

## AgentCore conventions

- Use the kit's pseudonymous `principal_id` as the AgentCore Memory **actorId**. The
  `integrations.agentcore.AgentCoreMemory` helper does this and tokenises every turn.
- Namespace templates in config (`/users/{actorId}/facts`) must match your memory strategies.
- Pass the context envelope into AgentCore Runtime as W3C `baggage`, or in the payload under `dpdp`.
  `envelope_from_agentcore_payload()` rebuilds it inside the entrypoint.
- Observability spans and runtime logs land in CloudWatch. Add `aws/spans` and
  `/aws/bedrock-agentcore/runtimes/<id>-<endpoint>` to the `aws_cloudwatch_logs` connector.

## Writing a connector

```python
from dpdp_erasure.connectors import Connector, Discovered, register
from dpdp_erasure.core.models import Action

@register("servicenow_incident")
class ServiceNowIncidents(Connector):
    supports = {Action.DELETE, Action.REDACT}

    def __init__(self, name, instance, token, **kw):
        super().__init__(name, **kw)
        ...

    def discover(self, ctx):
        # search incidents whose description contains any of ctx.needles
        return [Discovered("record", {"sys_id": sid}) for sid in ...]

    def _delete(self, artifact, ctx, fallback_from=None):
        ...
        return self._ok(artifact, Action.DELETE)

    def _redact(self, artifact, ctx):
        # replace ctx.tokens with [ERASED] in the incident text
        ...
```

Import the module before building the kit (or add it to `connectors/__init__.py`), then
reference `type: servicenow_incident` in YAML.
