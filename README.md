# GenAI DPDP Erasure Kit

**Lineage-aware right to erasure for LLM and agent systems, built for India's DPDP Act 2023 and DPDP Rules 2025.**
Works with **OpenAI**, **Anthropic Claude** (API direct, or on Bedrock / Vertex), **Amazon Bedrock / AgentCore** and **Google Vertex AI**.

Once a support message is used to answer a customer, it also lives in prompt logs, traces,
embeddings, semantic caches, agent memory, eval sets and summaries. Consent is usually stored
per *user*, but the data spreads per *element*. Deleting the CRM row does not erase the person.

This kit makes erasure tractable by:

1. **Tokenising PII before it reaches any model, log or index.** Each person gets their own
   KMS-wrapped key. One key destruction (crypto-shredding) makes every copy unreadable,
   including copies in immutable logs and backups.
2. **Recording lineage at write time.** Every artifact (log stream, vector, cache entry, eval row,
   AgentCore memory event, summary) is linked to the data elements and parent artifacts it came
   from, with typed edges: `copy`, `embed`, `transform`, `aggregate`, `train`.
3. **Tracking consent per element type and purpose**, not just per user.
4. **Orchestrating erasure:** native discovery, a policy per artifact (delete, redact,
   regenerate, shred, retain, flag for retraining), verification against raw values, and a
   hash-chained erasure certificate.
5. **Handling statutory retention.** Data leaves every operational and AI store immediately. A
   sealed escrow copy satisfies the one-year minimum in DPDP Rules 8(3) and is destroyed when
   the window ends.

> Not legal advice. See [docs/dpdp-mapping.md](docs/dpdp-mapping.md) and validate with counsel.

## Quick start (offline, about 1 minute)

```bash
pip install -e ".[dev]"
python examples/support_copilot/demo.py          # add --leak to watch verification catch a raw-PII log line
pytest -q
```

To use real models and clouds, install the matching extras:

```bash
pip install "genai-dpdp-erasure-kit[openai]"      # OpenAI API
pip install "genai-dpdp-erasure-kit[anthropic]"   # Claude API direct, or Claude on Bedrock / Vertex
pip install "genai-dpdp-erasure-kit[aws]"         # Bedrock, AgentCore, CloudWatch, KMS, DynamoDB, S3
pip install "genai-dpdp-erasure-kit[gcp]"         # Vertex AI, Cloud KMS, Firestore, Logging, BigQuery, DLP
pip install "genai-dpdp-erasure-kit[all]"         # everything, plus Redis, PostgreSQL and the API server
```

Until the package is on PyPI, install from a clone with `pip install -e ".[anthropic,aws]"`.

The demo puts four customers through a support copilot (tickets, vectors, cache, eval set, logs,
per-user and weekly summaries). Priya then asks to be erased:

```
redact            record       tickets         <- Principal is mentioned in another person's record
delete            embedding    vectors         <- default
delete            eval_row     eval_set        <- Eval rows are replaceable; never keep personal data in golden sets
delete            cache_entry  semantic_cache  <- default          (a rogue copy found by discovery)
crypto_shred      log          app_log         <- Immutable store; content is tokenised
regenerate        summary      summaries       <- Aggregate below k=5; rebuild without the principal's inputs
...
Rahul's ticket AFTER:  ... her email is [ERASED] ...
OK  vault  principal key destroyed; sealed escrow copy kept for statutory retention (365 days)
```

## Using it in your app

```python
from dpdp_erasure import ErasureKit, EdgeType

kit = ErasureKit.from_yaml("config/dpdp.aws.yaml")     # or dpdp.gcp.yaml / dpdp.openai.yaml / dpdp.anthropic.yaml

pid = kit.principal("cust-1042")                        # pseudonymous id, e.g. dp_9f3c...
kit.register_identifier(pid, "EMAIL", "asha@example.in")
kit.grant_consent(pid, "support_resolution")

logging.getLogger().handlers[0].addFilter(kit.logging_filter())   # logs get tokens, never PII

with kit.context(pid, purpose="support_resolution", session_id=sid):
    safe = kit.protect(user_message)                    # consent check + tokenisation
    ticket = kit.track_artifact("record", "tickets", {"id": tid}, content=safe.text,
                                element_ids=safe.element_ids)
    answer = kit.generate(safe.text, system=SYSTEM, already_protected=True)   # OpenAI / Claude / Bedrock / Vertex
    kit.track_artifact("cache_entry", "semantic_cache", {"id": key}, parents=[ticket.artifact_id],
                       content=answer.text)
    show_to_customer(answer.reveal())                   # detokenised only for the owner

kit.erase(pid)                                          # or POST /v1/erasure-requests
kit.withdraw_consent(pid, "analytics")                  # purpose-scoped erasure
```

AgentCore Memory, with the principal id used as `actorId`:

```python
from dpdp_erasure.integrations.agentcore import AgentCoreMemory
mem = AgentCoreMemory(kit, memory_id=os.environ["AGENTCORE_MEMORY_ID"])
with kit.context(pid, purpose="support_resolution", session_id=sid):
    mem.add_turn(user_message, role="USER")
```

## Choose a model provider and cloud

| Config | Models | PII detection | Vault | Native stores covered |
|---|---|---|---|---|
| `config/dpdp.aws.yaml` | Bedrock Converse (+ Guardrails) | regex + Comprehend / Guardrails | KMS + DynamoDB | AgentCore Memory, CloudWatch (incl. `aws/spans`, Bedrock invocation logs), Bedrock KB, S3, DynamoDB, Aurora pgvector |
| `config/dpdp.gcp.yaml` | Vertex AI Gemini | regex + Cloud DLP | Cloud KMS + Firestore | Memory Bank, Cloud Logging, Vector Search, BigQuery, GCS |
| `config/dpdp.openai.yaml` | OpenAI Responses API (`store=false`) | regex (+ either cloud) | local or KMS | OpenAI stored responses/files, Redis, SQL |
| `config/dpdp.anthropic.yaml` | Claude via Anthropic SDK: API direct, `AnthropicBedrock` or `AnthropicVertex` (`platform:`) | regex (+ either cloud) | local or KMS | Anthropic Files API uploads, SQL |
| `config/dpdp.local.yaml` | offline echo model | regex | local | SQLite, JSONL, log files |

Mix and match freely. For example, use OpenAI models with AWS stores by setting
`provider.type: openai` in the AWS config, or Claude on Bedrock with `provider.type: anthropic`
and `platform: bedrock`. Claude has no embeddings endpoint, so set `embedding_provider`
(openai, bedrock or vertex) for vectors.

## Rights API

```bash
dpdp-erasure -c config/dpdp.local.yaml serve --port 8080
curl -XPOST localhost:8080/v1/erasure-requests -d '{"external_id":"cust-1001","dry_run":true}' -H 'content-type: application/json'
curl localhost:8080/v1/erasure-requests/<id>
curl localhost:8080/v1/erasure-requests/<id>/certificate
```

Other CLI commands: `erase`, `lineage`, `certificate`, `connectors`, and `purge-escrows`
(schedule this daily with EventBridge Scheduler or Cloud Scheduler).

## Repository layout

```
src/dpdp_erasure/
  core/          models, context envelope (W3C baggage), config
  pii/           detectors (regex w/ Verhoeff Aadhaar, Comprehend, Guardrails, DLP) + tokenizer
  vault/         per-principal keys (local / AWS KMS / Cloud KMS) + storage (SQL / DynamoDB / Firestore)
  consent/       consent ledger (principal x element x purpose)
  lineage/       control-plane store + graph traversal
  providers/     OpenAI, Anthropic (direct/Bedrock/Vertex), Bedrock Converse, Vertex, echo
  connectors/    local, AWS, GCP, OpenAI platform, Anthropic platform
  erasure/       policy engine + orchestrator (+ certificates, escrow purge)
  integrations/  AgentCore Memory/Runtime helpers
  api/ cli.py    FastAPI rights API, CLI
config/          ready-to-edit configs per cloud
deploy/terraform AWS + GCP infra for vault, keys, IAM, log protection
docs/            architecture, lineage data model, DPDP mapping, connectors
examples/        offline demo, AgentCore agent, OpenAI direct
```

## Docs

- [Architecture and diagrams](docs/architecture.md)
- [Lineage data model (ERD, SQL, recursive CTE)](docs/lineage-data-model.md)
- [DPDP mapping](docs/dpdp-mapping.md)
- [Connectors and writing your own](docs/connectors.md)

## Roadmap

- Inactivity-based erasure with 48-hour notices (Rules r.8(1)-(2), Third Schedule platforms)
- Sealed-archive connector (S3 Object Lock / GCS Bucket Lock) for record-level statutory retention
- Consent Manager (Rule 4) webhook adapter
- Azure (Azure OpenAI, Monitor, AI Search) connectors
- OpenTelemetry span processor that tokenises attributes in-process
- Neptune / Spanner Graph lineage backends for very large graphs

## License

Apache-2.0
