# Integration guide

How to wire the framework into an AI agent so that consent is enforced, every copy of personal data
is tracked, and erasure reaches all of them. The examples use an insurance onboarding agent; the same
steps apply to lending, healthcare, telecom, HR or any other domain.

Work through the steps in order. Steps 1 and 2 are design work you do once with your product owner
and DPO; steps 3 to 8 are code.

## 1. Model your purposes

A *purpose* is a reason you process personal data. Consent is given, withdrawn and enforced per
purpose. Write them down with your DPO before writing code:

| Purpose | Legal basis | Example in an insurance agent |
|---|---|---|
| `policy_issuance` | consent | Collect details, underwrite, issue the policy |
| `analytics` | consent | Portfolio and funnel analytics |
| `marketing` | consent | Cross-sell and renewal campaigns |
| `model_improvement` | consent | Evaluation sets and fine-tuning from real conversations |
| `kyc_regulatory` | legitimate use, legal hold | KYC records that sector regulation requires you to keep |

```yaml
purposes:
  - id: policy_issuance
    description: Process the application, underwrite and issue the policy
  - id: marketing
    description: Cross-sell and renewal campaigns
  - id: kyc_regulatory
    description: KYC records
    legal_basis: legitimate_use
    legal_hold_basis: "KYC record keeping under <regulation, section>. Validated by counsel on <date>."
    retention_days: 1825
```

Guidelines:

- **Be specific.** "Improve our services" is not a purpose; "evaluate and improve the onboarding
  agent" is. DPDP consent must be specific to a purpose (Act s.6).
- **Separate what users can refuse.** If marketing is optional, it must be its own purpose so it can
  be withdrawn without stopping the application.
- **Legal holds need a citation.** `legal_hold_basis` appears on every erasure certificate. A data
  element under a legal hold is sealed, not deleted, and only readable through break-glass.
- **Ask what each purpose needs.** `grant_consent(..., element_types=[...])` limits a purpose to
  certain data elements (for example `marketing` may use `EMAIL` and `PHONE_IN` but not `AADHAAR`).

## 2. Inventory your stores

List every place the agent writes something derived from a user's input. Teams usually find more
than they expect:

| Store | Typical artifact kind | Edge from its source | Connector |
|---|---|---|---|
| Application database | `record` | copy | `sql_table` |
| Agent memory (AgentCore Memory, Agent Engine Sessions / Memory Bank) | `memory_event`, `memory_record` | copy, transform | `aws_agentcore_memory`, `gcp_*` |
| Vector index / knowledge base | `embedding`, `kb_document` | embed | `sql_table` (pgvector), `aws_bedrock_kb`, `gcp_vertex_vector_search` |
| Response or semantic cache | `cache_entry` | copy | `redis_cache`, `sql_table` |
| Logs, traces, LLM observability | `log`, `trace` | copy | `aws_cloudwatch_logs`, `aws_xray`, `gcp_cloud_logging`, `gcp_cloud_trace`, `langfuse` |
| Per-user summaries, notes | `summary` | transform | `sql_table`, `aws_dynamodb`, `aws_s3_objects` |
| Reports across many users | `summary` | aggregate | `sql_table`, `gcp_bigquery` |
| Eval sets, fine-tuning data | `eval_row`, `finetune_row` | copy | `jsonl_dataset` |
| Fine-tuned models | `model` | train | (flag for retraining) |
| Model provider state | `provider_response`, `provider_file` | copy | `openai_platform`, `anthropic_platform` |
| Uploaded documents | `record` | copy | `aws_s3_objects`, GCS |

For each one, add a connector to your config ([connectors.md](connectors.md) lists the types and
their options). If a store has no connector, write one: it is a small class with `discover`, `erase`
and `verify` methods ([connectors.md](connectors.md#writing-a-connector)).

**Edge types decide what happens on erasure.** The policy engine looks at how an artifact was
derived:

| Edge | Meaning | Default treatment |
|---|---|---|
| `copy` | Same content, different place | Deleted with its source |
| `embed` | Text turned into a vector | The person's own vectors are deleted (vectors can leak their source text). Vectors of other people's records that mention them are re-embedded from the redacted text (set `embedding_column`) or deleted |
| `transform` | Derived for one person (completion, per-user summary) | Summaries regenerated without the person's input; other kinds deleted |
| `aggregate` | Many people → one artifact (weekly report) | Regenerated without the person if fewer than `aggregate_k_threshold` contributors; otherwise retained as an anonymised aggregate and documented |
| `train` | Dataset → model weights | Model flagged for retraining |

Override per kind, store, edge or purpose in `policy.rules`. See [configuration.md](configuration.md#policy-erasure-decisions).

## 3. Set up the framework

```python
from dpdp_rights import DataRightsFramework, EdgeType

dpdp = DataRightsFramework.from_yaml(os.environ.get("DPDP_CONFIG", "config/dpdp.local.yaml"))
```

Create one instance per process and reuse it. In AWS deployments `DPDP_CONFIG` is an `ssm://`
parameter (see [deploy-aws.md](deploy-aws.md#step-9-connect-your-agents)).

## 4. Identify principals and record consent

Each person gets a **pseudonymous principal ID** (`dp_…`) derived from your own customer or
application ID. Use it everywhere you need a user key in AI systems (memory `actorId`, trace
attributes, cache keys), never the email or phone.

```python
pid = dpdp.principal("applicant-1042")                       # your own stable ID
dpdp.register_identifier(pid, "EMAIL", "asha@example.in")      # so mentions anywhere resolve to her
dpdp.register_identifier(pid, "PHONE_IN", "+91 98765 43210")

dpdp.grant_consent(pid, "policy_issuance", notice_version="2026-11",
                   consent_manager_ref="<ref from your Consent Manager, if any>")
```

`register_identifier` matters for multi-person data. When Rahul names Asha as his nominee, the
framework recognises her email in Rahul's application, links that element to Asha, and redacts it
when Asha asks for erasure, while Rahul's application stays.

If consent is captured in another system (your app, a registered Consent Manager), call
`grant_consent` and `withdraw_consent` from that system, or use `POST /v1/consents` and
`POST /v1/withdrawals` with a service API key.

## 5. Wrap processing in a context

Every unit of work that touches personal data runs inside a context that names the principal and the
purpose:

```python
with dpdp.context(pid, purpose="policy_issuance", session_id=session_id):
    safe = dpdp.protect(user_message)          # 1. consent check + tokenisation
    ...
```

`protect()`:

1. checks the principal has consent for this purpose (and these data element types), raising
   `ConsentDenied` if not, so a withdrawn purpose stops at once;
2. detects personal data (regex with Indian formats and scripts, plus whichever of Comprehend, Bedrock
   Guardrails, Cloud DLP, Presidio, IndicNER or an LLM detector you configure; see
   [pii-detection.md](pii-detection.md)) and replaces each value with a token such as `EMAIL_3f9a0c1b2d4e`;
3. returns the tokenised text and the IDs of the data elements it contained.

Send `safe.text` to models, memory, logs and indexes. **Nothing downstream should ever see the raw
value.** Show real values only to the person they belong to, with `reveal()` (or `reveal(masked=True)` for a masked form).

For KYC uploads and other documents, use `dpdp.protect_document(file_bytes, filename=...)`: it extracts the
text (locally for digital PDFs, OCR for scans) and tokenises it the same way.

Across services, pass the context as W3C `baggage` (`env.to_headers()` and
`ContextEnvelope.from_headers()`), or in the payload under `dpdp` for AgentCore Runtime
(`envelope_from_agentcore_payload()`).

## 6. Track every artifact

Wherever the agent persists something, register it, with its parents and how it was derived:

```python
with dpdp.context(pid, purpose="policy_issuance", session_id=session_id):
    safe = dpdp.protect(user_message)

    app = dpdp.track_artifact("record", "applications", {"id": app_id},
                              content=safe.text, element_ids=safe.element_ids)

    answer = dpdp.generate(safe.text, system=SYSTEM, already_protected=True)

    note = dpdp.track_artifact("summary", "summaries", {"id": note_id},
                               parents=[app.artifact_id], edge_type=EdgeType.TRANSFORM,
                               content=answer.text)

    reply_to_user(answer.reveal())
```

- `store` is the connector **name** from your config; `locator` is whatever that connector needs to
  find the item again (a primary key, an S3 URI, a memory event ID).
- Passing `content` lets the framework link the artifact to **every** principal whose tokens appear
  in it, which is how multi-person summaries and reports get handled.
- `dpdp.generate()` calls your configured model (OpenAI, Claude, Bedrock or Vertex) and registers any
  provider-side state (for example an OpenAI stored response) as an artifact automatically.
- Aggregates: track a report with `edge_type=EdgeType.AGGREGATE` and all its input artifacts as
  parents.

Helpers that do this for you:

```python
from dpdp_rights.integrations.agentcore import AgentCoreMemory
mem = AgentCoreMemory(dpdp, memory_id=os.environ["AGENTCORE_MEMORY_ID"])
with dpdp.context(pid, purpose="policy_issuance", session_id=session_id):
    mem.add_turn(user_message, role="USER")      # tokenises, uses pid as actorId, tracks the event

dpdp.track_cache_key(redis_client, cache_key)   # indexes a Redis key under the principal
```

**Missed a `track_artifact` call?** Discovery is the safety net. During erasure each connector also
searches its store for the principal's tokens and principal ID, so copies nobody registered are still
found, as long as the store has a connector. Verification then re-checks every store for tokens and
raw values.

## 7. Keep logs and traces clean

```python
import logging
logging.getLogger().handlers[0].addFilter(dpdp.logging_filter())
```

The filter tokenises log messages inside a context, and masks detected values (`[EMAIL]`) outside
one. Add it to every handler that ships logs off the host.

For OpenTelemetry:

```python
from dpdp_rights.observability.telemetry import install
install(dpdp)          # OTLP to the collector at observability.otlp_endpoint
```

This adds the pseudonymous principal, purpose and request ID to every span, and tokenises span
attributes and events before export. Run the collector from [`deploy/otel`](../deploy/otel) as a
second line of defence. Details in [observability.md](observability.md).

## 8. Handle regeneration (optional)

When a summary or report must be rebuilt without a person's input, the framework by default rebuilds
it from its surviving parents, or asks the model to rewrite it without the erased tokens. To use your
own logic (for example re-running a report query), register a regenerator keyed by store name or
artifact kind:

```python
def rebuild_weekly_report(artifact, ctx, orchestrator):
    return run_report(artifact.locator["week"], exclude=ctx.principal_id)   # new content, or None to delete

dpdp.orchestrator.register_regenerator("weekly_reports", rebuild_weekly_report)
```

Whatever the regenerator returns, any surviving token of the erased person is removed before it is
written.

## 9. Handle requests

Requests arrive **already verified** by your own channel (app login, KYC check, contact centre).
Record how it was verified:

```bash
curl -XPOST "$API/v1/withdrawals" -H "x-api-key: $KEY" -H 'Idempotency-Key: 7f3a' \
  -H 'content-type: application/json' \
  -d '{"external_id":"applicant-1042","purpose_id":"marketing","verified_by":"mobile-app","verification_ref":"sess-91f2"}'

curl -XPOST "$API/v1/erasure-requests" -H "x-api-key: $KEY" -H 'Idempotency-Key: 8e1c' \
  -H 'content-type: application/json' \
  -d '{"external_id":"applicant-1042","scope":"full","verified_by":"contact-centre","verification_ref":"case-5512"}'
```

| Endpoint | Role | Purpose |
|---|---|---|
| `POST /v1/consents` | service, principal (own) | Record consent |
| `POST /v1/withdrawals` | service, principal (own) | Withdraw a purpose; erases data held only for it |
| `POST /v1/erasure-requests` | service, principal (own) | Full or purpose-scoped erasure; `dry_run` to preview |
| `GET /v1/erasure-requests/{id}` | owner, dpo | Status and actions |
| `GET /v1/erasure-requests/{id}/certificate` | owner, dpo | Signed certificate |
| `GET /v1/erasure-requests/{id}/certificate/verify` | owner, dpo | Check hash, chain and signature |
| `GET /v1/principals/{id}/lineage` | dpo | Everything known about a principal |
| `GET /v1/sla` | dpo | Open requests by SLA bucket, queue depth |
| `/v1/break-glass/...` | dpo, approver | Sealed data access (see [operations.md](operations.md#break-glass-access)) |

Use an `Idempotency-Key` per request so retries from your backend never create duplicates. The
interactive API reference is at `/docs` on a running server.

## 10. Bring existing data under management

If the agent already ran before you integrated the framework, existing stores hold raw personal data
with no lineage. Options, from best to simplest:

1. **Re-tokenise.** For each existing record, inside a context for its owner, run `protect()` on the
   content, write the tokenised version back, and `track_artifact()` it.
2. **Rely on discovery.** Register identifiers for existing customers (`register_identifier`) and
   make sure every store has a connector that can search by principal or by raw value. Erasure will
   find and act on these items, but raw copies are only as discoverable as the connector's search.
3. **Expire.** Set short retention on logs, traces and caches created before the cut-over, so old raw
   data ages out.

Do one of these before relying on the certificates for those older stores.

## Checklist before go-live

- [ ] Purposes, legal bases and legal holds reviewed by your DPO and counsel
- [ ] Every store from step 2 has a connector in the config
- [ ] All user input passes through `protect()` before reaching a model, memory, index or log
- [ ] Every persisted artifact has a `track_artifact()` call with correct parents and edge type
- [ ] Logging filter on every shipping handler; OpenTelemetry installed with tokenisation
- [ ] A dry-run erasure for a test principal lists every store ([testing.md](testing.md#testing-your-own-deployment))
- [ ] A real erasure in staging ends `completed` with a verified certificate
- [ ] `dpdp-rights check-config` passes in CI with `environment: production`
