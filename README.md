# DPDP Data Rights Framework for AI Agents

**A framework for honouring consent withdrawal and erasure requests in GenAI and agentic applications, built for India's Digital Personal Data Protection (DPDP) Act 2023 and DPDP Rules 2025.**

Works with **OpenAI**, **Anthropic Claude** (API direct, or on Bedrock / Vertex), **Amazon Bedrock / AgentCore** and **Google Vertex AI**, and with any domain: insurance, lending, healthcare, telecom, retail, HR or the public sector.

> Not legal advice. See [docs/dpdp-mapping.md](docs/dpdp-mapping.md) and validate each deployment with privacy counsel.

## Why this exists

The DPDP Act gives every individual (the *Data Principal*) the right to withdraw consent at any time and to have their personal data erased. The organisation (the *Data Fiduciary*) must then stop processing, erase the data, and make its processors do the same, unless another law requires it to keep the data.

Traditional systems handle this by deleting a row in a system of record. AI agents make that insufficient. Take an applicant who gives an insurance onboarding agent their name, Aadhaar, PAN, health disclosures and a nominee's contact details. Within minutes that data has been:

- sent to a model and written to prompt logs, traces and observability spans
- chunked and embedded into a vector index for retrieval
- remembered by the agent (session memory and long-term extracted facts)
- cached as agent responses
- summarised into an underwriting note, and rolled up into a weekly portfolio report
- copied into an evaluation set used to improve the agent
- placed into a marketing audience for cross-sell
- kept in a KYC record that sector regulation says must be retained

Consent, meanwhile, was recorded once against the *customer*. Consent applies per purpose, but the data spreads per *data element* (email, phone, Aadhaar, free text) and across derived artifacts. When the applicant later withdraws consent, nobody can say where their data went, which copies must go, which may stay, or prove that it was done.

## What the framework does

| Capability | What it gives you |
|---|---|
| **Purpose-based consent ledger** | Consent recorded per Data Principal × data element × purpose, with notice version and Consent Manager reference. Processing for a purpose without valid consent is blocked. |
| **Tokenisation at the edge** | Personal data is detected (India-aware: Aadhaar with checksum, PAN, UPI, +91 phones, plus Comprehend / Bedrock Guardrails / Cloud DLP) and replaced with tokens *before* it reaches a model, log, index, cache or memory. Each person has their own encryption key, protected by your key management service (AWS KMS or Google Cloud KMS; a local key for development). |
| **Data lineage graph** | Every artifact the agent creates is linked to the data elements it contains and the artifacts it was derived from, with typed edges: `copy`, `embed`, `transform`, `aggregate`, `train`. |
| **Erasure orchestration** | On withdrawal or erasure request: discover copies (including ones nobody registered), decide per artifact (delete, redact, regenerate, crypto-shred, retain under legal hold, flag model for retraining), execute through native connectors. |
| **Verification and evidence** | Every store is re-checked for tokens and raw values. A hash-chained erasure certificate records every action, exception and legal basis for the DPO or the Data Protection Board. |
| **Retention-aware** | Legal holds (e.g. KYC record keeping) and the DPDP Rules' one-year minimum retention are handled with sealed keys usable only through audited break-glass access, purged automatically when the period ends. |
| **Production security** | Authenticated, role-based Rights API (API keys, OIDC); requester verification before anything is erased; durable job queue with resume; KMS-signed certificates in immutable storage; tenant isolation; production guardrails. See [docs/security.md](docs/security.md). |
| **Observability without leaks** | OpenTelemetry spans tagged with the pseudonymous principal and tokenised before export; erasure metrics and SLA alerts; collector configs for X-Ray/CloudWatch and Cloud Trace. See [docs/observability.md](docs/observability.md). |

Erasure becomes tractable because no store ever holds a raw identifier. Destroying one person's key makes every copy unreadable, including copies in immutable logs and backups. Lineage tells you which derived artifacts (summaries, audiences, eval rows, fine-tuned models) also need action.

## How it maps to DPDP

| DPDP obligation | Framework feature |
|---|---|
| Consent must be specific to a purpose; withdrawal as easy as giving it (Act s.6) | Consent ledger per element and purpose; `withdraw_consent()` |
| On withdrawal, stop processing and make processors stop (s.6(6)) | `protect()` refuses further processing; connectors reach processor-held data (model providers, clouds, SaaS) |
| Erase when consent is withdrawn or the purpose is served, unless law requires retention (s.8(7)) | Purpose-scoped and full erasure; legal-hold purposes |
| Right to erasure on request (s.12(3)) | Rights API / CLI → orchestrator → certificate |
| Reasonable security safeguards (s.8(5), Rule 6) | Tokenisation, per-person keys protected by AWS KMS / Cloud KMS, tokenised logs |
| Minimum one-year retention of personal data, traffic data and logs (Rule 8(3)) | Sealed retention escrow with scheduled purge |
| Grievance redressal within 90 days (Rule 14) | Requests carry an SLA `due_by` and a full audit trail |

Most of these obligations apply from **13 May 2027**. Full mapping: [docs/dpdp-mapping.md](docs/dpdp-mapping.md).

## Quick start (offline, about 1 minute)

```bash
pip install -e ".[dev]"
python examples/insurance_onboarding/demo.py      # add --leak to watch verification catch a raw-PII log line
pytest -q
```

The demo runs an insurance onboarding agent for four applicants (term life, motor, health, travel). Then:

1. **Anita withdraws marketing consent only.** Her marketing audience entry is erased; her application continues.
2. **Priya withdraws all consent and asks to be erased.**

```
delete            record       applications  <- default
redact            record       applications  <- Principal is only mentioned in another person's record   (Rahul named her as nominee)
delete            embedding    vectors       <- default
delete            eval_row     eval_set      <- Eval rows are replaceable; never keep personal data in golden sets
delete            cache_entry  agent_cache   <- default          (a copy nobody registered, found by discovery)
regenerate        summary      summaries     <- Aggregate below k=5; rebuild without the principal's inputs
retain_legal_hold record       kyc_records   <- Retention required: KYC record keeping (sealed)
further processing blocked: No consent for purpose 'policy_issuance' ...
Rahul's application AFTER:  ... Nominee is my wife, email [ERASED] ...
OK  vault  principal key destroyed; sealed escrow copy kept for statutory retention (365 days)
```

## Using it in your agent

Purposes and stores are configuration, so the same code serves an insurance, lending or healthcare agent.

```python
from dpdp_rights import DataRightsFramework, EdgeType

dpdp = DataRightsFramework.from_yaml("config/dpdp.aws.yaml")   # or gcp / openai / anthropic / local

pid = dpdp.principal("applicant-1042")                          # pseudonymous id, e.g. dp_9f3c...
dpdp.register_identifier(pid, "EMAIL", "asha@example.in")
dpdp.grant_consent(pid, "policy_issuance", notice_version="2026-11")

logging.getLogger().handlers[0].addFilter(dpdp.logging_filter())   # logs get tokens, never PII

with dpdp.context(pid, purpose="policy_issuance", session_id=sid):
    safe = dpdp.protect(user_message)                           # consent check + tokenisation
    app = dpdp.track_artifact("record", "applications", {"id": app_id},
                              content=safe.text, element_ids=safe.element_ids)
    answer = dpdp.generate(safe.text, system=SYSTEM, already_protected=True)   # OpenAI / Claude / Bedrock / Vertex
    dpdp.track_artifact("summary", "summaries", {"id": note_id}, parents=[app.artifact_id],
                        edge_type=EdgeType.TRANSFORM, content=answer.text)
    show_to_applicant(answer.reveal())                          # detokenised only for the owner

dpdp.withdraw_consent(pid, "marketing")                         # purpose-scoped erasure
dpdp.erase(pid)                                                 # full erasure, or POST /v1/erasure-requests
```

AgentCore Memory, with the pseudonymous id used as `actorId`:

```python
from dpdp_rights.integrations.agentcore import AgentCoreMemory
mem = AgentCoreMemory(dpdp, memory_id=os.environ["AGENTCORE_MEMORY_ID"])
with dpdp.context(pid, purpose="policy_issuance", session_id=sid):
    mem.add_turn(user_message, role="USER")
```

## Choose a model provider and cloud

| Config | Models | PII detection | Vault | Native stores covered |
|---|---|---|---|---|
| `config/dpdp.aws.yaml` | Bedrock Converse (+ Guardrails) | regex + Comprehend / Guardrails | KMS + DynamoDB | AgentCore Memory + Identity, CloudWatch (incl. `aws/spans`, Bedrock invocation logs), X-Ray, Bedrock KB, S3, DynamoDB, Aurora pgvector |
| `config/dpdp.gcp.yaml` | Vertex AI Gemini | regex + Cloud DLP | Cloud KMS + Firestore | Agent Engine Sessions + Memory Bank, Cloud Logging, Cloud Trace, Vector Search, BigQuery, GCS |
| `config/dpdp.openai.yaml` | OpenAI Responses API (`store=false`) | regex (+ either cloud) | local or KMS | OpenAI stored responses/files, Redis, SQL |
| `config/dpdp.anthropic.yaml` | Claude via Anthropic SDK: API direct, `AnthropicBedrock` or `AnthropicVertex` (`platform:`) | regex (+ either cloud) | local or KMS | Anthropic Files API uploads, SQL |
| `config/dpdp.local.yaml` | offline echo model | regex | local | SQLite, JSONL, log files |
| `config/dpdp.production.aws.yaml` / `.gcp.yaml` | production references with auth, verification, signing, sealed KEK, OTel | | | |

Mix and match freely, for example OpenAI models with AWS stores, or Claude on Bedrock with AgentCore Memory. Claude has no embeddings endpoint, so set `embedding_provider` (openai, bedrock or vertex) for vectors.

Install the extras you need:

```bash
pip install -e ".[openai]"      # OpenAI API
pip install -e ".[anthropic]"   # Claude API direct, or Claude on Bedrock / Vertex
pip install -e ".[aws]"         # Bedrock, AgentCore, CloudWatch, KMS, DynamoDB, S3
pip install -e ".[gcp]"         # Vertex AI, Cloud KMS, Firestore, Logging, BigQuery, DLP
pip install -e ".[otel,auth]"   # OpenTelemetry export, OIDC JWT verification
pip install -e ".[all]"         # everything, plus Redis, PostgreSQL and the API server
```

## Rights API and CLI

Requests are authenticated, verified, queued and then processed by workers:

```bash
dpdp-rights -c config/dpdp.local.yaml serve --port 8080     # API
dpdp-rights -c config/dpdp.local.yaml worker                # processes verified requests

# 1. a backend (role: service) submits a withdrawal; an OTP goes to the applicant's registered contact
curl -XPOST localhost:8080/v1/withdrawals -H "x-api-key: $KEY" -H 'Idempotency-Key: 7f3a' \
     -H 'content-type: application/json' -d '{"external_id":"app-1003","purpose_id":"marketing"}'
# 2. the applicant confirms with the code
curl -XPOST localhost:8080/v1/erasure-requests/<id>/verify -H "x-api-key: $KEY" \
     -H 'content-type: application/json' -d '{"code":"482913"}'
# 3. a DPO checks the signed certificate
curl localhost:8080/v1/erasure-requests/<id>/certificate/verify -H "authorization: Bearer $DPO_JWT"
```

A principal signed in through OIDC can submit for themselves (verified by their session), and a DPO
can attest identity verified out of band. CLI: `erase`, `lineage`, `certificate`, `verify-certificate`,
`worker`, `sla`, `check-config`, `hash-api-key`, `connectors`, `purge-escrows`.

## Production deployment

1. Start from `config/dpdp.production.aws.yaml` or `config/dpdp.production.gcp.yaml`
   (`environment: production` turns on guardrails that refuse unsafe settings).
2. Apply `deploy/terraform/aws` or `deploy/terraform/gcp`: vault keys and storage, a separate sealed KEK
   with a break-glass role, a certificate signing key, an immutable certificate bucket, IAM.
3. Run the API behind your gateway/WAF, and `dpdp-rights worker` as a service or scheduled job.
4. Run the OpenTelemetry collector from `deploy/otel/`, and alert on overdue requests.
5. `dpdp-rights -c <config> check-config` in CI; schedule `purge-escrows` daily.

Details: [docs/security.md](docs/security.md), [docs/observability.md](docs/observability.md).

## Repository layout

```
src/dpdp_rights/
  core/          models, context envelope (W3C baggage), config
  pii/           detectors (regex w/ Verhoeff Aadhaar, Comprehend, Guardrails, DLP) + tokenizer
  vault/         per-principal keys (local / AWS KMS / Cloud KMS) + storage (SQL / DynamoDB / Firestore)
  consent/       consent ledger (principal x element x purpose)
  lineage/       control-plane store + graph traversal
  providers/     OpenAI, Anthropic (direct/Bedrock/Vertex), Bedrock Converse, Vertex, echo
  connectors/    local, AWS, GCP, OpenAI platform, Anthropic platform
  erasure/       policy engine + orchestrator (+ certificates, escrow purge, resume)
  security/      auth, requester verification, signing + archive, break-glass, guardrails, tenancy
  jobs/          durable job queue
  observability/ OpenTelemetry spans, metrics, tokenising exporter
  integrations/  AgentCore Memory/Runtime helpers
  api/ cli.py    FastAPI rights API, CLI
config/          ready-to-edit configs per cloud / provider
deploy/terraform AWS + GCP infra: vault, keys, sealed KEK + break-glass, signing key, immutable bucket, IAM
deploy/otel      OpenTelemetry collector configs (AWS X-Ray/CloudWatch, GCP Cloud Trace)
docs/            architecture, lineage data model, DPDP mapping, connectors
examples/        insurance onboarding demo, AgentCore agent, OpenAI direct
```

## Docs

- [Architecture and diagrams](docs/architecture.md)
- [Lineage data model (ERD, SQL, recursive CTE)](docs/lineage-data-model.md)
- [DPDP mapping](docs/dpdp-mapping.md)
- [Connectors and writing your own](docs/connectors.md)
- [Security and production hardening](docs/security.md)
- [Observability (OpenTelemetry)](docs/observability.md)

## Roadmap

- Inactivity-based erasure with 48-hour notices (Rules r.8(1)-(2), Third Schedule platforms)
- Sealed-archive connector (S3 Object Lock / GCS Bucket Lock) for record-level statutory retention
- Consent Manager (Rule 4) webhook adapter
- Azure (Azure OpenAI, Monitor, AI Search, Key Vault) connectors
- LangSmith and Datadog LLM Observability connectors
- DPO console UI
- Independent security review
- Neptune / Spanner Graph lineage backends for very large graphs

## License

Apache-2.0
