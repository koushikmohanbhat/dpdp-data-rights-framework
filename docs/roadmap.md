# Roadmap

Candidate items, grouped by theme. Nothing here is committed; open an issue to discuss priority.

## Partner delivery kit

Built: connector capability declarations and [matrix](capabilities.md), deployment inventory and `coverage`
report, the [partner delivery pack](../partner-pack/README.md), the [plug-in contract](plugins.md)
(entry points for connectors, detectors, key wrappers, vault storage, providers, queues and notifiers),
notifications, the connector conformance kit with synthetic Indian test data, and the
[evidence and audit pack](evidence.md) (case records with reviewer sign-off, signed evidence bundles, period
audit packs; control-mapping, processor-responsibility and audit-evidence templates), and the
[rights workflow](rights.md) (one intake for access, correction, erasure, withdrawal, nomination and grievance
cases; versioned legal rule sets; access reports; corrections through the vault; the Rule 14(1) notice), and
[domain packs](domain-packs.md) for insurance, lending and healthcare. Next:

1. **More domain packs**: telecom, e-commerce (Third Schedule platforms), HR and education, each with cited
   holds, an inventory and scenarios.
2. **Plug-in packages**: move the AWS and GCP connectors into separately versioned packages once there is a
   second maintainer; add Azure, SQS and Pub/Sub queue, Azure Key Vault and HashiCorp Vault plug-ins.

Rights follow-ups: ticketing integration for grievances (ServiceNow, Zendesk, Freshdesk) as notifier plug-ins;
a multilingual access report and notice (Eighth Schedule languages); a principal-facing portal page; rule sets
for other regimes (see below).

Evidence follow-ups: a sign-off queue in the DPO console; exporters for GRC tools (ServiceNow GRC, Archer)
as notifier plug-ins; a sealed record archive referenced from case records (see below).

## DPDP rights and obligations

| Item | DPDP reference | What it would do |
|---|---|---|
| **Sealed record archive (priority)** | Rules r.8(3) | Before deleting full records, summaries and memory from operational stores, write a copy to a sealed archive (S3 Object Lock / locked GCS, encrypted under the sealed key), readable only through break-glass, purged with the escrow. Closes the "personal data" gap in Rule 8(3) |
| Rule 8(3) retention checks | Rules r.8(3) | `check-config` and a report that flag log groups, trace stores and traffic-data sources kept for less than a year |
| Children's data | Act s.9 | Verifiable parental consent flag; block purposes involving tracking, behavioural monitoring or targeted ads for minors |
| Inactivity-based erasure with 48-hour notice | Rules r.8(1)-(2), Third Schedule | Find inactive principals from lineage, send notice, erase after the window |
| Consent Manager integration | Act s.6(7)-(9), Rule 4 | Consume consent artifacts and withdrawals from registered Consent Managers |
| Purpose-end erasure | Act s.8(7) | Use `retention_days` per purpose to erase automatically when the purpose is served |
| Breach impact analysis | Act s.8(6), Rule 7 | Given a breached store, list affected principals and draft Board / principal notifications |
| Significant Data Fiduciary pack | Act s.10, Rule 13 | DPIA templates, periodic audit evidence export, algorithmic-risk notes for AI systems |
| Cross-border transfer controls | Act s.16 | Tag artifacts with region; block processing or provider calls to restricted jurisdictions |
| Multilingual consent notices | Rule 3 | Notice builder in English and Eighth Schedule languages, versioned and linked to consent records |
| Other regimes | GDPR, CCPA/CPRA, Singapore PDPA, UAE PDPL | Rule sets in the same format as `dpdp-in`: request types, deadlines, legal bases, retention rules |

## PII detection

Built in v0.2 (see [pii-detection.md](pii-detection.md)): Indian-script digits and name cues, more Indian
identifiers, Presidio, Hugging Face NER (IndicNER), an opt-in LLM detector, masked display and storage
surrogates, and document text extraction (local PDF, Textract, Document AI). Next:

- Visual redaction of document images and PDFs (black boxes over detected identifiers, using OCR geometry)
- A labelled evaluation set of Indian conversations (English, Hinglish, Hindi, regional) and a detection
  benchmark command, so partners can compare detector combinations on their own data
- Address detection without cue words (Indian address NER)
- Transliteration-aware matching, so "Priya" and "प्रिया" resolve to the same registered person

## Connectors

- **Azure:** Azure OpenAI, Azure AI Search, Azure Monitor / Application Insights, Cosmos DB, Key Vault (key wrapper)
- **Vector stores:** OpenSearch / Elasticsearch, Pinecone, Weaviate, Qdrant, MongoDB Atlas Vector Search, Milvus
- **Data platforms:** Snowflake, Databricks (Delta deletes + vacuum), BigQuery ML, Redshift, Kafka (tombstones)
- **Business apps:** Salesforce, ServiceNow, Zendesk, Freshdesk, HubSpot, core insurance / banking systems via webhooks
- **LLM observability:** LangSmith, Datadog LLM Observability, Arize Phoenix, Helicone, Braintrust
- **Model training:** Bedrock and Vertex fine-tuning datasets and jobs, OpenAI fine-tuning files
- **Agent platforms:** AgentCore Gateway tool-call logs, AgentCore Browser and Code Interpreter artifacts, Vertex Agent Engine code-execution artifacts

## Agent framework integrations

- Callbacks / middleware for LangChain and LangGraph, LlamaIndex, OpenAI Agents SDK, Strands Agents, Google ADK, CrewAI that call `protect` and `track_artifact` automatically
- MCP server exposing rights operations (status, lineage, withdrawal) to agents and assistants
- Automatic lineage capture from OpenTelemetry spans (derive artifacts and edges from GenAI spans)

## Security and operations

- Alembic schema migrations
- Packaged live test suite for Google Cloud (the AWS suite is in `tests/integration`), and a scheduled nightly run
- Independent security review and penetration test
- Queue backends: Amazon SQS, Google Pub/Sub
- Lineage backends for very large graphs: Amazon Neptune, Spanner Graph
- Key wrappers: Azure Key Vault, HashiCorp Vault, AWS CloudHSM
- Deployment: Helm chart, AWS CDK constructs, Cloud Run / ECS reference stacks, high-availability workers
- DPO console UI (requests, SLA, lineage explorer, certificates, break-glass approvals)
- Certificates as W3C Verifiable Credentials
- Publish to PyPI
