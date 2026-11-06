# Roadmap

Candidate items, grouped by theme. Nothing here is committed; open an issue to discuss priority.

## Partner delivery kit

Built: connector capability declarations and [matrix](capabilities.md), deployment inventory and `coverage`
report, and the [partner delivery pack](../partner-pack/README.md). Next, in order:

1. **Plug-in contract**: entry points so connectors, detectors, key wrappers, vault storage, queues and
   notifiers can ship as separate packages (AWS, GCP, Azure, client systems) without forking; capability
   declarations required for every plug-in.
2. **Connector conformance kit**: a reusable pytest suite every connector must pass against a sandbox
   (discover a synthetic record, act, verify, retry, report unsupported cases), with synthetic Indian test
   data.
3. **Evidence and audit pack**: a case record per request (received, verification, systems searched,
   actions, retained and why, not completed, reviewer sign-off) and exportable templates (control mapping,
   processor responsibilities, audit evidence).
4. **Rights workflow toolkit**: request intake, access, correction, nomination and grievance cases, with
   versioned, configurable legal rules (deadlines, commencement dates).
5. **Domain packs** (insurance, lending, healthcare) with sample policies, data flows and test cases, once
   the above is stable.

## DPDP rights and obligations

| Item | DPDP reference | What it would do |
|---|---|---|
| **Sealed record archive (priority)** | Rules r.8(3) | Before deleting full records, summaries and memory from operational stores, write a copy to a sealed archive (S3 Object Lock / locked GCS, encrypted under the sealed key), readable only through break-glass, purged with the escrow. Closes the "personal data" gap in Rule 8(3) |
| Rule 8(3) retention checks | Rules r.8(3) | `check-config` and a report that flag log groups, trace stores and traffic-data sources kept for less than a year |
| Right to access a summary | Act s.11 | Generate "what data you hold about me, where it went, who it was shared with" from the lineage graph |
| Right to correction and updating | Act s.12(1)-(2) | Propagate a corrected value (new address, name) through lineage: re-tokenise, update or regenerate derived artifacts |
| Right to nominate | Act s.14 | Let a principal nominate someone to exercise rights on death or incapacity; route requests from the nominee |
| Children's data | Act s.9 | Verifiable parental consent flag; block purposes involving tracking, behavioural monitoring or targeted ads for minors |
| Inactivity-based erasure with 48-hour notice | Rules r.8(1)-(2), Third Schedule | Find inactive principals from lineage, send notice, erase after the window |
| Consent Manager integration | Act s.6(7)-(9), Rule 4 | Consume consent artifacts and withdrawals from registered Consent Managers |
| Purpose-end erasure | Act s.8(7) | Use `retention_days` per purpose to erase automatically when the purpose is served |
| Breach impact analysis | Act s.8(6), Rule 7 | Given a breached store, list affected principals and draft Board / principal notifications |
| Significant Data Fiduciary pack | Act s.10, Rule 13 | DPIA templates, periodic audit evidence export, algorithmic-risk notes for AI systems |
| Cross-border transfer controls | Act s.16 | Tag artifacts with region; block processing or provider calls to restricted jurisdictions |
| Multilingual consent notices | Rule 3 | Notice builder in English and Eighth Schedule languages, versioned and linked to consent records |
| Grievance workflow | Act s.13, Rule 14(3) | Grievance cases separate from rights requests, with their own published response period (at most 90 days), ticketing integration and escalation |
| Other regimes | GDPR, CCPA/CPRA, Singapore PDPA, UAE PDPL | Regulation profiles: deadlines, legal bases, retention rules |

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
