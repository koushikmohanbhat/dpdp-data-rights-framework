# Known limitations and production readiness

Last reviewed: 6 November 2026 (v0.2.x). Read this before deploying.

## Production readiness assessment

The questions a team should ask before running this in production, and where v0.2 stands.

### Is security built in?

Yes, for the controls the framework owns:

| Control | Status |
|---|---|
| Per-person encryption keys wrapped by AWS KMS / Cloud KMS; crypto-shredding | Built |
| Separate sealed KEK for legal-hold and escrow data, decryptable only by a break-glass role | Built (Terraform included) |
| Authenticated, role-based Rights API (hashed API keys, OIDC JWT) | Built |
| Principals limited to their own data | Built |
| Durable job queue with leases, retries, idempotency, resume after crash | Built |
| Certificates hash-chained, KMS-signed, archived to S3 Object Lock / GCS locked bucket | Built |
| Two-person, time-boxed, audited break-glass access | Built |
| Tenant isolation (separate database, vault and keys per tenant) | Built |
| DEK cache TTL; sealed keys never cached | Built |
| Production guardrails (`environment: production`, `check-config`) | Built |
| Supply chain: CodeQL, Dependabot, pip-audit, SBOM, build provenance | Built |
| Requester identity verification | **Out of scope by design**: done upstream by the deployer; `verified_by` / `verification_ref` recorded |

### What else needs hardening?

| Gap | Severity | Notes |
|---|---|---|
| No independent security review or pen test | High | Commission one before production |
| Rule 8(3) retention only partly covered | High | Escrow keeps identifiers, not full records; log and traffic-data retention are deployer settings. See [Rule 8(3)](dpdp-mapping.md#rule-83-one-year-retention) |
| No schema migrations | High for upgrades | v0.2 added tables and columns; existing databases need Alembic or manual DDL |
| Network controls not provided | Medium | Gateway, WAF, TLS, rate limiting, private networking are the deployer's job |
| PII detection is probabilistic | Medium | Regex covers Indian identifiers and cue-based names; names and addresses without cues need Presidio, IndicNER, a cloud detector or the opt-in LLM detector. Measure coverage on your own data; see [pii-detection.md](pii-detection.md) |
| Discovery by content scan is expensive at scale | Medium | SQL `LIKE`, Logs Insights and trace queries; register artifacts through the SDK wherever possible |
| Backups and point-in-time recovery keep wrapped keys for their window | Low | Data stays unreadable once the live key is gone; document the window |

### Does it connect to OpenTelemetry?

Yes. Spans created inside a DPDP context (including spans from LLM SDK auto-instrumentation) are tagged
with the pseudonymous principal and tokenised, or masked if no principal is known, before export. The
framework emits its own spans and metrics, including an overdue-request gauge. Collector configs for AWS
(ADOT → X-Ray, CloudWatch) and GCP (Cloud Trace, Managed Prometheus) add a redaction processor.
See [observability.md](observability.md).

### Are there observability and monitoring connectors for AWS and GCP?

| Store | AWS | GCP |
|---|---|---|
| Logs | `aws_cloudwatch_logs` (incl. AgentCore `aws/spans`, runtime logs, Bedrock invocation logs) | `gcp_cloud_logging` |
| Traces | `aws_xray` | `gcp_cloud_trace` |
| Metrics | framework metrics via ADOT → CloudWatch (EMF) | framework metrics → Managed Prometheus / Cloud Monitoring |
| Cloud-neutral LLM tracing | `langfuse` | `langfuse` |

Metrics never contain personal data, so they need no erasure connector. LangSmith, Datadog and Arize are on the roadmap.

### What about AgentCore and its GCP equivalent?

| Capability | Amazon Bedrock AgentCore | Vertex AI Agent Engine |
|---|---|---|
| Short-term memory / sessions | `aws_agentcore_memory` (events) | `gcp_agent_engine_sessions` |
| Long-term memory | `aws_agentcore_memory` (records) | `gcp_vertex_memory_bank` |
| Observability | `aws_cloudwatch_logs`, `aws_xray` | `gcp_cloud_logging`, `gcp_cloud_trace` |
| Per-user credentials | `aws_agentcore_identity` (revocation at the IdP) | handled by your IdP |
| Runtime integration | `integrations.agentcore` (memory writer, context from payload/headers) | context via headers / payload |
| Not yet covered | Gateway tool-call logs, Browser and Code Interpreter artifacts | code-execution artifacts |

## Known limitations

### Platform behaviour the framework cannot change
- **X-Ray and Cloud Trace** have no API to delete individual traces. The framework prevents personal
  data reaching them (tokenisation) and verifies none did; traces expire under the services' retention.
- **CloudWatch Logs and Cloud Logging** entries are immutable. Same approach: tokenise, crypto-shred,
  verify, and rely on retention policies.
- **AgentCore Identity** has no API to delete one user's stored OAuth tokens. The connector revokes the
  user's sessions at the identity provider (Cognito global sign-out or a webhook), which makes the
  stored refresh tokens unusable. Without a configured IdP target, the certificate records a manual action.
- **Model provider retention** (OpenAI abuse-monitoring retention, Anthropic 30-day backend retention)
  is governed by those providers' terms, not by API calls. It is recorded in certificates; use
  zero-data-retention agreements where available.
- **Vertex AI Agent Engine Sessions and Memory Bank** connectors use v1beta1 REST APIs that may change.

### Scope and design choices
- **Requester identity verification is not done by the framework.** Requests must arrive already
  verified; the framework records who verified and the reference.
- **Fine-tuned models** are only flagged for retraining; the framework does not retrain or unlearn.
- **LLM regeneration of summaries** can paraphrase. The hard redaction pass only removes the erased
  principal's tokens, so content that was paraphrased without tokens depends on lineage-driven
  regeneration from the remaining sources.
- **Embeddings of records that only mention the person**: `sql_table` / pgvector re-embeds the redacted text
  when `embedding_column` is set, and otherwise deletes the row. Managed vector stores (Bedrock Knowledge
  Bases, Vertex Vector Search, OpenAI vector stores) cannot be edited in place, so the document is deleted
  and must be re-ingested from its source. Verification checks the text, not the vector itself.
- **Third-party mentions** are attributed to the right person only for identifiers registered with
  `register_identifier` (email, phone, PAN...). Unregistered names mentioned by someone else stay
  under the speaker's key.
- **Verification windows**: log and trace verification looks back `lookback_days` / `lookback_hours`;
  data outside the window is not scanned.
- **Statutory retention escrow** keeps vault values (identifiers). Free-text records deleted from
  operational stores are not archived, and traffic data is not managed, so escrow alone does not meet
  Rule 8(3). A sealed record archive is on the roadmap. Keep log retention at one year or more (the AWS
  Terraform defaults to 400 days).
- **Rights other than withdrawal and erasure** (access, correction, nomination, children's data) and breach
  response are not implemented; grievance handling is a due date and audit trail, not a workflow.
- **PII detection coverage** decides what is tokenised. Regex catches Indian identifiers and names after
  cue words (English, Hinglish, nine Indian languages); names and addresses without cues need an NER,
  cloud or LLM detector. The LLM detector sends raw text to its model. Data the detectors miss is stored
  as written, and is only found by connector discovery and verification. See [pii-detection.md](pii-detection.md).
- **Format-preserving surrogates** look like real identifiers in logs; a real value equal to an existing
  surrogate (very unlikely) is not tokenised.
- **Documents**: text is extracted and tokenised; the original file is not redacted and must be stored where
  a connector can delete it.
- **Re-sealing** into an existing hold key needs Decrypt on the sealed KEK (rare: only when the same
  principal gets a second legal hold).
- **Dry runs** through the API run synchronously.

### Legal
- The DPDP mapping, legal-hold examples, k-anonymity threshold and retention handling are engineering
  interpretations, not legal advice. Validate them with counsel for each deployment.
