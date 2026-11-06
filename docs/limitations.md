# Known limitations and production readiness

Last reviewed: 20 November 2026 (v0.2.x), after the Consent Manager, children, gateway, console, benchmark, scan
and backfill additions of 18-20 November. Read this before deploying.

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
| Supply chain: CodeQL, Dependabot, dependency audit gate over every production profile (blocks `main` and releases at an agreed severity, daily scheduled run, package-specific expiring exceptions), one SBOM per profile from the audited pins and checked against them, workflow actions pinned to commit SHAs, build provenance | Built |
| Signed consent history per principal (hash chain, signatures, fork-proof appends) | Built |
| Consent Manager events: HMAC or Ed25519 signature over timestamp and body, replay window, applied once | Built |
| Model gateway: the person bound to authentication (signed assertion, caller subject or LiteLLM key), mismatching claims refused; reveal limited to the bound person | Built |
| DPO console: static, strict CSP, no inline script, data only through the API's roles, credential kept for the tab only | Built |
| Requester identity verification | **Out of scope by design**: done upstream by the deployer; `verified_by` / `verification_ref` recorded |

### What else needs hardening?

| Gap | Severity | Notes |
|---|---|---|
| No independent security review or pen test | High | Commission one before production |
| Rule 8(3) retention only partly covered | High | Escrow keeps identifiers, not full records; log and traffic-data retention are deployer settings. See [Rule 8(3)](dpdp-mapping.md#rule-83-one-year-retention) |
| No schema migrations | High for upgrades | v0.2 added tables and columns; existing databases need Alembic or manual DDL. The 18-20 Nov features add new tables only (created at startup), no column changes |
| Gateway assertions are bearer tokens for their lifetime | Medium | No nonce or replay cache; keep `assertion_max_ttl_seconds` short and the secret in a secrets manager |
| Consent Manager HMAC secrets allow forged withdrawals if leaked | Medium | Prefer Ed25519; rotate with a coordinated overlap |
| Network controls not provided | Medium | Gateway, WAF, TLS, rate limiting, private networking are the deployer's job |
| PII detection is probabilistic | Medium | Regex covers Indian identifiers and cue-based names; names and addresses without cues need Presidio, IndicNER, a cloud detector or the opt-in LLM detector. Measure coverage on your own data; see [pii-detection.md](pii-detection.md) |
| Discovery by content scan is expensive at scale | Medium | SQL `LIKE`, Logs Insights and trace queries; register artifacts through the SDK wherever possible. Access requests now run the same discovery (`rights.access_search`); turning it off limits reports to "configured coverage" |
| The vault's own backups and point-in-time recovery keep wrapped keys for their window | Medium | A restored vault backup brings back erased people's wrapped keys, and the KEK can still unwrap them, so erasure is final only when the window passes. Set `vault_pitr_days` (AWS), keep restore rights with the break-glass role, state the window in the published erasure period ([security](security.md#encryption-and-key-management)). Backups of other stores hold only tokens and are unreadable at once |

### Features added 18-20 November: security assumptions, limits, upgrade risks

| Feature | Security assumptions | Operational limits | Upgrade risk |
|---|---|---|---|
| **Model gateway** ([gateway.md](gateway.md)) | In enforce mode the person comes only from `principal_binding`: a signed assertion the app's backend mints after authenticating its user (default), the caller's own OIDC subject, or a LiteLLM key's admin-set metadata. Headers, metadata and `user` are claims that must match. The assertion secret is shared with the app's backend: keep it in a secrets manager and rotate it like an API key. An assertion is a bearer credential for its lifetime (at most `assertion_max_ttl_seconds`, default 900); there is no one-time nonce, so keep lifetimes short. Observe mode trusts claims, because it creates nothing and reveals nothing. `principal_binding: header` lets any service credential act for anyone, and is refused in production together with reveal. | Model traffic only; no reveal while streaming; no rate limiting of its own; OpenAI wire formats only | **The default binding changed to `signed` on 20 Nov.** Enforce-mode deployments must set `DPDP_GATEWAY_ASSERTION_SECRET` and send assertions, or opt into `header` knowingly |
| **Consent Managers** ([consent-managers.md](consent-managers.md)) | The webhook is authenticated only by the Consent Manager's signature; a leaked HMAC secret lets anyone forge withdrawals (and erasures). Prefer Ed25519, where only the public key is held. Single secret per Consent Manager: rotation means a short overlap with both sides updated together | Provisional schema; no pull reconciliation; withdrawal per artefact; notice text not stored | New tables only; rule set now `2025.11-3` (existing cases keep the version they were judged under) |
| **Children and wards** ([children.md](children.md)) | Age and guardian verification are upstream; the framework trusts the recorded method, verifier and reference. Anyone with role `service` or `dpo` can set a status or record a guardian, so restrict those credentials | Turning it on with `unknown_status: deny` stops consent-based processing for everyone without a status: backfill statuses first. No automatic change at 18 | Off by default; new tables only |
| **DPO console** ([console.md](console.md)) | Security rests on the API's roles; the console adds no access. A pasted credential lives in the tab's session storage, so an XSS would expose it: the CSP and text-only rendering (tested) are the defence | No single sign-on; some tasks still API or CLI only | Served by default at `/console`; `api.console: false` turns it off |
| **Discovery scan** ([scan.md](scan.md)) | Run with a separate read-only role; reads raw content into memory, never stores values. Refuses the LLM detector | A sample, not a census; sources it isn't pointed at are not looked at; draft inventories always say `holds_personal_data: true` | None (new command) |
| **Backfill** ([backfill.md](backfill.md)) | Rewrites stores in place: take a backup first; needs `--confirm <store>`. Tokenises without a consent check (it lowers risk) and reports owners without consent | sql_table and jsonl_dataset only; rows written during a run after the cursor are caught, before it are not; backups from before keep raw values | New table only |
| **NER sidecar** ([pii-benchmark.md](pii-benchmark.md#the-ner-sidecar)) | No authentication: localhost only, inside the caller's task or pod. Gated model: the image is a licensed artefact | CPU; fails closed by default (callers stop when it is down) | None unless enabled |
| **Regex change** (20 Nov) | — | — | A 12-digit number named by "account" that passed the Aadhaar checksum is now `BANK_ACCOUNT`. Values tokenised before keep their old `AADHAAR` token; new writes get a `BANK_ACCOUNT` token. Both belong to the same person, so erasure covers both |

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
- **Rights workflow** ([rights.md](rights.md)): access reports cover data the framework has seen (through
  `protect()` and lineage) plus what a search run for the request finds. Each report says so to the person:
  "complete" needs a successful search of every in-scope system for that request and end-to-end tests within
  180 days; otherwise it is partial, configured coverage or coverage unknown, and needs a reviewer's note.
  `tested_on` is recorded by the partner, not measured by the framework, and an inventory that omits a
  system still produces a "complete" report, so keep it current. Corrections change the
  value behind a token: surrogates keep the old value's shape, and text an LLM wrote about a value is not
  changed. Grievances are cases with deadlines and responses, not a CRM. Breach support is an impact assessment and drafts from lineage records
  ([breach](breach.md)): it does not detect, investigate or send, and cannot list people in systems with no
  lineage records (it says so rather than counting zero).
- **Correction guard**: tokenising a value now reads the vault first, so a corrected value is never overwritten
  by the old one seen again; this adds one vault read per detected entity.
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
- **Case-log text checks** use the configured PII detectors, so a regex-only setup will not catch names in
  reviewer notes. Reviewers should write references, not descriptions of the person.
- **Evidence bundles** carry the signer's public key; they prove integrity only when auditors pin the key by
  its published fingerprint.
- **Consent Managers** ([consent-managers.md](consent-managers.md)) use a provisional schema, because the Board
  has not published an interoperability standard; a registered Consent Manager's API needs a plug-in. No pull
  reconciliation: artefact status comes from events and `expire-due`. Withdrawal is per artefact. Notice text is
  not stored, only its version. Reports of direct withdrawals to the Consent Manager are best effort (failures
  are recorded).
- **Children and wards** ([children.md](children.md)) are off by default. Age and guardian verification happen
  upstream; the framework records method, verifier and reference. Status does not change automatically at 18;
  parental consents stay valid once the status is `adult` (a counsel question). Fourth Schedule conditions are
  recorded, not enforced; s.9(2) (detrimental effect) is not modelled; the rights desk has no guardian role yet.
- **Brownfield backfill** ([backfill.md](backfill.md)) rewrites sql_table and jsonl_dataset stores only; managed
  vector services are re-ingested from a backfilled source. Items with personal data but no owner are left raw
  (listed) or masked. Only what the detectors find is tokenised. Backups and replicas from before the run keep
  raw values until they age out.
- **Discovery scan** ([scan.md](scan.md)) samples; it is not a census. Finds depend on the detectors (regex alone
  misses most uncued names). Connectors without a content reader (AgentCore, X-Ray, Cloud Trace, vector search
  services, model providers) are listed as not sampled. It finds only the stores it is pointed at.
- **DPO console** ([console.md](console.md)): sign-in takes a pasted API key or OIDC token (no single sign-on
  flow yet); request intake, breach assessment, break-glass and Consent Manager or children's records are still
  API and CLI only.
- **Model gateway** ([gateway.md](gateway.md)) sees model traffic only: memory, vector stores, CRMs and app logs
  need instrumentation. It needs the person and purpose per call (headers, metadata, a key's metadata or `user`).
  No reveal while streaming. OpenAI-style wire formats only (chat, Responses, embeddings); other providers go
  through LiteLLM. Observe mode protects nothing.
- **Agent-framework integrations** ([agent-frameworks.md](agent-frameworks.md)) cover LangChain / LangGraph
  and the OpenAI Agents SDK, tested with fake models. Framework tracing (LangSmith, the Agents SDK trace
  processor) records inputs before the hooks run; Agents SDK sessions cannot be listed, so sessions written
  without `ProtectedSession` are not found; streaming and LangGraph Platform's hosted store are not covered.
- **Idempotency** ([rights.md](rights.md#idempotency)): a retry must resend the identical request; any changed
  field returns 409. Keys stored before 18 November 2026 were not scoped to the caller, so after an upgrade a
  retry with an old key opens a new case instead of matching. The keyed request digest stays on a rights case
  after the person is erased; it cannot be reversed, only used to confirm a guessed request by someone who can
  also call the vault.
- **Dependency audit** ([security.md](security.md#dependency-audit-gate)) covers the named production profiles
  (aws, gcp, direct-api, full) as resolved for Linux x86-64 and Python 3.12. Other platforms, your own container's system packages and model
  files (spaCy, IndicNER weights) are outside it; scan your image as well.

### Legal
- The DPDP mapping, legal-hold examples, k-anonymity threshold and retention handling are engineering
  interpretations, not legal advice. Validate them with counsel for each deployment.
