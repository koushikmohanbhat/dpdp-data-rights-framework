# Discovery questionnaire

For the discovery workshop (phase 2). Plan for two sessions of about 90 minutes: one with product and
the DPO, one with engineering and security. Send it a week ahead so people can bring answers.

Every answer feeds a concrete output: the framework config, the [inventory](inventory.template.yaml), or
the implementation plan. The **Feeds** column says which.

## 1. The agent and its users

| # | Question | Who answers | Feeds |
|---|---|---|---|
| 1.1 | What does the agent do, for whom, and through which channels (web chat, app, WhatsApp, voice, contact centre)? | Product | Scope; inventory |
| 1.2 | How are users identified? Customer ID, mobile number, email, application number? Is there an anonymous phase before login? | Engineering | `principal()` mapping; `register_identifier` |
| 1.3 | Do users mention other people (nominees, family, dependants, employees)? | Product | Third-party mentions; identifiers to register |
| 1.4 | Which languages and scripts do users write in? English, Hinglish, Hindi, regional languages? Voice transcripts? | Product | PII detectors ([pii-detection.md](../docs/pii-detection.md)) |
| 1.5 | Do users upload documents (KYC, medical, income proof)? In which formats? | Product | `protect_document`, OCR choice |
| 1.6 | Are any users under 18? | Product, DPO | Out of scope for the framework today; flag for the DPO |

## 2. Purposes and legal basis

| # | Question | Who answers | Feeds |
|---|---|---|---|
| 2.1 | List each purpose for which personal data is processed (e.g. policy issuance, analytics, marketing, model improvement). | Product, DPO | `purposes` in the config |
| 2.2 | Which purposes rely on consent, and which on a legitimate use (Act s.7)? | DPO, counsel | `legal_basis` |
| 2.3 | Which data must be kept by law, under which provision, and for how long (KYC, tax, insurance records)? | DPO, counsel | Legal holds: `legal_hold_basis`, `retention_days` |
| 2.4 | Can a user refuse or withdraw one purpose (e.g. marketing) while keeping the service? | Product | Separate purposes |
| 2.5 | Where is consent captured today? Notice versions? A registered Consent Manager? | Product, Engineering | `grant_consent` integration |
| 2.6 | What is your published response period for rights requests and grievances? | DPO | `policy.sla_days` (≤ 90) |
| 2.7 | How has counsel interpreted Rule 8(3) (one-year retention) for this processing? | DPO, counsel | `policy.statutory_retention`, log retention |

## 3. Systems and data flows

Walk through one conversation end to end and list every place its content lands. Fill one inventory entry
per system.

| # | Question | Who answers | Feeds |
|---|---|---|---|
| 3.1 | Which model provider(s) and models? Through which API (Bedrock, Vertex, OpenAI, Anthropic)? Is any provider-side state kept (stored responses, files, threads)? | Engineering | `provider`; provider connectors |
| 3.2 | Agent platform and memory: AgentCore, Vertex Agent Engine, LangGraph, custom? Short- and long-term memory stores? | Engineering | Memory connectors |
| 3.3 | Retrieval: vector stores and knowledge bases; is user content ever indexed? | Engineering | Vector connectors, `embedding_column` |
| 3.4 | Caches: response, semantic, session caches? | Engineering | Cache connectors |
| 3.5 | Logs and traces: application logs, model invocation logs, traces, LLM observability (Langfuse, LangSmith, Datadog)? Retention of each? | Engineering, Platform | Log and trace connectors; retention ≥ 1 year |
| 3.6 | Derived data: summaries, notes, reports, CRM updates, analytics tables, marketing audiences? | Product, Data | Lineage edges; connectors |
| 3.7 | Evaluation and training: are real conversations copied into eval sets or fine-tuning data? Fine-tuned models in use? | AI team | Dataset connectors; retrain policy |
| 3.8 | SaaS tools and processors receiving the data (contact centre, ticketing, email, analytics)? | Product, Procurement | Inventory `processor`, `processor_contract` |
| 3.9 | Backups and replicas of each store, and their retention? | Platform | Inventory `backup` entries; restore procedure |
| 3.10 | Regions where each system stores data. Any outside India? | Platform, DPO | Inventory `region`; s.16 review |

## 4. Rights requests today

| # | Question | Who answers | Feeds |
|---|---|---|---|
| 4.1 | How do users raise withdrawal or erasure requests today? Who handles them? | Operations, DPO | Request intake integration |
| 4.2 | How is the requester's identity verified? What reference is recorded? | Operations | `verified_by`, `verification_ref` |
| 4.3 | How many requests per month, and what is the backlog? | Operations | Sizing; SLA |
| 4.4 | What evidence does the DPO need for each completed request? | DPO | Certificate review; audit pack |

## 5. Platform, security and operations

| # | Question | Who answers | Feeds |
|---|---|---|---|
| 5.1 | Target cloud account or project, region, VPC and subnets? Network egress (NAT, endpoints, proxy)? | Platform | Terraform variables |
| 5.2 | Key management: may we create KMS keys? Who may hold the break-glass role (two different people)? | Security | `break_glass_principals` |
| 5.3 | Identity provider for DPO and approver sign-in: Cognito, Entra ID, Okta, Google? | Security | `api.auth.oidc` |
| 5.4 | CI/CD: where will the image be built? Terraform state backend? Change approvals? | Platform | Deployment plan |
| 5.5 | Observability stack and on-call: where do alerts go? | Platform | Alarms ([operations.md](../docs/operations.md)) |
| 5.6 | A non-production account for live tests and a staging environment with realistic (synthetic) data? | Platform | Validation phase |

## 6. Success and constraints

| # | Question | Who answers | Feeds |
|---|---|---|---|
| 6.1 | What does "done" look like for you? Which systems must be covered at go-live? | Sponsor, DPO | Acceptance criteria |
| 6.2 | Deadlines (e.g. 13 May 2027 commencement), freezes, audits? | Sponsor | Plan |
| 6.3 | Who signs off each phase? | Sponsor | RACI |
