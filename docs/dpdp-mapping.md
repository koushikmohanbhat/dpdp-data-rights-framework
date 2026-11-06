# DPDP Act 2023 / DPDP Rules 2025: how the framework maps

> **Not legal advice.** This is an engineering mapping that partners should validate with privacy
> counsel for each deployment. Check section and rule references against the official gazette text
> (DPDP Rules 2025, G.S.R. 846(E), 13 November 2025).

## Scope

The framework covers **consent withdrawal and erasure** for data that AI agents process: purpose-specific
consent, stopping processing on withdrawal, erasure across every store and derived artifact, verification,
and evidence. It does **not** implement the other Data Principal rights or breach response:

| Not covered | Where it comes from | Status |
|---|---|---|
| Access to a summary of personal data and processing | Act s.11 | Roadmap. The lineage graph holds most of what an access summary needs |
| Correction, completion and updating | Act s.12(1)-(2) | Roadmap |
| Nomination | Act s.14; Rules r.14 | Roadmap |
| Children's data and verifiable parental consent | Act s.9; Rules r.10-12 | Roadmap |
| Breach intimation | Act s.8(6); Rules r.7 | Out of scope. The lineage graph shows which principals a breached store affects |
| Grievance redressal workflow | Act s.13; Rules r.14(3) | Partial: due dates, SLA metrics and an audit trail, not a case-management workflow |

## What the framework implements

| Obligation | Where it comes from | What the framework does | Status |
|---|---|---|---|
| Erase on request, unless retention is needed for the purpose or required by law | Act s.12(3) | `POST /v1/erasure-requests` (requester verified upstream) → queue → discover, plan, execute, verify, certify | Built |
| Erase when consent is withdrawn or the purpose is no longer served; make processors erase too | Act s.6(6), s.8(7) | `withdraw_consent(..., erase=True)` runs a purpose-scoped erasure; connectors reach processor-held state (OpenAI, Anthropic, Bedrock, Vertex, SaaS stores) | Built, for stores with a connector |
| Consent specific to a purpose; withdrawal as easy as giving it | Act s.6 | Consent ledger per principal × element type × purpose; `protect()` blocks processing without consent | Built |
| Legitimate uses without consent | Act s.7 | `legal_basis: legitimate_use` purposes skip the consent check | Built |
| Reasonable security safeguards (encryption, masking, tokenisation, access control, logs) | Act s.8(5); Rules r.6 | Per-principal keys wrapped by AWS KMS or Cloud KMS; tokenised prompts, logs, spans and vectors **for data that passes through `protect()` and is found by the configured detectors**; break-glass-only reads of sealed data | Built; coverage depends on instrumentation and detectors (see [limitations](limitations.md)) |
| Minimum one-year retention of personal data, traffic data and processing logs | Rules r.8(3), Seventh Schedule | Partial; see [below](#rule-83-one-year-retention) | **Partial** |
| Time-bound erasure for specified large platforms, with 48-hour notice | Rules r.8(1)-(2), Third Schedule | Not automated. Use lineage to find inactive principals, send notice, then call `erase()` | Roadmap |
| Time limits for rights requests and grievances | Rules r.14(3) | Separate clocks; see [below](#rule-143-response-times) | Partial |
| Demonstrable compliance, audits | Act s.10 (SDF), Board inquiries | Hash-chained, KMS-signed erasure certificates; per-action records; verification results | Built |

## Rule 8(3): one-year retention

**What the rule asks.** A Data Fiduciary must retain personal data, associated traffic data and other
processing logs, for processing done by it or by its Data Processors, for at least one year from the date of
processing, for the purposes in the Seventh Schedule, and then erase them unless another law requires
longer retention.

**Interpretations differ.** Some commentators read the rule as applying to all processing; others read it as
applying only where the processing relates to Seventh Schedule purposes. The framework does not decide
this. Counsel should, per deployment, and configure `policy.statutory_retention` accordingly.

**What the framework retains today when a person is erased:**

| Rule 8(3) category | What is kept | Gap |
|---|---|---|
| Personal data | The person's **identifiers** from the vault (email, phone, PAN, Aadhaar…), sealed under a separate key that applications cannot use, readable only through two-person break-glass, destroyed by `purge-escrows` after `policy.statutory_retention.days` | **Full records are not archived.** Free-text records, summaries and memory are deleted from operational stores at once. A sealed record archive is on the roadmap |
| Processing logs | Logs and traces hold tokens, not values. They stay in place until their retention expires; with the escrowed key they can be read through break-glass | Only as long as **your** log and trace retention is at least one year. The AWS Terraform defaults to 400 days for log groups; X-Ray keeps traces for 30 days and cannot be extended, so export traces if they count as processing logs for you |
| Traffic data | Not managed by the framework | Network and access logs (load balancer, VPC flow logs, CloudTrail, Cloud Audit Logs) are the deployer's; set their retention to at least one year |

**Do not treat escrow alone as meeting Rule 8(3).** It meets the identifier part. Logs depend on your
retention settings. Traffic data and full records need deployer controls until the sealed archive ships.

Note the tension: Rule 8(3) requires keeping data for a year, while s.12(3) and s.8(7) require erasure.
The framework resolves it by removing data from every place it can be **used** (applications, models,
search, analytics) at once, and keeping only sealed material that ordinary processing cannot read.

## Rule 14(3): response times

Two clocks, which the docs and configuration keep separate:

| Clock | What the rule says | What the framework does |
|---|---|---|
| **Grievances** (s.13) | Rule 14(3): publish, and meet, a response period for grievances of no more than 90 days | Not a workflow. Record grievances in your own case system; the framework's certificates and audit trail are the evidence you attach |
| **Rights requests** (erasure, withdrawal) | The Rules do not set a separate deadline in the text; government guidance describes 90 days for access, correction, updating and erasure requests, and commentators note the drafting is unclear | Every request gets `due_by` = received + `policy.sla_days` (default **30 days**, deliberately well inside 90); `/v1/sla` and the `dpdp.erasure.open` metric show requests that are due soon or overdue |

Set `sla_days` to the period you publish under Rule 14, never above 90.

## What "erasure" means for each kind of AI artifact

Configurable in `policy`; these are the defaults and the exact behaviour of the built-in connectors.

| Artifact | Default action | What exactly happens | How it is verified |
|---|---|---|---|
| The person's own records, copies, cache entries, eval rows | Delete | Row, item, object (all versions in S3) or dataset row removed | Store re-scanned for the person's tokens and, during the run, raw values |
| **The person's own embeddings** | Delete | Row or document removed, so the vector goes with it | Re-scan of the text column or document listing |
| **Embeddings of someone else's record that mentions the person** | Redact | `sql_table` / pgvector with `embedding_column`: text redacted **and the vector recomputed** from the redacted text (`on_redact: reembed`). Without `embedding_column`: row deleted, to be re-ingested from source (`on_redact: delete`). Bedrock Knowledge Bases, Vertex Vector Search and OpenAI vector stores cannot be edited in place: the document is deleted | Text re-scan; the action records `reembedded: true` or the delete. The vector itself is not inspected, but it is recomputed from the verified text |
| Someone else's record that mentions the person | Redact | The person's tokens replaced with `[ERASED]`; the rest of the record stays | Re-scan for tokens |
| Per-person derived content (summaries, memory records) | Regenerate | Rebuilt from surviving sources, or rewritten without the person; any surviving token is removed | Re-scan for tokens |
| Aggregates (reports across people) | Keep if ≥ `aggregate_k_threshold` contributors, with the person's tokens redacted; otherwise rebuild without them | Same | Re-scan for tokens |
| Fine-tuned models | Flag for retraining | Marked `pending_retrain`; the framework does not retrain or unlearn | Listed as an exception in the certificate |
| Immutable logs and traces (CloudWatch, Cloud Logging, X-Ray, Cloud Trace) | Crypto-shred | Entries cannot be edited; they hold tokens, and destroying the person's key makes them unreadable to applications. They expire under retention | Re-scan for raw values (a raw value found is reported as a failure) |
| Data under a legal hold (e.g. KYC) | Keep, sealed | Stays in place; its tokens are resolvable only with the sealed key through break-glass | Listed as an exception with its legal basis |

Anything the detectors did not recognise, or that was written without going through the framework, is
only found if a connector can search for it. Verification reports what it finds; it cannot prove the
absence of data it cannot see.

## Commencement

The Rules were notified on 13 November 2025. Most operational obligations, including erasure, retention
and the rights in Rule 14, apply from **13 May 2027**.
