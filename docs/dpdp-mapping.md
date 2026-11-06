# DPDP Act 2023 / DPDP Rules 2025: how the framework maps

> **Not legal advice.** This is an engineering mapping that partners should
> validate with privacy counsel for each deployment. Section and rule
> references should be checked against the official gazette text.

| Obligation | Where it comes from | What the framework does |
|---|---|---|
| Erase on request unless retention is needed for the purpose or by law | Act s.12(3) | `POST /v1/erasure-requests` -> discover, plan, execute, verify, certify |
| Erase when consent is withdrawn or the purpose is no longer served; make processors erase too | Act s.8(7), s.6(6) | `withdraw_consent(..., erase=True)` runs a purpose-scoped erasure; connectors reach processor-held state (OpenAI, Anthropic, Bedrock, Vertex, SaaS stores) |
| Consent specific to purpose; withdrawal as easy as giving it | Act s.6 | Consent ledger per principal x element type x purpose; `protect()` blocks processing without consent |
| Legitimate uses without consent | Act s.7 | `legal_basis: legitimate_use` purposes skip the consent check |
| Reasonable security safeguards (encryption, masking, tokenisation, access control, logs) | Act s.8(5); Rules r.6 | Per-principal keys wrapped by AWS KMS / Cloud KMS, tokenised logs/prompts/vectors, privileged-only reads of sealed data |
| Minimum one-year retention of personal data, traffic data and processing logs | Rules r.8(3) + Seventh Schedule | Statutory retention escrow: data leaves every operational/AI store at once; a sealed copy stays under an escrow key; `purge-escrows` destroys it after `policy.statutory_retention.days` |
| Time-bound erasure for specified large platforms with 48-hour prior notice | Rules r.8(1)-(2) + Third Schedule | Not automated in v0.1. Use the lineage DB to find inactive principals, send notice, then call `erase()` (roadmap) |
| Grievance redressal within 90 days | Rules r.14(3) | Requests carry `due_by` (configurable SLA, default 30 days) and an auditable action log |
| Demonstrable compliance / audits | Act s.10 (SDF), Board inquiries | Hash-chained erasure certificates, per-action records, verification results |
| Breach notification | Act s.8(6); Rules r.7 | Out of scope; the lineage graph shows which principals are affected by a breached store |

## Commencement

The Rules were notified on 13 November 2025. Most operational obligations,
including erasure and retention mechanics, apply from **13 May 2027**.

## Interpreting "erasure" for derived AI artifacts

The framework takes these positions, all configurable in `policy`:

- **Copies and embeddings** of a principal's text are personal data. They are deleted, because
  embeddings can be partly inverted.
- **Per-person derived content** (profile summaries, memory records) is regenerated or deleted.
- **Aggregates** are kept only when at least `aggregate_k_threshold` other principals contributed.
  The principal's tokens are still redacted. Below the threshold they are rebuilt from the
  remaining sources.
- **Model weights** trained on the data are flagged `pending_retrain`. Partners should avoid this
  case by training only on tokenised or synthetic data.
- **Immutable logs** hold tokens only, so shredding the key makes them unreadable. They then
  age out under the retention policy, which also satisfies the logging part of Rule 8(3).
