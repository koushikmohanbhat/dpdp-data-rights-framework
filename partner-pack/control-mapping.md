# Control mapping template

Maps DPDP obligations to controls, the evidence each control produces, an owner and a test. Copy it to the
client's engagement folder (outside this repository). Then:

1. Fill in the owners.
2. Replace the "Client" cells with the client's own processes.
3. Delete controls that do not apply and add the client's existing control IDs.

Walk through it with the DPO and counsel. The references are an engineering reading of the DPDP Act 2023
and DPDP Rules 2025 (G.S.R. 846(E)); **validate them with counsel**. The framework does not cover children's
data, Consent Manager integration or breach response; see [scope](../docs/dpdp-mapping.md#scope).

Evidence names refer to the [evidence and audit pack](../docs/evidence.md):

- **case** is the case record
- **bundle** is the signed evidence bundle
- **pack** is the period audit pack
- **coverage** is the coverage report

| ID | Obligation (source) | Control objective | How it is met: framework / client | Evidence | Owner | Frequency | Test |
|---|---|---|---|---|---|---|---|
| C01 | Purpose-specific consent (Act s.6(1)) | Personal data is processed only for purposes the principal consented to, or a legitimate use | Framework: consent ledger per element × purpose; `protect()` blocks processing without consent. Client: notice text and purpose list approved by the DPO | Config `purposes`; consent records in each case; test result for A7 | | Per release | Process data for a purpose with no consent; expect `ConsentDenied` |
| C02 | Withdrawal as easy as giving consent (s.6(4)) | Withdrawal is available in the same channels as consent | Client: withdrawal entry points in app, web, contact centre. Framework: `POST /v1/withdrawals` | Channel list; pack `by_channel` | | Quarterly | Withdraw through each channel in staging |
| C03 | Stop processing and erase on withdrawal, including processors (s.6(6), s.8(7)) | Withdrawal triggers a purpose-scoped erasure across every store and processor | Framework: purpose-scoped erasure; connectors for processor-held state. Client: manual procedures for systems with no connector | Case actions per store; case log manual actions; coverage | | Per request | Seeded withdrawal in staging (A7) |
| C04 | Erasure on request (s.12(3)) | Verified requests are erased across all stores, with exceptions justified | Framework: Rights API → queue → orchestrator → certificate. Client: upstream identity verification | Certificate; case; bundle | | Per request | Real erasure in staging ends `completed` and verifies (A5) |
| C05 | Requester identity verified (s.12(3), Rule 14) | Only the Data Principal (or their nominee) can trigger erasure | Client: verification in the channel (login, KYC, branch). Framework: records `verified_by`, `verification_ref` | `verification_ref` in case; checklist item `requester_verified` | | Per request | Sample 10 cases per quarter; trace each reference to its verification record |
| C06 | Retention only where law requires (s.8(7) proviso) | Data kept after erasure has a written legal basis and a sealed key | Framework: legal-hold purposes with `legal_hold_basis`; sealed KEK. Client: legal opinion per hold | Case exceptions with basis; checklist `exceptions_justified`; legal opinion reference | | Per change to holds | Erase a principal with a KYC record; expect `retain_legal_hold` with the basis text |
| C07 | One-year retention (Rule 8(3), Seventh Schedule) | Identifiers, logs and traffic data are kept for at least a year where the rule applies | Framework: sealed escrow + scheduled purge; log retention ≥ 365 days. Client: record archive and traffic-data retention (**partial coverage**, see [mapping](../docs/dpdp-mapping.md#rule-83-one-year-retention)) | Pack `escrow`; log group retention settings; coverage warnings for retention under one year | | Quarterly | Coverage has no "retention under one year" warnings for log systems; pack has no `escrow_purge_overdue` |
| C08 | Security safeguards (s.8(5), Rule 6) | Personal data is tokenised before it is stored; keys in KMS; access is logged | Framework: tokenisation, per-principal keys, tokenised logs and spans. Client: network controls, IAM reviews | `check-config` output; PII detection report (A10); IAM review record | | Per release; quarterly IAM | `check-config` no errors (A9); seeded leak caught (A6) |
| C09 | Restricted access to retained data (Rule 6) | Sealed data is read only with two-person approval, and every read is logged | Framework: break-glass (request, separate approver, read, revoke). Client: approver list | Break-glass section in pack and case; `/v1/break-glass/audit` | | Monthly review | Break-glass drill (A8) |
| C10 | Response time (Rule 14(3)) | Requests finish by their due date | Framework: `due_by`, SLA metrics and alarms. Client: escalation path | Pack `completed_within_sla_pct`, `overdue` and `sla_missed` findings | | Daily alarm; monthly pack | Alarm test (A11) |
| C11 | Accountability for automated results | Every finished request is reviewed by someone independent | Framework: case log, checklist, separation of duties, `required_approvals`. Client: reviewer roster | Pack `signed_off_pct`; `sign_off_overdue` findings; case log | | Daily queue; monthly pack | Try to approve a request you submitted; expect refusal |
| C12 | Manual steps are done and recorded | Systems with no connector are handled and evidenced | Client: runbook per manual system. Framework: manual-action entries with references | Case log; checklist `manual_systems_done`; coverage `manual` systems | | Per request | Sample cases with manual systems; trace each reference to its ticket |
| C13 | Evidence integrity | Certificates and case logs cannot be changed unnoticed | Framework: hash chains, KMS signatures, Object Lock / locked GCS archive. Client: publish key fingerprint | Pack `certificate_chain`; `evidence verify` output with `key_pinned: true` | | Monthly | `audit-pack --fail-on-errors`; verify one bundle with `--fingerprint` |
| C14 | Processor obligations (s.8(2)) | Every processor has a contract clause and an erasure route | Client: contracts; [processor responsibilities](processor-responsibilities.md). Framework: connectors, coverage checks for missing contract references | Processor register; coverage findings | | At onboarding; annually | Coverage has no "processor has no contract reference" warnings |
| C15 | Configuration change control | Changes to purposes, holds, connectors or policy are reviewed | Client: change management. Framework: config in SSM / Secret Manager, `check-config` in CI | Change tickets; CI logs | | Per change | Change ticket exists for each config version in the period |
| C16 | Coverage stays complete | New stores are found before data lands in them | Client: architecture review gate. Framework: inventory and `coverage --fail-on-gaps` in CI | Coverage report history | | Per release; quarterly | Coverage `tested` = 100% of automated systems (A2) |
| C17 | Publish how to exercise rights (Rule 14(1)) | The published means, identifiers and periods match what the system enforces | Framework: notice generated from the effective rules (`rights notice`, `/v1/rights/notice`). Client: publish it on the website and app | Published page; `rights rules` output (version and hash) | | Per rule change | Compare the live page with `rights notice` output |
| C18 | Access (s.11) | Access requests get a complete, reviewed report on time | Framework: access cases, report from vault and lineage, recipient list, review notes. Client: manual check of systems outside the framework | Rights section of the pack; case events; released report hash | | Per request; monthly | Sample access cases; compare each report with the inventory |
| C19 | Correction (s.12(1)-(2)) | Corrections are decided by someone else, applied everywhere, and followed up outside the vault | Framework: correction cases, vault correction, follow-up list. Client: tickets for follow-ups | Case outcome `follow_up`; tickets | | Per request | Correct a test value in staging; reveal it from every store |
| C20 | Nomination (s.14) | Only an approved nominee can act, and only for allowed request types | Framework: nomination records, invocation with evidence and review. Client: verification of the nominee and the event | Invocation cases; `rights nominations` | | Per invocation | Submit on behalf before invocation; expect refusal |
| C21 | Grievance redressal (s.13, Rule 14(3)) | Grievances are acknowledged and answered within the published period (≤ 90 days) | Framework: grievance cases, due dates, responses with Board escalation text. Client: owner for each category | Pack rights section; `rights_overdue` findings | | Daily queue; monthly pack | No overdue grievances in the pack |

## How to use it in an engagement

- **Discover phase:** fill in owners, mark which controls the client already has, and note any gaps.
- **Validate phase:** run each "Test" and file the output with the acceptance criteria.
- **Operate phase:** the "Frequency" column becomes the client's control calendar. The monthly audit pack
  provides the evidence for C10, C11, C13 and C18–C21 directly.
