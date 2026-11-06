# Implementation plan

A standard plan for one AI agent in one cloud, from kickoff to handover. Typical duration is 6 to 8 weeks.
It runs longer with many SaaS processors, custom connectors, or slow security approvals. Adjust the
durations; keep the phase gates and acceptance criteria.

## Phases

| Phase | Weeks | Client inputs | Partner deliverables | Gate |
|---|---|---|---|---|
| **0. Show** | before kickoff | Sponsor, DPO, tech lead attend | Demo session; scope statement agreed | Sponsor agrees scope: consent withdrawal and erasure for the named agent |
| **1. Discover** | 1 | Workshop attendees; answers to the [questionnaire](discovery-questionnaire.md); architecture diagrams | Filled [inventory](inventory.template.yaml); purposes and legal bases; first coverage report | DPO confirms purposes, legal bases and legal holds |
| **2. Design** | 1-2 | Cloud account details; security requirements; IdP; break-glass holders | Framework config; chosen [reference architecture](reference-architectures.md); detector choice; connector list; build plan for missing connectors | Security review of the design passed |
| **3. Build** | 2-4 | Access to non-production and staging; agent code repository; a test principal with synthetic data | Deployed stack (Terraform); agent instrumented (`protect`, `track_artifact`, logging filter, OpenTelemetry); connectors configured; custom connectors as [plug-in packages](../docs/plugins.md); notifications to the client's ticketing | Coverage report: no errors for systems planned as automated |
| **4. Validate** | 5-6 | Staging data refresh; testers; DPO and approver for the drill | Live test results; acceptance evidence pack (below) | All acceptance criteria met |
| **5. Handover** | 7-8 | Operations owner; on-call; DPO; reviewers | Runbook walkthrough; alarms live; final coverage report; control mapping and processor register; first audit pack; open-items list | Client operations accepts |

## Acceptance criteria

Each item is measurable and produces evidence for the handover pack.

| # | Criterion | Evidence |
|---|---|---|
| A1 | Coverage report shows **no errors**; every system holding personal data is automated or has a documented manual procedure | `coverage.html` |
| A2 | Every automated system's actions **tested end to end** in the last 180 days | `tested` = 100% of automated systems in the coverage report |
| A3 | Live connector tests pass in the client's non-production account; every custom connector passes the [conformance kit](../docs/plugins.md#conformance-kit) against a sandbox | CI run or JUnit report ([testing.md](../docs/testing.md)), conformance report with skip reasons |
| A4 | A **dry-run erasure** for a test principal who used every feature lists every inventoried system | Dry-run output, mapped to the inventory |
| A5 | A **real erasure in staging** ends `completed`, with a signed certificate that verifies | Certificate + `verify-certificate` output |
| A6 | A **seeded leak** (raw identifier written outside the framework) is caught by verification | Request ending `completed_with_exceptions` naming the store |
| A7 | A **purpose withdrawal** stops processing for that purpose only | `ConsentDenied` for the withdrawn purpose; other purposes continue |
| A8 | **Break-glass drill**: request, approval by a different person, read, revoke; audit trail complete | `/v1/break-glass/audit` export; CloudTrail events |
| A9 | `check-config` reports **no errors** in production mode; warnings reviewed and recorded | `check-config` output |
| A10 | PII detection measured on a sample of real conversations in the languages users write in | Short report: what each detector found and missed |
| A11 | Alarms configured and tested: overdue requests, failed actions, worker health | Alarm test screenshots |
| A12 | Operations team has run the runbook procedures once with the partner present | Signed handover checklist |
| A13 | **Evidence:** a staging case with a manual action is signed off by a reviewer who did not submit it; its evidence bundle verifies with the published key fingerprint; the audit pack for the validation period has no errors | `evidence verify --fingerprint` output; `audit-pack --fail-on-errors` output; [control mapping](control-mapping.md) with owners filled in |
| A14 | **Rights workflow:** in staging, an access report for a test principal lists every inventoried system that holds their data (or the reviewer notes the gaps); a correction is applied and every store reveals the new value; a grievance is answered within the published period; the published notice matches `rights notice` | Access report and case events; reveal output per store; grievance case; screenshot of the published page |
| A15 | **Domain scenarios:** the [domain pack](../docs/domain-packs.md) scenarios, adapted to the client's systems and purposes, pass against the client config (`packs test --config`), in CI | `packs test` output; the adapted `scenarios.yaml`; holds reviewed by counsel (`reviewed` filled in) |

The engagement's headline measures: time from kickoff to A4, and the A2 percentage.

## Roles

| Activity | Partner | Client engineering | Client platform / security | DPO / counsel | Sponsor |
|---|---|---|---|---|---|
| Purposes, legal bases, legal holds | Consulted | Informed | - | **Accountable** | Informed |
| Inventory | **Responsible** | Consulted | Consulted | Consulted | Informed |
| Deployment | **Responsible** | Consulted | **Accountable** | - | Informed |
| Agent instrumentation | Consulted | **Responsible** | - | - | Informed |
| Custom connectors | **Responsible** | Consulted | Consulted | - | Informed |
| Validation | **Responsible** | Consulted | Consulted | **Accountable** for A5-A8 | Informed |
| Operations after handover | Consulted | Consulted | **Responsible** | **Accountable** | Informed |

## Common risks

| Risk | Mitigation |
|---|---|
| A store is discovered late | Walk through a full conversation in discovery; re-run the coverage report each week; check unlisted connectors |
| A SaaS processor has no deletion API | Document a manual procedure and contract clause; record it as manual in the inventory |
| Agent code writes outside the SDK | Discovery and verification catch some; review write paths in code review; seed a leak test (A6) |
| Indian-language data not detected | Measure early (A10); add `transformers_ner` or the opt-in `llm` detector |
| Legal positions unsettled (Rule 8(3), k-anonymity, crypto-shredding) | Record counsel's position in the config comments and the handover pack; keep the policy configurable |
| Security approval delays | Share the design and [security.md](../docs/security.md) in week 1 |
