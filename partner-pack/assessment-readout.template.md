# DPDP AI readiness assessment: readout

**Client:** ______  **Agents assessed:** ______  **Period:** ______ to ______  **Partner team:** ______

> This readout reports measured gaps against the DPDP Act 2023 and the DPDP Rules 2025 for the agents above.
> It is not a legal opinion or a statement of compliance. The legal readings marked for counsel must be
> confirmed by the client's counsel.

## 1. Summary

- Three to five sentences on what the agents do and the main gaps.
- **Deadlines:** Rule 4 (Consent Managers) has applied since 13 Nov 2026. Rules 7-8 and 10-14 apply from 13 May 2027.
- The proposed implementation, with phases and the number of weeks.

## 2. Where raw personal data sits today (discovery scan)

Paste `scan --format md`, then add which stores were not sampled and why.

## 2a. What personal data reaches the models (gateway, observe mode)

Paste `gateway report --format md`.

| Measure | Value |
|---|---|
| Model calls observed | |
| With personal data | __% |
| Person identifiable at the gateway | __% |
| Calls enforce mode would refuse today (no consent record or no purpose) | |

What this means: ______

## 3. What the conversations contain (PII sample scan)

Paste `pii-scan --format md`, then add the sample size and how it was drawn.

- Detectors that add finds over regex: ______
- Recommended detector set: ______
- Measured on __ labelled messages (`pii-benchmark`): recall for names __, identifiers __, addresses __, by language: ______
- Sample deleted on: ______

## 4. Where the data goes (inventory and coverage)

| System | Kind | Holds personal data | Connector | Erasure tested | Retention | Processor contract |
|---|---|---|---|---|---|---|

Paste the coverage report summary, including the gaps it lists.

## 5. Control gap view

| Control | Status (met / partly / not met) | Evidence | What closes it |
|---|---|---|---|
| C01 ... C24 | | | |

## 6. Rights, consent and children

- **Rights channels today:** how access, correction, erasure, withdrawal, nomination and grievance requests arrive, and how long each takes.
- **Consent:** where it is recorded, whether there is proof of notice, and Consent Manager plans.
- **Children or wards:** whether they use the service, how age is checked, and which purposes are tracking or targeted advertising.

## 7. Breach readiness

Can the client list affected people and draft Rule 7 intimations within 72 hours for the riskiest store?

## 8. Sector holds and pack scenarios

- Holds applied (law and period), each marked for counsel.
- Scenario results against the draft config.

## 9. Recommended implementation

| Phase | Weeks | Scope | Acceptance criteria |
|---|---|---|---|

Include the assumptions, what is out of scope, and the client's inputs.

## 10. Questions for counsel

Start from section 11 of the design doc and the `reviewed` fields of the sector pack.
