# Insurance: discovery questions

Add these to the standard [discovery questionnaire](../../../../partner-pack/discovery-questionnaire.md).

| # | Question | Who answers | Feeds |
|---|---|---|---|
| I1 | Which product lines does the agent cover (life, health, motor, travel, group)? Which collect health disclosures? | Product | Purposes; detectors for health free text |
| I2 | What does the board-approved records policy say for policy and claim records, per product, and when does the period start? | Compliance, counsel | `policy_records` and `claims` legal holds |
| I3 | When does the business relationship end for PMLA purposes (policy expiry, maturity, claim settlement)? | Compliance | `kyc_aml` hold |
| I4 | Which TPAs, reinsurers, aggregators, brokers and corporate agents receive data, and under which contracts? | Procurement, legal | `rights.recipients`; processor register |
| I5 | How are nominees and assignees recorded, and can a nominee contact the agent directly? | Operations | Nominee identifiers; redaction on nominee erasure |
| I6 | What do policy, proposal and claim numbers look like? | Operations | `pii.patterns` |
| I7 | Are any records shared with industry registries or fraud databases that must not be disclosed in access reports? | Compliance, counsel | `exempt_from_access` recipients |
| I8 | Are call recordings and video KYC files kept, where, and for how long? | Customer service | Inventory; manual procedures |
