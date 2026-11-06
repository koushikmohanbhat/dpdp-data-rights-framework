# Audit evidence checklist

Questions an auditor, the DPO or the Data Protection Board is likely to ask about consent withdrawal and
erasure, and where the answer comes from. Use it to prepare for a periodic audit, a Significant Data
Fiduciary audit (Act s.10) or an inquiry. Store every output with the period's audit pack.

The commands assume `DPDP_CONFIG` points at the production config. See [evidence.md](../docs/evidence.md).

## Before the audit

- [ ] Agree the period with the auditor (for example the last quarter)
- [ ] Generate the pack: `dpdp-rights -c "$DPDP_CONFIG" audit-pack --from <start> --to <end> --inventory inventory.yaml --output audit-<period>.zip`
- [ ] Verify it with a pinned key: `dpdp-rights evidence verify audit-<period>.zip --fingerprint <published fingerprint>`
- [ ] Resolve or explain every **error** finding; write a one-line note for each **warning**
- [ ] Bring the [control mapping](control-mapping.md) and [processor register](processor-responsibilities.md), both up to date

## Questions and evidence

| # | Question | Evidence | How to produce it |
|---|---|---|---|
| 1 | Which purposes do you process personal data for, and on what basis? | Purpose list with legal basis and holds | `purposes` in the production config; notice versions in consent records |
| 2 | Where does an AI agent's personal data go? | Deployment inventory and coverage report | `coverage --inventory inventory.yaml --format html` |
| 3 | How many withdrawal and erasure requests did you receive, and how fast did you handle them? | Audit pack metrics | `audit.html`: received, within SLA, median and p95 days, by channel |
| 4 | Show me one request end to end | Evidence bundle | `evidence export --request-id <id>`; the auditor picks the ID from the pack |
| 5 | How do you know the requester was the Data Principal? | `verified_by` / `verification_ref` on each case; the upstream verification record | Case record; trace the reference in the channel's system |
| 6 | What did you keep, and why? | Exceptions with legal basis; legal opinion references | Case exceptions; [control C06](control-mapping.md) |
| 7 | How do you reach systems and processors with no API? | Manual actions with ticket references; processor register | Case log; [processor register](processor-responsibilities.md) |
| 8 | Who checked the result? Can people approve their own work? | Reviewer decisions; separation-of-duties rules | Case log reviews; pack `signed_off_pct`; [rules](../docs/evidence.md#rules-the-framework-enforces) |
| 9 | How do you know the evidence was not altered? | Certificate chain check; signed case logs; immutable archive | Pack `certificate_chain`; `evidence verify` with `key_pinned: true`; bucket Object Lock / retention-lock settings |
| 10 | Who can read data kept under a legal hold or for Rule 8(3)? | Break-glass grants, approvals and reads | Pack break-glass section; `GET /v1/break-glass/audit` |
| 11 | Do you keep logs and identifiers for a year where required? | Escrow status; log retention settings | Pack escrow section; coverage warnings for retention under one year; [Rule 8(3) mapping](../docs/dpdp-mapping.md#rule-83-one-year-retention) |
| 12 | How do you stop personal data reaching models and logs in clear text? | Detector configuration and measured detection coverage; production guardrails | `check-config` output; PII detection sample report (acceptance criterion A10) |
| 13 | How do you know a new store is not missed? | Coverage history; conformance runs for custom connectors | Coverage reports per release; CI logs for `--fail-on-gaps` and conformance tests |
| 14 | What happens when an erasure fails? | Failed and `completed_with_exceptions` cases with reviewer notes | Pack findings `failed`, `exceptions_unreviewed`; [operations runbook](../docs/operations.md#handling-a-failed-request) |
| 15 | How do people exercise their rights, and where is that published? | Rule 14(1) notice; channels and identifiers | `rights notice --format html`; the live page; `rights rules` (version, hash, reviewed by) |
| 16 | How many access, correction, nomination and grievance requests did you get, and did you meet your deadlines? | Rights section of the audit pack | `audit.html` rights table; `rights_overdue`, `rights_late` findings |
| 17 | Show me an access report and how you checked it | The case (events, review notes) and the released report | `rights show --case-id`; `rights access-report --case-id --values masked` |
| 18 | Which rules applied to a case, and who approved changes to them? | Rule-set id, version and hash on each case; counsel review in the rule-set file | `rights show`; the rule-set file's `reviewed` field |

## Sampling guidance

For a period with many requests, give the auditor the full pack and let them choose a sample. As a
minimum, include:

- every `failed`, `completed_with_exceptions`, `rejected` and `needs_info` case
- every case with a manual action
- every break-glass grant
- a random sample of 10 `completed` cases

Export a bundle for each case in the sample.

## What the evidence does not show

Say this to the auditor up front:

- The framework covers consent withdrawal and erasure only ([scope](../docs/dpdp-mapping.md#scope)).
- Detection of personal data is probabilistic. The pack shows what was found and acted on, not proof that
  nothing was missed.
- Rule 8(3) coverage is partial ([details](../docs/dpdp-mapping.md#rule-83-one-year-retention)).
