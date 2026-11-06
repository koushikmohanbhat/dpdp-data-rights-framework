# Domain packs

A domain pack is the starting configuration and evidence kit for one sector, tested offline:

| Pack | For |
|---|---|
| `insurance` | Agents that quote, onboard, service policies and handle claims |
| `lending` | Agents that take loan applications, assess credit, service loans and handle collections (banks, NBFCs, digital lenders, LSPs) |
| `healthcare` | Agents that book appointments, triage symptoms, support care teams and file claims |

Each pack contains:

| File | What it holds |
|---|---|
| `pack.yaml` | Purposes with legal bases and **legal holds**, citing the sector law (PMLA, IRDAI 2025 information regulations, RBI KYC Master Direction and Digital Lending Directions 2025, IMC Regulations 2002); policy rules; identifier patterns (policy, claim, loan-account, UHID numbers); rights settings (identifiers, recipients, period overrides); notes; a `reviewed` field for counsel |
| `inventory.yaml` | The systems an agent in this sector usually touches, with categories, data elements, purposes and suggested connector names |
| `scenarios.yaml` | Offline tests of the domain's hard cases (below) |
| `questions.md` | Sector questions to add to the [discovery questionnaire](../partner-pack/discovery-questionnaire.md) |
| `README.md` | A data-flow diagram, the purposes and what happens to each on erasure, and what to confirm with the client |

Packs live in [`src/dpdp_rights/packs/`](../src/dpdp_rights/packs/) and ship with the package.

**Not legal advice.** Every legal hold and period is an example drawn from public sources. Counsel must
confirm it for the client's products and record the review in `reviewed`. The holds say so in their text,
which appears in every certificate that relies on them.

## Commands

```bash
dpdp-rights packs list
dpdp-rights packs show insurance                     # sources, purposes, holds, patterns, recipients
dpdp-rights packs init insurance --output ~/engagements/acme --base config/dpdp.production.aws.yaml
dpdp-rights packs test insurance                     # or: all
dpdp-rights packs test insurance --config ~/engagements/acme/dpdp.yaml --scenarios ~/engagements/acme/scenarios.yaml
```

`packs init` writes an engagement folder (outside this repository):

- `dpdp.yaml`: the base config with the pack merged in. Purposes are replaced by the pack's; the pack's policy rules come first; PII patterns are added; rights identifiers, overrides and recipients are added. Provider, vault, connectors and auth stay as in the base.
- `inventory.yaml`, `scenarios.yaml`, `questions.md` and `PACK-README.md`.

It refuses to overwrite an existing `dpdp.yaml`.

`packs test --config` runs the scenarios against the **client's** purposes, holds, policy, patterns and rights
settings. Connectors are replaced with generated offline ones, so nothing is deployed. Run it after every
change to the client config: if someone removes a legal hold or changes a rule, the scenario that depends on
it fails. For example, `kyc-2: action delete != retain_legal_hold`.

## Scenarios

| Pack | Scenarios |
|---|---|
| insurance | Marketing withdrawal (servicing continues, marketing blocked); policyholder erasure (chats, vectors, eval rows deleted; policy, claim and KYC records held); a nominee's erasure redacts them from the policyholder's application; an access report names the TPA and not the reinsurer; grievance period |
| lending | A declined applicant is erased except KYC; an active borrower's marketing withdrawal, access report (with loan account and bank account) and erasure (loan records held, collections data deleted); a mobile-number correction every copy reflects |
| healthcare | ABDM linking withdrawn while care continues; patient erasure (clinical records held, a one-patient summary deleted); a caregiver's erasure redacts them from the patient's summary; access due in three days with the lab and insurer listed; **the regex safety net**: a name in a log without a cue survives shredding, verification catches it, and the case ends `completed_with_exceptions` |

Each pack also has detection checks: identifiers that must be found, and look-alikes that must not be.

### Scenario format

```yaml
scenarios:
  - id: ins-02-policyholder-erasure
    title: An erasure request from a policyholder with an issued policy
    people:
      - id: cust-2
        identifiers: {EMAIL: arjun.k@example.in}           # registered so mentions elsewhere resolve
        consents: [quote_and_onboarding, claims]
        records:                                           # each store becomes an offline connector
          - {id: chat-2, store: agent_chats, kind: record, purpose: quote_and_onboarding, text: "..."}
          - {id: pol-2, store: policy_admin, kind: record, purpose: policy_records, text: "..."}
    derived:                                               # optional: artifacts built from several records
      - {id: rpt, store: reports, kind: summary, from: [chat-2], edge: aggregate, purpose: analytics}
    steps:
      - erase: {person: cust-2}
        expect:
          status: completed
          actions: {chat-2: delete, pol-2: retain_legal_hold}   # the plan's action per record
          removed: [chat-2]
          kept: [pol-2]
          reads: {some-record: "[ERASED]"}                 # revealed text contains this
detection:
  - {text: "Policy no HLT-20261187", types: [POLICY_NUMBER], absent: [AADHAAR]}
```

| Step | Arguments | Expectations |
|---|---|---|
| `withdraw` | `person`, `purpose` | `actions`, `untouched`, `removed`, `kept`, `reads`, `status` |
| `erase` | `person`, `scope` | as above |
| `protect` | `person`, `purpose`, `text` | `consent_denied` |
| `access` | `person` | `types`, `recipients`, `not_recipients`, `due_days` |
| `correct` | `person`, `element_type`, `new_value` | `reads` |
| `grievance` | `person`, `category`, `text` | `due_days` |

Kinds map to offline connectors:

- `record`, `summary`, `embedding`, `cache_entry`, `memory_record` → `sql_table`
- `log`, `trace` → `log_file`
- `eval_row`, `finetune_row` → `jsonl_dataset`

Detection runs with the regex detector and the configured patterns only. Cloud, NER and LLM detectors are not
exercised offline.

## Using a pack in an engagement

1. **Show:** run the pack's scenarios with the client (`packs test <pack> --verbose`). They are the domain's
   hard cases in a minute.
2. **Discover:** add `questions.md` to the workshop. Fill in `inventory.yaml`.
3. **Design:** `packs init` on top of the cloud template. Replace the example holds with counsel's wording and
   periods. Set the identifier patterns and recipients.
4. **Validate:** adapt `scenarios.yaml` to the client's systems and run `packs test --config` in CI (acceptance
   criterion A15).

## Adding a pack

Copy a pack folder under `src/dpdp_rights/packs/<id>/`, keep the five files, and cite a source for every hold.
`tests/test_packs.py` picks up new packs automatically: their scenarios must pass, their holds must tell the
reader to validate with counsel, and `packs init` must produce a config and inventory that load. Telecom,
e-commerce, HR and education are on the [roadmap](roadmap.md).
