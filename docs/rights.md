# Rights workflow: access, correction, nomination, grievance

The rights desk gives every Data Principal right one intake, one case model and one audit trail:

| Type | DPDP | What happens |
|---|---|---|
| `access` | Act s.11 | An access report is prepared from the vault, lineage, consents and your recipient list; a reviewer releases it |
| `correction` | s.12(1)-(2) | Correct, update or complete a value; a reviewer approves; the correction is applied through the vault |
| `erasure` | s.12(3), s.8(7) | Routed to the erasure orchestrator; the case mirrors the request and links its certificate |
| `withdrawal` | s.6(4)-(6) | Purpose-scoped withdrawal and erasure, as above |
| `nomination` | s.14, r.14(4) | Register or revoke a nominee for death, incapacity, or both |
| `nominee_invocation` | s.14 | A nominee asks to act, with an evidence reference; a reviewer approves; the nominee may then file requests |
| `grievance` | s.13, r.14(3) | Acknowledged, then resolved or rejected with a response; the response tells the person about the Board |

Every case gets a due date from a **versioned rule set**, records which rules applied, and keeps a signed,
hash-chained event history. Personal data in a case (new values, messages, nominee details) is stored as
vault tokens of the principal: it is readable only through the vault and is crypto-shredded with the person.

Not covered: children's data and verifiable parental consent (s.9), Consent Manager integration (Rule 4),
inactivity erasure (Rule 8(1)-(2)). See the [roadmap](roadmap.md). Requester identity verification stays
upstream, as for erasure.

**Not legal advice.** The rule set is an engineering reading of the Act and Rules. Have counsel review it
before production use.

## Legal rules

```bash
dpdp-rights -c "$DPDP_CONFIG" rights rules              # effective rules, hash, overrides, versions
dpdp-rights -c "$DPDP_CONFIG" rights rules --on 2027-06-01
```

The package ships `dpdp-in` version `2025.11-1`
([source](../src/dpdp_rights/rights/rulesets/dpdp-in-2025.11.yaml)). For each request type it records:

- the legal basis and a plain-language summary
- `respond_within_days`: the due date set on new cases
- `max_days`, and whether that limit is `prescribed` by law (only the grievance period, Rule 14(3), is) or a conservative framework default
- who may ask: the principal, a nominee, or both
- whether a reviewer must decide by default

It also holds the commencement date (13 May 2027), the Rule 14(1) publication duty and the Board escalation
text.

**Versions.** To change rules, add a new file with the same `id`, a new `version` and a later
`effective_from`, in your own `rights.rule_sets_dir` (with `reviewed:` filled in by counsel). A case uses the
version in effect on the day it was received. Earlier cases keep the rules they were judged under: each case
stores the rule-set id, version and the SHA-256 of the effective rules.

**Overrides.** Small changes go in config. They are validated: a period above a *prescribed* limit is refused
(the service will not start in production), and a period above a framework default produces a `check-config`
warning. Only `respond_within_days`, `review_by_default`, `requesters`, `notes` and `summary` can be overridden.

```yaml
rights:
  overrides:
    grievance: {respond_within_days: 15}     # what you publish; must be <= 90
    access: {review_by_default: false}
```

## Configuration

```yaml
rights:
  rule_set: dpdp-in
  rule_sets_dir: /etc/dpdp/rules        # optional: your counsel-reviewed versions
  review_required: null                 # null = the rule set's defaults; or a list of types
  access_values: masked                 # masked | full | none (types and counts only)
  channels:                             # published in the notice (Rule 14(1))
    - {name: Mobile app, how: "Profile > Privacy > My data rights"}
  identifiers: ["Policy number", "Registered mobile number"]
  contact: "Data Protection Officer, dpo@example.com"
  recipients:                           # who receives data from each store (Act s.11(1)(b))
    - {store: audiences, name: "Marketing email platform", role: processor,
       description: "Sends renewal emails on our behalf"}
    - {store: fraud_feed, name: "Industry fraud registry", role: fiduciary, exempt_from_access: true,
       exemption_basis: "s.11(2), notification ..."}
```

`check-config` warns when `channels`, `identifiers`, `contact` or `recipients` are empty.

## Intake

All request types use the same intake: `POST /v1/rights-requests`, `dpdp-rights rights submit`, or
`dpdp.rights.submit(...)`.

```bash
curl -XPOST $API/v1/rights-requests -H "x-api-key: $KEY" -H 'Idempotency-Key: 4b1e' -H 'content-type: application/json' \
  -d '{"type":"correction","external_id":"app-1002","verified_by":"mobile-app","verification_ref":"sess-77a1",
       "details":{"element_type":"UPI_ID","new_value":"rahul.verma@okicici","reason":"Changed my UPI handle"}}'
```

| Type | `details` |
|---|---|
| `access` | none |
| `correction` | `element_type`; `new_value`; `action`: `correct` (default; `update` is the same) or `complete` (add a value that is missing); `ref` (which value, when there are several of that type: the access report lists each value's ref); `reason` |
| `erasure` | `scope` (`full` by default) |
| `withdrawal` | `purpose_id` |
| `nomination` | `nominee_name`, `nominee_contact`, `relationship`, `events` (`death`, `incapacity`, `both`); or `action: revoke` with `nomination_id` |
| `nominee_invocation` | `event` (`death` or `incapacity`), `evidence_ref` (the verified certificate or record reference); `on_behalf_of` = the nomination id |
| `grievance` | `category` (`request_handling`, `consent`, `data_accuracy`, `security_concern`, `notice`, `nominee`, `other`), `description`, optional `related_case_id` |

Who can submit:

- A principal signed in through OIDC can submit for themselves.
- Services and the DPO submit for verified principals.
- Nominee requests (`on_behalf_of`) can only be submitted by a service or the DPO, after they verify the nominee. They are accepted only once the nomination has been invoked and approved.
- Requests are idempotent with an `Idempotency-Key` header.

## Case lifecycle

| Type | Statuses |
|---|---|
| access | `received` → (`report_prepared`) → `in_review` → `fulfilled` (released) or `rejected` |
| correction | `received` → `in_review` → `fulfilled` (applied) or `rejected` |
| nominee_invocation | `received` → `in_review` → `fulfilled` (nominee may act) or `rejected` |
| nomination | `received` → `fulfilled` |
| grievance | `received` → `acknowledged` → `fulfilled` (resolved) or `rejected` |
| erasure, withdrawal | `received` → `in_review` (processing) → `fulfilled` or `failed`, following the erasure request |

**Decisions.** For access, correction and nominee invocation:
`POST /v1/rights-requests/{id}/decision` (`reviewer` or `dpo` role) or `rights decide`.

- The person who submitted a case cannot decide it.
- A rejection needs a reason the principal can read.
- With `review_required: []`, cases are fulfilled straight away.

**Grievance responses.** `POST /v1/rights-requests/{id}/response` (`dpo` role) or `rights respond`.

- Acknowledge first, then close as `fulfilled` (resolved) or `rejected`, with a response.
- The closing response carries the Board escalation text from the rule set.
- Whoever raised the grievance cannot respond to it.

**Events and integrity.** Every state change is an event in a per-case log. Each event's SHA-256 covers the
previous one, the first is anchored to the case, and each is signed with the certificate signer. `rights show`
and `GET /v1/rights-requests/{id}` report the log's integrity. The audit pack flags broken logs.

## Access report (s.11)

The report is prepared at intake and stored with **tokens only**. Values are revealed when it is delivered:

- `masked` (default): `r•••••@okhdfc`
- `full`
- `none`: types and counts only

After the principal is erased, every value reads `[ERASED]`.

| Section | Source |
|---|---|
| What we hold | Every value in the vault for the principal, by type, with a `ref` per value (used to target corrections) |
| Where it is and what we made from it | The lineage graph: places in plain language ("Search index used by the assistant", "Assistant memory"), items, derived items, purposes, items kept under law |
| Why we process it | Purposes, legal basis, consent status and dates, notice version, legal-hold basis |
| Who we shared it with | `rights.recipients` for stores that hold the principal's data, with the kinds of data in each |
| Your rights | Request types, response periods and legal basis from the effective rules; contact; Board escalation |

The reviewer sees **review notes** that the principal does not. Notes are added when:

- a recipient is withheld because it is marked `exempt_from_access` (s.11(2))
- a cloud or SaaS store holds the principal's data but has no recipient entry ("if it is a processor, add it")

Delivery: `GET /v1/rights-requests/{id}/access-report[?format=html]`, for the principal themselves or the DPO,
or `rights access-report --format html`.

The report covers what the framework knows: data that passed through `protect()` and artifacts registered
or discovered in lineage. Systems outside the framework need a manual check before release. The reviewer
should compare the report with the [deployment inventory](../partner-pack/inventory.template.yaml).

## Correction (s.12(1)-(2))

Tokenisation makes correction cheap. When a correction is approved, the vault re-encrypts the **new value
under the existing token**. Every log, record, summary, memory and index entry that holds the token reads
the corrected value from then on, and no store is rewritten.

Then:

- Identifiers (email, phone, PAN, Aadhaar, UPI) are linked to the principal, so later mentions resolve to them.
- **Old values seen again are not resurrected.** If the agent later sees the old value (a stale CRM sync, the person saying "my old number was…"), it gets a new token of its own. The correction is never overwritten.
- `complete` adds a value that was missing and registers it.

Each correction also records **follow-ups**:

- items stored before tokenisation, which need correcting by hand
- recipients holding the data, to be told of the correction

Record those as manual actions or tickets.

Limits:

- A format-preserving surrogate keeps the *shape* of the old value.
- Text an LLM wrote *about* a value (a paraphrase, not a token) is not changed.
- Embeddings computed from tokenised text are unaffected, which is correct, because they never saw the value.

## Nomination (s.14, Rule 14(4))

- The principal nominates one or more people for `death`, `incapacity` or `both`. The nominee's name and contact are tokenised under the principal.
- To act, the nominee (through your verified channel) files a `nominee_invocation` with the event and an evidence reference. A reviewer approves it, and the nomination becomes `invoked`.
- From then on, requests with `on_behalf_of` set to the nomination id are accepted, for the types the rule set allows nominees to make.
- A revoked nomination cannot be invoked.

`rights nominations --external-id ...` lists a principal's nominations.

## Grievance (s.13, Rule 14(3))

Grievances get a due date from the published period (default 30 days; the rule refuses more than 90). A
`related_case_id` can link the case or erasure request the grievance is about. The audit pack reports
grievances like other cases and flags overdue ones as errors.

## The published notice (Rule 14(1))

```bash
dpdp-rights -c "$DPDP_CONFIG" rights notice --format html > rights-notice.html    # or md / json
```

It is also served publicly at `GET /v1/rights/notice[?format=html]`, with no credentials needed. It lists:

- where to make a request (`channels`) and what identifies a person (`identifiers`)
- every request type with its response period and who can ask
- the grievance period, the Board escalation text and the contact

It is generated from the effective rules, so the published periods always match the due dates the system
sets. Republish it when you change the rules.

## Monitoring

- `GET /v1/sla` and `dpdp-rights sla` include `rights_cases` by type: ok, due soon, overdue.
- `rights list --overdue` lists open cases past their due date.
- The **audit pack** has a rights section (received, fulfilled, rejected, open, share within the due date, by type) and findings:
  - `rights_overdue` (error)
  - `rights_late` (closed after the due date)
  - `rights_log_broken` (error)
- Notifications: `rights_case_received` and `rights_case_closed`, carrying the case id, type, status, due date and pseudonymous principal id.
