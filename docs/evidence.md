# Evidence and audit pack

The erasure certificate proves what the framework did automatically. An auditor, the DPO or the Data
Protection Board usually also asks:

- What did people do by hand for systems with no connector?
- Who checked the result, and against what checklist?
- Were requests handled on time?
- Has any evidence been altered since it was recorded?

This guide covers the four pieces that answer those questions:

| Piece | What it is | Command / endpoint |
|---|---|---|
| [Case record](#case-record) | Everything about one request: request and verification references, timeline, actions per store, exceptions, verification, certificate check, case log, sign-off, break-glass reads | `dpdp-rights case show`, `GET /v1/erasure-requests/{id}/case` |
| [Case log](#case-log-manual-actions-and-reviews) | Append-only, hash-chained, signed entries: manual actions and reviewer decisions | `case manual-action`, `case review`, `POST .../manual-actions`, `POST .../reviews` |
| [Evidence bundle](#evidence-bundle) | Signed zip of one case record, checkable offline | `evidence export`, `evidence verify`, `GET .../evidence` |
| [Audit pack](#audit-pack) | Signed zip for a period: metrics, findings, a check of the whole certificate chain, and every case record | `audit-pack`, `GET /v1/audit-pack` |

Templates for the paperwork around them are in the partner pack:
[control mapping](../partner-pack/control-mapping.md),
[processor responsibilities](../partner-pack/processor-responsibilities.md) and
[audit evidence checklist](../partner-pack/audit-evidence-checklist.md).

Nothing here is legal advice. These records support a compliance position; they do not by themselves
establish one.

## Case record

```bash
dpdp-rights -c "$DPDP_CONFIG" case show --request-id er_... --format html --output case.html   # or md / json
```

A case record holds:

- the request: scope, channel, `requested_by`, `verified_by`, `verification_ref`, received, due and completed times
- the SLA result: days taken, whether it finished by the due date, whether it is open and overdue
- the principal's consent records, by purpose
- every action per store, with exceptions (legal holds, the Rule 8(3) escrow), failures and verification results
- the certificate, re-checked: hash, chain link and signature
- the case log and its integrity check
- the sign-off state
- break-glass grants and reads for this principal

It contains **no personal data**. The principal is a pseudonymous ID, stores hold tokens, and free text
entered into the case log is checked before it is accepted (see below).

## Case log: manual actions and reviews

The case log has two kinds of entry.

**Manual action.** Some work happens outside the framework: a system with no connector, a processor
instructed by email, paper files. The person who did it records:

- the system, using the name from the [deployment inventory](../partner-pack/inventory.template.yaml)
- the action: `deleted`, `redacted`, `retained`, `processor_instructed`, `processor_confirmed`, `not_applicable` or `other`
- a ticket, change or case reference, which is required

```bash
dpdp-rights -c "$DPDP_CONFIG" case manual-action --request-id er_... --actor ops:meena \
  --system "Contact-centre call recordings" --action deleted --reference CC-2026-1187 \
  --notes "Runbook CC-07 followed in the vendor console"
```

**Review.** A reviewer records `approved`, `rejected` or `needs_info` against the review checklist:

```bash
dpdp-rights -c "$DPDP_CONFIG" case review --request-id er_... --reviewer dpo:asha --decision approved \
  --check all=yes --notes "KYC hold per sector regulation; recordings deleted by CC-2026-1187"
# or answer items one by one: --check requester_verified=yes --check manual_systems_done=n/a ...
```

Over the API, manual actions need the `dpo` or `service` role and reviews need `reviewer` or `dpo`. The
actor recorded is the authenticated caller, never a value from the request body.

### Rules the framework enforces

| Rule | Why |
|---|---|
| Reviews only after processing has finished (`completed`, `completed_with_exceptions`, `failed`) | A reviewer signs off a result, not a plan |
| The reviewer cannot be the requester (`requested_by`) or anyone who recorded a manual action on the case | Separation of duties |
| To approve, every checklist item must be answered `yes` or `n/a`; any `no` blocks approval | The checklist is a control, not a form to skim |
| Approving a case with exceptions (other than the routine Rule 8(3) escrow) or failures needs notes | The basis for keeping or missing data must be written down |
| A `failed` request cannot be approved | Fix the cause and re-run it; the reviewer can record `needs_info` or `rejected` |
| `rejected` and `needs_info` need notes | The next person needs to know what to do |
| Notes, systems and references that look like personal data are refused | Case records must not become a new copy of the data being erased. Record ticket IDs instead |
| A manual action recorded after an approval makes that approval **stale** | The reviewer approved a different state of the case |

The personal-data check uses the PII detectors you configured, so a regex-only setup will miss names in
notes. To turn the check off, set `evidence.reject_personal_data: false`; `check-config` warns when you do.

### Sign-off state

Each reviewer's latest decision counts. The case's state is decided in this order:

1. **`rejected`** if any reviewer's latest decision is a rejection.
2. Otherwise **`needs_info`** if any reviewer's latest decision asks for more information.
3. Otherwise **`approved`** once `evidence.required_approvals` different reviewers have approved since the last manual action.
4. Otherwise **`pending`**.

There are two other states. With `required_approvals: 0` the state is `not_required`; `check-config` warns
about this setting in production. While the request is still being processed, the state is
`not_reviewable`.

### Integrity

Each entry stores a SHA-256 over its event ID, request ID, kind, actor, exact stored text and the
previous entry's hash. The first entry links to the request's certificate, or to the request itself if
there is no certificate. Entries are signed with the certificate signer (KMS in production). If anyone
edits or deletes a row in the database, the chain breaks at that entry. The case record, the evidence
bundle and the audit pack all report where.

The `notifications` event `case_reviewed` carries the request ID, the decision, the sign-off state and
the approval counts. It never includes notes.

## Evidence bundle

```bash
dpdp-rights -c "$DPDP_CONFIG" evidence export --request-id er_... --output er_....zip
dpdp-rights evidence verify er_....zip --fingerprint <published key fingerprint>     # no config needed
```

| File | Contents |
|---|---|
| `case.json`, `case.md`, `case.html` | The case record in three formats |
| `certificate.json` | The certificate exactly as stored: payload, hash, previous hash, signature, signer, archive URI |
| `public_key.pem` | The signer's public key (local Ed25519, AWS KMS or Cloud KMS) |
| `manifest.json` | SHA-256 of every file, signer key ID, key fingerprint, sign-off state |
| `manifest.sig` | Signature over the manifest |

`evidence verify` checks the following without contacting any service:

- every file matches the manifest, and nothing was added
- the manifest signature
- the certificate's hash and signature
- that the case record refers to that certificate
- the whole case log chain and its signatures

**Pin the key.** The public key inside a bundle only shows the files were signed by *that* key. Anyone
could build a bundle signed with their own key. Publish the key fingerprint (it is printed by
`evidence export` and stored in every manifest) to the DPO and auditors. They verify with
`--fingerprint` or with `--public-key` pointing to a copy they hold. Without either, the result says
`key_pinned: false`.

## Audit pack

```bash
dpdp-rights -c "$DPDP_CONFIG" audit-pack --from 2026-10-01 --to 2027-01-01 --output audit-2026Q4.zip \
  --inventory inventory.yaml --fail-on-errors
```

The pack covers requests *received* in the period (from inclusive, to exclusive). Dry runs are left out.
It contains `audit.json`, `audit.md`, `audit.html`, `cases/<request_id>.json` (left out with
`--no-cases`), and a signed manifest. `evidence verify` checks it the same way as a case bundle.

| Section | Contents |
|---|---|
| Metrics | Requests received and finished; share completed within SLA; median and p95 days; share signed off; by status, scope (full or purpose), channel and sign-off state |
| Certificate chain | Every certificate ever issued, in order: hash, link to the previous one, signature; the first break if any |
| Findings | See the table below |
| Break-glass | Grants and approvals in the period; sealed reads allowed and denied |
| Retention escrow | Escrows sealed and purged; escrows whose purge date has passed |
| Coverage | The [coverage report](../partner-pack/README.md) for an inventory, if you pass `--inventory` |

Findings:

| Level | Code | Meaning |
|---|---|---|
| error | `overdue` | Open past its due date |
| error | `certificate_invalid`, `certificate_signature_invalid`, `certificate_chain_broken`, `certificate_chain_signature` | Evidence does not verify |
| error | `case_log_broken` | A case log entry was altered or removed |
| warning | `sla_missed` | Finished after its due date |
| warning | `failed` | Request failed |
| warning | `exceptions_unreviewed` | Finished with exceptions and not signed off |
| warning | `sign_off_overdue` | Finished more than `evidence.sign_off_due_days` ago and still pending |
| warning | `review_rejected`, `review_needs_info` | A reviewer rejected the case or asked for more information |
| warning | `stale_approval` | Approved before a later manual action |
| warning | `escrow_purge_overdue` | Run `purge-escrows` |
| warning | `unsigned` | `certificates.signer: none` |
| warning | `coverage_errors` | The inventory has coverage errors |

Use `--fail-on-errors` in a scheduled job so a broken chain or an overdue request fails loudly.

## Configuration

```yaml
evidence:
  required_approvals: 1        # distinct reviewers needed; 2 for high-risk deployments
  sign_off_due_days: 7         # audit pack flags cases pending longer than this
  reject_personal_data: true
  review_checklist:            # replace or extend; ids are what reviewers answer
    - {id: requester_verified, text: The upstream verification reference matches a real, closed verification case}
    - {id: scope_matches_request, text: The scope erased (full or purpose) is what the Data Principal asked for}
    - {id: exceptions_justified, text: Every retained, failed or crypto-shredded item has a documented basis}
    - {id: verification_reviewed, text: Verification results were reviewed; any leftovers were resolved or escalated}
    - {id: manual_systems_done, text: Systems without a connector (manual or processor-held) have a recorded manual action}
```

Add a `reviewer` role to the people who sign off (API key `roles: [reviewer]`, or the OIDC roles claim).
The case log table (`case_event`) is created automatically on first start, including on existing
databases.

## Scheduling

| When | What |
|---|---|
| Daily | Work the sign-off queue: audit pack for the last 30 days, findings `exceptions_unreviewed`, `sign_off_overdue` |
| Monthly | `audit-pack` for the month with `--fail-on-errors`; store the zip in the certificate archive bucket |
| Quarterly | Audit pack with `--inventory` for the DPO and, for Significant Data Fiduciaries, the independent auditor |
| Once, and after key rotation | Publish the signing-key fingerprint to the DPO and auditors |
