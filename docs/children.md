# Children and persons with a lawful guardian

**Law:** Act s.9 and s.2(f), (j); Rules r.10, r.11, r.12 and the Fourth Schedule. These apply from **13 May 2027**. The rule set `dpdp-in` 2025.11-3 carries them for counsel to review.

This feature is **off unless `children.enabled: true`**. When it is on, `protect()`, the middleware and every other consent check apply the rules below. Each refusal raises a subclass of `ConsentDenied`, so code that already handles `ConsentDenied` keeps working.

## What it enforces

| Rule | Behaviour |
|---|---|
| s.9(1), r.10: verifiable consent of a parent | For a principal whose status is `child`, a consent counts only if a verified parent gave it (`guardian_id`), and only while that guardian record is active. Otherwise `ParentalConsentRequired` is raised. |
| r.11: a person with disability who has a lawful guardian | The same, with status `ward`. The guardian must have been appointed by a court, a designated authority or a local level committee. |
| s.9(3): no tracking, behavioural monitoring or targeted advertising | Purposes marked `child_restricted: true` are refused for a child or ward even with a parent's consent (`ChildProcessingRestricted`). Adults are not affected. |
| r.12, Fourth Schedule: exemptions | A purpose with `child_exemption: <id>` runs for a child or ward without parental consent and despite `child_restricted`. The id must exist in the rule set (11 entries: Part A classes such as educational institutions and clinical establishments, Part B purposes such as email accounts and age confirmation). Keeping within the exemption's **condition** is the deployer's responsibility. |
| Unknown status | With `unknown_status: deny` (the default), consent-based processing is refused until a status is recorded. Legitimate uses and exempt purposes still run. Set `unknown_status: adult` only if the service is not offered to children, and record why; `check-config` warns about it. |

s.9(2), no processing likely to have a detrimental effect on a child's well-being, is a judgement about the purpose. Record it in the purpose's description and in the processor register; the framework can't decide it.

## Recording status and guardians

Age and guardian checks happen **upstream**, like requester verification: DigiLocker, your KYC, a guardianship order. The framework records which method was used, who checked, the issuer or authority, and a reference. It never stores a date of birth.

```python
kid = dpdp.principal("CUST-881")
dpdp.children.set_status(kid, "child", basis="declared_then_verified", set_by="onboarding", verification_ref="onb-77")

g = dpdp.children.record_guardian(
    kid, dpdp.principal("CUST-880"),
    method="virtual_token", issuer="digilocker",      # Rule 10(1)(b)
    verification_ref="dl-txn-5521", verified_by="kyc-service", relationship="mother")

dpdp.grant_consent(kid, "learning_app", guardian_id=g["guardian_id"], actor="parent-app")
```

**Parent methods** (`children.parent_methods`, from Rule 10(1)):
- `fiduciary_records`: identity and age details you already hold.
- `voluntary_details`: details the parent provides.
- `virtual_token`: a token from an issuer in `children.token_issuers`, such as `digilocker`.

**Guardian methods** (`children.guardian_methods`, from Rule 11): `court`, `designated_authority` and `local_level_committee`. Pass the authority as `issuer`.

**Checks when a guardian is recorded:**
- The child's status must already be set.
- The method must suit the status.
- A virtual token needs an accepted issuer.
- A `verification_ref` is required, and is refused if it contains personal data.
- The guardian can't be the child, and can't be a child or ward themselves.
- If the guardian has no status yet, they get status `adult`, with the verification as the basis, because Rule 10 needs the parent to be an identifiable adult.

**Storage:** the relationship is stored as a vault token. Status changes, guardian verifications and revocations go into the child's [signed consent history](consent-managers.md#the-consent-history-s610).

**Revocation:** `revoke_guardian(guardian_id, reason=..., actor=...)` stops every consent that guardian gave. A parent withdrawing a specific consent uses the normal withdrawal, which erases data for that purpose.

**Ordering matters:** a consent recorded before a principal was identified as a child does not count once they are, because no guardian gave it.

**Through a Consent Manager:** a `given` event for a child or ward must carry the `guardian_id` verified with you. Without it, the event is refused and recorded in the history.

## Configuration

```yaml
children:
  enabled: true
  unknown_status: deny
  token_issuers: [digilocker]
purposes:
  - id: learning_app
  - id: personalised_ads
    child_restricted: true                     # s.9(3)
  - id: bus_tracking
    child_restricted: true
    child_exemption: part_a.child_transport    # Fourth Schedule, Part A; counsel to confirm
```

## API and CLI

| | API (roles) | CLI |
|---|---|---|
| Set status | `POST /v1/children/status` (service, dpo) | `children status --external-id --status --basis [--ref] --by` |
| Record a guardian | `POST /v1/children/guardians` (service, dpo); the verifier is the authenticated caller | `children guardian --external-id --guardian-external-id --method --ref [--issuer] [--relationship] --by` |
| Revoke | `POST /v1/children/guardians/{id}/revoke` (service, dpo) | `children revoke ID --reason --by` |
| View | `GET /v1/children/{external_id}` (dpo, reviewer) | `children show --external-id` |
| Consent by a guardian | `POST /v1/consents` with `guardian_id` | — |

## Limits and questions for counsel

- **Verification and age checks are upstream.** The framework records the evidence reference, not the evidence. It doesn't move anyone to adult automatically on their 18th birthday: call `set_status(..., "adult")` from your own process.
- **Coming of age:** whether consents a parent gave continue after the child turns 18, or must be given again, is for counsel. The framework keeps them valid once the status is `adult`.
- **Rights requests:** a guardian acting on a child's rights requests (access, erasure) uses the existing rights desk with the parent as requester; there is no separate guardian role in the rights desk yet.
- **Exemption conditions:** they are recorded, not enforced. "Only to the extent necessary" is a design and audit question.
- **Detrimental effect (s.9(2))** is not modelled.
