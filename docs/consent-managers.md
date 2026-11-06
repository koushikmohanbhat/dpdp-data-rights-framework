# Consent Managers and the consent history

**Law:** Act s.6(7)-(10); Rules r.4 and First Schedule. Rule 4 and s.6(9) came into force on **13 Nov 2026**.

A Data Principal can give, manage, review and withdraw consent through a Consent Manager registered with the Data Protection Board. The Consent Manager keeps its own record of consents given, denied and withdrawn for at least seven years (First Schedule, Part B). The Data Fiduciary still has to prove that notice was given and consent obtained (s.6(10)).

The framework adds three things:

1. **A signed consent history** for every principal, whatever the channel.
2. **An inbound adapter** that verifies and applies Consent Manager events.
3. **Outbound reporting** of withdrawals made directly with the Fiduciary.

> **The schema is provisional.** The Board has not published an interoperability standard for Consent Managers. The built-in `generic` adapter speaks `dpdp-cm-events/0.1`, described below, so you can integrate and test now. When a registered Consent Manager publishes its API, write a plug-in for it (see [Plug-ins](#plug-ins)); nothing else changes.

## The consent history (s.6(10))

Every consent change is appended to one hash chain per principal: `given`, `denied`, `withdrawn`, `expired`, `status_set`, `guardian_verified`, `guardian_revoked`, `reported_to_consent_manager` and `consent_manager_event_refused`.

- **Signing:** each event links to the previous one and is signed with the certificate signer (KMS, Cloud KMS or local Ed25519), so a later edit or deletion breaks verification.
- **Concurrency:** a unique constraint on (principal, previous hash) means two concurrent writers can't fork the chain. The loser re-reads the head and retries.
- **Contents:** pseudonymous ids, purposes, element types, notice versions, the source (`direct`, `consent_manager:<name>`, `children`), the actor, and references such as a session id or the Consent Manager event id. No values: the external id a Consent Manager sends is resolved through the vault and never stored in the history.
- **Erasure:** the history is kept, like rights cases, because it is the Fiduciary's proof. It holds no personal values, only the principal's pseudonymous id.

```bash
dpdp-rights -c config.yaml consent history --external-id cust-1
dpdp-rights -c config.yaml consent verify --external-id cust-1     # exit code 1 if the chain is broken
```

The API is `GET /v1/principals/{external_id}/consent-history`, which returns the events plus a verification result. Roles: the principal (self only), dpo and reviewer.

Direct changes go into the history too. `grant_consent`, `deny_consent` (`POST /v1/consent-denials`) and `withdraw_consent` all accept `actor`, and grants also accept `verification_ref`, which should identify the session, form submission or notice acceptance.

## Configuring a Consent Manager

```yaml
consent_managers:
  - name: acme_cm                       # used in URLs, refs and the history
    type: generic                       # or a consent_managers plug-in
    registration_ref: "DPB/CM/2026/0007"   # the Board registration number
    verification:
      mode: hmac                        # or ed25519 with public_key_pem / public_key_path
      secret_env: ACME_CM_SECRET        # never inline in production
      replay_window_seconds: 300
    purpose_map:                        # the Consent Manager's purpose codes -> your purposes
      MKTG-01: marketing
      SVC-01: service
    element_map:                        # its data items -> element types
      email: EMAIL
      mobile: PHONE_IN
      chat: FREE_TEXT
    id_type: EXTERNAL_ID                # how principal_ref resolves in the vault (e.g. PHONE_IN)
    create_principals: true
    erase_on_withdrawal: true
    erase_on_expiry: true
    report_url: https://cm.example/v1/fiduciary-withdrawals   # optional
```

`check-config` refuses a Consent Manager with no secret or public key, or with an inline secret. It also warns about a replay window over 15 minutes, a missing registration number, and unsigned outbound reports.

## Receiving events

`POST /v1/consent-managers/{name}/events` (add `?tenant=<id>` with tenants). The endpoint is authenticated by the Consent Manager's signature, not by an API credential: each tenant's own configuration supplies the key, so naming another tenant does not help a forger.

**Headers:**
- `X-CM-Timestamp`: Unix seconds.
- `X-CM-Signature`: `sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>` or `ed25519=<base64 signature over "<timestamp>.<body>">`.

Events outside the replay window are refused (401).

**Body** (`dpdp-cm-events/0.1`):

```json
{
  "schema": "dpdp-cm-events/0.1",
  "consent_manager": "acme_cm",
  "events": [
    {
      "event_id": "evt-8f2c",
      "type": "given",
      "occurred_at": "2026-11-18T10:00:00+05:30",
      "artefact": {
        "id": "art-1931",
        "principal_ref": "CUST-000123",
        "purposes": ["MKTG-01"],
        "data_items": ["email", "chat"],
        "notice_version": "2026-11",
        "valid_until": "2027-11-18T00:00:00+05:30"
      },
      "guardian_id": null
    }
  ]
}
```

| Type | What happens |
|---|---|
| `given` | Consent is recorded per mapped purpose and element type, with `consent_manager_ref` set to `<name>:<artefact id>`. It counts only while the artefact is active and before `valid_until`. An empty `data_items` means all element types. |
| `denied` | Recorded in the history; nothing is granted. |
| `withdrawn` | The artefact's consents are withdrawn. For each purpose with no consent left through any channel, a purpose-scoped erasure is queued. The request records the Consent Manager as requester and verifier and the event id as `verification_ref`. Consent still held another way (`still_held`) is not erased. |
| `expired` | The same as `withdrawn`, governed by `erase_on_expiry`. |

**Refusals.** Events that can't be applied are refused and recorded in the history: unmapped purposes or data items, an artefact that has already ended or expired, an unknown principal on a withdrawal, or a child's consent without a verified guardian. Nothing is half-applied, because every purpose is checked before any is granted.

**Exactly once.** Each `(consent manager, event id)` is claimed in `cm_event_receipt` before it is applied. A redelivery returns `duplicate`. A concurrent delivery returns `in_progress`; redeliver it later. If applying fails unexpectedly, the claim is released so a redelivery can apply it.

**Response:** `200`, with one result per event: `applied`, `recorded`, `refused` (with a reason), `duplicate` or `in_progress`. Other statuses: `401` for a bad signature or timestamp, `404` for an unknown Consent Manager, `422` for a body that doesn't match the schema.

**Expiry without an event.** Processing stops as soon as `valid_until` passes. Schedule `dpdp-rights consent-managers expire-due` daily, next to `purge-escrows`, so expired artefacts are also erased.

**Testing without the webhook:** `dpdp-rights consent-managers receive acme_cm --body events.json --timestamp T --signature S` applies a signed file exactly as the webhook would.

## Withdrawals made directly with the Fiduciary

When a principal withdraws in your app, through the rights desk or through `POST /v1/withdrawals`, any of those consents that came from a Consent Manager are reported to its `report_url`. The report is HMAC-signed with the same secret when there is one, and has this shape: `{"schema", "consent_manager", "events": [{"type": "withdrawn", "artefact_id", "purposes", "occurred_at", "withdrawn_via": "data_fiduciary"}]}`.

Reporting is best effort. A failure never blocks the withdrawal and is recorded in the history (`reported_to_consent_manager`, `ok: false`), so operations can follow up. Withdrawals that came from the Consent Manager are not reported back to it.

## Plug-ins

Register a factory in the entry-point group `dpdp_rights.consent_managers`. It is called as `factory(config, opener=None)` and must return an object with:

- `verify(headers, body)`: raise `SignatureError` if the request is not authentic.
- `parse(body) -> list[CmEvent]`: raise `CmEventError` if the body is invalid.
- `report(payload)`: optional.

`CmEvent` has `event_id`, `type`, `artefact_id`, `principal_ref`, `purposes`, `data_items`, `notice_version`, `valid_until`, `occurred_at` and `guardian_id`. Mapping, exactly-once application, the children's rules, erasure and the history are all handled by the framework.

## Limits

- **Provisional schema:** a real Consent Manager integration is a plug-in written against its published API.
- **No pull reconciliation yet:** the framework does not fetch artefact status from the Consent Manager. It relies on events plus `expire-due`.
- **Withdrawals by artefact:** withdrawal applies to the whole artefact. A partial withdrawal (some purposes of an artefact) should arrive as a new artefact or as one event per purpose.
- **Notices are not stored:** the framework records `notice_version` but does not keep the notice text. Keep versioned notices in your content system.
- **Consent Manager obligations stay with it:** the seven-year record, its own interoperability, and the Board's registration conditions are the Consent Manager's obligations, not the framework's.
