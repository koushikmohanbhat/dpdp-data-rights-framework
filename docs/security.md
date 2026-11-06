# Security and production hardening

This page describes the security controls in the framework, what you must configure for
production, and what remains your responsibility.

Set `environment: production` in the config. The framework then **refuses to start** with
development-only settings (see [Production guardrails](#production-guardrails)). Run
`dpdp-rights -c <config> check-config` in CI to catch these issues before deploy.

## Threat model in brief

| Threat | Control |
|---|---|
| Raw personal data leaks into logs, traces, prompts, vectors, caches | Tokenisation at the edge; tokenising log filter; tokenising span exporter; masking when no principal is known; verification scans for raw values |
| Someone files an erasure or withdrawal for another person | Requester identity is verified upstream by the deployer; the API is authenticated, principals can only act on their own data, and `verified_by` / `verification_ref` are recorded on every request and certificate |
| Unauthorised API use | API keys (hashed) and OIDC JWTs, role checks on every endpoint |
| Insider reads sealed (legal-hold / escrow) data | Separate sealed KEK that only a break-glass role can decrypt; two-person grants; time-boxed; every attempt audited |
| Erasure silently fails halfway | Durable job queue with leases and retries; runs resume without repeating work; failures recorded in the certificate |
| Evidence is altered after the fact | Certificates hash-chained, signed with KMS asymmetric keys, archived to S3 Object Lock / GCS locked buckets |
| One tenant sees another tenant's data | Silo model: each tenant has its own database, vault and keys; tenant taken from the credential only |
| Unwrapped keys linger in memory | DEK cache TTL (default 300 s); sealed keys never cached |
| Vulnerable dependencies / tampered releases | Dependabot, CodeQL, pip-audit, SBOM and build provenance attestation on release |

## Controls in detail

### Encryption and key management
- One AES-256-GCM data key (DEK) per Data Principal, wrapped by a key-encryption key in
  **AWS KMS** (encryption context = principal id) or **Google Cloud KMS** (AAD = principal id).
- Values are encrypted with the token as associated data; tokens are `HMAC(DEK, type|value)`.
- **Sealed keys** (`hold_*`, `escrow_*`) are wrapped by a *separate* KEK
  (`vault.sealed_key_wrapper`). The application role may only `Encrypt` with it; `Decrypt` is
  reserved for the break-glass role (`deploy/terraform/*/security.tf`). On AWS the framework
  assumes `vault.sealed_role_arn` only for sealed unwraps.
- Keep the vault in a separate AWS account / GCP project from the lineage database and apps.

### Authentication and authorization (Rights API)
- `api.auth.mode`: `api_key`, `oidc` or `both`. `none` is rejected in production.
- API keys are stored as SHA-256 digests (`dpdp-rights hash-api-key <key>`), compared in constant time.
- OIDC: any issuer with a JWKS endpoint (Cognito, Google Identity Platform, Entra ID, Okta,
  Auth0, Keycloak). `iss`, `aud`, `exp`, `iat`, `sub` are required and verified.
- Roles: `principal` (self-service, own data only), `service`, `dpo`, `approver`, `admin`.

| Endpoint | Roles |
|---|---|
| `POST /v1/consents` | service, dpo |
| `POST /v1/withdrawals`, `POST /v1/erasure-requests` | principal (own), service, dpo |
| `GET /v1/erasure-requests/{id}` and `/certificate` | owner principal, service, dpo |
| `GET .../certificate/verify`, `/v1/principals/{id}/lineage`, `/v1/sla` | dpo |
| `POST /v1/break-glass/grants`, `.../read` | dpo |
| `POST /v1/break-glass/grants/{id}/approve` | approver |

### Requester identity verification (upstream)
The framework does **not** verify the Data Principal's identity itself. Requests are expected to
arrive already verified through the deployer's own channel: app or web login, KYC re-check, OTP in
the customer's existing app, contact-centre process, or branch visit. The API records:

- `requested_by`: the authenticated caller (API key name or OIDC identity)
- `verified_by`: the system or person that verified the requester (`self:<identity>` when a principal
  submits through their own authenticated session)
- `verification_ref`: a reference to that verification (session id, KYC check id, case number)

All three appear on the request and in the signed certificate. A principal authenticated through
OIDC can only submit requests for their own `external_id`.

### Durable processing
Verified requests become jobs in the control-plane database. Run `dpdp-rights worker` (ECS service,
Cloud Run job, Kubernetes deployment). Jobs are leased (default 300 s), retried with exponential
backoff, and deduplicated by idempotency key (send an `Idempotency-Key` header on submissions).
If a worker dies mid-run, the next attempt skips completed actions, never shreds the vault twice,
and a finished request simply returns its certificate.

### Certificates
Each certificate payload is hashed, chained to the previous certificate, signed
(`certificates.signer`: `aws_kms` with an `ECC_NIST_P256` key, `gcp_kms` with
`EC_SIGN_P256_SHA256`, or `local` Ed25519 for development), and archived
(`certificates.archive`: `s3` with Object Lock COMPLIANCE, `gcs` with a locked retention policy).
Check one with `dpdp-rights verify-certificate --request-id ...` or
`GET /v1/erasure-requests/{id}/certificate/verify`.

### Break-glass access to sealed data
1. A DPO requests a grant with a reason and ticket reference.
2. A different person with the `approver` role approves it (two-person rule).
3. The requester reads specific tokens within the grant window (default 60 min).
Every request, approval, denial and read is written to `access_log` (`GET /v1/break-glass/audit`).

### Tenant isolation
List tenants under `tenants:` in the root config, each pointing to its own config with its own
`lineage.url`, vault storage and KMS keys. The API resolves the tenant from the API key's `tenant`
or the OIDC `tenant` claim. In production, startup fails if two tenants share a database or key.

### Logging and tracing hygiene
- `logging_filter()` tokenises messages inside a DPDP context and **masks** detected PII outside one.
- OpenTelemetry: see [observability.md](observability.md). Spans are tagged with the pseudonymous
  principal and tokenised before export; the collector configs add a redaction processor.

## Production guardrails

`environment: production` blocks startup on: local key wrapper; echo model; SQLite lineage DB;
`api.auth.mode: none`; malformed API key digests; `verification.notifier: log`; unsigned
certificates; regex-only PII detection (unless `pii.allow_regex_only` is set after review); local
sealed key wrapper. It warns on: no separate sealed KEK; vault sharing the lineage DB; local
certificate signer; non-immutable archive; long DEK cache TTL; verification disabled.

## Your responsibilities

- Network: run the API behind a private load balancer / API gateway with TLS, WAF and rate limits.
- Database: PostgreSQL with TLS, encryption at rest, backups, least-privilege users; restrict who can
  read `access_log` and certificates.
- Identity: MFA for DPO and approver accounts; rotate API keys; short JWT lifetimes.
- Deletion windows: database PITR and backups keep wrapped keys for their retention window. Data stays
  unreadable once the live key is gone, but document the window.
- Legal: validate purposes, legal holds, retention periods and the k-anonymity threshold with counsel.
- Pen-test the deployment; this repository has not been independently audited.
