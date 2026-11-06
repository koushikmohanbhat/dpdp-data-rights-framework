# Operations runbook

For the team that runs the framework day to day: the DPO office, platform engineers and on-call.
Commands assume the AWS deployment from [deploy-aws.md](deploy-aws.md); the API and CLI are the same
on Google Cloud.

```bash
API=<api_url output>                     # internal Rights API
dpdp-rights -c "$DPDP_CONFIG" <command>  # CLI, run where the config and its environment are available
```

## Daily and weekly checks

| When | Check | How |
|---|---|---|
| Daily | No requests overdue or close to due | `GET /v1/sla` or `dpdp-rights sla`; alarm on `dpdp.erasure.open{sla=overdue}` |
| Daily | No failed jobs | `GET /v1/sla` → `jobs.failed` |
| Daily | Escrow purge ran | Scheduler invocation succeeded; worker log line for `purge-escrows` |
| Weekly | Requests that ended `completed_with_exceptions` reviewed | Read the certificate's `failures` and `exceptions` |
| Weekly | Break-glass audit reviewed | `GET /v1/break-glass/audit` |
| Monthly | Certificates verify | `dpdp-rights verify-certificate --request-id <id>` on a sample |
| Quarterly | Connector coverage still matches the agent's stores | Dry-run erasure for a test principal; compare with your store inventory |
| Quarterly | Live integration suite in a non-production account | [testing.md](testing.md) |

## Request lifecycle

```
received ─► planned ─► executing ─► verifying ─► completed
                                         └─────► completed_with_exceptions
         (any stage, after retries) ───────────► failed
```

| Status | Meaning | Action |
|---|---|---|
| `received` | Queued, not yet picked up | None, unless it stays here: check the worker |
| `planned`, `executing`, `verifying` | In progress | None |
| `completed` | Every action succeeded and every store verified clean | None |
| `completed_with_exceptions` | Done, but some action failed or verification found a token or raw value | Investigate (below) |
| `failed` | The job failed `queue.max_attempts` times | Fix the cause and resubmit (below) |

Legal holds, retained aggregates and models flagged for retraining are listed as **exceptions** in
the certificate with their reason. They are expected outcomes, not failures.

## Handling a request that ended with exceptions

1. Get the request and certificate:
   ```bash
   curl -s "$API/v1/erasure-requests/<id>" -H "authorization: Bearer $DPO_JWT"
   curl -s "$API/v1/erasure-requests/<id>/certificate" -H "authorization: Bearer $DPO_JWT"
   ```
2. Look at `failures` (actions that returned an error) and `verification` (per connector: passed,
   and what was found where).
3. Typical causes:

   | Finding | Cause | Fix |
   |---|---|---|
   | `AccessDenied` on a store | Missing IAM permission | Add it to the policy in `extra_task_policy_arns` |
   | Raw value found in a log or trace | Something logged without the logging filter or tokenising exporter | Fix the emitter; the value is under the principal's now-destroyed key only if it was tokenised, so a raw leak needs the log stream or object deleted |
   | Token found after delete | Eventual consistency (search indexes, Logs Insights) | Re-run verification later by resubmitting; if it persists, the item was copied somewhere untracked |
   | Store unreachable | Network or throttling | Resubmit once resolved |

4. Resubmit for the same person (`POST /v1/erasure-requests` with a new `Idempotency-Key`). The new
   run rediscovers what is left; items already erased are not touched again.
5. If a raw value cannot be removed (for example an immutable third-party log), record the reason and
   the compensating control in your case file, and escalate to the DPO.

## Handling a failed request

Jobs are retried with backoff (`queue.backoff_seconds`) up to `queue.max_attempts`. A run that
stopped halfway resumes where it stopped: it does not redo completed actions, and it recovers the
token list from lineage if the principal's key was already destroyed. A job that still fails is marked
`failed`.

1. Read the error: worker logs (`/ecs/<name>/worker`) filtered by the request ID, or the trace in
   X-Ray by `dpdp.request_id`.
2. Fix the cause (permissions, a connector option, an unreachable store).
3. Resubmit with a new `Idempotency-Key`.

For a one-off run with full output in your terminal, use the CLI from an environment with the
production config and role:

```bash
dpdp-rights -c "$DPDP_CONFIG" erase --principal-id <dp_...> --dry-run     # plan only
dpdp-rights -c "$DPDP_CONFIG" erase --principal-id <dp_...>
```

## SLA

Each erasure or withdrawal request gets `due_by = received + policy.sla_days` (default 30). Set
`sla_days` to the response period you publish under Rule 14, never above 90. Grievances are a separate
clock (Rule 14(3): at most 90 days) handled in your own case system; attach the request's certificate
and audit trail as evidence. See [Rule 14(3) response times](dpdp-mapping.md#rule-143-response-times).
`/v1/sla` reports open requests as `ok`, `due_soon` (7 days or less) and `overdue`, plus queue depth.

## Break-glass access

Sealed data (legal holds, statutory retention escrow) cannot be read by the application. Reading it
needs two people and leaves an audit trail.

1. **Request** (role `dpo`), with a reason and a ticket reference:
   ```bash
   curl -XPOST "$API/v1/break-glass/grants" -H "authorization: Bearer $DPO_JWT" \
     -H 'content-type: application/json' \
     -d '{"principal_id":"dp_...","reason":"Regulator request ref ...","ticket_ref":"LEGAL-231"}'
   ```
2. **Approve** (role `approver`, and a different person from the requester):
   `POST /v1/break-glass/grants/<grant_id>/approve`
3. **Read** specific tokens (role `dpo`) within `break_glass.max_grant_minutes` (default 60):
   ```bash
   curl -XPOST "$API/v1/break-glass/grants/<grant_id>/read" -H "authorization: Bearer $DPO_JWT" \
     -H 'content-type: application/json' -d '{"tokens":["PAN_1a2b3c4d5e6f"]}'
   ```
   The API task assumes the break-glass role to decrypt, inside the approved grant only
   (`allow_app_break_glass = true`). If you set it to `false`, the read endpoint cannot decrypt, and
   sealed data can only be read by a DPO who assumes the break-glass role with MFA, outside the API.
4. **Revoke** when done: `POST /v1/break-glass/grants/<grant_id>/revoke`.
5. Every request, approval, read and denial is in `GET /v1/break-glass/audit` and in CloudTrail
   (`AssumeRole` on the break-glass role, `Decrypt` on the sealed key).

Alert on any `AssumeRole` of the break-glass role and any `Decrypt` on the sealed key, and review
each against an approved grant.

## Statutory retention and escrow purge

When a principal's key is destroyed, their identifiers are kept in escrow, sealed under the separate key, for
`policy.statutory_retention` (DPDP Rules 8(3): one year by default). This does not archive full records;
keep log groups for at least a year as well ([details](dpdp-mapping.md#rule-83-one-year-retention)). `purge-escrows` destroys escrows
whose period has ended and records `escrow_purged` on the original request.

- AWS: EventBridge Scheduler runs the worker task with `purge-escrows` daily
  (`purge_escrows_schedule`).
- Run it by hand: `dpdp-rights -c "$DPDP_CONFIG" purge-escrows`.

If the schedule fails for a few days nothing is lost; the next run purges everything that is due.

## Keys

| Key | Rotation | Notes |
|---|---|---|
| Vault KMS key | Automatic yearly rotation (enabled by Terraform) | Old key material stays available for unwrapping; nothing to re-encrypt |
| Sealed KMS key | Automatic yearly rotation | Same |
| Certificate signing key (asymmetric) | Not rotated automatically | To rotate: create a new key, point `certificates.key_id` at it, apply. Keep the old key enabled so old certificates still verify |
| Per-principal data keys | Not rotated | Destroyed on erasure (crypto-shredding) |
| Service API keys | Your schedule | Add the new hash next to the old one, deploy, switch the backend, remove the old one |

**Never schedule deletion of the vault KMS key** in production: every token for every principal
becomes unreadable. Scheduling deletion of the sealed key ends statutory retention for everyone early.
Restrict `kms:ScheduleKeyDeletion` on these keys with an SCP or key policy.

## Certificates

Each completed request has a certificate: every artifact, action, exception with its legal basis,
verification result, and how the request was verified upstream. Certificates are hash-chained (each
includes the previous one's hash), signed with the KMS signing key, and archived to the Object Lock
bucket.

```bash
dpdp-rights -c "$DPDP_CONFIG" certificate --request-id <id>          # print
dpdp-rights -c "$DPDP_CONFIG" verify-certificate --request-id <id>   # hash, chain link, signature
```

For an audit or a Data Protection Board inquiry, export the certificates for the period from the
bucket together with the break-glass audit and the config version in force.

## Changing purposes, connectors and policy

1. Edit your config (outside the repository), run `check-config`.
2. Dry-run an erasure for a test principal to see the effect.
3. Apply (Terraform updates the SSM parameter) and restart the API and worker services.

Removing a connector does not remove lineage for its artifacts; erasure will report them as
unreachable. Keep a connector until its store is decommissioned and empty.

## Upgrades

1. Read the release notes.
2. Build and push the new image tag, set `image_tag`, `terraform apply`. ECS rolls the services and
   rolls back automatically if new tasks fail health checks.
3. The framework adds tables and columns on start and never drops data, so there are no migration
   steps. Take an RDS snapshot first anyway.
4. Run the live integration suite in your non-production account for releases that change connectors.

## Backups and disaster recovery

| Data | Protection | Note |
|---|---|---|
| Control plane (RDS) | Automated backups, Multi-AZ | Holds consent, lineage, requests and jobs; restore to a point in time |
| Vault (DynamoDB) | Point-in-time recovery | **Restoring an old copy can bring back destroyed keys.** After any restore, re-run `purge-escrows` and re-apply erasures completed since the restore point (list them from RDS) |
| Certificates (S3) | Object Lock, versioning | Immutable |
| Config | SSM and your private repository | Your copy outside this repository is the source of truth |

The same caution applies to backups of your own stores: a restored backup can contain data that was
erased. Keep a record of completed erasures and re-apply them after any restore.

## Troubleshooting

| Symptom | Check |
|---|---|
| Requests stay `received` | Worker service running? Worker logs? Can it reach RDS? |
| `401` from the API | Wrong key, or the hash in the config does not match; Cognito token expired or wrong audience |
| `403` from the API | Caller lacks the role; a `principal` acting on someone else's data |
| `403 ConsentDenied` from the agent | Working as intended: no consent for that purpose and element types |
| Erasure plan misses a store | No connector for it, or the agent never called `track_artifact` and the connector cannot search by principal |
| Verification fails on CloudWatch right after an erasure | Logs Insights indexing delay; resubmit later |
| Certificate signature does not verify | Signing key changed or disabled; the certificate was edited; check the hash chain |
| Tasks restart in a loop | Config error at start; read the first lines of the task log |
| High latency in `protect()` | Comprehend or Guardrails calls; consider regex-only for low-risk paths, and check the DEK cache TTL |
