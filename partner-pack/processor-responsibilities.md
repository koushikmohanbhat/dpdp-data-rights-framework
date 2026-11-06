# Processor responsibilities template

One row per Data Processor that receives personal data from the AI agent: model providers, cloud
services, observability tools, SaaS systems, BPOs. The Data Fiduciary stays responsible for what its
processors do (Act s.8(1)–(2)). On withdrawal or erasure, processors must stop and erase as well
(s.6(6), s.8(7)). This register records how that happens for each processor, and the evidence for it.

Copy it to the client's engagement folder, fill it in during discovery with procurement and legal, and
keep it in step with the [deployment inventory](inventory.template.yaml). The inventory's `processor` and
`processor_contract` fields feed the coverage report, which flags processors with no contract reference.

**Provider terms change.** Do not copy retention periods from this template or from memory. Read the
provider's current data-use and retention terms. Record the version or date you checked, and re-check
every year. The certificate records the provider-side retention notes you configure.

## Register

| Processor | Service and region | Data elements received | Purposes | How erasure reaches it | Provider-side retention (as checked) | Contract clause | Evidence of erasure | Contact / escalation | Last checked |
|---|---|---|---|---|---|---|---|---|---|
| | | | | Connector `<name>` / manual procedure `<runbook>` / instruction by contract | | | | | |

### Columns

| Column | What to record |
|---|---|
| Service and region | The exact service (for example "Amazon Bedrock, ap-south-1", "Langfuse Cloud EU") and where data is processed and stored |
| Data elements received | Use the same element types as the inventory. Note whether the processor receives tokens only or raw values (for example a contact-centre vendor that records voice) |
| How erasure reaches it | One of: **connector** (name, and its [capability](../docs/capabilities.md) row: item, container, revoke or none); **manual** (runbook ID; recorded per request as a [manual action](../docs/evidence.md#case-log-manual-actions-and-reviews)); **contractual** (the processor deletes on instruction or after a fixed period; recorded as `processor_instructed`, then `processor_confirmed`) |
| Provider-side retention | Anything the processor keeps that you cannot delete through the connector: abuse-monitoring logs, backups, zero-data-retention status, and whether that status is approved in writing |
| Contract clause | The DPA or MSA clause that requires processing only on instructions, security, erasure on instruction, sub-processor notice, and breach notice |
| Evidence of erasure | Where proof comes from: connector verification in the certificate, a manual-action reference, or the processor's written confirmation (store the confirmation in the client's DMS and record its ID, not the document) |

## Worked examples (insurance onboarding agent)

These rows show the level of detail expected. They are **illustrative**: confirm every term, clause and
retention period for the client's actual contracts.

| Processor | Service and region | Data elements | Purposes | How erasure reaches it | Provider-side retention (as checked) | Contract clause | Evidence | Last checked |
|---|---|---|---|---|---|---|---|---|
| Model provider (via Amazon Bedrock) | Bedrock in ap-south-1 | Tokens only (prompts tokenised by `protect()`) | policy_issuance | No stored state when used without features that store data; crypto-shredding covers tokens in any logs | Per AWS service terms for Bedrock; record the version checked | Cloud customer agreement + DPA §… | Certificate shows no Bedrock store in scope; tokens unreadable after shred | |
| OpenAI API (direct) | Region per the client's agreement | Tokens only | policy_issuance | Connector `openai_platform` deletes stored responses and files | Abuse-monitoring retention and ZDR status per the client's agreement; record what was approved | DPA §… | Certificate verification for `openai_platform` | |
| Observability SaaS | Langfuse, region … | Tokens in traces | All | Connector `langfuse` deletes traces by session / user | Backups per vendor DPA | DPA §… | Certificate verification for `langfuse` | |
| Contact-centre vendor | Cloud contact centre, India | NAME, PHONE_IN, FREE_TEXT (voice, raw) | policy_issuance | Manual: runbook CC-07, delete recordings by caller number | Vendor backups … days per contract | MSA schedule 4, clause 7.2 | Case-log manual action with ticket reference | |
| Email campaign platform | Marketing SaaS | EMAIL, NAME | marketing | Manual or vendor API through a plug-in connector; suppression list kept so the person is not re-imported | Suppression entry kept (hashed email) to honour withdrawal | DPA §… | Manual action `processor_confirmed` with the vendor's ticket | |

## Review cadence

| When | What |
|---|---|
| New processor | Add a row before any personal data is sent; add it to the inventory; run `coverage` |
| Every request | Manual and contractual processors get a case-log entry; the reviewer checks `manual_systems_done` |
| Annually | Re-check provider terms and retention; update "Last checked" |
| Processor change or exit | Instruct erasure of all data; record the confirmation; remove the connector and inventory entry |
