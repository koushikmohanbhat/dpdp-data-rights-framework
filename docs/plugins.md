# Plug-ins

Everything that touches a specific cloud, product or client system is a plug-in. A partner adds support
for a client's systems (a CRM, a ticketing tool, Azure, an in-house database) by publishing a small
Python package, without forking this repository. The framework finds installed plug-ins through Python
entry points.

```bash
dpdp-rights plugins          # every plug-in, built-in and installed, with the package it came from
```

A complete example to copy: [`examples/plugin_example`](../examples/plugin_example), with a connector, a
detector and a notifier, and tests that run the conformance kit.

## Plug-in groups

| Group (entry point) | Config field that selects it | The entry point loads | Built-ins |
|---|---|---|---|
| `dpdp_rights.connectors` | `connectors[].type` | A `Connector` subclass | 20 ([capability matrix](capabilities.md)) |
| `dpdp_rights.detectors` | `pii.detectors` (options in `pii.detector_options.<name>`) | A callable `(**options)` returning an object with `detect(text) -> list[Entity]` | regex, aws_comprehend, bedrock_guardrail, gcp_dlp, presidio, transformers_ner, llm |
| `dpdp_rights.key_wrappers` | `vault.key_wrapper`, `vault.sealed_key_wrapper` | A callable `(vault_config, sealed: bool)` returning a `KeyWrapper` (`wrap`, `unwrap`) | local, aws_kms, gcp_kms |
| `dpdp_rights.vault_storage` | `vault.storage` | A callable `(vault_config, lineage_url)` returning a `VaultStorage` | sql, dynamodb, firestore |
| `dpdp_rights.providers` | `provider.type`, `pii.llm.type` | A callable `(provider_config)` returning an `LLMProvider` (`generate`, `embed`) | openai, anthropic, bedrock, vertex, echo |
| `dpdp_rights.queues` | `queue.type` (options in `queue.options`) | A callable `(lineage_store, queue_config)` returning an object with the `JobQueue` interface: `enqueue`, `claim`, `complete`, `fail`, `get`, `counts` | database |
| `dpdp_rights.notifiers` | `notifications[].type` | A callable `(**options)` returning an object with `notify(event, payload)` | webhook, log |

Plug-in-specific settings go in the matching `options` field (`connectors[].options`,
`pii.detector_options`, `vault.options`, `provider.options`, `queue.options`, `notifications[].options`).

Rules:

- The entry-point **name** is the type name in configs. A plug-in cannot take a built-in's name; if it
  tries, it is ignored and `dpdp-rights plugins` reports the clash.
- A plug-in that fails to import is reported by `dpdp-rights plugins` (exit code 1) and by `check-config`.
  The framework only loads plug-ins that a config uses.
- Plug-ins run with the framework's privileges and see tokens, and some (connectors, detectors) see raw
  values. Install only packages you trust, pin their versions, and review them like your own code.

## Declaring entry points

```toml
# pyproject.toml of your package
[project.entry-points."dpdp_rights.connectors"]
zendesk = "acme_dpdp.zendesk:ZendeskConnector"

[project.entry-points."dpdp_rights.detectors"]
employee_id = "acme_dpdp.detectors:EmployeeIdDetector"

[project.entry-points."dpdp_rights.notifiers"]
servicenow = "acme_dpdp.servicenow:ServiceNowNotifier"
```

Then `pip install acme-dpdp` next to the framework (in the container image, add it to the `pip install`
line or the `EXTRAS`), and reference the names in your config.

## Writing a connector

A connector knows how to find, act on and verify personal data in one kind of store.

```python
from dpdp_rights.connectors.base import Capabilities, Connector, Discovered, VerifyResult, redact_tokens
from dpdp_rights.core.models import Action


class ZendeskConnector(Connector):
    supports = {Action.DELETE, Action.REDACT}                 # what it can do natively
    capabilities = Capabilities(                               # required: what it can and cannot do
        store="Zendesk tickets and comments",
        discover="native", discover_how="ticket search by requester external_id",
        verify="rediscover", verify_how="search returns nothing",
        limits=("ticket audit logs cannot be redacted; Zendesk purges them per its retention",),
    )

    def __init__(self, name, subdomain, token_env, **kw): ...

    def discover(self, ctx):          # find data nobody registered (optional, but strongly recommended)
        return [Discovered("ticket", {"id": t.id}) for t in self._search(ctx.principal_id, ctx.tokens)]

    def _delete(self, artifact, ctx, fallback_from=None): ...   # return self._ok(artifact, Action.DELETE)
    def _redact(self, artifact, ctx): ...                         # replace ctx.tokens with [ERASED]
    def verify(self, ctx):                                        # default: re-run discover()
        ...
```

What the framework expects:

| Topic | Rule |
|---|---|
| `supports` | Only actions the store really performs. A redact request on a connector without `REDACT` falls back to delete. |
| `capabilities` | Required. `discover` is `native` (finds unregistered data) or `lineage` (acts on registered items only). `verify` is `rescan`, `rediscover`, `api_confirmation`, `action_status` or `none`. `deletion` says what "delete" removes (`item`, `container`, `revoke`, `none`). `limits` are plain-language statements of what the service does not allow. Production `check-config` refuses connectors without capabilities. |
| Results | Return `self._ok(...)` with useful detail. Never raise for "not supported": return a result. Raise only on transient errors (network, throttling): the job queue retries, and a retried run skips completed actions. |
| Idempotency | Acting twice on the same item must succeed (deleting something already gone is success). |
| Raw values | `ctx.probes` holds raw values in memory during the run, for verification only. Never log or store them. |
| Credentials | Read secrets from the environment or a secrets manager named in options, never from inline config. |
| IAM | Document the permissions the connector needs (see the table in [connectors.md](connectors.md)). |

## Writing other plug-ins

- **Detector**: `detect(text)` returns `Entity(type, start, end, text, score)` for each finding, with
  offsets into `text`. Set a class attribute `ner = True` only if it finds names, addresses or free text
  (it then satisfies the production rule that requires an NER detector).
- **Key wrapper**: `wrap(dek: bytes) -> bytes` and `unwrap(blob: bytes) -> bytes`, backed by an HSM or KMS
  (Azure Key Vault, HashiCorp Vault, CloudHSM). The sealed variant (`sealed=True`) must use a separate key
  that application credentials cannot decrypt.
- **Vault storage**: implement the `VaultStorage` interface in `dpdp_rights/vault/storage.py`, and run the
  vault tests against it.
- **Provider**: `generate(prompt, system=None, **kw)` returning an object with `.text`, and
  `embed(texts) -> list[list[float]]`. Providers only ever receive tokenised text.
- **Queue**: the `JobQueue` interface; `claim` must lease a job so that two workers never run it at once,
  and `fail` must return `"failed"` after the last attempt.
- **Notifier**: `notify(event, payload)`. Payloads contain no personal data (request id, pseudonymous
  principal id, status, counts, certificate hash). Raise on failure; the framework logs it and carries on.
  Events: `request_completed`, `request_completed_with_exceptions`, `request_failed`, `request_planned`.

## Conformance kit

Every connector, built-in or plug-in, should pass the same suite. It drives the real framework
(tokenisation, lineage, policy, erasure, verification) against your connector with synthetic Indian
personal data, in a sandbox you provide.

```python
# tests/test_zendesk_conformance.py
from dpdp_rights.testing.conformance import ConnectorConformance, ConnectorHarness


class ZendeskHarness(ConnectorHarness):
    def connector(self):
        return ZendeskConnector("sut", subdomain="acme-sandbox", token_env="ZENDESK_SANDBOX_TOKEN")

    def write(self, record_id, content, principal_id):
        ticket = sandbox.create_ticket(external_id=principal_id, body=content, tag=record_id)
        return {"id": ticket.id}

    def read(self, locator):
        t = sandbox.get_ticket(locator["id"])
        return t.body if t else None

    def cleanup(self):
        sandbox.delete_tickets(tag_prefix="r-")


class TestZendeskConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return ZendeskHarness()
```

```bash
pip install "dpdp-data-rights-framework[testing]"
pytest tests/test_zendesk_conformance.py -rs        # -rs shows why any test was skipped
```

| Test | Checks |
|---|---|
| `test_declares_capabilities` | Capabilities are declared and consistent with `supports` |
| `test_erases_registered_record` | A tracked record is deleted, or left unreadable; verification passes |
| `test_discovers_unregistered_record` | A record written without `track_artifact` is found and erased (native discovery only) |
| `test_mention_in_another_persons_record` | A record owned by someone else that names the person is redacted (keeping the owner's data) where the store allows, otherwise removed |
| `test_verification_catches_raw_values` | A raw value written by a legacy job is reported by verification (rescan verifiers only) |
| `test_dry_run_changes_nothing` | A dry run leaves the store untouched |
| `test_rerun_is_safe` | Erasing twice succeeds |
| `test_unsupported_action_is_reported_not_raised` | Unsupported actions return a result instead of raising |

Tests that a connector's declared capabilities rule out are **skipped with the reason**, so the test
report also documents what the connector does not do. Attach it to the engagement's acceptance evidence
([implementation plan](../partner-pack/implementation-plan.md#acceptance-criteria)).

The built-in SQL, JSONL, log file, Redis, S3 and DynamoDB connectors run this kit in CI
(`tests/test_conformance_builtin.py`, using fakeredis and moto); the cloud connectors also have live tests
([testing.md](testing.md)).

Synthetic people for your own tests: `from dpdp_rights.testing.synthetic import people` (names, emails
on `example.com`, +91 mobiles, Verhoeff-valid Aadhaar numbers, PANs, UPI IDs, addresses with PIN codes).
