# Model gateway: DPDP controls in front of existing agents

For brownfield apps and low-code builders, where changing code is slow: put the gateway between the app and its model and change one URL. There are two ways to run it:

- **The built-in OpenAI-compatible endpoint** in the Rights API: `/v1/gateway/openai/v1/chat/completions`, `/responses` and `/embeddings`.
- **A LiteLLM guardrail**, `dpdp_rights.integrations.litellm.DPDPGuardrail`, for teams that already run LiteLLM in front of their models (verified against LiteLLM 1.110).

Both use the same engine and the `gateway` section of the config.

## What a gateway can and cannot do

A gateway only sees **model traffic**. Agent memory, vector stores, CRMs, tickets and the app's own logs never pass through it. So:

- **It can:**
  - measure what personal data reaches which model, for which purpose (observe);
  - refuse calls without consent;
  - keep raw identifiers out of prompts and out of the provider's logs and retention (enforce).
- **It cannot:**
  - build lineage for the app's own stores;
  - make erasure complete.

That still needs `protect()` and `track_artifact()` or the framework integrations ([integration guide](integration-guide.md), [agent frameworks](agent-frameworks.md)). Use the gateway as the first layer and as discovery evidence, then instrument.

## Modes

| | `observe` | `enforce` |
|---|---|---|
| Request to the model | Unchanged | Every text field tokenised; Responses API `store` forced to `false` |
| No person identified | Recorded | `block` (403, default) or `mask` (irreversible `[EMAIL]` placeholders) |
| No consent for the purpose | Recorded as what enforce *would* do | 403, OpenAI-style error with `code` such as `blocked:consent` |
| Recorded | Counts per kind of personal data, purpose, model, and the would-be decision | Counts and the decision |
| Values stored | None | Tokens in the vault, as with `protect()` |

**Which fields are tokenised:**
- **Chat:** message `content` (strings and `text` parts) and tool-call `arguments`.
- **Responses:** `instructions`, string `input`, and in input items `content` text parts, `output` and `arguments`.
- **Embeddings:** `input`.

Roles, ids, tool names, images, files and audio are never touched.

**Revealing responses.** With `reveal_responses: true`, tokens in the response are turned back into real values for the person, so the end user sees their own email address. The app then holds real values again (in its database and its logs), so leave it off when the app can display tokens or resolve them itself. Streaming isn't supported together with reveal; streaming otherwise passes straight through.

## Binding the person to authentication

In **enforce** mode, the gateway acts for one person: it tokenises under their key, checks their consent and, with `reveal_responses`, reveals their values. So the caller must not be able to choose who that person is. If the person came straight from a header or the `user` field, anyone holding a service key could name someone else. They could pass that person's consent check, and with reveal on, send that person's token (found in a log, say) and have the model repeat it back as the raw value.

`gateway.principal_binding` decides where the person comes from:

| Binding | The person is | Use it when |
|---|---|---|
| `signed` (default) | The `sub` of a short-lived assertion in `X-DPDP-Assertion`, minted by the app's backend after it authenticated its user, with the HMAC secret in `DPDP_GATEWAY_ASSERTION_SECRET` (32+ characters) | A backend calls the gateway on behalf of its users (most apps) |
| `subject` | The authenticated caller's own subject: an OIDC end-user token with role `principal` | End users call the gateway with their own tokens |
| `key` | `dpdp_principal` in a LiteLLM virtual key's metadata, which only the proxy admin can set | One LiteLLM key per end user or per service account |
| `header` | Whatever `X-DPDP-Principal` or `user` says | Development only. `check-config` refuses it in production together with `reveal_responses`, and warns otherwise |

**Claims must agree with the binding.** The headers `X-DPDP-Principal` and `X-DPDP-Purpose`, `dpdp_principal` in request metadata, and the `user` field are what the request *claims*. With any binding but `header`:
- a claim naming a different person is refused (`blocked:principal_mismatch`);
- a claim without the binding's proof is refused (`blocked:unverified_principal`);
- a purpose that differs from the assertion's is refused (`blocked:purpose_mismatch`).

Missing, expired, over-long, tampered or malformed assertions are refused (`blocked:bad_assertion`), and nothing is created. Reveal is always limited to the bound person's own tokens, so another person's token in a response stays a token.

**Minting an assertion** in the app's backend, right after it has authenticated the user:

```python
from dpdp_rights.gateway import mint_assertion

assertion = mint_assertion(os.environ["DPDP_GATEWAY_ASSERTION_SECRET"], customer_id, "support", ttl_seconds=300)
client = OpenAI(base_url=".../v1/gateway/openai/v1", api_key=SERVICE_KEY,
                default_headers={"X-DPDP-Assertion": assertion})
```

The format is `v1.<payload>.<signature>`: URL-safe base64 of `{"sub", "purpose", "iat", "exp"}`, and HMAC-SHA256 over `v1.<payload>`, so a backend in any language can produce it. Lifetimes over `assertion_max_ttl_seconds` (default 900) are refused, with 30 seconds of clock skew allowed. An assertion is a bearer credential until it expires, so keep lifetimes short and the secret in a secrets manager.

**Observe mode** takes the claims as given, because it creates nothing, tokenises nothing and reveals nothing; it only counts.

**Purpose:** from the assertion (`signed`), the key's `dpdp_purpose` (`key`), the purpose header, or `default_purpose`.

## The built-in endpoint

```yaml
gateway:
  enabled: true
  mode: enforce
  upstream_base_url: https://api.openai.com/v1   # any OpenAI-compatible upstream: Azure OpenAI, vLLM, LiteLLM
  upstream_api_key_env: OPENAI_API_KEY
```

The app keeps its OpenAI SDK and changes the base URL and key:

```python
client = OpenAI(base_url="https://dpdp-api.internal/v1/gateway/openai/v1", api_key="<this API's key, role service>",
                default_headers={"X-DPDP-Assertion": mint_assertion(secret, customer_id, "support")})
```

The gateway authenticates the caller with this API's own keys (sent as the bearer token, as SDKs do) and calls the upstream with its own key. Upstream errors are passed back with their status code.

## LiteLLM

```yaml
# litellm config.yaml (full example: examples/gateway/litellm.config.yaml)
guardrails:
  - guardrail_name: dpdp
    litellm_params:
      guardrail: dpdp_rights.integrations.litellm.DPDPGuardrail
      mode: [pre_call, post_call]
      default_on: true
      dpdp_config: /etc/dpdp/config.yaml     # or DPDP_CONFIG
```

Use `principal_binding: key` (with `dpdp_principal` and `dpdp_purpose` in each virtual key's metadata) or `signed` (the app sends `X-DPDP-Assertion`). Request metadata from the caller is a claim, never a source of the person. Install `dpdp-data-rights-framework` in the LiteLLM image. Refusals come back as LiteLLM's 403 with `provider_specific_fields.code` set, for example `blocked:missing_principal`. LiteLLM isn't a dependency of this package.

## The report

```bash
dpdp-rights -c config.yaml gateway report --since 2026-11-01T00:00:00+05:30 --format md
```

The API equivalent is `GET /v1/gateway/report?since=...` (roles dpo and reviewer). It shows:
- the number of requests, and the share carrying personal data;
- the share where the person was identified;
- detections by kind of personal data;
- requests by purpose and by model;
- decisions, and what enforce mode would have decided.

In a [rapid assessment](../partner-pack/rapid-assessment.md), a week of observe mode in front of the client's agent produces this evidence. Observation rows hold no values and no person ids; turn them off with `record_observations: false`.

## Production checks

`check-config` flags:
- **Error:** a non-https upstream.
- **Warnings:**
  - observe mode, which protects nothing;
  - `enforce_consent` off;
  - `missing_principal: mask`;
  - `reveal_responses` on;
  - `force_store_false` off.

## Limits

- **Model traffic only**, as above.
- **No reveal while streaming.** When streaming, the response passes through unchanged.
- **Accuracy:** detection is only as good as the configured detectors ([PII detection](pii-detection.md)). The report counts what was found, not what was missed.
- **No lineage:** the gateway registers no lineage artifacts. Provider-side state is covered by the provider connectors (`openai_platform`, `anthropic_platform`).
- **Not an API gateway:** run it behind your own gateway or WAF, with TLS and rate limits ([security](security.md)).
