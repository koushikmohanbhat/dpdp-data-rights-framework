"""Model gateway: observe and enforce modes, the OpenAI-compatible endpoint, the LiteLLM guardrail, pii-scan."""
import asyncio
import json
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from test_rights import _cfg

from dpdp_rights import DataRightsFramework
from dpdp_rights.api.app import create_app
from dpdp_rights.core.models import utcnow
from dpdp_rights.gateway import GatewayRefused, mint_assertion, report_markdown
from dpdp_rights.security.auth import hash_api_key
from dpdp_rights.security.guardrails import production_issues

EMAIL, PHONE = "asha.k@example.in", "9876543210"
SECRET = "test-assertion-secret-0123456789abcdef"


def _assert(ext="cust-1", purpose="service", **kw):
    return mint_assertion(SECRET, ext, purpose, **kw)


# What an app's backend sends after authenticating its user: the signed assertion (and, optionally, matching claims).
H = {"x-dpdp-principal": "cust-1", "x-dpdp-purpose": "service", "x-dpdp-assertion": _assert()}


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("DPDP_GATEWAY_ASSERTION_SECRET", SECRET)


def _gw(tmp, **gw):
    return _cfg(tmp, gateway={"enabled": True, **gw})


@pytest.fixture
def obs(workdir):
    return DataRightsFramework(_gw(workdir[0]))


@pytest.fixture
def enf(workdir):
    return DataRightsFramework(_gw(workdir[0], mode="enforce"))


def _chat(text=f"My email is {EMAIL}, call {PHONE}"):
    return {"model": "gpt-5", "messages": [
        {"role": "system", "content": "You are a helpful agent."},
        {"role": "user", "content": [{"type": "text", "text": text},
                                     {"type": "image_url", "image_url": {"url": "data:image/png;base64,OTg3NjU0MzIxMA=="}}]},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "type": "function", "function": {
            "name": "lookup_customer", "arguments": json.dumps({"phone": PHONE})}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": f"found {EMAIL}"}]}


def _consent(f, ext="cust-1", purpose="service"):
    pid = f.principal(ext)
    f.grant_consent(pid, purpose)
    return pid


# ---- observe -------------------------------------------------------------------------------------------------------
def test_observe_passes_the_request_through_unchanged_and_records_counts_only(obs):
    body = _chat()
    out, st = obs.gateway.inbound("chat", body, H)
    assert out is body and json.dumps(out) == json.dumps(_chat())
    assert st.entities["EMAIL"] == 2 and st.entities["PHONE_IN"] == 2
    assert st.would == "blocked:no_consent_record"         # nobody known yet: enforce would refuse
    rows = obs.store.gateway_observations()
    assert len(rows) == 1 and rows[0]["mode"] == "observe" and rows[0]["entities"]["EMAIL"] == 2
    assert EMAIL not in json.dumps(rows, default=str) and PHONE not in json.dumps(rows, default=str)
    assert obs.vault.resolve_principal("cust-1", create=False) is None   # observing creates no one


@pytest.mark.parametrize("headers,setup,would", [
    ({}, None, "blocked:missing_principal"),
    ({"x-dpdp-principal": "cust-1"}, None, "blocked:missing_purpose"),
    ({"x-dpdp-principal": "cust-1", "x-dpdp-purpose": "nope"}, None, "blocked:unknown_purpose"),
    (H, "consent", "tokenised"),
    (H, "principal", "blocked:consent"),
])
def test_observe_says_what_enforce_mode_would_have_decided(obs, headers, setup, would):
    if setup == "consent":
        _consent(obs)
    elif setup == "principal":
        obs.principal("cust-1")
    _, st = obs.gateway.inbound("chat", _chat(), headers)
    assert st.would == would


# ---- enforce ---------------------------------------------------------------------------------------------------------
def test_enforce_tokenises_every_text_field_and_nothing_else(enf):
    _consent(enf)
    body = _chat()
    out, st = enf.gateway.inbound("chat", body, H)
    text = json.dumps(out)
    assert EMAIL not in text and PHONE not in text
    assert out["messages"][1]["content"][1] == body["messages"][1]["content"][1]      # image untouched
    assert out["messages"][2]["tool_calls"][0]["function"]["name"] == "lookup_customer"
    assert "<PHONE_IN_" in json.loads(out["messages"][2]["tool_calls"][0]["function"]["arguments"])["phone"]
    assert out["messages"][0]["content"] == "You are a helpful agent." and out["messages"][3]["tool_call_id"] == "call_1"
    assert body["messages"][3]["content"] == f"found {EMAIL}"                       # the caller's dict is not changed
    assert st.decision == "tokenised" and st.entities["EMAIL"] == 2


def test_enforce_refuses_without_consent_and_records_the_refusal(enf):
    enf.principal("cust-1")
    with pytest.raises(GatewayRefused) as e:
        enf.gateway.inbound("chat", _chat(), H)
    assert e.value.status == 403 and e.value.decision == "blocked:consent"
    assert enf.store.gateway_observations()[-1]["decision"] == "blocked:consent"


def test_enforce_without_a_person_blocks_or_masks(workdir):
    tmp, _ = workdir
    f = DataRightsFramework(_gw(tmp, mode="enforce"))
    with pytest.raises(GatewayRefused, match="x-dpdp-assertion") as e:
        f.gateway.inbound("chat", _chat(), {"x-dpdp-purpose": "service"})
    assert e.value.decision == "blocked:missing_principal"
    m = DataRightsFramework(_gw(tmp, mode="enforce", missing_principal="mask"))
    out, st = m.gateway.inbound("chat", _chat(), {})
    assert "[EMAIL]" in json.dumps(out) and EMAIL not in json.dumps(out) and st.decision == "masked"


def test_the_user_field_and_a_default_purpose_identify_the_call(workdir):
    tmp, _ = workdir
    f = DataRightsFramework(_gw(tmp, mode="enforce", default_purpose="service", principal_binding="header"))
    _consent(f)
    out, st = f.gateway.inbound("chat", _chat() | {"user": "cust-1"}, {})
    assert st.decision == "tokenised" and st.purpose_id == "service"


def test_responses_api_input_and_instructions_are_tokenised_and_store_forced_off(enf):
    _consent(enf)
    body = {"model": "gpt-5", "instructions": f"Customer email {EMAIL}", "input": [
        {"role": "user", "content": [{"type": "input_text", "text": f"call me on {PHONE}"}]},
        {"type": "function_call_output", "call_id": "c1", "output": f"{EMAIL} verified"}]}
    out, _ = enf.gateway.inbound("responses", body, H)
    assert EMAIL not in json.dumps(out) and PHONE not in json.dumps(out) and out["store"] is False
    out2, _ = enf.gateway.inbound("responses", {"model": "m", "input": f"hi {EMAIL}"}, H)
    assert EMAIL not in out2["input"]


def test_embeddings_inputs_are_tokenised(enf):
    _consent(enf)
    out, _ = enf.gateway.inbound("embeddings", {"model": "e", "input": [f"a {EMAIL}", "nothing here"]}, H)
    assert EMAIL not in out["input"][0] and out["input"][1] == "nothing here"


def test_responses_are_revealed_only_when_configured(workdir):
    tmp, _ = workdir
    f = DataRightsFramework(_gw(tmp, mode="enforce", reveal_responses=True))
    _consent(f)
    out, st = f.gateway.inbound("chat", _chat(), H)
    tok = out["messages"][3]["content"].split()[-1]
    resp = {"choices": [{"message": {"role": "assistant", "content": f"I will write to {tok}"}}]}
    assert f.gateway.outbound(st, resp)["choices"][0]["message"]["content"] == f"I will write to {EMAIL}"
    g = DataRightsFramework(_gw(tmp, mode="enforce"))
    _, st2 = g.gateway.inbound("chat", _chat(), H)
    r2 = {"choices": [{"message": {"content": f"to {tok}"}}]}
    assert g.gateway.outbound(st2, r2)["choices"][0]["message"]["content"] == f"to {tok}"


# ---- report -----------------------------------------------------------------------------------------------------------
def test_report_summarises_what_the_gateway_saw(obs):
    _consent(obs)
    obs.gateway.inbound("chat", _chat(), H)
    obs.gateway.inbound("chat", {"model": "gpt-5", "messages": [{"role": "user", "content": "no personal data"}]}, H)
    obs.gateway.inbound("embeddings", {"model": "e", "input": f"x {EMAIL}"}, {})
    rep = obs.gateway.report()
    assert rep["requests"] == 3 and rep["with_personal_data"] == 2 and rep["with_personal_data_pct"] == 66.7
    assert rep["would_have_decided"] == {"tokenised": 2, "blocked:missing_principal": 1}
    assert rep["by_purpose"] == {"service": 2, "(none)": 1} and rep["entity_types"]["EMAIL"] == 3
    assert obs.gateway.report(since=utcnow() + timedelta(minutes=1))["requests"] == 0
    md = report_markdown(rep)
    assert "| EMAIL | 3 |" in md and "never records values" in md


# ---- the OpenAI-compatible endpoint ------------------------------------------------------------------------------------
class _Upstream:
    def __init__(self, reply=None, status=200, chunks=None):
        self.calls, self.reply, self.status, self.chunks = [], reply, status, chunks

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append({"url": str(request.url), "auth": request.headers.get("authorization"),
                           "body": json.loads(request.content)})
        if self.chunks:
            return httpx.Response(200, content=b"".join(self.chunks), headers={"content-type": "text/event-stream"})
        body = self.reply(self.calls[-1]["body"]) if callable(self.reply) else self.reply
        return httpx.Response(self.status, json=body)


def _client(tmp, monkeypatch, up: _Upstream, **gw):
    monkeypatch.setenv("UPSTREAM_KEY", "sk-upstream")
    real = httpx.AsyncClient

    class Patched(real):
        def __init__(self, *a, **k):
            k["transport"] = httpx.MockTransport(up.handler)
            super().__init__(*a, **k)
    monkeypatch.setattr(httpx, "AsyncClient", Patched)
    keys = {"app": ["service"], "dpo": ["dpo"]}
    cfg = _cfg(tmp, gateway={"enabled": True, "upstream_api_key_env": "UPSTREAM_KEY",
                             "upstream_base_url": "https://llm.example/v1", **gw},
               api={"auth": {"mode": "api_key", "api_keys": [
                   {"name": n, "sha256": hash_api_key(f"k-{n}"), "roles": r} for n, r in keys.items()]}})
    app = create_app(config=cfg)
    return TestClient(app), app


def _echo(body):
    last = body["messages"][-1]["content"]
    return {"id": "chatcmpl-1", "object": "chat.completion", "created": 0, "model": body["model"], "choices": [
        {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": f"echo: {last}"}}]}


def test_the_openai_sdk_works_through_the_gateway_unchanged_except_the_url(workdir, monkeypatch):
    from openai import OpenAI

    tmp, _ = workdir
    up = _Upstream(_echo)
    c, _app = _client(tmp, monkeypatch, up, mode="enforce", reveal_responses=True)
    f = _app.state.registry.get(None) if hasattr(_app.state, "registry") else None
    pid_setup = c.post("/v1/consents", json={"external_id": "cust-1", "purpose_id": "service"},
                       headers={"X-API-Key": "k-app"})
    assert pid_setup.status_code in (200, 201), f
    sdk = OpenAI(api_key="k-app", base_url="http://testserver/v1/gateway/openai/v1", http_client=c,
                 default_headers=H)
    r = sdk.chat.completions.create(model="gpt-5", messages=[{"role": "user", "content": f"mail {EMAIL}"}])
    assert r.choices[0].message.content == f"echo: mail {EMAIL}"            # revealed for the user
    sent = up.calls[0]
    assert EMAIL not in json.dumps(sent["body"]) and sent["auth"] == "Bearer sk-upstream"
    assert sent["url"] == "https://llm.example/v1/chat/completions"


def test_endpoint_refusals_look_like_openai_errors(workdir, monkeypatch):
    tmp, _ = workdir
    up = _Upstream(_echo)
    c, _ = _client(tmp, monkeypatch, up, mode="enforce")
    r = c.post("/v1/gateway/openai/v1/chat/completions", json=_chat(), headers={"Authorization": "Bearer k-app", **H})
    assert r.status_code == 403 and r.json()["error"]["code"] == "blocked:consent" and not up.calls
    assert c.post("/v1/gateway/openai/v1/chat/completions", json=_chat(),
                  headers={"Authorization": "Bearer k-dpo", **H}).status_code == 403   # role check
    assert c.post("/v1/gateway/openai/v1/chat/completions", json=_chat(),
                  headers={"Authorization": "Bearer wrong", **H}).status_code == 401


def test_observe_mode_forwards_the_exact_body_and_streams(workdir, monkeypatch):
    tmp, _ = workdir
    chunks = [b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n', b"data: [DONE]\n\n"]
    up = _Upstream(chunks=chunks)
    c, _ = _client(tmp, monkeypatch, up)
    body = _chat() | {"stream": True}
    r = c.post("/v1/gateway/openai/v1/chat/completions", json=body, headers={"Authorization": "Bearer k-app"})
    assert r.status_code == 200 and r.content == b"".join(chunks)
    assert up.calls[0]["body"] == body
    rep = c.get("/v1/gateway/report", headers={"X-API-Key": "k-dpo"}).json()
    assert rep["requests"] == 1 and rep["would_have_decided"] == {"blocked:missing_principal": 1}


def test_upstream_errors_are_passed_back_and_a_disabled_gateway_is_404(workdir, monkeypatch):
    tmp, _ = workdir
    up = _Upstream({"error": {"message": "rate limited"}}, status=429)
    c, _ = _client(tmp, monkeypatch, up)
    r = c.post("/v1/gateway/openai/v1/responses", json={"model": "m", "input": "hi"},
               headers={"Authorization": "Bearer k-app"})
    assert r.status_code == 429 and r.json()["error"]["message"] == "rate limited"
    c2, _ = _client(tmp, monkeypatch, up, enabled=False)
    assert c2.post("/v1/gateway/openai/v1/responses", json={"model": "m", "input": "hi"},
                   headers={"Authorization": "Bearer k-app"}).status_code == 404


def test_streaming_with_reveal_is_refused(workdir, monkeypatch):
    tmp, _ = workdir
    c, _ = _client(tmp, monkeypatch, _Upstream(_echo), mode="enforce", reveal_responses=True)
    r = c.post("/v1/gateway/openai/v1/chat/completions", json=_chat() | {"stream": True},
               headers={"Authorization": "Bearer k-app", **H})
    assert r.status_code == 400


# ---- LiteLLM guardrail -----------------------------------------------------------------------------------------------------
class _Key:
    def __init__(self, metadata):
        self.metadata = metadata


def test_litellm_guardrail_tokenises_before_and_reveals_after(workdir):
    from dpdp_rights.integrations.litellm import DPDPGuardrail

    tmp, _ = workdir
    f = DataRightsFramework(_gw(tmp, mode="enforce", reveal_responses=True, principal_binding="key"))
    _consent(f)
    g = DPDPGuardrail(dpdp=f, guardrail_name="dpdp")
    data = {"model": "gpt-5", "messages": [{"role": "user", "content": f"email {EMAIL}"}], "metadata": {},
            "proxy_server_request": {"headers": {"x-dpdp-principal": "cust-1"}}}
    key = _Key({"dpdp_principal": "cust-1", "dpdp_purpose": "service"})      # set by the proxy admin
    out = asyncio.run(g.async_pre_call_hook(key, None, data, "acompletion"))
    tok = out["messages"][0]["content"].split()[-1]
    assert EMAIL not in tok and out["metadata"]["dpdp_call"]
    resp = {"choices": [{"message": {"content": f"sent to {tok}"}}]}
    back = asyncio.run(g.async_post_call_success_hook(out, _Key({}), resp))
    assert back["choices"][0]["message"]["content"] == f"sent to {EMAIL}"


def test_litellm_guardrail_refuses_with_an_http_error_and_ignores_other_calls(workdir):
    from fastapi import HTTPException

    from dpdp_rights.integrations.litellm import DPDPGuardrail

    tmp, _ = workdir
    f = DataRightsFramework(_gw(tmp, mode="enforce"))
    g = DPDPGuardrail(dpdp=f)
    data = {"model": "m", "messages": [{"role": "user", "content": EMAIL}]}
    with pytest.raises(HTTPException) as e:
        asyncio.run(g.async_pre_call_hook(_Key({}), None, data, "completion"))
    assert e.value.status_code == 403 and e.value.detail["code"] == "blocked:missing_principal"
    other = {"model": "m", "prompt": EMAIL}
    assert asyncio.run(g.async_pre_call_hook(_Key({}), None, other, "image_generation")) is other


def test_litellm_guardrail_needs_a_config(monkeypatch):
    from dpdp_rights.integrations.litellm import DPDPGuardrail

    monkeypatch.delenv("DPDP_CONFIG", raising=False)
    with pytest.raises(ValueError, match="DPDP_CONFIG"):
        DPDPGuardrail()


# ---- pii-scan ----------------------------------------------------------------------------------------------------------------
def test_pii_scan_counts_per_detector_without_values(obs, tmp_path, capsys):
    import yaml

    from dpdp_rights.cli import main
    from dpdp_rights.pii.scan import read_sample, scan

    sample = tmp_path / "s.jsonl"
    sample.write_text("\n".join([json.dumps({"text": f"mail {EMAIL}"}), json.dumps(_chat()),
                                 json.dumps("nothing"), ""]))
    rep = scan(read_sample(sample), obs.tokenizer.detector)
    assert rep["records"] == 3 and rep["with_personal_data"] == 2 and rep["entity_types"]["EMAIL"] == 3
    assert "RegexDetector" in rep["by_detector"] and EMAIL not in json.dumps(rep)
    (tmp_path / "c.yaml").write_text(yaml.safe_dump(obs.config.model_dump()))
    main(["-c", str(tmp_path / "c.yaml"), "pii-scan", "--input", str(sample), "--format", "md"])
    assert "| EMAIL | 3 |" in capsys.readouterr().out
    bad = tmp_path / "b.jsonl"
    bad.write_text('{"other": 1}\n')
    with pytest.raises(ValueError, match="expected"):
        read_sample(bad)


# ---- production checks -----------------------------------------------------------------------------------------------------
def test_production_check_flags_gateway_settings(workdir):
    tmp, _ = workdir
    msgs = {m: lvl for lvl, m in production_issues(_gw(tmp, upstream_base_url="http://llm.local"))}
    assert any("must use https" in m and lvl == "error" for m, lvl in msgs.items())
    assert any("observe" in m for m in msgs)
    msgs = [m for _, m in production_issues(_gw(tmp, mode="enforce", reveal_responses=True, enforce_consent=False,
                                                missing_principal="mask"))]
    assert any("reveal_responses" in m for m in msgs) and any("enforce_consent" in m for m in msgs)
    assert any("masked, not blocked" in m for m in msgs)


# ---- binding the person to authentication ---------------------------------------------------------------------------
@pytest.mark.parametrize("headers,body_extra,code", [
    ({"x-dpdp-principal": "cust-2", "x-dpdp-assertion": _assert("cust-1")}, {}, "blocked:principal_mismatch"),
    ({"x-dpdp-assertion": _assert("cust-1")}, {"user": "cust-2"}, "blocked:principal_mismatch"),
    ({"x-dpdp-assertion": _assert("cust-1")}, {"metadata": {"dpdp_principal": "cust-2"}}, "blocked:principal_mismatch"),
    ({"x-dpdp-principal": "cust-1"}, {}, "blocked:unverified_principal"),
    ({}, {"user": "cust-1"}, "blocked:unverified_principal"),
    ({"x-dpdp-assertion": _assert("cust-1", "service"), "x-dpdp-purpose": "marketing"}, {}, "blocked:purpose_mismatch"),
])
def test_a_caller_cannot_choose_another_person(enf, headers, body_extra, code):
    _consent(enf)
    _consent(enf, "cust-2")
    with pytest.raises(GatewayRefused) as e:
        enf.gateway.inbound("chat", _chat() | body_extra, headers)
    assert e.value.status == 403 and e.value.decision == code
    assert enf.store.gateway_observations()[-1]["decision"] == code


@pytest.mark.parametrize("token,why", [
    (mint_assertion("another-secret-0123456789abcdefghij", "cust-1", "service"), "signature"),
    (_assert(now=0), "expired"),
    (_assert(ttl_seconds=86400), "lifetime"),
    (_assert(now=4102444800), "future"),
    ("v1.not.base64!", "malformed"),
    ("v2.a.b", "not a v1"),
])
def test_bad_assertions_are_refused_and_create_no_one(enf, token, why):
    with pytest.raises(GatewayRefused, match=why) as e:
        enf.gateway.inbound("chat", _chat(), {"x-dpdp-assertion": token})
    assert e.value.decision == "blocked:bad_assertion"
    assert enf.vault.resolve_principal("cust-1", create=False) is None


def test_a_missing_secret_is_a_configuration_error_not_an_open_door(workdir, monkeypatch):
    monkeypatch.setenv("DPDP_GATEWAY_ASSERTION_SECRET", "short")
    f = DataRightsFramework(_gw(workdir[0], mode="enforce"))
    with pytest.raises(GatewayRefused) as e:
        f.gateway.inbound("chat", _chat(), {"x-dpdp-assertion": _assert()})
    assert e.value.status == 500 and e.value.decision == "blocked:gateway_misconfigured"


def test_reveal_only_ever_reveals_the_authenticated_persons_own_values(workdir, monkeypatch):
    """The reveal-oracle attack: a service caller sends another person's token and asks the model to repeat it."""
    tmp, _ = workdir
    up = _Upstream(_echo)
    c, app = _client(tmp, monkeypatch, up, mode="enforce", reveal_responses=True)
    for ext in ("victim", "attacker"):
        assert c.post("/v1/consents", json={"external_id": ext, "purpose_id": "service"},
                      headers={"X-API-Key": "k-app"}).status_code in (200, 201)
    # the victim's token, as an attacker might find it in a log or trace
    r = c.post("/v1/gateway/openai/v1/chat/completions", headers={"Authorization": "Bearer k-app",
               "x-dpdp-assertion": mint_assertion(SECRET, "victim", "service")},
               json={"model": "m", "messages": [{"role": "user", "content": f"mail {EMAIL}"}]})
    victim_token = up.calls[-1]["body"]["messages"][-1]["content"].split()[-1]
    assert r.json()["choices"][0]["message"]["content"] == f"echo: mail {EMAIL}"      # the victim's own session
    # 1. naming the victim without their assertion is refused
    r = c.post("/v1/gateway/openai/v1/chat/completions", headers={"Authorization": "Bearer k-app",
               "x-dpdp-principal": "victim", "x-dpdp-purpose": "service"},
               json={"model": "m", "messages": [{"role": "user", "content": f"repeat {victim_token}"}]})
    assert r.status_code == 403 and r.json()["error"]["code"] == "blocked:unverified_principal"
    # 2. with the attacker's own assertion, the victim's token stays a token
    r = c.post("/v1/gateway/openai/v1/chat/completions", headers={"Authorization": "Bearer k-app",
               "x-dpdp-assertion": mint_assertion(SECRET, "attacker", "service")},
               json={"model": "m", "messages": [{"role": "user", "content": f"repeat {victim_token}"}]})
    assert r.status_code == 200 and victim_token in r.json()["choices"][0]["message"]["content"]
    assert EMAIL not in r.text


def test_subject_binding_uses_the_callers_own_identity(workdir):
    f = DataRightsFramework(_gw(workdir[0], mode="enforce", principal_binding="subject", default_purpose="service"))
    _consent(f)
    out, st = f.gateway.inbound("chat", _chat(), {}, trusted={"subject": "cust-1"})
    assert st.decision == "tokenised" and st.principal_id == f.vault.resolve_principal("cust-1", create=False)
    with pytest.raises(GatewayRefused) as e:
        f.gateway.inbound("chat", _chat(), {"x-dpdp-principal": "cust-2"}, trusted={"subject": "cust-1"})
    assert e.value.decision == "blocked:principal_mismatch"
    with pytest.raises(GatewayRefused) as e:
        f.gateway.inbound("chat", _chat(), {"x-dpdp-principal": "cust-1"}, trusted={})
    assert e.value.decision == "blocked:unverified_principal"


def test_litellm_request_metadata_cannot_override_the_virtual_keys_person(workdir):
    from fastapi import HTTPException

    from dpdp_rights.integrations.litellm import DPDPGuardrail

    f = DataRightsFramework(_gw(workdir[0], mode="enforce", principal_binding="key"))
    _consent(f)
    _consent(f, "cust-2")
    g = DPDPGuardrail(dpdp=f)
    spoof = {"model": "m", "messages": [{"role": "user", "content": EMAIL}], "metadata": {"dpdp_principal": "cust-2"}}
    with pytest.raises(HTTPException) as e:
        asyncio.run(g.async_pre_call_hook(_Key({"dpdp_principal": "cust-1", "dpdp_purpose": "service"}), None, spoof,
                                          "completion"))
    assert e.value.detail["code"] == "blocked:principal_mismatch"
    alone = {"model": "m", "messages": [{"role": "user", "content": EMAIL}], "metadata": {"dpdp_principal": "cust-2"}}
    with pytest.raises(HTTPException) as e:
        asyncio.run(g.async_pre_call_hook(_Key({}), None, alone, "completion"))
    assert e.value.detail["code"] == "blocked:unverified_principal"


def test_observe_mode_still_takes_claims_since_it_changes_nothing(obs):
    _, st = obs.gateway.inbound("chat", _chat(), {"x-dpdp-principal": "cust-1", "x-dpdp-purpose": "service"})
    assert st.decision == "observed" and obs.vault.resolve_principal("cust-1", create=False) is None


def test_production_check_refuses_header_binding_with_reveal(workdir, monkeypatch):
    tmp, _ = workdir
    msgs = {m: lvl for lvl, m in production_issues(_gw(tmp, mode="enforce", principal_binding="header",
                                                        reveal_responses=True))}
    assert any("principal_binding is header" in m and lvl == "error" for m, lvl in msgs.items())
    msgs = {m: lvl for lvl, m in production_issues(_gw(tmp, mode="enforce", principal_binding="header"))}
    assert any("principal_binding is header" in m and lvl == "warning" for m, lvl in msgs.items())
    monkeypatch.delenv("DPDP_GATEWAY_ASSERTION_SECRET")
    msgs = {m: lvl for lvl, m in production_issues(_gw(tmp, mode="enforce"))}
    assert any("DPDP_GATEWAY_ASSERTION_SECRET is not set" in m and lvl == "error" for m, lvl in msgs.items())
