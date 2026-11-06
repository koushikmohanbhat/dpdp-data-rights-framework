"""OpenTelemetry tokenisation + X-Ray, Langfuse, Agent Engine Sessions and AgentCore Identity connectors."""
from types import SimpleNamespace

import boto3
import pytest
from botocore.stub import ANY, Stubber

from dpdp_rights.connectors.agents import AgentCoreIdentityConnector, AgentEngineSessionsConnector
from dpdp_rights.connectors.base import ErasureContext
from dpdp_rights.connectors.observability import LangfuseConnector, XRayConnector
from dpdp_rights.core.models import Action, Artifact

otel = pytest.importorskip("opentelemetry.sdk.trace")


def test_spans_are_tagged_and_tokenized_before_export(dpdp):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from dpdp_rights.observability.telemetry import principal_span_processor, tokenizing_exporter

    mem = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(principal_span_processor())
    tp.add_span_processor(SimpleSpanProcessor(tokenizing_exporter(mem, dpdp)))
    tracer = tp.get_tracer("auto-instrumentation")           # stands in for an OpenAI/Bedrock instrumentor

    pid = dpdp.principal("o-1")
    dpdp.grant_consent(pid, "service")
    with dpdp.context(pid, purpose="service"):
        with tracer.start_as_current_span("chat gpt") as sp:
            sp.set_attribute("gen_ai.prompt", "refund to o1@x.in, phone 9876543210")
            sp.add_event("gen_ai.choice", {"content": "Sure, emailing o1@x.in"})
    with tracer.start_as_current_span("batch job") as sp:      # no principal context
        sp.set_attribute("note", "retry for z@y.in")

    spans = {s.name: s for s in mem.get_finished_spans()}
    chat = spans["chat gpt"]
    assert chat.attributes["dpdp.principal"] == pid and chat.attributes["dpdp.purpose"] == "service"
    assert "o1@x.in" not in chat.attributes["gen_ai.prompt"] and "<EMAIL_" in chat.attributes["gen_ai.prompt"]
    assert "9876543210" not in chat.attributes["gen_ai.prompt"]
    assert "o1@x.in" not in chat.events[0].attributes["content"]
    assert spans["batch job"].attributes["note"] == "retry for [EMAIL]"
    trace.get_tracer_provider()   # global provider untouched


def test_framework_emits_metrics(dpdp):
    from opentelemetry import metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    from dpdp_rights.observability.telemetry import Telemetry

    reader = InMemoryMetricReader()
    metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))
    dpdp.telemetry = Telemetry(True)
    dpdp.orchestrator.telemetry = dpdp.telemetry
    dpdp.telemetry.watch_sla(dpdp.sla_counts)
    pid = dpdp.principal("m-1")
    dpdp.grant_consent(pid, "service")
    dpdp.erase(pid)
    names = {m.name for rm in reader.get_metrics_data().resource_metrics for sm in rm.scope_metrics for m in sm.metrics}
    assert {"dpdp.erasure.requests", "dpdp.erasure.duration", "dpdp.erasure.open"} <= names


def test_xray_discover_and_verify_no_raw_values():
    client = boto3.client("xray", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="y")
    st = Stubber(client)
    st.add_response("get_trace_summaries", {"TraceSummaries": [{"Id": "1-abc-def"}]},
                    {"StartTime": ANY, "EndTime": ANY, "TimeRangeType": "TraceId",
                     "FilterExpression": 'annotation.dpdp_principal = "dp_1"'})
    st.add_response("get_trace_summaries", {"TraceSummaries": [{"Id": "1-abc-def"}]},
                    {"StartTime": ANY, "EndTime": ANY, "TimeRangeType": "TraceId",
                     "FilterExpression": 'annotation.dpdp_principal = "dp_1"'})
    st.add_response("batch_get_traces", {"Traces": [{"Id": "1-abc-def", "Segments": [
        {"Id": "s1", "Document": '{"annotations":{"dpdp_principal":"dp_1"},"metadata":{"p":"<EMAIL_aaaaaaaaaaaa>"}}'}]}]},
        {"TraceIds": ["1-abc-def"]})
    with st:
        c = XRayConnector("xray", client=client, lookback_hours=24)
        ctx = ErasureContext("dp_1", ["<EMAIL_aaaaaaaaaaaa>"], {"<EMAIL_aaaaaaaaaaaa>": "a@x.in"})
        found = c.discover(ctx)
        assert found[0].locator["trace_ids"] == ["1-abc-def"]
        r = c.erase(Artifact("a", "trace", "xray", found[0].locator), Action.CRYPTO_SHRED, ctx)
        assert r.ok and "cannot be deleted" in r.detail["note"]
        assert c.verify(ctx).ok
    st.assert_no_pending_responses()


def test_langfuse_finds_and_deletes_by_user_id():
    calls = []

    def http(method, path, body=None):
        calls.append((method, path, body))
        if method == "GET":
            return {"data": [{"id": "t1"}, {"id": "t2"}], "meta": {"totalPages": 1}}
        return {}

    c = LangfuseConnector("langfuse", "pk", "sk", http=http)
    ctx = ErasureContext("dp_9", [])
    d = c.discover(ctx)[0]
    r = c.erase(Artifact("a", "trace", "langfuse", d.locator), Action.DELETE, ctx)
    assert r.ok and calls[-1] == ("DELETE", "/api/public/traces", {"traceIds": ["t1", "t2"]})
    assert "userId=dp_9" in calls[0][1]


def test_agent_engine_sessions_discover_and_delete():
    class Resp:
        def __init__(self, data):
            self._d = data

        def raise_for_status(self):
            pass

        def json(self):
            return self._d

    seen = {}

    class Http:
        def get(self, url, params):
            seen["get"] = (url, params)
            return Resp({"sessions": [{"name": "projects/p/locations/asia-south1/reasoningEngines/1/sessions/s1"}]})

        def delete(self, url):
            seen["delete"] = url
            return Resp({})

    c = AgentEngineSessionsConnector("sessions", "projects/p/locations/asia-south1/reasoningEngines/1", session=Http())
    ctx = ErasureContext("dp_7", [])
    d = c.discover(ctx)
    assert seen["get"][1]["filter"] == 'user_id="dp_7"'
    assert seen["get"][0].startswith("https://asia-south1-aiplatform.googleapis.com/v1beta1/")
    r = c.erase(Artifact("a", d[0].kind, "sessions", d[0].locator), Action.DELETE, ctx)
    assert r.ok and seen["delete"].endswith("/sessions/s1")


def test_agentcore_identity_revokes_at_idp():
    cognito = SimpleNamespace(calls=[])
    cognito.admin_user_global_sign_out = lambda **kw: cognito.calls.append(kw)
    c = AgentCoreIdentityConnector("identity", cognito_user_pool_id="ap-south-1_abc", cognito_client=cognito)
    ctx = ErasureContext("dp_5", [])
    d = c.discover(ctx)[0]
    r = c.erase(Artifact("a", d.kind, "identity", d.locator), Action.DELETE, ctx)
    assert r.ok and cognito.calls == [{"UserPoolId": "ap-south-1_abc", "Username": "dp_5"}]
    manual = AgentCoreIdentityConnector("identity").erase(Artifact("b", d.kind, "identity", d.locator), Action.DELETE, ctx)
    assert manual.ok is False and manual.detail["manual"]
