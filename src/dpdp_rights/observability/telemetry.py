"""OpenTelemetry integration.

1. Framework telemetry: spans for protect / generate / erasure / connector actions, and metrics
   (requests, actions, withdrawals, blocked processing, erasure duration, overdue requests).
   Spans carry pseudonymous ids and counts, never content.
2. ``PrincipalSpanProcessor`` tags every span started inside ``dpdp.context(...)``, including spans
   from auto-instrumentation (OpenAI, Anthropic, Bedrock, LangChain, HTTP clients), with
   ``dpdp.principal`` and ``dpdp.purpose``.
3. ``TokenizingSpanExporter`` wraps any exporter (OTLP to ADOT / OTel Collector, X-Ray, Cloud Trace,
   Langfuse, Datadog...). Before export it replaces personal data in span attributes and events:
   tokenised with the span's principal when known, otherwise masked as ``[EMAIL]``, ``[AADHAAR]``...

Works without the OpenTelemetry SDK installed: everything degrades to no-ops.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

try:  # API is tiny and optional
    from opentelemetry import metrics as _metrics
    from opentelemetry import trace as _trace

    _HAS_OTEL = True
except Exception:  # noqa: BLE001
    _HAS_OTEL = False

from ..core import context as ctxmod

SCOPE = "dpdp_rights"


class _NoopSpan:
    def set_attribute(self, *a, **k): ...
    def set_attributes(self, *a, **k): ...
    def add_event(self, *a, **k): ...
    def record_exception(self, *a, **k): ...
    def set_status(self, *a, **k): ...


class _NoopInstrument:
    def add(self, *a, **k): ...
    def record(self, *a, **k): ...


class Telemetry:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and _HAS_OTEL
        if self.enabled:
            self.tracer = _trace.get_tracer(SCOPE)
            m = _metrics.get_meter(SCOPE)
            self.requests = m.create_counter("dpdp.erasure.requests", description="Erasure requests by status")
            self.actions = m.create_counter("dpdp.erasure.actions", description="Erasure actions by action/store/ok")
            self.withdrawals = m.create_counter("dpdp.consent.withdrawals", description="Consent withdrawals by purpose")
            self.blocked = m.create_counter("dpdp.processing.blocked", description="Processing blocked for lack of consent")
            self.pii = m.create_counter("dpdp.pii.tokenized", description="PII entities tokenised by type")
            self.duration = m.create_histogram("dpdp.erasure.duration", unit="s", description="Erasure run duration")
            self._sla_source = None
            m.create_observable_gauge("dpdp.erasure.open", callbacks=[self._observe_open],
                                      description="Open erasure requests (label sla=ok|due_soon|overdue)")
        else:
            self.requests = self.actions = self.withdrawals = self.blocked = self.pii = self.duration = _NoopInstrument()

    def watch_sla(self, fn) -> None:
        """fn() -> dict(ok=int, due_soon=int, overdue=int); exported as the dpdp.erasure.open gauge."""
        self._sla_source = fn

    def _observe_open(self, _options):
        if not self._sla_source:
            return []
        try:
            counts = self._sla_source()
        except Exception:  # noqa: BLE001
            return []
        return [_metrics.Observation(v, {"sla": k}) for k, v in counts.items()]

    @contextmanager
    def span(self, name: str, **attrs: Any) -> Iterator[Any]:
        if not self.enabled:
            yield _NoopSpan()
            return
        with self.tracer.start_as_current_span(name) as sp:
            for k, v in attrs.items():
                if v is not None:
                    sp.set_attribute(k, v)
            yield sp


# ---------------------------------------------------------------------------
# SDK pieces (need opentelemetry-sdk)
# ---------------------------------------------------------------------------
def _sdk():
    from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    return ReadableSpan, SpanProcessor, SpanExporter, SpanExportResult


def principal_span_processor():
    _, SpanProcessor, _, _ = _sdk()

    class PrincipalSpanProcessor(SpanProcessor):
        def on_start(self, span, parent_context=None):
            env = ctxmod.current()
            if env is not None:
                span.set_attribute("dpdp.principal", env.principal_id)
                span.set_attribute("dpdp.purpose", env.purpose_id)
                if env.session_id:
                    span.set_attribute("session.id", env.session_id)

        def on_end(self, span): ...
        def shutdown(self): ...
        def force_flush(self, timeout_millis: int = 30000): return True

    return PrincipalSpanProcessor()


def tokenizing_exporter(inner, framework, mask_unknown: bool = True):
    """Wrap an exporter so no raw personal data leaves the process in spans."""
    ReadableSpan, _, SpanExporter, _ = _sdk()

    detector = framework.tokenizer.detector

    def clean(value, pid):
        if isinstance(value, str) and value:
            if pid and pid != "-":
                return framework.tokenizer.tokenize(value, pid).text
            if mask_unknown:
                out, cur = [], 0
                for e in detector.detect(value):
                    out += [value[cur:e.start], f"[{e.type}]"]
                    cur = e.end
                out.append(value[cur:])
                return "".join(out)
        if isinstance(value, (list, tuple)):
            return type(value)(clean(v, pid) for v in value)
        return value

    def clean_attrs(attrs, pid):
        return {k: (v if k.startswith("dpdp.") else clean(v, pid)) for k, v in (attrs or {}).items()}

    class TokenizingSpanExporter(SpanExporter):
        def __init__(self):
            self.inner = inner

        def export(self, spans):
            safe = []
            for s in spans:
                pid = (s.attributes or {}).get("dpdp.principal")
                from opentelemetry.sdk.trace import Event

                events = [Event(e.name, clean_attrs(e.attributes, pid), e.timestamp) for e in s.events]
                safe.append(ReadableSpan(
                    name=s.name, context=s.context, parent=s.parent, resource=s.resource,
                    attributes=clean_attrs(s.attributes, pid), events=events, links=s.links, kind=s.kind,
                    status=s.status, start_time=s.start_time, end_time=s.end_time,
                    instrumentation_scope=s.instrumentation_scope))
            return self.inner.export(safe)

        def shutdown(self):
            return self.inner.shutdown()

        def force_flush(self, timeout_millis: int = 30000):
            return self.inner.force_flush(timeout_millis)

    return TokenizingSpanExporter()


def install(framework, exporter=None, service_name: str | None = None, endpoint: str | None = None,
            metric_reader=None):
    """Configure a TracerProvider (and MeterProvider) that tags and tokenises every span.

    exporter: any SpanExporter; default OTLP/HTTP to ``endpoint`` (ADOT / OTel Collector), which
    then forwards to AWS X-Ray + CloudWatch or Google Cloud Trace + Monitoring.
    """
    from opentelemetry import metrics, trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    obs = framework.config.observability
    resource = Resource.create({"service.name": service_name or obs.service_name,
                                "deployment.environment": framework.config.environment})
    if exporter is None:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore

        exporter = OTLPSpanExporter(endpoint=(endpoint or obs.otlp_endpoint or "http://localhost:4318") + "/v1/traces")
    tp = TracerProvider(resource=resource)
    tp.add_span_processor(principal_span_processor())
    tp.add_span_processor(BatchSpanProcessor(tokenizing_exporter(exporter, framework) if obs.tokenize_spans else exporter))
    trace.set_tracer_provider(tp)
    if metric_reader is not None:
        from opentelemetry.sdk.metrics import MeterProvider

        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[metric_reader]))
    framework.telemetry = Telemetry(True)
    framework.orchestrator.telemetry = framework.telemetry
    framework.telemetry.watch_sla(framework.sla_counts)
    return tp
