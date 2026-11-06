"""Tracing / LLM-observability connectors.

* aws_xray          - AWS X-Ray traces (incl. ADOT exports and AgentCore traces)
* gcp_cloud_trace   - Google Cloud Trace
* langfuse          - Langfuse (self-hosted or cloud) LLM traces

X-Ray and Cloud Trace have no API to delete individual traces; data expires after the service's
fixed retention (30 days for both at the time of writing). For these, the framework's job is to
make sure spans never contain raw personal data in the first place (PrincipalSpanProcessor +
TokenizingSpanExporter), then *prove* it: discovery finds the principal's traces through the
indexed ``dpdp.principal`` attribute and verification scans them for raw values. The erasure
action is crypto-shredding.

Langfuse supports deleting traces, so the connector deletes them (traces should carry the
pseudonymous principal id as ``userId``).
"""
from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from ..core.models import Action
from .base import Capabilities, Connector, Discovered, ErasureContext, VerifyResult, register


def _contains_raw(blob: str, probes: dict[str, str]) -> list[str]:
    return sorted({t.split("_")[0].strip("<") for t, v in probes.items() if v and len(v) >= 4 and v in blob})


@register("aws_xray")
class XRayConnector(Connector):
    """Options: region, lookback_hours (max 24h per query window; iterated), annotation (default dpdp_principal).

    Index the attribute in the ADOT collector (awsxray exporter: indexed_attributes: [dpdp.principal]).
    X-Ray converts it to the annotation ``dpdp_principal``.
    """

    supports = {Action.CRYPTO_SHRED}
    capabilities = Capabilities(
        store='AWS X-Ray traces',
        discover='native', discover_how='trace summaries by the dpdp_principal annotation',
        verify='rescan', verify_how='scans segments for raw values',
        limits=(
            'traces cannot be deleted; they expire after 30 days',
            'only the lookback window is searched',
        ))

    def __init__(self, name: str, region: str | None = None, lookback_hours: int = 24 * 30,
                 annotation: str = "dpdp_principal", client=None, **kw):
        super().__init__(name, **kw)
        if client is None:
            import boto3

            client = boto3.client("xray", region_name=region)
        self.xray, self.lookback, self.annotation = client, lookback_hours, annotation

    def _trace_ids(self, pid: str) -> list[str]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=self.lookback)
        ids: list[str] = []
        win_end = end
        while win_end > start:                       # GetTraceSummaries accepts windows up to 24h
            win_start = max(start, win_end - timedelta(hours=24))
            kw = {"StartTime": win_start, "EndTime": win_end, "TimeRangeType": "TraceId",
                  "FilterExpression": f'annotation.{self.annotation} = "{pid}"'}
            while True:
                r = self.xray.get_trace_summaries(**kw)
                ids += [t["Id"] for t in r.get("TraceSummaries", [])]
                if not r.get("NextToken"):
                    break
                kw["NextToken"] = r["NextToken"]
            win_end = win_start
        return ids

    def discover(self, ctx: ErasureContext):
        ids = self._trace_ids(ctx.principal_id)
        return [Discovered("trace", {"service": "xray", "trace_ids": ids}, note=f"{len(ids)} traces")] if ids else []

    def _crypto_shred(self, artifact, ctx):
        res = super()._crypto_shred(artifact, ctx)
        res.detail["note"] += " X-Ray traces cannot be deleted; they expire under X-Ray's fixed retention."
        return res

    def verify(self, ctx):
        ids = self._trace_ids(ctx.principal_id)
        leaks: list[dict] = []
        for i in range(0, len(ids), 5):              # BatchGetTraces takes up to 5 ids
            r = self.xray.batch_get_traces(TraceIds=ids[i:i + 5])
            for t in r.get("Traces", []):
                blob = json.dumps([s.get("Document") for s in t.get("Segments", [])])
                hit = _contains_raw(blob, ctx.probes)
                if hit:
                    leaks.append({"trace_id": t.get("Id"), "raw_types": hit})
        return VerifyResult(self.name, not leaks, leaks,
                            note=f"{len(ids)} traces checked; tokens remain until X-Ray retention expires")


@register("gcp_cloud_trace")
class CloudTraceConnector(Connector):
    """Options: project, lookback_days. Spans must carry the ``dpdp.principal`` label (PrincipalSpanProcessor)."""

    supports = {Action.CRYPTO_SHRED}
    capabilities = Capabilities(
        store='Google Cloud Trace',
        discover='native', discover_how='traces by the dpdp.principal label',
        verify='rescan', verify_how='scans span labels for raw values',
        limits=(
            "spans cannot be deleted; they expire under the service's retention",
        ))

    def __init__(self, name: str, project: str, lookback_days: int = 30, client=None, **kw):
        super().__init__(name, **kw)
        if client is None:
            from google.cloud import trace_v1  # type: ignore

            client = trace_v1.TraceServiceClient()
        self.client, self.project, self.lookback = client, project, lookback_days

    def _traces(self, pid: str):
        start = datetime.now(timezone.utc) - timedelta(days=self.lookback)
        return list(self.client.list_traces(request={
            "project_id": self.project, "filter": f"+dpdp.principal:{pid}", "view": "COMPLETE",
            "start_time": start}))

    def discover(self, ctx):
        ids = [t.trace_id for t in self._traces(ctx.principal_id)]
        return [Discovered("trace", {"service": "cloud_trace", "trace_ids": ids}, note=f"{len(ids)} traces")] if ids else []

    def _crypto_shred(self, artifact, ctx):
        res = super()._crypto_shred(artifact, ctx)
        res.detail["note"] += " Cloud Trace spans cannot be deleted; they expire under Cloud Trace retention."
        return res

    def verify(self, ctx):
        leaks, n = [], 0
        for t in self._traces(ctx.principal_id):
            n += 1
            blob = json.dumps([dict(s.labels) | {"name": s.name} for s in t.spans])
            hit = _contains_raw(blob, ctx.probes)
            if hit:
                leaks.append({"trace_id": t.trace_id, "raw_types": hit})
        return VerifyResult(self.name, not leaks, leaks, note=f"{n} traces checked")


@register("langfuse")
class LangfuseConnector(Connector):
    """Options: host (default https://cloud.langfuse.com), public_key, secret_key.

    Tag traces with ``user_id=<pseudonymous principal id>`` (Langfuse SDK) so they can be found.
    """

    supports = {Action.DELETE}
    capabilities = Capabilities(
        store='Langfuse LLM traces',
        discover='native', discover_how='traces by userId',
        verify='rediscover', verify_how='re-discovery returns nothing',
        limits=())

    def __init__(self, name: str, public_key: str, secret_key: str, host: str = "https://cloud.langfuse.com",
                 http=None, **kw):
        super().__init__(name, **kw)
        self.host = host.rstrip("/")
        self._auth = "Basic " + base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
        self.http = http or self._urllib

    def _urllib(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(self.host + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": self._auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    def _trace_ids(self, pid: str) -> list[str]:
        ids, page = [], 1
        while True:
            r = self.http("GET", f"/api/public/traces?userId={urllib.parse.quote(pid)}&page={page}&limit=100")
            ids += [t["id"] for t in r.get("data", [])]
            meta = r.get("meta", {})
            if page >= meta.get("totalPages", 1):
                return ids
            page += 1

    def discover(self, ctx):
        ids = self._trace_ids(ctx.principal_id)
        return [Discovered("trace", {"service": "langfuse", "trace_ids": ids}, note=f"{len(ids)} traces")] if ids else []

    def _delete(self, artifact, ctx, fallback_from=None):
        ids = artifact.locator.get("trace_ids") or []
        for i in range(0, len(ids), 100):
            self.http("DELETE", "/api/public/traces", {"traceIds": ids[i:i + 100]})
        return self._ok(artifact, Action.DELETE, traces=len(ids))

