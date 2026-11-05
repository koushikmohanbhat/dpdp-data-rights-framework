"""Google Cloud connectors.

* gcp_cloud_logging        - Cloud Logging (discovery + raw-value verification; entries are immutable)
* gcp_bigquery             - BigQuery tables (DML delete / redact)
* gcp_vertex_vector_search - Vertex AI Vector Search datapoints
* gcp_vertex_memory_bank   - Vertex AI Agent Engine Memory Bank (beta API)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..core.models import Action
from .base import Connector, Discovered, ErasureContext, VerifyResult, register


@register("gcp_cloud_logging")
class CloudLoggingConnector(Connector):
    """Options: project, base_filter (e.g. 'resource.type="cloud_run_revision"'), lookback_days."""

    supports = {Action.CRYPTO_SHRED}

    def __init__(self, name: str, project: str, base_filter: str = "", lookback_days: int = 30, client=None, **kw):
        super().__init__(name, **kw)
        if client is None:
            from google.cloud import logging as gcl  # type: ignore

            client = gcl.Client(project=project)
        self.client, self.project, self.base, self.lookback = client, project, base_filter, lookback_days

    def _search(self, needles: list[str]) -> dict[str, int]:
        if not needles:
            return {}
        since = (datetime.now(timezone.utc) - timedelta(days=self.lookback)).isoformat()
        terms = " OR ".join('"' + n.replace('"', '\\"') + '"' for n in needles)
        flt = f'timestamp>="{since}" AND ({terms})' + (f" AND {self.base}" if self.base else "")
        counts: dict[str, int] = {}
        for entry in self.client.list_entries(filter_=flt, page_size=1000):
            counts[entry.log_name] = counts.get(entry.log_name, 0) + 1
        return counts

    def discover(self, ctx: ErasureContext):
        return [Discovered("log", {"project": self.project, "logName": ln}, note=f"{n} entries")
                for ln, n in self._search(ctx.needles).items()]

    def verify(self, ctx):
        raw = sorted({v for v in ctx.probes.values() if v and len(v) >= 4})
        hits = self._search(raw)
        return VerifyResult(self.name, not hits, [{"raw_value_in_log": k, "entries": v} for k, v in hits.items()],
                            note="Entries are immutable; tokens age out under log bucket retention.")


@register("gcp_bigquery")
class BigQueryConnector(Connector):
    """Options: table (project.dataset.table), id_column, content_column?, principal_column?, kind."""

    supports = {Action.DELETE, Action.REDACT}

    def __init__(self, name: str, table: str, id_column: str = "id", content_column: str | None = None,
                 principal_column: str | None = None, kind: str = "record", project: str | None = None,
                 client=None, **kw):
        super().__init__(name, **kw)
        if client is None:
            from google.cloud import bigquery  # type: ignore

            client = bigquery.Client(project=project)
        self.bq, self.table = client, table
        self.id_col, self.content_col, self.principal_col, self.kind = id_column, content_column, principal_column, kind

    def _run(self, sql: str, params: list):
        from google.cloud import bigquery  # type: ignore

        cfg = bigquery.QueryJobConfig(query_parameters=params)
        return list(self.bq.query(sql, job_config=cfg).result())

    def discover(self, ctx):
        from google.cloud import bigquery  # type: ignore

        conds, params = [], []
        if self.principal_col:
            conds.append(f"{self.principal_col} = @pid")
            params.append(bigquery.ScalarQueryParameter("pid", "STRING", ctx.principal_id))
        if self.content_col and ctx.tokens:
            conds.append(f"EXISTS (SELECT 1 FROM UNNEST(@toks) t WHERE STRPOS({self.content_col}, t) > 0)")
            params.append(bigquery.ArrayQueryParameter("toks", "STRING", ctx.tokens))
        if not conds:
            return []
        rows = self._run(f"SELECT {self.id_col} AS id FROM `{self.table}` WHERE " + " OR ".join(conds), params)
        return [Discovered(self.kind, {"id": r["id"]}) for r in rows]

    def _delete(self, artifact, ctx, fallback_from=None):
        from google.cloud import bigquery  # type: ignore

        self._run(f"DELETE FROM `{self.table}` WHERE {self.id_col} = @id",
                  [bigquery.ScalarQueryParameter("id", "STRING", str(artifact.locator["id"]))])
        return self._ok(artifact, Action.DELETE)

    def _redact(self, artifact, ctx):
        from google.cloud import bigquery  # type: ignore

        if not self.content_col:
            return self._delete(artifact, ctx, Action.REDACT)
        expr = self.content_col
        for i, _ in enumerate(ctx.tokens):
            expr = f"REPLACE({expr}, @t{i}, '[ERASED]')"
        params = [bigquery.ScalarQueryParameter(f"t{i}", "STRING", t) for i, t in enumerate(ctx.tokens)]
        params.append(bigquery.ScalarQueryParameter("id", "STRING", str(artifact.locator["id"])))
        self._run(f"UPDATE `{self.table}` SET {self.content_col} = {expr} WHERE {self.id_col} = @id", params)
        return self._ok(artifact, Action.REDACT)


@register("gcp_vertex_vector_search")
class VertexVectorSearchConnector(Connector):
    """Options: index (projects/../locations/../indexes/ID), project, location.
    Locator: {"datapoint_ids": [...]}. Register datapoint ids via kit.track_artifact."""

    supports = {Action.DELETE}

    def __init__(self, name: str, index: str, project: str | None = None, location: str | None = None,
                 index_obj=None, **kw):
        super().__init__(name, **kw)
        if index_obj is None:
            from google.cloud import aiplatform  # type: ignore

            aiplatform.init(project=project, location=location)
            index_obj = aiplatform.MatchingEngineIndex(index_name=index)
        self.index = index_obj

    def _delete(self, artifact, ctx, fallback_from=None):
        ids = artifact.locator["datapoint_ids"]
        self.index.remove_datapoints(datapoint_ids=ids)
        return self._ok(artifact, Action.DELETE, datapoints=len(ids))


@register("gcp_vertex_memory_bank")
class VertexMemoryBankConnector(Connector):
    """Vertex AI Agent Engine Memory Bank. Uses scope {"user_id": <principal_id>}.
    Options: reasoning_engine (projects/../locations/../reasoningEngines/ID), scope_key."""

    supports = {Action.DELETE}

    def __init__(self, name: str, reasoning_engine: str, scope_key: str = "user_id", session=None, **kw):
        super().__init__(name, **kw)
        if session is None:
            import google.auth  # type: ignore
            from google.auth.transport.requests import AuthorizedSession  # type: ignore

            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            session = AuthorizedSession(creds)
        self.http = session
        self.engine = reasoning_engine
        loc = reasoning_engine.split("/locations/")[1].split("/")[0]
        self.base = f"https://{loc}-aiplatform.googleapis.com/v1beta1"
        self.scope_key = scope_key

    def discover(self, ctx):
        body = {"scope": {self.scope_key: ctx.principal_id}, "simpleRetrievalParams": {"pageSize": 100}}
        out, token = [], None
        while True:
            if token:
                body["simpleRetrievalParams"]["pageToken"] = token
            r = self.http.post(f"{self.base}/{self.engine}/memories:retrieve", json=body)
            r.raise_for_status()
            data = r.json()
            out += [Discovered("memory_record", {"name": m["memory"]["name"]}) for m in data.get("retrievedMemories", [])]
            token = data.get("nextPageToken")
            if not token:
                return out

    def _delete(self, artifact, ctx, fallback_from=None):
        r = self.http.delete(f"{self.base}/{artifact.locator['name']}")
        r.raise_for_status()
        return self._ok(artifact, Action.DELETE)
