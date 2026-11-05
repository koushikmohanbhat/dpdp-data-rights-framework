"""Cloud-neutral connectors: any SQL table (incl. pgvector, warehouse tables),
JSONL datasets (eval / fine-tuning sets on local disk, S3 or GCS), log files,
and Redis caches."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, delete, or_, select, update

from ..core.models import Action, Artifact
from .base import Connector, Discovered, ErasureContext, VerifyResult, redact_tokens, register


@register("sql_table")
class SqlTableConnector(Connector):
    """Options: url, table, id_column, content_column?, principal_column?, kind (default 'record').

    Works for app tables, summary tables, pgvector tables (delete the row, the
    vector goes with it), Aurora/RDS/Cloud SQL/AlloyDB, Redshift/Postgres-compatible warehouses.
    """

    supports = {Action.DELETE, Action.REDACT, Action.REGENERATE, Action.CRYPTO_SHRED}

    def __init__(self, name: str, url: str, table: str, id_column: str = "id",
                 content_column: str | None = None, principal_column: str | None = None,
                 kind: str = "record", **kw):
        super().__init__(name, **kw)
        self.engine = create_engine(url, future=True)
        self._table_name, self._table = table, None
        self.id_col, self.content_col, self.principal_col, self.kind = id_column, content_column, principal_column, kind

    @property
    def table(self) -> Table:
        """Reflected lazily so the kit can start before application tables exist."""
        if self._table is None:
            self._table = Table(self._table_name, MetaData(), autoload_with=self.engine)
        return self._table

    def _where_mentions(self, needles: list[str]):
        conds = []
        if self.principal_col:
            conds.append(self.table.c[self.principal_col].in_(needles[:1]))
        if self.content_col:
            conds += [self.table.c[self.content_col].contains(n) for n in needles[1:] if n]
        return or_(*conds) if conds else None

    def discover(self, ctx: ErasureContext) -> list[Discovered]:
        cond = self._where_mentions(ctx.needles)
        if cond is None:
            return []
        with self.engine.connect() as c:
            rows = c.execute(select(self.table.c[self.id_col]).where(cond)).all()
        return [Discovered(self.kind, {"id": r[0]}) for r in rows]

    def fetch(self, artifact: Artifact) -> str | None:
        if not self.content_col:
            return None
        with self.engine.connect() as c:
            r = c.execute(select(self.table.c[self.content_col])
                          .where(self.table.c[self.id_col] == artifact.locator["id"])).first()
        return r[0] if r else None

    def _delete(self, artifact, ctx, fallback_from=None):
        with self.engine.begin() as c:
            n = c.execute(delete(self.table).where(self.table.c[self.id_col] == artifact.locator["id"])).rowcount
        return self._ok(artifact, Action.DELETE, rows=n, **({"fallback_from": fallback_from.value} if fallback_from else {}))

    def _redact(self, artifact, ctx):
        content = self.fetch(artifact)
        if content is None:
            return self._delete(artifact, ctx, fallback_from=Action.REDACT)
        new = redact_tokens(content, ctx.tokens)
        with self.engine.begin() as c:
            c.execute(update(self.table).where(self.table.c[self.id_col] == artifact.locator["id"])
                      .values({self.content_col: new}))
        return self._ok(artifact, Action.REDACT, changed=new != content)

    def replace(self, artifact, new_content, ctx):
        with self.engine.begin() as c:
            c.execute(update(self.table).where(self.table.c[self.id_col] == artifact.locator["id"])
                      .values({self.content_col: new_content}))
        return self._ok(artifact, Action.REGENERATE)

    def verify(self, ctx: ErasureContext) -> VerifyResult:
        findings = [d.__dict__ for d in self.discover(ctx)]
        if self.content_col and ctx.probes:
            with self.engine.connect() as c:
                for raw in set(ctx.probes.values()):
                    for r in c.execute(select(self.table.c[self.id_col])
                                       .where(self.table.c[self.content_col].contains(raw))):
                        findings.append({"id": r[0], "raw_value_found": True})
        return VerifyResult(self.name, not findings, findings)


# ---------------------------------------------------------------------------
def _read_text(path: str) -> str:
    if path.startswith("s3://"):
        import boto3

        b, k = path[5:].split("/", 1)
        return boto3.client("s3").get_object(Bucket=b, Key=k)["Body"].read().decode()
    if path.startswith("gs://"):
        from google.cloud import storage  # type: ignore

        b, k = path[5:].split("/", 1)
        return storage.Client().bucket(b).blob(k).download_as_text()
    p = Path(path)
    return p.read_text() if p.exists() else ""


def _write_text(path: str, text: str) -> None:
    if path.startswith("s3://"):
        import boto3

        b, k = path[5:].split("/", 1)
        boto3.client("s3").put_object(Bucket=b, Key=k, Body=text.encode())
        return
    if path.startswith("gs://"):
        from google.cloud import storage  # type: ignore

        b, k = path[5:].split("/", 1)
        storage.Client().bucket(b).blob(k).upload_from_string(text)
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text)


@register("jsonl_dataset")
class JsonlDatasetConnector(Connector):
    """Eval sets, fine-tuning sets, batch files. Options: path (local / s3:// / gs://), id_field, kind.

    For S3, enable bucket versioning carefully: old versions still hold the
    rows. Pair with the ``aws_s3_objects`` connector (purge_versions: true)."""

    supports = {Action.DELETE, Action.REDACT, Action.CRYPTO_SHRED}

    def __init__(self, name: str, path: str, id_field: str = "id", kind: str = "eval_row", **kw):
        super().__init__(name, **kw)
        self.path, self.id_field, self.kind = path, id_field, kind

    def _rows(self) -> list[dict[str, Any]]:
        return [json.loads(l) for l in _read_text(self.path).splitlines() if l.strip()]

    def _save(self, rows) -> None:
        _write_text(self.path, "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))

    def discover(self, ctx):
        out = []
        for r in self._rows():
            blob = json.dumps(r, ensure_ascii=False)
            if any(n in blob for n in ctx.needles):
                out.append(Discovered(self.kind, {"id": r.get(self.id_field)}))
        return out

    def _delete(self, artifact, ctx, fallback_from=None):
        rows = self._rows()
        kept = [r for r in rows if r.get(self.id_field) != artifact.locator["id"]]
        self._save(kept)
        return self._ok(artifact, Action.DELETE, rows_removed=len(rows) - len(kept))

    def _redact(self, artifact, ctx):
        rows = self._rows()
        for i, r in enumerate(rows):
            if r.get(self.id_field) == artifact.locator["id"]:
                rows[i] = json.loads(redact_tokens(json.dumps(r, ensure_ascii=False), ctx.tokens))
        self._save(rows)
        return self._ok(artifact, Action.REDACT)

    def verify(self, ctx):
        text = _read_text(self.path)
        findings = [d.__dict__ for d in self.discover(ctx)]
        findings += [{"raw_value_found": True} for v in set(ctx.probes.values()) if v in text]
        return VerifyResult(self.name, not findings, findings)


@register("log_file")
class LogFileConnector(Connector):
    """Append-only application log files. Treated as immutable: erasure is by
    crypto-shredding (logs hold tokens only, via the kit's logging filter).
    Verification proves no raw value is present."""

    supports = {Action.CRYPTO_SHRED, Action.DELETE}

    def __init__(self, name: str, path: str, **kw):
        super().__init__(name, **kw)
        self.path = path

    def discover(self, ctx):
        text = _read_text(self.path)
        return [Discovered("log", {"path": self.path})] if any(n in text for n in ctx.needles) else []

    def _delete(self, artifact, ctx, fallback_from=None):
        # Deleting a shared log file would destroy other people's audit trail; shred instead.
        return self._crypto_shred(artifact, ctx)

    def verify(self, ctx):
        text = _read_text(self.path)
        raw_hits = [{"raw_value_found": True, "type": t.split("_")[0].strip("<")}
                    for t, v in ctx.probes.items() if v and v in text]
        token_hits = sum(text.count(t) for t in ctx.tokens)
        return VerifyResult(self.name, not raw_hits, raw_hits,
                            note=f"{token_hits} token occurrences remain; unreadable after key destruction")


@register("redis_cache")
class RedisCacheConnector(Connector):
    """Semantic / response caches. The kit records cache keys per principal in the
    set ``<index_prefix><principal_id>`` (see ErasureKit.track_cache_key)."""

    supports = {Action.DELETE}

    def __init__(self, name: str, url: str = "redis://localhost:6379/0", index_prefix: str = "dpdp:idx:", **kw):
        super().__init__(name, **kw)
        import redis  # type: ignore

        self.r = redis.Redis.from_url(url)
        self.index_prefix = index_prefix

    def discover(self, ctx):
        keys = self.r.smembers(self.index_prefix + ctx.principal_id)
        return [Discovered("cache_entry", {"key": k.decode() if isinstance(k, bytes) else k}) for k in keys]

    def _delete(self, artifact, ctx, fallback_from=None):
        n = self.r.delete(artifact.locator["key"])
        self.r.srem(self.index_prefix + ctx.principal_id, artifact.locator["key"])
        return self._ok(artifact, Action.DELETE, deleted=n)
