"""Cloud-neutral connectors: any SQL table (incl. pgvector, warehouse tables),
JSONL datasets (eval / fine-tuning sets on local disk, S3 or GCS), log files,
and Redis caches."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, delete, or_, select, update

from ..core.models import Action, Artifact
from .base import (
    BackfillItem,
    Capabilities,
    Connector,
    Discovered,
    ErasureContext,
    Sample,
    VerifyResult,
    redact_tokens,
    register,
)


@register("sql_table")
class SqlTableConnector(Connector):
    """Options: url, table, id_column, content_column?, principal_column?, kind (default 'record').

    Works for app tables, summary tables, pgvector tables, Aurora/RDS/Cloud SQL/AlloyDB,
    Redshift/Postgres-compatible warehouses.

    Vector rows (``embedding_column`` set, or ``kind: embedding``): deleting the row removes the vector.
    When a row is *redacted* because it only mentions the principal, ``on_redact`` decides what happens
    to its vector:
      reembed    the text is redacted and the vector recomputed from the redacted text (default when
                 ``embedding_column`` is set; uses the framework's embedding model)
      delete     the row is deleted; re-ingest it from its source (default for ``kind: embedding``
                 without ``embedding_column``, since the vector cannot be updated)
      text_only  only the text is redacted (default for ordinary records, which have no vector)
    """

    supports = {Action.DELETE, Action.REDACT, Action.REGENERATE, Action.CRYPTO_SHRED}
    capabilities = Capabilities(
        store='Any SQL database: application tables, pgvector, summaries, Aurora, RDS, Cloud SQL, AlloyDB',
        discover='native', discover_how='principal column, and token search in the content column',
        verify='rescan', verify_how='searches for tokens and the raw values held in memory during the run',
        limits=())

    def __init__(self, name: str, url: str, table: str, id_column: str = "id",
                 content_column: str | None = None, principal_column: str | None = None,
                 kind: str = "record", embedding_column: str | None = None, on_redact: str | None = None,
                 **kw):
        super().__init__(name, **kw)
        self.engine = create_engine(url, future=True)
        self._table_name, self._table = table, None
        self.id_col, self.content_col, self.principal_col, self.kind = id_column, content_column, principal_column, kind
        self.embedding_col = embedding_column
        self.on_redact = on_redact or ("reembed" if embedding_column else
                                       "delete" if kind == "embedding" else "text_only")
        if self.on_redact not in ("reembed", "delete", "text_only"):
            raise ValueError(f"{name}: on_redact must be reembed, delete or text_only")
        if self.on_redact == "reembed" and not embedding_column:
            raise ValueError(f"{name}: on_redact=reembed needs embedding_column")
        self.embedder = None   # set by the framework: callable(list[str]) -> list[list[float]]

    @property
    def table(self) -> Table:
        """Reflected lazily so the framework can start before application tables exist."""
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

    can_sample = True

    def sample(self, limit: int):
        """Newest rows first (by the id column): the content column, or every text column."""
        cols = [self.table.c[self.content_col]] if self.content_col else [
            c for c in self.table.columns if str(c.type).upper().startswith(("VARCHAR", "TEXT", "CHAR", "JSON",
                                                                              "STRING", "NVARCHAR", "CLOB"))]
        if not cols:
            return
        with self.engine.connect() as c:
            q = select(self.table.c[self.id_col], *cols).order_by(self.table.c[self.id_col].desc()).limit(limit)
            for r in c.execute(q):
                text = "\n".join(str(v) for v in r[1:] if v is not None)
                yield Sample({"table": self._table_name, "id": r[0]}, text)

    @property
    def can_backfill(self) -> bool:
        return bool(self.content_col)

    @property
    def has_embeddings(self) -> bool:
        return bool(self.embedding_col)

    def backfill_items(self, after, batch: int):
        """Rows in id order after the cursor; the owner from ``owner_column`` (default principal_column)."""
        owner_col = self.options.get("owner_column") or self.principal_col
        cols = [self.table.c[self.id_col], self.table.c[self.content_col]]
        if owner_col:
            cols.append(self.table.c[owner_col])
        q = select(*cols).order_by(self.table.c[self.id_col])
        if after is not None:
            q = q.where(self.table.c[self.id_col] > after)
        with self.engine.connect() as c:
            rows = c.execute(q.limit(batch)).all()
        return [BackfillItem({"id": r[0]}, r[1] or "", (str(r[2]) if owner_col and r[2] is not None else None), r[0])
                for r in rows]

    def backfill_write(self, changes):
        with self.engine.begin() as c:
            for item, text, vec in changes:
                values: dict[str, Any] = {self.content_col: text}
                if self.embedding_col:
                    if vec is None:
                        raise ValueError(f"{self.name}: a vector is required for every rewritten row")
                    values[self.embedding_col] = self._vector_value(vec)
                c.execute(update(self.table).where(self.table.c[self.id_col] == item.locator["id"]).values(values))
        return len(changes)

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
        if self.on_redact == "delete":
            return self._delete(artifact, ctx, fallback_from=Action.REDACT)
        content = self.fetch(artifact)
        if content is None:
            return self._delete(artifact, ctx, fallback_from=Action.REDACT)
        new = redact_tokens(content, ctx.tokens)
        values: dict[str, Any] = {self.content_col: new}
        detail: dict[str, Any] = {"changed": new != content}
        if self.on_redact == "reembed":
            if self.embedder is None:     # no embedding model available: never leave a stale vector
                return self._delete(artifact, ctx, fallback_from=Action.REDACT)
            values[self.embedding_col] = self._vector_value(self.embedder([new])[0])
            detail["reembedded"] = True
        with self.engine.begin() as c:
            c.execute(update(self.table).where(self.table.c[self.id_col] == artifact.locator["id"])
                      .values(values))
        return self._ok(artifact, Action.REDACT, **detail)

    def _vector_value(self, vec: list[float]):
        """pgvector / array columns take the list; text and JSON columns take a JSON string."""
        col = self.table.c[self.embedding_col]
        try:
            py = col.type.python_type
        except NotImplementedError:
            return vec
        return json.dumps(vec) if py is str else vec

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
    capabilities = Capabilities(
        store='JSONL eval, fine-tuning or batch files on disk, S3 or GCS',
        discover='native', discover_how='scans every row for tokens',
        verify='rescan', verify_how='rescans rows for tokens and raw values',
        limits=(
            'rewrites the whole file on each change',
        ))

    def __init__(self, name: str, path: str, id_field: str = "id", kind: str = "eval_row", **kw):
        super().__init__(name, **kw)
        self.path, self.id_field, self.kind = path, id_field, kind
        self.embedder = None   # set by the framework; used when a backfill rewrites rows with embedding_field

    def _rows(self) -> list[dict[str, Any]]:
        return [json.loads(l) for l in _read_text(self.path).splitlines() if l.strip()]

    @property
    def can_backfill(self) -> bool:
        return bool(self.options.get("text_field"))

    @property
    def has_embeddings(self) -> bool:
        return bool(self.options.get("embedding_field"))

    def backfill_items(self, after, batch: int):
        """Rows in file order (cursor = row index); text in ``text_field``, owner in ``owner_field``."""
        tf, of = self.options["text_field"], self.options.get("owner_field")
        rows = self._rows()
        start = 0 if after is None else int(after) + 1
        out = []
        for i in range(start, min(len(rows), start + batch)):
            r = rows[i]
            out.append(BackfillItem({"id": r.get(self.id_field), "row": i}, str(r.get(tf) or ""),
                                    str(r[of]) if of and r.get(of) is not None else None, i))
        return out

    def backfill_write(self, changes):
        tf, ef = self.options["text_field"], self.options.get("embedding_field")
        rows = self._rows()
        for item, text, vec in changes:
            r = rows[item.locator["row"]]
            if r.get(self.id_field) != item.locator["id"]:
                raise RuntimeError(f"{self.name}: the file changed during the backfill; re-run from the start")
            r[tf] = text
            if ef:
                if vec is None:
                    raise ValueError(f"{self.name}: a vector is required for every rewritten row")
                r[ef] = vec
        self._save(rows)
        return len(changes)

    can_sample = True

    def sample(self, limit: int):
        rows = self._rows()
        for r in rows[-limit:][::-1]:
            yield Sample({"path": self.path, "id": r.get(self.id_field)}, json.dumps(r, ensure_ascii=False))

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
    crypto-shredding (logs hold tokens only, via the framework's logging filter).
    Verification proves no raw value is present."""

    supports = {Action.CRYPTO_SHRED, Action.DELETE}
    capabilities = Capabilities(
        store='Local log files',
        discover='native', discover_how='scans lines for tokens',
        verify='rescan', verify_how='scans for raw values',
        limits=(
            'lines are not edited; tokens become unreadable when the key is destroyed',
        ),
        deletion='none')

    def __init__(self, name: str, path: str, **kw):
        super().__init__(name, **kw)
        self.path = path

    can_sample = True

    def sample(self, limit: int):
        lines = [ln for ln in _read_text(self.path).splitlines() if ln.strip()]
        start = max(0, len(lines) - limit)
        for i in range(len(lines) - 1, start - 1, -1):
            yield Sample({"path": self.path, "line": i + 1}, lines[i])

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
    """Semantic / response caches. The framework records cache keys per principal in the
    set ``<index_prefix><principal_id>`` (see DataRightsFramework.track_cache_key)."""

    supports = {Action.DELETE}
    capabilities = Capabilities(
        store='Redis response and semantic caches',
        discover='native', discover_how='per-principal key index maintained by track_cache_key',
        verify='rediscover', verify_how='index is empty',
        limits=(
            'keys written without track_cache_key are not found',
        ))

    def __init__(self, name: str, url: str = "redis://localhost:6379/0", index_prefix: str = "dpdp:idx:",
                 client=None, **kw):
        super().__init__(name, **kw)
        if client is None:
            import redis  # type: ignore

            client = redis.Redis.from_url(url)
        self.r = client
        self.index_prefix = index_prefix

    can_sample = True

    def sample(self, limit: int):
        """SCAN (never KEYS) for string values; index sets are skipped."""
        n = 0
        for k in self.r.scan_iter(count=200):
            key = k.decode() if isinstance(k, bytes) else k
            if key.startswith(self.index_prefix):
                continue
            try:
                v = self.r.get(k)
            except Exception:  # noqa: BLE001 - not a string value (hash, list ...): skip
                continue
            if v is None:
                continue
            yield Sample({"key": key}, v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v))
            n += 1
            if n >= limit:
                return

    def discover(self, ctx):
        keys = self.r.smembers(self.index_prefix + ctx.principal_id)
        return [Discovered("cache_entry", {"key": k.decode() if isinstance(k, bytes) else k}) for k in keys]

    def _delete(self, artifact, ctx, fallback_from=None):
        n = self.r.delete(artifact.locator["key"])
        self.r.srem(self.index_prefix + ctx.principal_id, artifact.locator["key"])
        return self._ok(artifact, Action.DELETE, deleted=n)
