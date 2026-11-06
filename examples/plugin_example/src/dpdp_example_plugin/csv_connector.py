"""A connector for CSV record files (id, principal_id, text), standing in for a client system such as an
HR or CRM export. It shows everything a connector needs: supported actions, declared capabilities,
discovery, the action handlers, and verification."""
from __future__ import annotations

import csv
from pathlib import Path

from dpdp_rights.connectors.base import Capabilities, Connector, Discovered, VerifyResult, redact_tokens
from dpdp_rights.core.models import Action

FIELDS = ["id", "principal_id", "text"]


class CsvRecordsConnector(Connector):
    supports = {Action.DELETE, Action.REDACT, Action.CRYPTO_SHRED}
    capabilities = Capabilities(
        store="CSV record files (id, principal_id, text)",
        discover="native", discover_how="principal_id column, and token search in the text column",
        verify="rescan", verify_how="rescans for tokens and raw values",
        limits=("rewrites the whole file on each change; not for concurrent writers",),
    )

    def __init__(self, name: str, path: str, **kw):
        super().__init__(name, **kw)
        self.path = Path(path)

    # -- file helpers -----------------------------------------------------------------------------------
    def _rows(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def _save(self, rows: list[dict]) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
        tmp.replace(self.path)          # atomic swap

    # -- the connector contract -------------------------------------------------------------------------
    def discover(self, ctx):
        return [Discovered("record", {"id": r["id"]}) for r in self._rows()
                if r["principal_id"] == ctx.principal_id or any(t in r["text"] for t in ctx.tokens)]

    def fetch(self, artifact):
        return next((r["text"] for r in self._rows() if r["id"] == artifact.locator["id"]), None)

    def _delete(self, artifact, ctx, fallback_from=None):
        rows = self._rows()
        kept = [r for r in rows if r["id"] != artifact.locator["id"]]
        self._save(kept)
        return self._ok(artifact, Action.DELETE, removed=len(rows) - len(kept),
                        **({"fallback_from": fallback_from.value} if fallback_from else {}))

    def _redact(self, artifact, ctx):
        rows = self._rows()
        for r in rows:
            if r["id"] == artifact.locator["id"]:
                r["text"] = redact_tokens(r["text"], ctx.tokens)
        self._save(rows)
        return self._ok(artifact, Action.REDACT)

    def verify(self, ctx):
        findings = [d.__dict__ for d in self.discover(ctx)]
        text = "\n".join(r["text"] for r in self._rows())
        findings += [{"raw_value_found": True} for v in set(ctx.probes.values()) if v and v in text]
        return VerifyResult(self.name, not findings, findings)
