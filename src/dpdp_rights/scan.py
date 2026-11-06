"""Read-only discovery scan: where raw personal data sits today, before any integration (docs/scan.md).

Two kinds of source:

- **Configured stores:** each connector in the config that can read content (SQL tables, JSONL datasets, log
  files, Redis, CloudWatch Logs, S3, DynamoDB, Cloud Logging, BigQuery, Langfuse) is sampled through its
  ``sample()`` method, which never writes.
- **Exported files:** ``--path`` takes files or folders of exports: CloudWatch or Cloud Logging exports, trace
  exports, chat logs, transcripts (``.log``, ``.txt``, ``.json``, ``.jsonl``, ``.ndjson``, ``.csv``, and the same
  gzipped). No credentials needed.

For each source it reports how many sampled items held raw personal data, of which kinds, and how many already
carry vault tokens; and it drafts inventory entries for the coverage report. Text is read into memory, run
through the detectors and discarded: the report and the draft hold counts and locations only, never values.

The scan builds detectors and connectors from the config but not the framework, so it creates nothing in the
control-plane database either.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Iterable, Iterator

TOKEN_RE = re.compile(r"<[A-Z][A-Z0-9_]*_[0-9a-f]{12}>")
FILE_SUFFIXES = (".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv")
MAX_LIMIT = 10_000

# What kind of system a connector type is, for the draft inventory.
CATEGORY = {"sql_table": "database", "jsonl_dataset": "dataset", "log_file": "logs", "redis_cache": "cache",
            "aws_cloudwatch_logs": "logs", "aws_s3_objects": "object_store", "aws_dynamodb": "database",
            "gcp_cloud_logging": "logs", "gcp_bigquery": "warehouse", "langfuse": "traces"}
PLATFORM = {"sql_table": "SQL database", "jsonl_dataset": "JSONL files", "log_file": "Log files",
            "redis_cache": "Redis", "aws_cloudwatch_logs": "Amazon CloudWatch Logs", "aws_s3_objects": "Amazon S3",
            "aws_dynamodb": "Amazon DynamoDB", "gcp_cloud_logging": "Google Cloud Logging",
            "gcp_bigquery": "BigQuery", "langfuse": "Langfuse"}


@dataclass
class SourceResult:
    name: str
    kind: str                       # connector type, or "file"
    sampled: int = 0
    with_raw_pii: int = 0
    with_tokens: int = 0
    entity_types: Counter = field(default_factory=Counter)
    examples: list[dict] = field(default_factory=list)    # locators of items with raw PII (no values)
    error: str | None = None
    not_sampled: str | None = None

    def to_dict(self) -> dict:
        n = self.sampled
        return {"name": self.name, "kind": self.kind, "sampled": n, "with_raw_pii": self.with_raw_pii,
                "with_raw_pii_pct": round(100 * self.with_raw_pii / n, 1) if n else 0.0,
                "with_tokens": self.with_tokens, "entity_types": dict(self.entity_types.most_common()),
                "examples": self.examples, "error": self.error, "not_sampled": self.not_sampled}


def _scan_items(res: SourceResult, items: Iterable, detector, examples: int) -> None:
    for s in items:
        text = s.text if hasattr(s, "text") else s[1]
        loc = s.locator if hasattr(s, "locator") else s[0]
        res.sampled += 1
        if TOKEN_RE.search(text):
            res.with_tokens += 1
        found = [e for e in detector.detect(TOKEN_RE.sub(" ", text))]
        if found:
            res.with_raw_pii += 1
            res.entity_types.update(e.type for e in found)
            if len(res.examples) < examples:
                res.examples.append({"locator": loc, "types": sorted({e.type for e in found})})


# ---- files ---------------------------------------------------------------------------------------------------------
def _open_text(p: Path) -> str:
    raw = p.read_bytes()
    if p.suffix == ".gz":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", "replace")


def _records(p: Path) -> Iterator[tuple[dict, str]]:
    """Records in an export file: one per line, JSON array item, or CSV row."""
    name = p.name[:-3] if p.name.endswith(".gz") else p.name
    text = _open_text(p)
    if name.endswith(".json"):
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, list):
            for i, item in enumerate(doc):
                yield {"path": str(p), "item": i}, json.dumps(item, ensure_ascii=False, default=str)
            return
        if isinstance(doc, dict):
            # e.g. {"events": [...]} (CloudWatch get-log-events), {"entries": [...]}, {"data": [...]}
            for key in ("events", "entries", "data", "logEvents", "records", "items"):
                if isinstance(doc.get(key), list):
                    for i, item in enumerate(doc[key]):
                        yield {"path": str(p), key: i}, json.dumps(item, ensure_ascii=False, default=str)
                    return
            yield {"path": str(p)}, json.dumps(doc, ensure_ascii=False, default=str)
            return
    if name.endswith(".csv"):
        for i, row in enumerate(csv.reader(io.StringIO(text)), 1):
            yield {"path": str(p), "row": i}, " | ".join(row)
        return
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.strip():
            yield {"path": str(p), "line": i}, ln


def _files(paths: list[str]) -> list[Path]:
    out = []
    for raw in paths:
        p = Path(raw)
        cands = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())
        for f in cands:
            n = f.name[:-3] if f.name.endswith(".gz") else f.name
            if n.endswith(FILE_SUFFIXES):
                out.append(f)
    return out


def _reservoir(it: Iterator, k: int, seed: int = 7) -> list:
    """An even sample of k items from a stream of unknown length (whole file read once, not kept)."""
    rng, out = random.Random(seed), []
    for i, x in enumerate(it):
        if i < k:
            out.append(x)
        else:
            j = rng.randint(0, i)
            if j < k:
                out[j] = x
    return out


# ---- the scan ------------------------------------------------------------------------------------------------------
def scan(detector, connectors: dict | None = None, paths: list[str] | None = None, limit: int = 200,
         examples: int = 5) -> dict:
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    results: list[SourceResult] = []
    for name, conn in (connectors or {}).items():
        res = SourceResult(name, conn.type_name)
        if not getattr(conn, "can_sample", False):
            res.not_sampled = "this connector cannot read content; check the store by hand or through lineage"
        else:
            try:
                _scan_items(res, conn.sample(limit), detector, examples)
            except Exception as exc:  # noqa: BLE001 - one store failing must not stop the scan
                res.error = f"{type(exc).__name__}: {exc}"[:300]
        results.append(res)
    for f in _files(paths or []):
        res = SourceResult(str(f), "file")
        try:
            _scan_items(res, _reservoir(_records(f), limit), detector, examples)
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"[:300]
        results.append(res)
    total = Counter()
    for r in results:
        total.update(r.entity_types)
    leaking = [r.name for r in results if r.with_raw_pii]
    scope = {"sources_scanned": [r.name for r in results if not r.not_sampled and not r.error],
             "sources_not_sampled": [r.name for r in results if r.not_sampled],
             "sources_failed": [r.name for r in results if r.error],
             "items_sampled": sum(r.sampled for r in results),
             "limit_per_source": limit,
             "complete_inventory": False,
             "statement": ("This scan read a sample of the sources listed and nothing else. A sample can miss personal "
                           "data, a source with no finds may still hold it, and systems not listed here were not "
                           "looked at. It is not a complete inventory of where personal data is.")}
    return {"scanned_on": date.today().isoformat(), "limit_per_source": limit, "scope": scope,
            "sources": [r.to_dict() for r in results],
            "summary": {"sources": len(results), "with_raw_pii": len(leaking),
                        "not_sampled": [r.name for r in results if r.not_sampled],
                        "errors": [r.name for r in results if r.error],
                        "entity_types": dict(total.most_common())},
            "note": ("Samples only: a store with no finds in the sample may still hold personal data. Finds depend "
                     "on the configured detectors (see docs/pii-benchmark.md). No values are kept.")}


DRAFT_HEADER = """# DRAFT from dpdp-rights scan: confirm every entry before running coverage.
#
# This lists only the sources the scan was pointed at. It is NOT a complete inventory: add every other system
# the agent writes to or reads from (see partner-pack/inventory.template.yaml and the discovery questionnaire).
# Every entry says holds_personal_data: true, because a sample with no finds does not show a system holds none.
"""


def draft_inventory(rep: dict, client: str = "<client name>", connector_types: dict | None = None) -> dict:
    """Draft inventory entries (partner-pack/inventory.template.yaml) for the coverage report."""
    systems = []
    for s in rep["sources"]:
        is_file = s["kind"] == "file"
        held = sorted(set(s["entity_types"]) | ({"FREE_TEXT"} if s["with_raw_pii"] or s["with_tokens"] else set()))
        systems.append({
            "name": s["name"],
            "description": (f"DRAFT from dpdp-rights scan on {rep['scanned_on']}: {s['with_raw_pii']} of "
                            f"{s['sampled']} sampled items held raw personal data; {s['with_tokens']} held tokens. "
                            "Confirm every field."),
            "category": "other" if is_file else CATEGORY.get(s["kind"], "other"),
            "platform": "exported file" if is_file else PLATFORM.get(s["kind"], s["kind"]),
            # Never false from a sample: no finds in a sample does not show the system holds no personal data, and
            # coverage treats false as out of scope. A person sets it to false after checking.
            "holds_personal_data": True,
            "data_elements": held,
            "purposes": [],
            "region": "",
            "owner": "",
            "processor": None,
            "processor_contract": None,
            "connector": None if is_file else s["name"],
            "manual_procedure": None,
            "retention_days": None,
            "tested_on": None,
            "test_evidence": None,
            "notes": ("not sampled: " + s["not_sampled"]) if s["not_sampled"] else
                     ("scan error: " + s["error"]) if s["error"] else
                     (f"no finds in {s['sampled']} sampled items; this does not show the system holds no personal "
                      "data. Set holds_personal_data: false only after checking." if not s["with_raw_pii"] else
                      f"raw personal data in {s['with_raw_pii']} of {s['sampled']} sampled items"),
        })
    return {"engagement": {"client": client, "system": "", "prepared_by": "dpdp-rights scan (draft)", "dpo": "",
                           "prepared_on": rep["scanned_on"]}, "systems": systems}


def markdown(rep: dict) -> str:
    s, sc = rep["summary"], rep["scope"]
    lines = ["# DPDP exposure scan", "",
             "> **Scope and limits.** " + sc["statement"], ">",
             f"> - Sampled: {sc['items_sampled']} items, at most {sc['limit_per_source']} per source, from "
             f"{len(sc['sources_scanned'])} sources.",
             f"> - Not sampled (cannot read content): {', '.join(sc['sources_not_sampled']) or 'none'}.",
             f"> - Failed: {', '.join(sc['sources_failed']) or 'none'}.",
             "> - Finds depend on the detectors used: " + ", ".join(rep.get("detectors") or ["as configured"]) + ".",
             "",
             f"Scanned on {rep['scanned_on']}. **{s['with_raw_pii']} of {s['sources']} sources** held raw personal "
             "data in the sample.", "",
             "| Source | Kind | Sampled | With raw personal data | With tokens | Kinds found |", "|---|---|---|---|---|---|"]
    for r in rep["sources"]:
        if r["not_sampled"]:
            lines.append(f"| {r['name']} | {r['kind']} | – | not sampled | – | {r['not_sampled']} |")
        elif r["error"]:
            lines.append(f"| {r['name']} | {r['kind']} | – | error | – | {r['error']} |")
        else:
            kinds = ", ".join(f"{k} {v}" for k, v in r["entity_types"].items()) or "none found"
            lines.append(f"| {r['name']} | {r['kind']} | {r['sampled']} | {r['with_raw_pii']} "
                         f"({r['with_raw_pii_pct']}%) | {r['with_tokens']} | {kinds} |")
    if s["entity_types"]:
        lines += ["", "## Kinds of personal data found (detections)", "", "| Kind | Count |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in s["entity_types"].items()]
    ex = [(r["name"], e) for r in rep["sources"] for e in r["examples"]]
    if ex:
        lines += ["", "## Where (first finds per source, locations only)", "", "| Source | Location | Kinds |",
                  "|---|---|---|"]
        lines += [f"| {n} | `{json.dumps(e['locator'], default=str)}` | {', '.join(e['types'])} |" for n, e in ex]
    lines += ["", rep["note"]]
    return "\n".join(lines) + "\n"
