"""Measure what personal data a sample of conversations carries, per detector, without keeping any values.

Used in readiness assessments (partner-pack/rapid-assessment.md): run the client's own sample (exported chat
logs, transcripts) through the detectors configured for them and report counts. The per-detector columns show
what each detector adds, e.g. names only IndicNER finds; they do not measure misses, which needs a labelled set.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def read_sample(path: str | Path, field: str = "text") -> list[str]:
    """One record per line of a .txt file; or JSON Lines with a text field, or OpenAI-style ``messages``."""
    from ..gateway import _read, _text_slots

    p = Path(path)
    if p.suffix not in (".jsonl", ".ndjson"):
        return [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    out = []
    for i, ln in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except ValueError as e:
            raise ValueError(f"{p.name}:{i}: not JSON") from e
        if isinstance(rec, str):
            out.append(rec)
        elif isinstance(rec, dict) and isinstance(rec.get(field), str):
            out.append(rec[field])
        elif isinstance(rec, dict) and isinstance(rec.get("messages"), list):
            out.append("\n".join(_read(c, k) for c, k in _text_slots("chat", rec)))
        else:
            raise ValueError(f"{p.name}:{i}: expected a string, a '{field}' field or 'messages'")
    return out


def scan(texts: list[str], composite) -> dict:
    names = [type(d).__name__ for d in composite.detectors]
    total, per = Counter(), {n: Counter() for n in names}
    with_pii = 0
    for t in texts:
        found = composite.detect(t)
        if found:
            with_pii += 1
        total.update(e.type for e in found)
        for n, d in zip(names, composite.detectors, strict=True):
            per[n].update(e.type for e in d.detect(t))
    n = len(texts)
    return {"records": n, "with_personal_data": with_pii,
            "with_personal_data_pct": round(100 * with_pii / n, 1) if n else 0.0,
            "entity_types": dict(total.most_common()),
            "by_detector": {k: dict(v.most_common()) for k, v in per.items()},
            "note": "Counts of what was found. Misses are not measured; that needs a labelled sample."}


def scan_markdown(rep: dict) -> str:
    dets = list(rep["by_detector"])
    types = list(rep["entity_types"]) or sorted({t for v in rep["by_detector"].values() for t in v})
    lines = ["# PII sample scan", "",
             f"- Records: **{rep['records']}**; with personal data: **{rep['with_personal_data']}** "
             f"({rep['with_personal_data_pct']}%)", "",
             "| Type | Combined | " + " | ".join(dets) + " |", "|---|---|" + "---|" * len(dets)]
    for t in types:
        lines.append(f"| {t} | {rep['entity_types'].get(t, 0)} | "
                     + " | ".join(str(rep["by_detector"][d].get(t, 0)) for d in dets) + " |")
    lines += ["", rep["note"]]
    return "\n".join(lines) + "\n"
