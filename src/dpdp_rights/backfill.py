"""Brownfield backfill: tokenise personal data already sitting in a store, in place (docs/backfill.md).

Existing RAG corpora, ticket tables and eval sets were written before the framework, so they hold raw values. A
backfill walks a store item by item and, for each item:

1. **Decides whose it is**, from the owner field (a customer id column, a metadata field). Per-person keys
   mean every value needs an owner. Items with no owner are left alone and listed (``unowned: skip``, the
   default), or masked irreversibly (``unowned: mask``) when the values are not needed.
2. **Tokenises** the text in that person's context. This is the same ``protect()`` agents use, so the same
   value of the same person gets the same token. It runs without a consent check, because tokenising existing
   data reduces risk; owners with no consent record for the purpose are counted as a gap instead.
3. **Re-embeds** the chunk from the tokenised text (stores with vectors), and writes text and vector back.
4. **Registers lineage after the fact**, so erasure, access and breach assessment know the item exists.

The default is a **dry run**: it changes nothing and reports items, finds, owners, unowned items, and the text
that would be re-embedded, with a cost estimate. ``--apply`` needs ``--confirm <store>``, writes batch by
batch, and records a resumable run: re-running after a failure continues from the last finished batch, and
items already tokenised are left as they are.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .core.context import ContextEnvelope
from .core.models import new_id, utcnow

MAX_LISTED = 50


@dataclass
class BackfillReport:
    store: str
    purpose: str
    apply: bool
    run_id: str | None = None
    items: int = 0
    with_pii: int = 0
    rewritten: int = 0
    reembedded: int = 0
    already_tokenised: int = 0
    owners: set = field(default_factory=set)
    owners_new: int = 0
    owners_without_consent: int = 0
    unowned_with_pii: int = 0
    unowned_masked: int = 0
    unowned_locations: list = field(default_factory=list)
    entity_types: Counter = field(default_factory=Counter)
    chars_to_embed: int = 0
    residual_raw: int = 0                # after apply: items where the detectors still find raw values
    status: str = "dry_run"

    def to_dict(self, price_per_million_tokens: float | None = None) -> dict:
        tokens = self.chars_to_embed // 4
        out = {"store": self.store, "purpose": self.purpose, "mode": "apply" if self.apply else "dry_run",
               "run_id": self.run_id, "status": self.status, "items": self.items, "with_personal_data": self.with_pii,
               "rewritten": self.rewritten, "reembedded": self.reembedded, "already_tokenised": self.already_tokenised,
               "owners": len(self.owners), "owners_new_to_the_vault": self.owners_new,
               "owners_without_consent_for_purpose": self.owners_without_consent,
               "unowned_with_personal_data": self.unowned_with_pii, "unowned_masked": self.unowned_masked,
               "unowned_locations": self.unowned_locations, "entity_types": dict(self.entity_types.most_common()),
               "embedding": {"characters": self.chars_to_embed, "approx_tokens": tokens,
                             "approx_cost": round(tokens / 1e6 * price_per_million_tokens, 4)
                             if price_per_million_tokens is not None else None},
               "residual_raw_after_apply": self.residual_raw if self.apply else None}
        return out

    def counts(self) -> dict:
        return {k: v for k, v in self.to_dict().items() if isinstance(v, int)}


class BackfillError(RuntimeError):
    pass


def run(f, store: str, purpose: str, *, apply: bool = False, confirm: str | None = None, batch: int = 100,
        limit: int | None = None, unowned: str = "skip", id_type: str = "EXTERNAL_ID", kind: str | None = None,
        resume: str | None = None, started_by: str = "cli") -> BackfillReport:
    from .vault.vault import TOKEN_RE as TOK

    conn = f.connectors.get(store)
    if conn is None:
        raise BackfillError(f"unknown store '{store}'")
    if not conn.can_backfill:
        raise BackfillError(f"store '{store}' ({conn.type_name}) cannot be backfilled in place: sql_table needs "
                            "content_column; jsonl_dataset needs text_field")
    if f.store.get_purpose(purpose) is None:
        raise BackfillError(f"unknown purpose '{purpose}'")
    if unowned not in ("skip", "mask"):
        raise BackfillError("unowned must be skip or mask")
    if not 1 <= batch <= 5000:
        raise BackfillError("batch must be between 1 and 5000")
    if apply and confirm != store:
        raise BackfillError(f"--apply rewrites '{store}' in place: pass --confirm {store} (after taking a backup)")
    if apply and conn.has_embeddings and getattr(conn, "embedder", None) is None:
        raise BackfillError(f"'{store}' has vectors but no embedding model is configured; nothing was changed")
    kind = kind or getattr(conn, "kind", None) or "record"
    rep = BackfillReport(store, purpose, apply)
    cursor = None
    if resume:
        prev = f.store.get_backfill_run(resume)
        if prev is None or prev["store"] != store:
            raise BackfillError(f"no run {resume} for store '{store}'")
        if prev["status"] == "completed":
            raise BackfillError(f"run {resume} already completed")
        cursor, rep.run_id = prev["cursor"], resume
        for k, v in (prev["counts"] or {}).items():
            if hasattr(rep, k) and isinstance(getattr(rep, k), int):
                setattr(rep, k, v)
    elif apply:
        rep.run_id = new_id("bf")
    det = f.tokenizer.detector
    needs_consent = (f.store.get_purpose(purpose).legal_basis != "legitimate_use")
    seen_owner: dict[str, str] = {}

    def save(status: str, error: str | None = None):
        if not apply:
            return
        now = utcnow()
        row = {"run_id": rep.run_id, "store": store, "purpose_id": purpose, "status": status, "cursor": cursor,
               "counts": rep.counts(), "started_by": started_by, "updated_at": now, "error": error}
        if f.store.get_backfill_run(rep.run_id) is None:
            row["started_at"] = now
        f.store.put_backfill_run(row)

    save("running")
    done = 0
    try:
        while limit is None or done < limit:
            items = conn.backfill_items(cursor, batch if limit is None else min(batch, limit - done))
            if not items:
                break
            changes, lineage = [], []
            for it in items:
                done += 1
                rep.items += 1
                raw_text = TOK.sub(" ", it.text)
                found = det.detect(raw_text)
                if not found:
                    if TOK.search(it.text):
                        rep.already_tokenised += 1
                    continue
                rep.with_pii += 1
                rep.entity_types.update(e.type for e in found)
                if not it.owner_ref:
                    rep.unowned_with_pii += 1
                    if len(rep.unowned_locations) < MAX_LISTED:
                        rep.unowned_locations.append(it.locator)
                    if unowned == "mask":
                        new = _mask(it.text, det)
                        rep.unowned_masked += 1
                        rep.chars_to_embed += len(new) if conn.has_embeddings else 0
                        changes.append((it, new))
                    continue
                pid = seen_owner.get(it.owner_ref)
                if pid is None:
                    pid = f.vault.resolve_principal(it.owner_ref, id_type, create=False)
                    if pid is None:
                        rep.owners_new += 1
                        if apply:
                            pid = f.vault.resolve_principal(it.owner_ref, id_type, create=True)
                            f.store.ensure_principal(pid)
                    if pid is not None and needs_consent and not f.ledger.has_effective(pid, purpose):
                        rep.owners_without_consent += 1
                    if pid is None and needs_consent:
                        rep.owners_without_consent += 1
                    seen_owner[it.owner_ref] = pid or f"new:{it.owner_ref}"
                rep.owners.add(it.owner_ref)
                if not apply:
                    rep.chars_to_embed += len(it.text) if conn.has_embeddings else 0
                    continue
                from .core import context as ctxmod

                tok = ctxmod.set_current(ContextEnvelope(pid, purpose))
                try:
                    p = f.protect(it.text, enforce_consent=False)
                finally:
                    ctxmod.reset(tok)
                if p.text == it.text:
                    continue
                rep.chars_to_embed += len(p.text) if conn.has_embeddings else 0
                changes.append((it, p.text))
                lineage.append((it, pid, p))
            if apply and changes:
                vecs: list[Any] = [None] * len(changes)
                if conn.has_embeddings:
                    vecs = conn.embedder([t for _, t in changes])
                    rep.reembedded += len(changes)
                conn.backfill_write([(it, t, v) for (it, t), v in zip(changes, vecs, strict=True)])
                rep.rewritten += len(changes)
                for it, _pid, p in lineage:
                    loc = {"id": it.locator["id"]}
                    f.touch_artifact(kind, store, loc, content=p.text, element_ids=p.element_ids, purpose=purpose)
                for _it, t in changes:
                    if det.detect(TOK.sub(" ", t)):
                        rep.residual_raw += 1
            cursor = items[-1].cursor
            save("running")
    except Exception as exc:
        rep.status = "failed"
        save("failed", f"{type(exc).__name__}: {exc}"[:500])
        raise
    rep.status = "completed" if apply else "dry_run"
    save("completed")
    return rep


def _mask(text: str, det) -> str:
    parts, cur = [], 0
    for e in sorted(det.detect(text), key=lambda e: e.start):
        if e.start < cur:
            continue
        parts += [text[cur:e.start], f"[{e.type}]"]
        cur = e.end
    return "".join(parts) + text[cur:]


def markdown(rep: dict) -> str:
    e = rep["embedding"]
    lines = [f"# Backfill {'run' if rep['mode'] == 'apply' else 'dry run'}: {rep['store']} ({rep['purpose']})", ""]
    if rep["mode"] == "dry_run":
        lines += ["Nothing was changed. Run again with `--apply --confirm " + rep["store"] + "` after a backup.", ""]
    lines += ["| | |", "|---|---|",
              f"| Items read | {rep['items']} |", f"| With personal data | {rep['with_personal_data']} |",
              f"| Already tokenised | {rep['already_tokenised']} |",
              f"| Owners | {rep['owners']} ({rep['owners_new_to_the_vault']} new to the vault) |",
              f"| Owners without consent for the purpose | {rep['owners_without_consent_for_purpose']} |",
              f"| With personal data but no owner | {rep['unowned_with_personal_data']} "
              f"({rep['unowned_masked']} masked) |",
              f"| Text to re-embed | {e['characters']} characters, about {e['approx_tokens']} tokens"
              + (f", about {e['approx_cost']} at the given price |" if e["approx_cost"] is not None else " |")]
    if rep["mode"] == "apply":
        lines += [f"| Rewritten | {rep['rewritten']} (re-embedded {rep['reembedded']}) |",
                  f"| Still holding raw values the detectors find | {rep['residual_raw_after_apply']} |",
                  f"| Run | `{rep['run_id']}` ({rep['status']}) |"]
    if rep["entity_types"]:
        lines += ["", "Kinds found: " + ", ".join(f"{k} {v}" for k, v in rep["entity_types"].items())]
    if rep["unowned_locations"]:
        lines += ["", "Items with personal data but no owner (left raw unless `--unowned mask`):", ""]
        lines += [f"- `{loc}`" for loc in rep["unowned_locations"]]
    return "\n".join(lines) + "\n"
