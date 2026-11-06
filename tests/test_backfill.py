"""Brownfield backfill (docs/backfill.md): dry run, apply, resume, owners, re-embedding, and erasure afterwards."""
import json

import pytest
from sqlalchemy import create_engine, text
from test_rights import _cfg

from dpdp_rights import DataRightsFramework
from dpdp_rights import backfill as bf
from dpdp_rights.vault.vault import TOKEN_RE

ROWS = [  # (id, customer, text): a legacy RAG table written before the framework
    (1, "CUST-1", "Customer Asha Rao, mobile 9876543210, email asha.rao@example.in asked about claim 4411"),
    (2, "CUST-1", "Follow-up: Asha confirmed PAN ABCPE1234F for KYC"),
    (3, "CUST-2", "Ravi called from 9123456780 about his renewal"),
    (4, "CUST-2", "Policy wording section 4: exclusions apply"),            # no personal data
    (5, None, "Shared note: escalate to manager at ops.lead@example.in"),    # personal data, no owner
]


def _store(tmp, rows=ROWS):
    e = create_engine(f"sqlite:///{tmp}/rag.db")
    with e.begin() as c:
        c.execute(text("CREATE TABLE chunks (id INTEGER PRIMARY KEY, customer_id TEXT, chunk TEXT, embedding TEXT)"))
        for r in rows:
            c.execute(text("INSERT INTO chunks VALUES (:i, :c, :t, :e)"), {"i": r[0], "c": r[1], "t": r[2],
                                                                           "e": json.dumps([0.0])})
    return e


def _fw(tmp, **opts):
    conn = {"name": "rag_chunks", "type": "sql_table", "options": {
        "url": f"sqlite:///{tmp}/rag.db", "table": "chunks", "content_column": "chunk", "principal_column": "customer_id",
        "embedding_column": "embedding", "kind": "embedding", **opts}}
    base = _cfg(tmp)
    return DataRightsFramework(_cfg(tmp, connectors=[c.model_dump() for c in base.connectors] + [conn]))


def _rows(e):
    with e.connect() as c:
        return {r[0]: (r[1], r[2]) for r in c.execute(text("SELECT id, chunk, embedding FROM chunks"))}


@pytest.fixture
def setup(workdir):
    tmp, _ = workdir
    e = _store(tmp)
    return _fw(tmp), e


def test_dry_run_changes_nothing_and_reports_what_would_happen(setup):
    f, e = setup
    before = _rows(e)
    rep = bf.run(f, "rag_chunks", "service").to_dict(price_per_million_tokens=0.02)
    assert _rows(e) == before
    assert rep["mode"] == "dry_run" and rep["items"] == 5 and rep["with_personal_data"] == 4
    assert rep["owners"] == 2 and rep["owners_new_to_the_vault"] == 2 and rep["owners_without_consent_for_purpose"] == 2
    assert rep["unowned_with_personal_data"] == 1 and rep["unowned_locations"] == [{"id": 5}]
    assert rep["embedding"]["characters"] > 0 and rep["embedding"]["approx_cost"] is not None
    assert f.vault.resolve_principal("CUST-1", create=False) is None          # no one created
    assert f.store.backfill_runs() == []


def test_apply_tokenises_reembeds_and_registers_lineage(setup):
    f, e = setup
    rep = bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks", batch=2).to_dict()
    rows = _rows(e)
    assert rep["rewritten"] == 3 and rep["reembedded"] == 3 and rep["status"] == "completed"
    assert "9876543210" not in rows[1][0] and "asha.rao@example.in" not in rows[1][0] and TOKEN_RE.search(rows[1][0])
    assert "ABCPE1234F" not in rows[2][0] and "9123456780" not in rows[3][0]
    assert rows[4][0] == ROWS[3][2] and rows[5][0] == ROWS[4][2]               # nothing to do / no owner: left
    assert rows[1][1] != json.dumps([0.0])                                    # new vector from the tokenised text
    pid = f.vault.resolve_principal("CUST-1", create=False)
    arts = [a for a in f.store.direct_artifacts(pid) if a.store == "rag_chunks"]
    assert {a.locator["id"] for a in arts} == {1, 2}
    run = f.store.backfill_runs()[0]
    assert run["status"] == "completed" and run["counts"]["rewritten"] == 3 and "chunk" not in json.dumps(run["counts"])


def test_rerunning_is_safe_and_leaves_tokenised_items_alone(setup):
    f, e = setup
    bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks")
    after = _rows(e)
    rep = bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks").to_dict()
    assert _rows(e) == after and rep["rewritten"] == 0 and rep["already_tokenised"] == 3


def test_after_a_backfill_an_ordinary_erasure_reaches_the_legacy_rows(setup):
    f, e = setup
    bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks")
    pid = f.vault.resolve_principal("CUST-1", create=False)
    cert = f.erase(pid)
    rows = _rows(e)
    assert 1 not in rows and 2 not in rows and 3 in rows                      # Asha's chunks gone, Ravi's kept
    assert cert["verification"] and all(v["ok"] for v in cert["verification"] if v["store"] == "rag_chunks")


def test_the_same_person_gets_the_same_tokens_so_tokenised_queries_still_match(setup):
    f, e = setup
    bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks")
    pid = f.vault.resolve_principal("CUST-1", create=False)
    stored = _rows(e)[1][0]
    f.grant_consent(pid, "service")
    with f.context(pid, purpose="service"):
        q = f.protect("what did 9876543210 ask about?").text
    tok = TOKEN_RE.search(q).group(0)
    assert tok in stored


def test_unowned_items_can_be_masked_irreversibly(setup):
    f, e = setup
    rep = bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks", unowned="mask").to_dict()
    assert rep["unowned_masked"] == 1 and _rows(e)[5][0] == "Shared note: escalate to manager at [EMAIL]"


def test_a_failed_run_resumes_from_its_last_finished_batch(setup, monkeypatch):
    f, e = setup
    conn = f.connectors["rag_chunks"]
    real, calls = conn.backfill_write, {"n": 0}

    def flaky(changes):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("connection reset")
        return real(changes)
    monkeypatch.setattr(conn, "backfill_write", flaky)
    with pytest.raises(RuntimeError):
        bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks", batch=1)
    run = f.store.backfill_runs()[0]
    assert run["status"] == "failed" and "connection reset" in run["error"] and run["cursor"] == 1
    monkeypatch.setattr(conn, "backfill_write", real)
    rep = bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks", batch=1, resume=run["run_id"]).to_dict()
    assert rep["status"] == "completed" and rep["rewritten"] == 3
    with pytest.raises(bf.BackfillError, match="already completed"):
        bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks", resume=run["run_id"])


@pytest.mark.parametrize("kw,msg", [
    ({"store": "nope"}, "unknown store"),
    ({"purpose": "nope"}, "unknown purpose"),
    ({"apply": True}, "--confirm rag_chunks"),
    ({"apply": True, "confirm": "other"}, "--confirm rag_chunks"),
    ({"unowned": "delete"}, "skip or mask"),
    ({"batch": 0}, "batch"),
])
def test_refusals(setup, kw, msg):
    f, e = setup
    args = {"store": "rag_chunks", "purpose": "service"} | kw
    with pytest.raises(bf.BackfillError, match=msg):
        bf.run(f, args.pop("store"), args.pop("purpose"), **args)


def test_a_store_with_vectors_but_no_embedding_model_is_refused(setup):
    f, e = setup
    f.connectors["rag_chunks"].embedder = None
    before = _rows(e)
    with pytest.raises(bf.BackfillError, match="no embedding model"):
        bf.run(f, "rag_chunks", "service", apply=True, confirm="rag_chunks")
    assert _rows(e) == before


def test_jsonl_datasets_backfill_by_row(workdir):
    tmp, _ = workdir
    p = tmp / "eval.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in [
        {"id": "a", "user": "CUST-9", "q": "my number is 9876543210"}, {"id": "b", "user": "CUST-9", "q": "hello"}]))
    base = _cfg(tmp)
    f = DataRightsFramework(_cfg(tmp, connectors=[c.model_dump() for c in base.connectors] + [
        {"name": "evals", "type": "jsonl_dataset", "options": {"path": str(p), "text_field": "q", "owner_field": "user"}}]))
    rep = bf.run(f, "evals", "service", apply=True, confirm="evals").to_dict()
    rows = [json.loads(x) for x in p.read_text().splitlines()]
    assert rep["rewritten"] == 1 and "9876543210" not in rows[0]["q"] and rows[1]["q"] == "hello"


def test_stores_that_cannot_be_rewritten_are_refused(workdir):
    tmp, _ = workdir
    base = _cfg(tmp)
    f = DataRightsFramework(_cfg(tmp, connectors=[c.model_dump() for c in base.connectors] + [
        {"name": "log", "type": "log_file", "options": {"path": str(tmp / "a.log")}}]))
    with pytest.raises(bf.BackfillError, match="cannot be backfilled"):
        bf.run(f, "log", "service")


def test_cli_dry_run_apply_and_runs(workdir, capsys):
    import yaml

    from dpdp_rights.cli import main

    tmp, _ = workdir
    _store(tmp)
    f = _fw(tmp)
    (tmp / "c.yaml").write_text(yaml.safe_dump(f.config.model_dump(mode="json")))
    base = ["-c", str(tmp / "c.yaml"), "backfill"]
    main(base + ["rag_chunks", "--purpose", "service"])
    assert "Nothing was changed" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="--confirm"):
        main(base + ["rag_chunks", "--purpose", "service", "--apply"])
    main(base + ["rag_chunks", "--purpose", "service", "--apply", "--confirm", "rag_chunks", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["rewritten"] == 3
    main(base + ["--runs"])
    assert json.loads(capsys.readouterr().out)[0]["status"] == "completed"
