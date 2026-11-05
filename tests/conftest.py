import sqlite3

import pytest

from dpdp_erasure import ErasureKit, KitConfig


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = sqlite3.connect(tmp_path / "app.db")
    db.executescript("""
        CREATE TABLE tickets (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT);
        CREATE TABLE summaries (id TEXT PRIMARY KEY, body TEXT);
    """)
    db.commit()
    return tmp_path, db


@pytest.fixture
def kit(workdir):
    tmp, _ = workdir
    cfg = KitConfig.from_dict({
        "provider": {"type": "echo"},
        "vault": {"local_master_key_path": str(tmp / "master.key")},
        "lineage": {"url": f"sqlite:///{tmp}/lineage.db"},
        "purposes": [
            {"id": "support"}, {"id": "analytics"},
            {"id": "kyc", "legal_basis": "legitimate_use", "legal_hold_basis": "Test statute"},
        ],
        "connectors": [
            {"name": "tickets", "type": "sql_table",
             "options": {"url": f"sqlite:///{tmp}/app.db", "table": "tickets", "content_column": "body",
                         "principal_column": "principal_id"}},
            {"name": "summaries", "type": "sql_table",
             "options": {"url": f"sqlite:///{tmp}/app.db", "table": "summaries", "content_column": "body",
                         "kind": "summary"}},
            {"name": "evals", "type": "jsonl_dataset", "options": {"path": str(tmp / "evals.jsonl")}},
            {"name": "log", "type": "log_file", "options": {"path": str(tmp / "app.log")}},
        ],
        "policy": {"aggregate_k_threshold": 2},
    })
    return ErasureKit(cfg)
