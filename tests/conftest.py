import sqlite3

import pytest
from _db import lineage_url

from dpdp_rights import DataRightsFramework, FrameworkConfig


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = sqlite3.connect(tmp_path / "app.db")
    db.executescript("""
        CREATE TABLE records (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT);
        CREATE TABLE summaries (id TEXT PRIMARY KEY, body TEXT);
    """)
    db.commit()
    return tmp_path, db


@pytest.fixture
def dpdp(workdir):
    tmp, _ = workdir
    cfg = FrameworkConfig.from_dict({
        "provider": {"type": "echo"},
        "vault": {"local_master_key_path": str(tmp / "master.key")},
        "lineage": {"url": lineage_url(tmp)},
        "purposes": [
            {"id": "service"}, {"id": "analytics"},
            {"id": "kyc", "legal_basis": "legitimate_use", "legal_hold_basis": "Test statute"},
        ],
        "connectors": [
            {"name": "records", "type": "sql_table",
             "options": {"url": f"sqlite:///{tmp}/app.db", "table": "records", "content_column": "body",
                         "principal_column": "principal_id"}},
            {"name": "summaries", "type": "sql_table",
             "options": {"url": f"sqlite:///{tmp}/app.db", "table": "summaries", "content_column": "body",
                         "kind": "summary"}},
            {"name": "evals", "type": "jsonl_dataset", "options": {"path": str(tmp / "evals.jsonl")}},
            {"name": "log", "type": "log_file", "options": {"path": str(tmp / "app.log")}},
        ],
        "policy": {"aggregate_k_threshold": 2},
    })
    return DataRightsFramework(cfg)
