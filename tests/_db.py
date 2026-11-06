"""Control-plane database for tests: SQLite by default, PostgreSQL when DPDP_TEST_PG_URL is set.

DPDP_TEST_PG_URL is an admin URL, e.g. postgresql+psycopg://postgres:postgres@localhost:5432/postgres.
Each test directory gets its own database (same path -> same database, like a SQLite file).
"""
from __future__ import annotations

import hashlib
import os


def lineage_url(tmp) -> str:
    admin = os.environ.get("DPDP_TEST_PG_URL")
    if not admin:
        return f"sqlite:///{tmp}/l.db"
    from sqlalchemy import create_engine, text

    name = "dpdp_t_" + hashlib.sha1(str(tmp).encode()).hexdigest()[:16]
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        if not c.execute(text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": name}).first():
            c.execute(text(f'CREATE DATABASE "{name}"'))
    eng.dispose()
    return admin.rsplit("/", 1)[0] + "/" + name
