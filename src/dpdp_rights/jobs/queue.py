"""Durable job queue in the control-plane database.

Jobs survive restarts, are leased to one worker at a time, retried with backoff, and
deduplicated by idempotency key. Works on PostgreSQL and SQLite (claiming uses a
conditional UPDATE, so two workers can never take the same job).

Run workers with ``dpdp-rights worker`` (ECS service / Cloud Run job / Kubernetes deployment).
"""
from __future__ import annotations

import os
import socket
from datetime import timedelta

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError

from ..core.models import new_id, utcnow
from ..lineage.store import LineageStore, job


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)


class JobQueue:
    def __init__(self, store: LineageStore, lease_seconds: int = 300, max_attempts: int = 5,
                 backoff_seconds: int = 60):
        self.store, self.lease, self.max_attempts, self.backoff = store, lease_seconds, max_attempts, backoff_seconds
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}"

    def enqueue(self, kind: str, payload: dict, idempotency_key: str | None = None, delay_seconds: int = 0) -> str:
        now = utcnow()
        jid = new_id("job")
        try:
            with self.store.engine.begin() as c:
                c.execute(job.insert().values(job_id=jid, kind=kind, payload=payload, status="queued", attempts=0,
                                              max_attempts=self.max_attempts,
                                              run_after=now + timedelta(seconds=delay_seconds),
                                              idempotency_key=idempotency_key, created_at=now, updated_at=now))
            return jid
        except IntegrityError:
            with self.store.engine.connect() as c:
                return c.execute(select(job.c.job_id).where(job.c.idempotency_key == idempotency_key)).scalar_one()

    def claim(self) -> dict | None:
        now = utcnow()
        ready = or_(and_(job.c.status == "queued", job.c.run_after <= now),
                    and_(job.c.status == "running", job.c.locked_until < now))    # lease expired: worker died
        with self.store.engine.connect() as c:
            candidates = [r[0] for r in c.execute(select(job.c.job_id).where(ready).order_by(job.c.created_at).limit(10))]
        for jid in candidates:
            with self.store.engine.begin() as c:
                n = c.execute(update(job).where(job.c.job_id == jid, ready).values(
                    status="running", locked_by=self.worker_id, locked_until=now + timedelta(seconds=self.lease),
                    attempts=job.c.attempts + 1, updated_at=now)).rowcount
                if n == 1:
                    return dict(c.execute(select(job).where(job.c.job_id == jid)).first()._mapping)
        return None

    def complete(self, job_id: str) -> None:
        with self.store.engine.begin() as c:
            c.execute(update(job).where(job.c.job_id == job_id).values(status="done", locked_until=None,
                                                                        updated_at=utcnow()))

    def fail(self, job_id: str, error: str) -> str:
        with self.store.engine.begin() as c:
            r = c.execute(select(job.c.attempts, job.c.max_attempts).where(job.c.job_id == job_id)).first()
            final = r.attempts >= r.max_attempts
            c.execute(update(job).where(job.c.job_id == job_id).values(
                status="failed" if final else "queued", last_error=error[:4000], locked_until=None,
                run_after=utcnow() + timedelta(seconds=self.backoff * (2 ** max(r.attempts - 1, 0))),
                updated_at=utcnow()))
        return "failed" if final else "retrying"

    def get(self, job_id: str) -> dict | None:
        with self.store.engine.connect() as c:
            r = c.execute(select(job).where(job.c.job_id == job_id)).first()
        return dict(r._mapping) if r else None

    def counts(self) -> dict[str, int]:
        with self.store.engine.connect() as c:
            rows = c.execute(select(job.c.status)).all()
        out: dict[str, int] = {}
        for (s,) in rows:
            out[s] = out.get(s, 0) + 1
        return out
