"""Idempotency keys bound to the caller and the request.

A client's ``Idempotency-Key`` is stored only as ``sha256(caller, key)``, so two callers can never collide or
look up each other's requests. A repeat counts as a duplicate only when it is the *same request*: every field
the caller sent, including personal ones such as a correction's new value, a nominee's details or a grievance
description. Rights cases compare a keyed digest of the canonical request (HMAC-SHA256 under a subkey of the
vault's KMS-wrapped lookup key), so the digest cannot be brute-forced from the database alone and no plain
value is stored for the comparison. Anything else is a conflict that reveals nothing about the stored request.
The unique constraint on the column makes concurrent retries safe: the loser re-reads and applies the same
comparison.
"""
from __future__ import annotations

import hashlib
import json


class IdempotencyConflict(ValueError):
    """The key was already used for a different request (HTTP 409)."""

    def __init__(self) -> None:
        super().__init__("Idempotency-Key was already used for a different request; use a new key")


def scoped_key(key: str, caller: str | None) -> str:
    return hashlib.sha256(f"dpdp-rights:idem:{caller or ''}\x00{key}".encode()).hexdigest()


def canonical_request(**fields) -> bytes:
    """Canonical JSON of a request: sorted keys, no whitespace, absent and ``None`` fields treated alike."""
    def clean(v):
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items() if x is not None}
        if isinstance(v, (list, tuple)):
            return [clean(x) for x in v]
        return v
    return json.dumps(clean(fields), sort_keys=True, default=str, separators=(",", ":"), ensure_ascii=False).encode()


def is_unique_violation(exc: Exception) -> bool:
    from sqlalchemy.exc import IntegrityError

    return isinstance(exc, IntegrityError)


def references_with_personal_data(detector, **fields: str | None) -> list[str]:
    """Names of fields whose text the PII detectors flag (references must be IDs, not descriptions of people)."""
    from ..vault.vault import TOKEN_RE

    bad = []
    for name, value in fields.items():
        if value and detector is not None:
            if any(not TOKEN_RE.fullmatch(e.text) for e in detector.detect(value)):
                bad.append(name)
    return bad
