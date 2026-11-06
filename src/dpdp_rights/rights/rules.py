"""Versioned, configurable legal rules for rights requests.

A rule set is a YAML file (``rights/rulesets/*.yaml`` in the package, plus ``rights.rule_sets_dir``).
Several versions of the same rule-set id can exist; a case uses the latest version whose
``effective_from`` is on or before the day the case was received. Deployer overrides
(``rights.overrides``) are applied on top and validated: a deadline above a *prescribed* limit is
refused. The effective rules are hashed, and every case stores id, version and hash.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

BUILTIN_DIR = Path(__file__).parent / "rulesets"
REQUEST_TYPES = ("access", "correction", "erasure", "withdrawal", "nomination", "nominee_invocation", "grievance")
OVERRIDABLE = {"respond_within_days", "review_by_default", "requesters", "notes", "summary"}


class RuleError(ValueError):
    pass


def _day(v) -> date | None:
    if v is None or isinstance(v, date) and not isinstance(v, datetime):
        return v
    if isinstance(v, datetime):
        return v.date()
    return date.fromisoformat(str(v))


@dataclass(frozen=True)
class RuleSet:
    id: str
    version: str
    data: dict
    sha256: str
    overridden: tuple[str, ...] = ()

    def request(self, rtype: str) -> dict:
        try:
            return self.data["requests"][rtype]
        except KeyError as e:
            raise RuleError(f"rule set {self.id} {self.version} has no rules for '{rtype}'") from e

    def due_days(self, rtype: str) -> int:
        return int(self.request(rtype)["respond_within_days"])

    @property
    def commencement(self) -> date | None:
        return _day(self.data.get("commencement"))

    def ref(self) -> dict:
        return {"rule_set": self.id, "rule_version": self.version, "rule_sha256": self.sha256}

    def describe(self) -> dict:
        return {"id": self.id, "version": self.version, "sha256": self.sha256, "overridden": list(self.overridden),
                **{k: v for k, v in self.data.items() if k not in ("id", "version")}}


def load_all(extra_dir: str | None = None) -> list[dict]:
    out = []
    for d in [BUILTIN_DIR] + ([Path(extra_dir)] if extra_dir else []):
        if not d.exists():
            raise RuleError(f"rule set directory not found: {d}")
        for p in sorted(d.glob("*.y*ml")):
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            for k in ("id", "version", "effective_from", "requests"):
                if k not in data:
                    raise RuleError(f"{p.name}: missing '{k}'")
            data["_file"] = p.name
            out.append(data)
    return out


def _validate(data: dict, where: str) -> list[str]:
    """Returns warnings; raises RuleError on anything that would make a case unlawful by construction."""
    warnings = []
    for rtype, r in data["requests"].items():
        if rtype not in REQUEST_TYPES:
            raise RuleError(f"{where}: unknown request type '{rtype}'")
        days = r.get("respond_within_days")
        if not isinstance(days, int) or days < 1:
            raise RuleError(f"{where}: {rtype}.respond_within_days must be a positive integer")
        mx = r.get("max_days")
        if mx is not None and days > mx:
            if r.get("prescribed"):
                raise RuleError(f"{where}: {rtype}.respond_within_days={days} exceeds the prescribed limit of {mx} "
                                f"days ({r.get('basis')})")
            warnings.append(f"{rtype}.respond_within_days={days} is above the framework's default limit of {mx} days")
    return warnings


def resolve(rule_set: str = "dpdp-in", on: date | datetime | str | None = None, overrides: dict | None = None,
            extra_dir: str | None = None) -> tuple[RuleSet, list[str]]:
    """The effective rule set for a case received on ``on`` (default: today), with overrides applied."""
    day = _day(on) or date.today()
    cands = [d for d in load_all(extra_dir) if d["id"] == rule_set and _day(d["effective_from"]) <= day]
    if not cands:
        raise RuleError(f"no version of rule set '{rule_set}' is in effect on {day.isoformat()}")
    base = max(cands, key=lambda d: (_day(d["effective_from"]), str(d["version"])))
    data = copy.deepcopy({k: v for k, v in base.items() if k != "_file"})
    changed = []
    for rtype, ov in (overrides or {}).items():
        if rtype not in data["requests"]:
            raise RuleError(f"rights.overrides: unknown request type '{rtype}'")
        bad = set(ov) - OVERRIDABLE
        if bad:
            raise RuleError(f"rights.overrides.{rtype}: cannot override {sorted(bad)} (allowed: {sorted(OVERRIDABLE)})")
        for k, v in ov.items():
            if data["requests"][rtype].get(k) != v:
                data["requests"][rtype][k] = v
                changed.append(f"{rtype}.{k}")
    warnings = _validate(data, f"rule set {rule_set} {base['version']}")
    canon = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
    return RuleSet(rule_set, str(base["version"]), data, hashlib.sha256(canon.encode()).hexdigest(),
                   tuple(changed)), warnings


def versions(rule_set: str = "dpdp-in", extra_dir: str | None = None) -> list[dict[str, Any]]:
    return [{"id": d["id"], "version": str(d["version"]), "effective_from": str(d["effective_from"]),
             "file": d["_file"], "reviewed": d.get("reviewed")}
            for d in sorted(load_all(extra_dir), key=lambda d: str(d["effective_from"])) if d["id"] == rule_set]
