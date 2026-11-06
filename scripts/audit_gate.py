"""Dependency audit gate: block on known vulnerabilities at or above an agreed severity.

Usage (CI, the scheduled audit and the release workflow):

    python scripts/audit_gate.py [--target . | dist/pkg.whl] [--profile aws ...] [--pins-dir DIR]

1. **Profiles.** ``profiles`` in the policy names the supported production profiles (e.g. ``aws``, ``gcp``,
   ``full``), each a list of extras. Every extra declared in ``pyproject.toml`` must be in at least one profile
   (directly or through an aggregate such as ``all``) or listed in ``excluded_extras`` with a reason, so a new
   extra cannot silently escape the audit.
2. **Resolve.** Each profile is resolved on its own with ``pip install --dry-run --report`` into exact pins,
   using package metadata only (heavy wheels such as torch are not downloaded). Resolving per profile matters:
   a single-cloud install can pick different versions of shared dependencies than a union of every extra.
3. **Audit.** ``pip-audit --no-deps --disable-pip --strict`` checks exactly those pins.
4. **Severity.** Each finding's GitHub advisory level (low, moderate, high, critical) comes from OSV.
   pip-audit does not report severity itself. A finding with no severity on record counts as critical.
5. **Policy.** Findings at or above ``fail_on`` block, unless a valid exception covers that vulnerability
   **in that package**. An exception needs ``id``, ``package``, ``reason``, ``owner`` and ``expires`` (at most
   ``max_exception_days`` ahead). Expired, incomplete or over-long exceptions block.

Exit code 0: passed. Exit code 1: blocked. The summary is printed and, on GitHub Actions, added to the job summary.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from datetime import date, timedelta
from pathlib import Path

LEVELS = ["low", "moderate", "high", "critical"]
OSV_URL = "https://api.osv.dev/v1/vulns/{}"
REQUIRED = ("id", "package", "reason", "owner", "expires")


def norm(name: str) -> str:
    """PEP 503 normalised package name."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def load_policy(path: str | None) -> dict:
    policy = {"fail_on": "moderate", "max_exception_days": 90, "exceptions": [],
              "profiles": {}, "excluded_extras": {}}
    if path and Path(path).exists():
        import yaml

        policy |= yaml.safe_load(Path(path).read_text()) or {}
    if str(policy["fail_on"]).lower() not in LEVELS:
        raise SystemExit(f"fail_on must be one of {LEVELS}")
    policy["fail_on"] = str(policy["fail_on"]).lower()
    if "production_extras" in policy:
        raise SystemExit("production_extras was replaced by named profiles: use profiles: {name: [extras]}")
    return policy


# ---- 1. profile ---------------------------------------------------------------------------------------------
def check_profiles(pyproject: dict, policy: dict) -> tuple[list[str], dict[str, list[str]]]:
    """(problems, {profile: declared extras it covers once aggregates such as ``all`` are expanded})."""
    project = pyproject["project"]
    own = norm(project["name"])
    declared = {norm(k): v for k, v in (project.get("optional-dependencies") or {}).items()}
    problems: list[str] = []

    def expand(extra: str, seen: set[str]) -> set[str]:
        out = {extra}
        for req in declared.get(extra, []):
            m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*\[([^\]]+)\]", req)
            if m and norm(m.group(1)) == own:
                for sub in (norm(x) for x in m.group(2).split(",")):
                    if sub not in seen:
                        out |= expand(sub, seen | {sub})
        return out

    profiles = policy.get("profiles") or {}
    excluded = {norm(k): v for k, v in (policy.get("excluded_extras") or {}).items()}
    if not profiles:
        problems.append("profiles is empty: define at least one supported production profile")
    covered: dict[str, list[str]] = {}
    for name, extras in profiles.items():
        if not extras:
            problems.append(f"profile '{name}' lists no extras")
        got: set[str] = set()
        for x in (norm(e) for e in extras or []):
            if x not in declared:
                problems.append(f"profile '{name}': extra '{x}' is not declared in pyproject.toml")
            got |= expand(x, {x})
        covered[name] = sorted(got & set(declared))
    union = set().union(*covered.values()) if covered else set()
    for x, reason in excluded.items():
        if x not in declared:
            problems.append(f"excluded extra '{x}' is not declared in pyproject.toml: remove it from the policy")
        elif x in union:
            problems.append(f"extra '{x}' is both in a production profile and excluded")
        elif not str(reason or "").strip():
            problems.append(f"excluded extra '{x}' needs a reason")
    for x in sorted(set(declared) - union - set(excluded)):
        problems.append(f"extra '{x}' is in no profile and not in excluded_extras: decide which")
    return problems, covered


# ---- 2. resolve ---------------------------------------------------------------------------------------------
def resolve(target: str, extras: list[str], own: str) -> str:
    """Exact pins for target[extras], from package metadata (nothing is installed)."""
    spec = f"{target}[{','.join(extras)}]" if extras else target
    with tempfile.TemporaryDirectory() as d:
        rep = Path(d) / "report.json"
        out = subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet",
                              "--report", str(rep), spec], capture_output=True, text=True)
        if out.returncode != 0:
            sys.stderr.write(out.stderr)
            raise SystemExit("could not resolve the production profile: blocking")
        items = json.loads(rep.read_text())["install"]
    pins = sorted(f"{i['metadata']['name']}=={i['metadata']['version']}" for i in items
                  if norm(i["metadata"]["name"]) != own)
    return "\n".join(pins) + "\n"


# ---- 3. audit -----------------------------------------------------------------------------------------------
def run_pip_audit(requirements: str) -> dict:
    out = subprocess.run([sys.executable, "-m", "pip_audit", "-r", requirements, "--no-deps", "--disable-pip",
                          "-f", "json", "--strict", "--progress-spinner", "off"], capture_output=True, text=True)
    if out.returncode not in (0, 1) or not out.stdout.strip():
        sys.stderr.write(out.stderr)
        raise SystemExit("pip-audit could not complete the audit: blocking")
    return json.loads(out.stdout)


# ---- 4. severity --------------------------------------------------------------------------------------------
_SEVERITY: dict[str, str | None] = {}


def osv_severity(vuln_id: str, aliases: list[str], fetch=None) -> str | None:
    """GitHub advisory severity from OSV for the id or any alias; None if no record states one."""
    if fetch is None and vuln_id in _SEVERITY:          # profiles share findings; look each up once
        return _SEVERITY[vuln_id]
    sev = _osv_severity(vuln_id, aliases, fetch or _fetch)
    if fetch is None:
        _SEVERITY[vuln_id] = sev
    return sev


def _osv_severity(vuln_id: str, aliases: list[str], fetch) -> str | None:
    todo, seen = [vuln_id, *aliases], set()
    while todo:
        vid = todo.pop(0)
        if vid in seen:
            continue
        seen.add(vid)
        try:
            rec = fetch(vid)
        except Exception:  # noqa: BLE001
            continue
        sev = str((rec.get("database_specific") or {}).get("severity") or "").lower()
        sev = {"medium": "moderate"}.get(sev, sev)
        if sev in LEVELS:
            return sev
        todo += [a for a in rec.get("aliases") or [] if a.startswith("GHSA-")]
    return None


def _fetch(vid: str) -> dict:
    with urllib.request.urlopen(OSV_URL.format(vid), timeout=20) as r:   # noqa: S310 (fixed https host)
        return json.load(r)


# ---- 5. policy ----------------------------------------------------------------------------------------------
def check_exceptions(policy: dict, today: date) -> tuple[list[dict], list[str]]:
    """Valid exceptions, and problems that fail the gate."""
    valid, problems = [], []
    limit = today + timedelta(days=int(policy["max_exception_days"]))
    for e in policy.get("exceptions") or []:
        missing = [k for k in REQUIRED if not e.get(k)]
        if missing:
            problems.append(f"exception {e.get('id', '?')}: missing {', '.join(missing)}")
            continue
        exp = e["expires"] if isinstance(e["expires"], date) else date.fromisoformat(str(e["expires"]))
        if exp < today:
            problems.append(f"exception {e['id']} ({e['package']}) expired on {exp}: fix it or re-approve it")
        elif exp > limit:
            problems.append(f"exception {e['id']} expires {exp}, more than {policy['max_exception_days']} days "
                            "ahead: shorten it")
        else:
            valid.append(e)
    return valid, problems


def evaluate(report: dict, policy: dict, today: date, fetch=None) -> tuple[bool, list[str]]:
    """(blocked, lines for the summary)."""
    valid, problems = check_exceptions(policy, today)
    threshold = LEVELS.index(policy["fail_on"])
    lines, blocked = [f"Dependency audit: blocking at **{policy['fail_on']}** and above."], bool(problems)
    lines += [f"- ❌ {p}" for p in problems]
    used: set[int] = set()
    findings = [(d["name"], d["version"], v) for d in report.get("dependencies", []) for v in d.get("vulns", [])]
    for name, version, v in findings:
        sev = osv_severity(v["id"], v.get("aliases") or [], fetch)
        level = sev or "critical"
        fix = ", ".join(v.get("fix_versions") or []) or "no fix yet"
        label = f"{name} {version}: {v['id']} ({sev or 'severity unknown, treated as critical'}; fix: {fix})"
        ids = {v["id"], *(v.get("aliases") or [])}
        same_id = [e for e in valid if e["id"] in ids]
        exc = next((e for e in same_id if norm(e["package"]) == norm(name)), None)
        if exc:
            used.add(id(exc))
            lines.append(f"- ⚠️ {label}: accepted until {exc['expires']} by {exc['owner']} ({exc['reason']})")
            continue
        wrong = "; ".join(f"exception {e['id']} is for {e['package']}, not {name}" for e in same_id)
        if LEVELS.index(level) >= threshold:
            blocked = True
            lines.append(f"- ❌ {label}" + (f" ({wrong})" if wrong else ""))
        else:
            lines.append(f"- ℹ️ {label}: below the threshold")
    for e in valid:
        if id(e) not in used:
            lines.append(f"- ℹ️ exception {e['id']} ({e['package']}) no longer matches any finding: remove it")
    if not findings and not problems:
        lines.append("- ✅ no known vulnerabilities")
    lines.append("**Blocked.**" if blocked else "**Passed.**")
    return blocked, lines


def main(argv: list[str] | None = None, today: date | None = None, pyproject: dict | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=".", help="project directory or built wheel to audit (default .)")
    ap.add_argument("--pyproject", default="pyproject.toml")
    ap.add_argument("--policy", default=".github/audit-policy.yml")
    ap.add_argument("--profile", action="append", help="audit only this profile (repeatable; default: all)")
    ap.add_argument("--pins-dir", help="write each profile's resolved pins to DIR/<profile>.txt (for the SBOM)")
    a = ap.parse_args(argv)
    policy = load_policy(a.policy)
    if pyproject is None:
        import tomllib  # Python 3.11+; the gate runs on 3.12

        pyproject = tomllib.loads(Path(a.pyproject).read_text())
    problems, covered = check_profiles(pyproject, policy)
    head = [f"Production profiles: {', '.join(f'{n} ({len(x)} extras)' for n, x in covered.items())}; "
            f"excluded: {', '.join(policy['excluded_extras']) or 'none'}."]
    unknown = [p for p in a.profile or [] if p not in covered]
    problems += [f"unknown profile '{p}'" for p in unknown]
    if problems:
        _emit("\n".join(head + [f"- ❌ {p}" for p in problems] + ["**Blocked.**"]))
        return 1
    own = norm(pyproject["project"]["name"])
    blocked_any, out = False, list(head)
    for name in a.profile or list(covered):
        extras = [norm(x) for x in policy["profiles"][name]]
        pins = resolve(a.target, extras, own)
        if a.pins_dir:
            Path(a.pins_dir).mkdir(parents=True, exist_ok=True)
            (Path(a.pins_dir) / f"{name}.txt").write_text(pins)
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "pins.txt"
            req.write_text(pins)
            blocked, lines = evaluate(run_pip_audit(str(req)), policy, today or date.today())
        blocked_any |= blocked
        out.append(f"\n### Profile `{name}`: {len(pins.splitlines())} pinned packages")
        out += lines
    out.append("\n**Gate: blocked.**" if blocked_any else "\n**Gate: passed.**")
    _emit("\n".join(out))
    return 1 if blocked_any else 0


def _emit(text: str) -> None:
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as s:
            s.write(text + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
