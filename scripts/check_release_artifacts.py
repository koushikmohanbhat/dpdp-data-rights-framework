"""Check that every audited profile produced its release artifacts, and that each SBOM matches its pins.

    python scripts/check_release_artifacts.py [--dist dist] [--policy .github/audit-policy.yml]

Runs in the release workflow after the SBOMs are built and before attestation and publishing. For every profile
in the audit policy it requires:

- ``dist/audit-pins-<profile>.txt``: present, non-empty, every line ``name==version``, no duplicates
- ``dist/sbom-<profile>.cdx.json``: present, valid CycloneDX JSON, the package as the root component, and
  exactly the same set of (name, version) components as the pins (names compared PEP 503-normalised)

It also refuses pin or SBOM files for profiles the policy does not define, so a renamed or removed profile cannot
leave a stale artifact in the release. Exit code 0: all present and consistent. Exit code 1: the release stops.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s=]+)$")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def read_pins(path: Path) -> tuple[set[tuple[str, str]], list[str]]:
    problems, pins = [], set()
    lines = [x.strip() for x in path.read_text().splitlines() if x.strip() and not x.startswith("#")]
    if not lines:
        return pins, [f"{path.name} is empty"]
    seen = set()
    for x in lines:
        m = PIN.match(x)
        if not m:
            problems.append(f"{path.name}: not an exact pin: {x!r}")
            continue
        key = norm(m.group(1))
        if key in seen:
            problems.append(f"{path.name}: {m.group(1)} pinned twice")
        seen.add(key)
        pins.add((key, m.group(2)))
    return pins, problems


def read_sbom(path: Path, package: str) -> tuple[set[tuple[str, str]], list[str]]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        return set(), [f"{path.name} is not valid JSON ({type(e).__name__})"]
    problems = []
    if doc.get("bomFormat") != "CycloneDX":
        problems.append(f"{path.name} is not a CycloneDX document")
    root = ((doc.get("metadata") or {}).get("component") or {}).get("name")
    if norm(root or "") != norm(package):
        problems.append(f"{path.name}: root component is {root!r}, expected {package!r}")
    comps = {(norm(c.get("name", "")), str(c.get("version", ""))) for c in doc.get("components") or []}
    if not comps:
        problems.append(f"{path.name} lists no components")
    return comps, problems


def check(dist: Path, profiles: list[str], package: str) -> list[str]:
    problems: list[str] = []
    for p in profiles:
        pins_f, sbom_f = dist / f"audit-pins-{p}.txt", dist / f"sbom-{p}.cdx.json"
        if not pins_f.exists():
            problems.append(f"profile '{p}': {pins_f.name} is missing")
        if not sbom_f.exists():
            problems.append(f"profile '{p}': {sbom_f.name} is missing")
        if not (pins_f.exists() and sbom_f.exists()):
            continue
        pins, e1 = read_pins(pins_f)
        comps, e2 = read_sbom(sbom_f, package)
        problems += [f"profile '{p}': {x}" for x in e1 + e2]
        if pins and comps and pins != comps:
            only_pins = sorted(f"{n}=={v}" for n, v in pins - comps)[:5]
            only_sbom = sorted(f"{n}=={v}" for n, v in comps - pins)[:5]
            problems.append(f"profile '{p}': SBOM does not match the audited pins "
                            f"(only in pins: {only_pins or '-'}; only in SBOM: {only_sbom or '-'})")
    known = set(profiles)
    for f in sorted(dist.glob("audit-pins-*.txt")) + sorted(dist.glob("sbom-*.cdx.json")):
        name = f.name.removeprefix("audit-pins-").removeprefix("sbom-").removesuffix(".txt").removesuffix(".cdx.json")
        if name not in known:
            problems.append(f"{f.name} belongs to no profile in the audit policy")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--policy", default=".github/audit-policy.yml")
    ap.add_argument("--package", default="dpdp-data-rights-framework")
    a = ap.parse_args(argv)
    import yaml

    profiles = list((yaml.safe_load(Path(a.policy).read_text()) or {}).get("profiles") or {})
    if not profiles:
        print("❌ the audit policy defines no profiles", file=sys.stderr)
        return 1
    problems = check(Path(a.dist), profiles, a.package)
    for p in problems:
        print(f"❌ {p}", file=sys.stderr)
    if not problems:
        print(f"✅ release artifacts complete for {len(profiles)} profiles: {', '.join(profiles)}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
