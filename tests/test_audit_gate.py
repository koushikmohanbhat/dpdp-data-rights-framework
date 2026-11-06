"""The release and CI dependency gate (scripts/audit_gate.py), with OSV lookups faked."""
import importlib.util
from datetime import date, timedelta
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("audit_gate", Path(__file__).parents[1] / "scripts" / "audit_gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

TODAY = date(2026, 11, 18)
OSV = {
    "PYSEC-1": {"aliases": ["GHSA-high"]},
    "GHSA-high": {"database_specific": {"severity": "HIGH"}},
    "GHSA-low": {"database_specific": {"severity": "LOW"}},
    "GHSA-mod": {"database_specific": {"severity": "MODERATE"}},
}


def fetch(vid):
    if vid not in OSV:
        raise KeyError(vid)
    return OSV[vid]


def report(*vulns):
    return {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [
        {"id": v, "aliases": [], "fix_versions": ["1.1"]} for v in vulns]}]}


def policy(**kw):
    return {"fail_on": "moderate", "max_exception_days": 90, "exceptions": []} | kw


def test_blocks_at_or_above_the_agreed_severity():
    assert gate.evaluate(report("GHSA-mod"), policy(), TODAY, fetch)[0]
    assert not gate.evaluate(report("GHSA-low"), policy(), TODAY, fetch)[0]          # reported, not blocking
    assert not gate.evaluate(report("GHSA-mod"), policy(fail_on="high"), TODAY, fetch)[0]
    blocked, lines = gate.evaluate(report("PYSEC-1"), policy(fail_on="high"), TODAY, fetch)
    assert blocked and "high" in "\n".join(lines)                                    # severity found via alias


def test_unknown_severity_fails_closed():
    blocked, lines = gate.evaluate(report("PYSEC-unknown"), policy(fail_on="critical"), TODAY, fetch)
    assert blocked and "treated as critical" in "\n".join(lines)


def test_valid_exception_passes_and_is_shown():
    exc = {"id": "GHSA-mod", "package": "pkg", "reason": "not reachable", "owner": "sec@x",
           "expires": (TODAY + timedelta(days=30)).isoformat()}
    blocked, lines = gate.evaluate(report("GHSA-mod"), policy(exceptions=[exc]), TODAY, fetch)
    assert not blocked and "accepted until" in "\n".join(lines)


@pytest.mark.parametrize("change,msg", [
    ({"expires": (TODAY - timedelta(days=1)).isoformat()}, "expired"),
    ({"expires": (TODAY + timedelta(days=200)).isoformat()}, "shorten"),
    ({"owner": ""}, "missing owner"),
])
def test_bad_exceptions_block(change, msg):
    exc = {"id": "GHSA-mod", "package": "pkg", "reason": "r", "owner": "o",
           "expires": (TODAY + timedelta(days=10)).isoformat()} | change
    blocked, lines = gate.evaluate(report(), policy(exceptions=[exc]), TODAY, fetch)
    assert blocked and msg in "\n".join(lines)


def test_clean_report_passes_and_policy_file_loads():
    assert gate.evaluate(report(), policy(), TODAY, fetch) == (False, [
        "Dependency audit: blocking at **moderate** and above.", "- ✅ no known vulnerabilities", "**Passed.**"])
    p = gate.load_policy(str(Path(__file__).parents[1] / ".github" / "audit-policy.yml"))
    assert p["fail_on"] == "moderate" and p["exceptions"] == []


# ---- review 18 Nov 2026 (fourth round) ----------------------------------------------------------------------
def test_exception_covers_only_its_own_package():
    exc = {"id": "GHSA-mod", "package": "other-pkg", "reason": "r", "owner": "o",
           "expires": (TODAY + timedelta(days=10)).isoformat()}
    blocked, lines = gate.evaluate(report("GHSA-mod"), policy(exceptions=[exc]), TODAY, fetch)
    text = "\n".join(lines)
    assert blocked and "exception GHSA-mod is for other-pkg, not pkg" in text
    assert "no longer matches any finding" in text                      # the stray exception is flagged too


def test_exception_package_names_are_pep503_normalised_and_alias_ids_match():
    exc = {"id": "CVE-1", "package": "PKG", "reason": "r", "owner": "o",
           "expires": (TODAY + timedelta(days=10)).isoformat()}
    rep = {"dependencies": [{"name": "pkg", "version": "1", "vulns": [
        {"id": "GHSA-mod", "aliases": ["CVE-1"], "fix_versions": []}]}]}
    assert not gate.evaluate(rep, policy(exceptions=[exc]), TODAY, fetch)[0]
    rep2 = {"dependencies": [{"name": "my_pkg.x", "version": "1", "vulns": [
        {"id": "GHSA-mod", "aliases": [], "fix_versions": []}]}]}
    exc2 = exc | {"id": "GHSA-mod", "package": "My-Pkg-X"}
    assert not gate.evaluate(rep2, policy(exceptions=[exc2]), TODAY, fetch)[0]


def test_same_vulnerability_in_two_packages_needs_two_exceptions():
    exc = {"id": "GHSA-mod", "package": "a", "reason": "r", "owner": "o",
           "expires": (TODAY + timedelta(days=10)).isoformat()}
    rep = {"dependencies": [{"name": n, "version": "1", "vulns": [{"id": "GHSA-mod", "aliases": []}]}
                            for n in ("a", "b")]}
    blocked, lines = gate.evaluate(rep, policy(exceptions=[exc]), TODAY, fetch)
    assert blocked and any("accepted" in x and x.startswith("- ⚠️ a ") for x in lines)
    assert any(x.startswith("- ❌ b ") for x in lines)


PYPROJECT = {"project": {"name": "demo-pkg", "optional-dependencies": {
    "aws": ["boto3"], "gcp": ["google-cloud-kms"], "heavy": ["torch"], "testing": ["pytest"],
    "all": ["demo-pkg[aws,gcp]"]}}}


def test_profiles_must_account_for_every_declared_extra():
    pol = {"profiles": {"aws": ["aws"], "gcp": ["gcp"]}, "excluded_extras": {"testing": "test only"}}
    problems, covered = gate.check_profiles(PYPROJECT, pol)
    assert covered == {"aws": ["aws"], "gcp": ["gcp"]}
    assert problems == ["extra 'all' is in no profile and not in excluded_extras: decide which",
                        "extra 'heavy' is in no profile and not in excluded_extras: decide which"]
    ok, covered = gate.check_profiles(PYPROJECT, {"profiles": {"aws": ["aws"], "full": ["all", "heavy"]},
                                                  "excluded_extras": {"testing": "test only"}})
    assert ok == [] and covered["full"] == ["all", "aws", "gcp", "heavy"]            # aggregates expanded


@pytest.mark.parametrize("pol,msg", [
    ({"profiles": {}, "excluded_extras": {}}, "profiles is empty"),
    ({"profiles": {"x": []}, "excluded_extras": {}}, "profile 'x' lists no extras"),
    ({"profiles": {"full": ["all", "heavy", "nope"]}, "excluded_extras": {"testing": "x"}},
     "profile 'full': extra 'nope' is not declared"),
    ({"profiles": {"full": ["all", "heavy"]}, "excluded_extras": {"testing": ""}}, "needs a reason"),
    ({"profiles": {"full": ["all", "heavy"]}, "excluded_extras": {"testing": "x", "aws": "y"}},
     "both in a production profile and excluded"),
    ({"profiles": {"full": ["all", "heavy"]}, "excluded_extras": {"testing": "x", "ghost": "y"}},
     "'ghost' is not declared"),
])
def test_profile_problems_block(pol, msg):
    problems, _ = gate.check_profiles(PYPROJECT, pol)
    assert any(msg in p for p in problems), problems


def test_old_production_extras_key_is_refused(tmp_path):
    f = tmp_path / "p.yml"
    f.write_text("production_extras: [all]\n")
    with pytest.raises(SystemExit, match="named profiles"):
        gate.load_policy(str(f))


def test_repository_policy_covers_every_extra_in_pyproject():
    tomllib = pytest.importorskip("tomllib")
    root = Path(__file__).parents[1]
    problems, covered = gate.check_profiles(tomllib.loads((root / "pyproject.toml").read_text()),
                                            gate.load_policy(str(root / ".github" / "audit-policy.yml")))
    assert problems == []
    assert {"aws", "gcp", "full"} <= set(covered) and "indic-ner" in covered["full"]
    assert "gcp" not in covered["aws"] and "aws" not in covered["gcp"]               # single-cloud profiles


# ---- resolution and audit, with pip and pip-audit faked (review 18 Nov 2026, fifth round) -------------------
class FakeRun:
    """Stands in for subprocess.run: records commands, writes pip's --report file, returns canned results."""

    def __init__(self, install=None, pip_rc=0, audit=None, audit_rc=0, audit_stdout=None):
        self.calls, self.install, self.pip_rc = [], install, pip_rc
        self.audit, self.audit_rc, self.audit_stdout = audit, audit_rc, audit_stdout

    def __call__(self, cmd, capture_output=True, text=True):
        import json
        import types
        self.calls.append(cmd)
        if cmd[1:4] == ["-m", "pip", "install"]:
            if self.pip_rc == 0:
                Path(cmd[cmd.index("--report") + 1]).write_text(json.dumps({"install": [
                    {"metadata": {"name": n, "version": v}} for n, v in self.install]}))
            return types.SimpleNamespace(returncode=self.pip_rc, stdout="", stderr="ResolutionImpossible")
        if cmd[1:3] == ["-m", "pip_audit"]:
            self.audited = Path(cmd[cmd.index("-r") + 1]).read_text()
            out = self.audit_stdout if self.audit_stdout is not None else json.dumps(self.audit or {"dependencies": []})
            return types.SimpleNamespace(returncode=self.audit_rc, stdout=out, stderr="network down")
        raise AssertionError(cmd)


def test_resolve_uses_a_metadata_only_dry_run_and_drops_the_project_itself(monkeypatch):
    fake = FakeRun(install=[("Demo_Pkg", "1.0"), ("boto3", "1.40.1"), ("botocore", "1.40.1")])
    monkeypatch.setattr(gate.subprocess, "run", fake)
    pins = gate.resolve("dist/demo_pkg-1.0-py3-none-any.whl", ["aws", "otel"], "demo-pkg")
    assert pins == "boto3==1.40.1\nbotocore==1.40.1\n"
    cmd = fake.calls[0]
    assert {"--dry-run", "--ignore-installed", "--report"} <= set(cmd)
    assert cmd[-1] == "dist/demo_pkg-1.0-py3-none-any.whl[aws,otel]"


def test_resolution_failure_blocks(monkeypatch):
    monkeypatch.setattr(gate.subprocess, "run", FakeRun(pip_rc=1))
    with pytest.raises(SystemExit, match="could not resolve"):
        gate.resolve(".", ["aws"], "demo-pkg")


@pytest.mark.parametrize("rc,stdout", [(2, ""), (0, ""), (1, "")])
def test_pip_audit_failure_blocks(monkeypatch, tmp_path, rc, stdout):
    monkeypatch.setattr(gate.subprocess, "run", FakeRun(audit_rc=rc, audit_stdout=stdout))
    req = tmp_path / "r.txt"
    req.write_text("boto3==1\n")
    with pytest.raises(SystemExit, match="could not complete"):
        gate.run_pip_audit(str(req))


def test_pip_audit_checks_only_the_given_pins(monkeypatch, tmp_path):
    fake = FakeRun()
    monkeypatch.setattr(gate.subprocess, "run", fake)
    req = tmp_path / "r.txt"
    req.write_text("boto3==1\n")
    gate.run_pip_audit(str(req))
    assert {"--no-deps", "--disable-pip", "--strict"} <= set(fake.calls[0])


def _policy_file(tmp_path, extra=""):
    f = tmp_path / "policy.yml"
    f.write_text("fail_on: moderate\nprofiles:\n  aws: [aws]\n  full: [all, heavy]\n"
                 "excluded_extras: {testing: test only}\n" + extra)
    return str(f)


def test_main_audits_each_profile_separately_and_writes_pins(monkeypatch, tmp_path, capsys):
    fake = FakeRun(install=[("demo-pkg", "1"), ("boto3", "1.40.1")])
    monkeypatch.setattr(gate.subprocess, "run", fake)
    rc = gate.main(["--policy", _policy_file(tmp_path), "--pins-dir", str(tmp_path / "pins")],
                   today=TODAY, pyproject=PYPROJECT)
    assert rc == 0
    specs = [c[-1] for c in fake.calls if c[1:4] == ["-m", "pip", "install"]]
    assert specs == [".[aws]", ".[all,heavy]"]                                      # one resolution per profile
    assert (tmp_path / "pins" / "aws.txt").read_text() == "boto3==1.40.1\n"
    assert (tmp_path / "pins" / "full.txt").exists()
    out = capsys.readouterr().out
    assert "Profile `aws`" in out and "Profile `full`" in out and "Gate: passed" in out


def test_main_blocks_when_any_profile_blocks(monkeypatch, tmp_path, capsys):
    vuln = {"dependencies": [{"name": "boto3", "version": "1", "vulns": [{"id": "GHSA-high", "aliases": []}]}]}
    monkeypatch.setattr(gate.subprocess, "run", FakeRun(install=[("boto3", "1")], audit=vuln))
    monkeypatch.setattr(gate, "_fetch", fetch)
    assert gate.main(["--policy", _policy_file(tmp_path), "--profile", "aws"], today=TODAY, pyproject=PYPROJECT) == 1
    assert "Gate: blocked" in capsys.readouterr().out


def test_main_profile_problems_block_before_resolving(monkeypatch, tmp_path, capsys):
    fake = FakeRun()
    monkeypatch.setattr(gate.subprocess, "run", fake)
    pyproject = {"project": PYPROJECT["project"] | {"optional-dependencies":
                 PYPROJECT["project"]["optional-dependencies"] | {"new-extra": ["x"]}}}
    assert gate.main(["--policy", _policy_file(tmp_path)], today=TODAY, pyproject=pyproject) == 1
    assert fake.calls == [] and "new-extra" in capsys.readouterr().out
    assert gate.main(["--policy", _policy_file(tmp_path), "--profile", "nope"], today=TODAY,
                     pyproject=PYPROJECT) == 1                                      # unknown profile


def test_summary_goes_to_the_github_job_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(gate.subprocess, "run", FakeRun(install=[]))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    gate.main(["--policy", _policy_file(tmp_path), "--profile", "aws"], today=TODAY, pyproject=PYPROJECT)
    assert "Profile `aws`" in summary.read_text()
