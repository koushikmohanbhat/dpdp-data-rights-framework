"""The scheduled audit's issue handling (scripts/audit_issue.py) and the shape of the audit and release workflows."""
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
_spec = importlib.util.spec_from_file_location("audit_issue", ROOT / "scripts" / "audit_issue.py")
issue = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(issue)


class FakeGh:
    def __init__(self, open_issues=(), fail_on=None):
        self.calls, self.open_issues, self.fail_on = [], list(open_issues), fail_on

    def __call__(self, *args):
        self.calls.append(args)
        if self.fail_on and args[:2] == self.fail_on:
            raise RuntimeError("gh failed")
        if args[:2] == ("issue", "list"):
            return json.dumps(self.open_issues)
        return ""


def test_creates_the_issue_when_none_is_open():
    gh = FakeGh()
    assert issue.open_or_update("- ❌ pkg 1: GHSA-x", "https://run/1", run=gh) == "created"
    create = gh.calls[-1]
    assert create[:4] == ("issue", "create", "--title", issue.TITLE)
    body = create[create.index("--body") + 1]
    assert "GHSA-x" in body and "https://run/1" in body and "audit-policy.yml" in body


def test_comments_on_the_open_issue_instead_of_opening_another():
    gh = FakeGh([{"number": 7, "title": issue.TITLE}, {"number": 3, "title": issue.TITLE}])
    assert issue.open_or_update("summary", "https://run/2", run=gh) == "commented on #3"
    assert gh.calls[-1][:3] == ("issue", "comment", "3")
    assert not any(c[:2] == ("issue", "create") for c in gh.calls)


def test_fuzzy_search_hits_with_other_titles_are_ignored():
    gh = FakeGh([{"number": 9, "title": "Scheduled dependency audit failed on a fork (old)"}])
    assert issue.open_or_update("s", "u", run=gh) == "created"


def test_gh_failure_fails_the_step(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(issue, "gh", FakeGh(fail_on=("issue", "list")))
    monkeypatch.setattr(issue.open_or_update, "__defaults__", (issue.gh,))
    assert issue.main(["--summary", str(tmp_path / "missing.md"), "--run-url", "u"]) == 1
    assert "gh failed" in capsys.readouterr().err


def test_missing_summary_still_reports():
    gh = FakeGh()
    issue.open_or_update("", "u", run=gh)
    assert "no summary" in gh.calls[-1][-1]


def _wf(name):
    d = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())
    return d, d.get("on", d.get(True))                   # PyYAML reads the key `on` as True


def _steps(d, job):
    return d["jobs"][job]["steps"]


def test_scheduled_audit_runs_daily_and_opens_an_issue_only_on_failure():
    d, on = _wf("audit-scheduled.yml")
    assert on["schedule"][0]["cron"] and "workflow_dispatch" in on
    assert d["permissions"] == {"contents": "read", "issues": "write"}
    steps = _steps(d, "audit")
    gate = next(i for i, s in enumerate(steps) if "audit_gate.py" in s.get("run", ""))
    note = next(i for i, s in enumerate(steps) if "audit_issue.py" in s.get("run", ""))
    assert gate < note and steps[note]["if"] == "failure()" and "GH_TOKEN" in steps[note]["env"]
    assert steps[gate]["shell"] == "bash" and "tee" in steps[gate]["run"]    # bash -eo pipefail: tee keeps the exit


def test_ci_audit_blocks_on_main_and_is_advisory_on_pull_requests():
    d, _ = _wf("ci.yml")
    assert d["jobs"]["audit"]["continue-on-error"] == "${{ github.event_name == 'pull_request' }}"
    assert any("audit_gate.py" in s.get("run", "") for s in _steps(d, "audit"))


def test_release_gate_runs_before_anything_is_published_and_sboms_come_from_audited_pins():
    d, _ = _wf("release.yml")
    steps = _steps(d, next(iter(d["jobs"])))
    text = [s.get("run", "") + " " + s.get("uses", "") for s in steps]
    gate = next(i for i, t in enumerate(text) if "audit_gate.py" in t)
    sbom = next(i for i, t in enumerate(text) if "cyclonedx-py" in t)
    check = next(i for i, t in enumerate(text) if "check_release_artifacts.py" in t)
    attest = next(i for i, t in enumerate(text) if "attest-build-provenance" in t)
    publish = next(i for i, t in enumerate(text) if "gh release create" in t)
    assert gate < sbom < check < attest < publish                              # nothing published unchecked
    assert "--policy .github/audit-policy.yml" in text[check]
    assert "--pins-dir audit-pins" in text[gate] and "--target" in text[gate]
    assert "cyclonedx-py requirements" in text[sbom] and "audit-pins/" in text[sbom]
    assert not any("cyclonedx-py environment" in t for t in text)             # never the build environment
    assert not any("pip install dist/" in t for t in text)
    assert "dist/audit-pins-" in text[sbom]                                    # pins published beside the SBOMs


def test_every_policy_profile_produces_an_sbom_in_the_release():
    """The SBOM loop iterates over whatever pins the gate wrote: one per profile, none hard-coded."""
    d, _ = _wf("release.yml")
    run = next(s["run"] for s in _steps(d, next(iter(d["jobs"]))) if "cyclonedx-py" in s.get("run", ""))
    assert "for pins in audit-pins/*.txt" in run
    pol = yaml.safe_load((ROOT / ".github" / "audit-policy.yml").read_text())
    assert pol["profiles"] and "production_extras" not in pol


@pytest.mark.parametrize("name", ["ci.yml", "release.yml", "audit-scheduled.yml"])
def test_workflows_parse(name):
    d, on = _wf(name)
    assert d["jobs"] and on


def test_every_action_is_pinned_to_a_full_commit_sha_with_its_version():
    """Review 18 Nov 2026: tags can move; a 40-hex SHA cannot. The comment lets Dependabot keep pins current."""
    import re
    uses = []
    for f in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = re.search(r"uses:\s*(\S+)(.*)$", line)
            if m and not m.group(1).startswith("./"):
                uses.append((f.name, n, m.group(1), m.group(2)))
    assert len(uses) >= 20
    for name, n, ref, rest in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"{name}:{n} not SHA-pinned: {ref}"
        assert re.search(r"#\s*v\d+\.\d+\.\d+", rest), f"{name}:{n} has no version comment"
    by_action = {}
    for _, _, ref, _ in uses:                                                  # one SHA per action repo
        repo = "/".join(ref.split("@")[0].split("/")[:2])
        by_action.setdefault(repo, set()).add(ref.split("@")[1])
    assert all(len(v) == 1 for v in by_action.values()), by_action


def test_dependabot_updates_the_pinned_actions():
    import yaml
    d = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert any(u["package-ecosystem"] == "github-actions" for u in d["updates"])
