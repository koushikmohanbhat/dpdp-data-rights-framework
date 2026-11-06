"""scripts/check_release_artifacts.py: every audited profile has a non-empty pin file and a matching SBOM."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
_spec = importlib.util.spec_from_file_location("check_release_artifacts",
                                               ROOT / "scripts" / "check_release_artifacts.py")
art = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(art)
PKG = "dpdp-data-rights-framework"


def sbom(pins, root=PKG, fmt="CycloneDX"):
    return json.dumps({"bomFormat": fmt, "metadata": {"component": {"name": root, "version": "0.2.0"}},
                       "components": [{"name": n, "version": v} for n, v in pins]})


def write(dist, profile, pins, sbom_pins=None, **kw):
    (dist / f"audit-pins-{profile}.txt").write_text("".join(f"{n}=={v}\n" for n, v in pins))
    (dist / f"sbom-{profile}.cdx.json").write_text(sbom(pins if sbom_pins is None else sbom_pins, **kw))


@pytest.fixture
def dist(tmp_path):
    d = tmp_path / "dist"
    d.mkdir()
    write(d, "aws", [("boto3", "1.40.1"), ("botocore", "1.40.1")])
    write(d, "gcp", [("google-cloud-kms", "3.0.0")])
    return d


def test_complete_and_consistent_artifacts_pass(dist):
    assert art.check(dist, ["aws", "gcp"], PKG) == []


def test_names_are_compared_pep503_normalised(dist):
    write(dist, "aws", [("PyJWT", "2.8.0")], sbom_pins=[("pyjwt", "2.8.0")])
    assert art.check(dist, ["aws", "gcp"], PKG) == []


@pytest.mark.parametrize("damage,msg", [
    (lambda d: (d / "audit-pins-gcp.txt").unlink(), "audit-pins-gcp.txt is missing"),
    (lambda d: (d / "sbom-gcp.cdx.json").unlink(), "sbom-gcp.cdx.json is missing"),
    (lambda d: (d / "audit-pins-gcp.txt").write_text(""), "audit-pins-gcp.txt is empty"),
    (lambda d: (d / "audit-pins-gcp.txt").write_text("google-cloud-kms>=3\n"), "not an exact pin"),
    (lambda d: (d / "audit-pins-gcp.txt").write_text("a==1\nA==1\n"), "pinned twice"),
    (lambda d: (d / "sbom-gcp.cdx.json").write_text("{not json"), "not valid JSON"),
    (lambda d: (d / "sbom-gcp.cdx.json").write_text(sbom([])), "lists no components"),
    (lambda d: (d / "sbom-gcp.cdx.json").write_text(sbom([("google-cloud-kms", "3.0.0")], root="other")),
     "root component is 'other'"),
    (lambda d: (d / "sbom-gcp.cdx.json").write_text(sbom([("google-cloud-kms", "3.0.0")], fmt="SPDX")),
     "not a CycloneDX document"),
    (lambda d: (d / "sbom-gcp.cdx.json").write_text(sbom([("google-cloud-kms", "2.9.0")])),
     "SBOM does not match the audited pins"),
    (lambda d: (d / "sbom-gcp.cdx.json").write_text(sbom([("google-cloud-kms", "3.0.0"), ("extra", "1")])),
     "only in SBOM: ['extra==1']"),
    (lambda d: (d / "sbom-legacy.cdx.json").write_text(sbom([("x", "1")])), "belongs to no profile"),
    (lambda d: (d / "audit-pins-legacy.txt").write_text("x==1\n"), "belongs to no profile"),
])
def test_missing_empty_or_mismatched_artifacts_fail(dist, damage, msg):
    damage(dist)
    problems = art.check(dist, ["aws", "gcp"], PKG)
    assert any(msg in p for p in problems), problems


def test_a_profile_added_to_the_policy_without_artifacts_fails(dist):
    problems = art.check(dist, ["aws", "gcp", "direct-api"], PKG)
    assert problems == ["profile 'direct-api': audit-pins-direct-api.txt is missing",
                        "profile 'direct-api': sbom-direct-api.cdx.json is missing"]


def test_main_reads_profiles_from_the_policy(dist, tmp_path, capsys):
    pol = tmp_path / "policy.yml"
    pol.write_text("profiles:\n  aws: [aws]\n  gcp: [gcp]\n")
    assert art.main(["--dist", str(dist), "--policy", str(pol)]) == 0
    assert "complete for 2 profiles" in capsys.readouterr().out
    pol.write_text("profiles:\n  aws: [aws]\n  gcp: [gcp]\n  full: [all]\n")
    assert art.main(["--dist", str(dist), "--policy", str(pol)]) == 1
    pol.write_text("profiles: {}\n")
    assert art.main(["--dist", str(dist), "--policy", str(pol)]) == 1


def test_repository_policy_profiles_are_what_the_release_checks():
    import yaml
    profiles = list(yaml.safe_load((ROOT / ".github" / "audit-policy.yml").read_text())["profiles"])
    assert profiles == ["aws", "gcp", "direct-api", "full"]
