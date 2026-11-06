"""Connector conformance kit: the tests every connector must pass, built-in or plug-in.

Write a small harness that can put a record into your sandbox store and read it back, then subclass
``ConnectorConformance``::

    from dpdp_rights.testing.conformance import ConnectorConformance, ConnectorHarness

    class ZendeskHarness(ConnectorHarness):
        def connector(self): return ZendeskConnector("sut", subdomain="acme-sandbox", ...)
        def write(self, record_id, content, principal_id): ...   # create a ticket; return its locator
        def read(self, locator): ...                              # ticket text, or None if gone
        def cleanup(self): ...

    class TestZendeskConformance(ConnectorConformance):
        def make_harness(self, tmp_path):
            return ZendeskHarness()

Each test drives the real framework (tokenisation, lineage, policy, erasure, verification) against the
connector, using synthetic Indian personal data. Tests a connector's declared capabilities say it cannot
pass are skipped with the reason, so the report also documents what the connector does not do.

Requires pytest (``pip install "dpdp-data-rights-framework[testing]"``).
"""
from __future__ import annotations

import abc
from pathlib import Path
from typing import Any

import pytest

from ..connectors.base import Connector
from ..core.config import FrameworkConfig
from ..core.models import Action, Artifact
from ..framework import DataRightsFramework
from ..vault.vault import ERASED_MARKER
from .synthetic import people

SUT = "sut"          # connector name used in the framework under test
PURPOSE = "service"


class ConnectorHarness(abc.ABC):
    """Puts records into the store a connector covers, and reads them back."""

    #: artifact kind registered for records written by ``write``
    kind: str = "record"
    #: whether ``write`` can store arbitrary raw text (needed for the leak-detection test)
    accepts_raw_text: bool = True

    @abc.abstractmethod
    def connector(self) -> Connector:
        """The connector under test, configured against the sandbox, named ``"sut"``."""

    @abc.abstractmethod
    def write(self, record_id: str, content: str, principal_id: str) -> dict[str, Any]:
        """Store ``content`` as one record owned by ``principal_id`` the way the application would
        (including any index the connector's discovery relies on); return the locator for track_artifact."""

    @abc.abstractmethod
    def read(self, locator: dict[str, Any]) -> str | None:
        """The record's current text, or None if it no longer exists."""

    def cleanup(self) -> None:  # noqa: B027 - optional hook, deliberately not abstract
        """Remove everything the harness created."""


class ConnectorConformance:
    """Subclass as ``TestXxx`` and implement ``make_harness``. Not collected by pytest on its own."""

    def make_harness(self, tmp_path: Path) -> ConnectorHarness:  # pragma: no cover - overridden
        raise NotImplementedError

    # ---- fixtures ---------------------------------------------------------------------------------
    @pytest.fixture
    def harness(self, tmp_path):
        h = self.make_harness(tmp_path)
        yield h
        h.cleanup()

    @pytest.fixture
    def env(self, harness, tmp_path):
        conn = harness.connector()
        assert conn.name == SUT, f"the harness connector must be named '{SUT}'"
        cfg = FrameworkConfig.model_validate({
            "vault": {"key_wrapper": "local", "local_master_key_path": str(tmp_path / "conformance.key")},
            "lineage": {"url": f"sqlite:///{tmp_path}/conformance.db"},
            "purposes": [{"id": PURPOSE, "description": "Conformance test"}],
        })
        dpdp = DataRightsFramework(cfg, connectors={SUT: conn})
        if getattr(conn, "embedder", "absent") is None:
            conn.embedder = dpdp.provider.embed
        asha, ravi = people(2, seed=11)
        pa, pr = dpdp.principal(asha.external_id), dpdp.principal(ravi.external_id)
        for pid, person in ((pa, asha), (pr, ravi)):
            dpdp.grant_consent(pid, PURPOSE)
            dpdp.register_identifier(pid, "EMAIL", person.email)
        return {"dpdp": dpdp, "conn": conn, "harness": harness, "asha": asha, "ravi": ravi, "pa": pa, "pr": pr}

    # ---- helpers ----------------------------------------------------------------------------------
    @staticmethod
    def _store(env, record_id: str, pid: str, text: str, track: bool = True) -> tuple[dict, str]:
        dpdp = env["dpdp"]
        with dpdp.context(pid, purpose=PURPOSE):
            safe = dpdp.protect(text)
        loc = env["harness"].write(record_id, safe.text, pid)
        if track:
            with dpdp.context(pid, purpose=PURPOSE):
                dpdp.track_artifact(env["harness"].kind, SUT, loc, content=safe.text, element_ids=safe.element_ids)
        return loc, safe.text

    @staticmethod
    def _unreadable_or_gone(env, loc: dict, owner: str) -> None:
        now = env["harness"].read(loc)
        if now is None:
            return
        tokens = set(env["dpdp"].vault.tokens_for(owner))
        assert not [t for t in tokens if t in now] or ERASED_MARKER in env["dpdp"].vault.reveal(now), \
            f"record still holds readable personal data: {now!r}"

    def _caps(self, env):
        return env["conn"].capabilities

    # ---- the suite --------------------------------------------------------------------------------
    def test_declares_capabilities(self, env):
        conn, caps = env["conn"], self._caps(env)
        assert caps is not None, "set `capabilities = Capabilities(...)` on the connector class"
        assert caps.discover in ("native", "lineage")
        assert caps.verify in ("rescan", "rediscover", "api_confirmation", "action_status", "none")
        d = caps.to_dict(conn.supports)
        if d["deletion"] == "item":
            assert Action.DELETE in conn.supports, "deletion='item' requires Action.DELETE in supports"

    def test_erases_registered_record(self, env):
        loc, _ = self._store(env, "r-own", env["pa"], env["asha"].message())
        out = env["dpdp"].erase(env["pa"])
        assert out["status"] in ("completed", "completed_with_exceptions"), out
        self._unreadable_or_gone(env, loc, env["pa"])
        mine = [v for v in out["verification"] if v["store"] == SUT]
        assert mine and mine[0]["ok"], mine

    def test_discovers_unregistered_record(self, env):
        if self._caps(env).discover != "native":
            pytest.skip("connector acts on registered items only (discover='lineage')")
        loc, _ = self._store(env, "r-untracked", env["pa"], env["asha"].message(), track=False)
        plan = env["dpdp"].erase(env["pa"], dry_run=True)
        assert any(p["store"] == SUT for p in plan["plan"]), "discovery did not find the unregistered record"
        env["dpdp"].erase(env["pa"])
        self._unreadable_or_gone(env, loc, env["pa"])

    def test_mention_in_another_persons_record(self, env):
        """Ravi's record names Asha. Erasing Asha must remove her, and keep Ravi's data if the store allows."""
        loc, before = self._store(env, "r-mention", env["pr"],
                                  f"My name is {env['ravi'].name}. Nominee email {env['asha'].email}")
        assert any(t in before for t in env["dpdp"].vault.tokens_for(env["pa"])), "mention was not resolved to Asha"
        env["dpdp"].erase(env["pa"])
        now = env["harness"].read(loc)
        conn = env["conn"]
        if Action.REDACT in conn.supports:
            assert now is not None, "a record that only mentions the person must be redacted, not deleted"
            assert ERASED_MARKER in now
            ravi_tokens = [t for t in env["dpdp"].vault.tokens_for(env["pr"]) if t in before]
            assert all(t in now for t in ravi_tokens), "redaction removed the other person's data"
        elif self._caps(env).discover == "native" or Action.DELETE in conn.supports:
            self._unreadable_or_gone(env, loc, env["pa"])
        else:  # pragma: no cover
            pytest.skip("connector cannot redact or delete")

    def test_verification_catches_raw_values(self, env):
        if self._caps(env).verify != "rescan":
            pytest.skip(f"connector verifies by '{self._caps(env).verify}', not by rescanning for raw values")
        if not env["harness"].accepts_raw_text:
            pytest.skip("harness cannot write raw text")
        self._store(env, "r-own", env["pa"], env["asha"].message())
        # A legacy job bypasses protect() and does not know her principal id: only a raw-value scan finds it.
        env["harness"].write("r-leak", f"legacy job wrote {env['asha'].email}", "legacy-system")
        out = env["dpdp"].erase(env["pa"])
        mine = [v for v in out["verification"] if v["store"] == SUT]
        assert mine and not mine[0]["ok"], "verification did not report the raw value"
        assert out["status"] == "completed_with_exceptions"

    def test_dry_run_changes_nothing(self, env):
        loc, text = self._store(env, "r-dry", env["pa"], env["asha"].message())
        env["dpdp"].erase(env["pa"], dry_run=True)
        assert env["harness"].read(loc) == text

    def test_rerun_is_safe(self, env):
        loc, _ = self._store(env, "r-twice", env["pa"], env["asha"].message())
        first = env["dpdp"].erase(env["pa"])
        second = env["dpdp"].erase(env["pa"])
        assert first["status"] in ("completed", "completed_with_exceptions")
        assert second["status"] in ("completed", "completed_with_exceptions"), second
        self._unreadable_or_gone(env, loc, env["pa"])

    def test_unsupported_action_is_reported_not_raised(self, env):
        conn = env["conn"]
        missing = [a for a in (Action.REGENERATE, Action.REDACT, Action.CRYPTO_SHRED) if a not in conn.supports]
        if not missing:
            pytest.skip("connector supports every action")
        loc, _ = self._store(env, "r-unsup", env["pa"], env["asha"].message())
        art = Artifact("art_conformance", env["harness"].kind, SUT, loc)
        from ..connectors.base import ErasureContext

        ctx = ErasureContext(env["pa"], env["dpdp"].vault.tokens_for(env["pa"]))
        res = conn.erase(art, missing[0], ctx)      # must return a result, never raise
        assert res.store == SUT
