"""Anthropic provider + platform connector with fake clients (no API key needed)."""
from types import SimpleNamespace

import pytest

from dpdp_rights.connectors.anthropic_platform import AnthropicPlatformConnector
from dpdp_rights.core.config import ProviderConfig
from dpdp_rights.providers.anthropic_provider import AnthropicProvider
from dpdp_rights.providers.base import EchoProvider, build_provider


class FakeMessages:
    def __init__(self):
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        tok = kw["messages"][0]["content"].split()[-1]
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=f"Refund raised for {tok}")], usage=None)


class FakeFiles:
    def __init__(self):
        self.deleted = []

    def delete(self, file_id, betas=None):
        self.deleted.append((file_id, tuple(betas or ())))


def test_claude_sees_tokens_only_and_files_are_erased(dpdp):
    fake = SimpleNamespace(messages=FakeMessages(), beta=SimpleNamespace(files=FakeFiles()))
    dpdp.provider = AnthropicProvider("claude-test", client=fake, embedder=EchoProvider())
    dpdp.connectors["anthropic_platform"] = AnthropicPlatformConnector("anthropic_platform", client=fake)
    dpdp.orchestrator.connectors = dpdp.connectors
    pid = dpdp.principal("a-1")
    dpdp.grant_consent(pid, "service")
    with dpdp.context(pid, purpose="service"):
        ans = dpdp.generate("please refund a1@x.in", system="be brief")
        dpdp.track_artifact("provider_file", "anthropic_platform", {"type": "file", "file_id": "file_011"},
                           content=ans.text)
        assert ans.reveal().endswith("a1@x.in")
        assert len(dpdp.embed(["mail a1@x.in"])[0]) == 16
    call = fake.messages.calls[0]
    assert "a1@x.in" not in call["messages"][0]["content"] and call["system"] == "be brief"
    res = dpdp.erase(pid)
    assert fake.beta.files.deleted[0][0] == "file_011" and res["status"] == "completed"


def test_build_anthropic_provider_needs_embedder_for_vectors():
    p = build_provider(ProviderConfig(type="anthropic", model="m", embedding_provider="echo",
                                      options={"client": SimpleNamespace(messages=FakeMessages())}))
    assert isinstance(p, AnthropicProvider) and isinstance(p.embedder, EchoProvider)
    bare = AnthropicProvider("m", client=SimpleNamespace(messages=FakeMessages()))
    with pytest.raises(NotImplementedError):
        bare.embed(["x"])
