"""Anthropic provider + platform connector with fake clients (no API key needed)."""
from types import SimpleNamespace

import pytest

from dpdp_erasure.connectors.anthropic_platform import AnthropicPlatformConnector
from dpdp_erasure.core.config import ProviderConfig
from dpdp_erasure.providers.anthropic_provider import AnthropicProvider
from dpdp_erasure.providers.base import EchoProvider, build_provider


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


def test_claude_sees_tokens_only_and_files_are_erased(kit):
    fake = SimpleNamespace(messages=FakeMessages(), beta=SimpleNamespace(files=FakeFiles()))
    kit.provider = AnthropicProvider("claude-test", client=fake, embedder=EchoProvider())
    kit.connectors["anthropic_platform"] = AnthropicPlatformConnector("anthropic_platform", client=fake)
    kit.orchestrator.connectors = kit.connectors
    pid = kit.principal("a-1")
    kit.grant_consent(pid, "support")
    with kit.context(pid, purpose="support"):
        ans = kit.generate("please refund a1@x.in", system="be brief")
        kit.track_artifact("provider_file", "anthropic_platform", {"type": "file", "file_id": "file_011"},
                           content=ans.text)
        assert ans.reveal().endswith("a1@x.in")
        assert len(kit.embed(["mail a1@x.in"])[0]) == 16
    call = fake.messages.calls[0]
    assert "a1@x.in" not in call["messages"][0]["content"] and call["system"] == "be brief"
    res = kit.erase(pid)
    assert fake.beta.files.deleted[0][0] == "file_011" and res["status"] == "completed"


def test_build_anthropic_provider_needs_embedder_for_vectors():
    p = build_provider(ProviderConfig(type="anthropic", model="m", embedding_provider="echo",
                                      options={"client": SimpleNamespace(messages=FakeMessages())}))
    assert isinstance(p, AnthropicProvider) and isinstance(p.embedder, EchoProvider)
    bare = AnthropicProvider("m", client=SimpleNamespace(messages=FakeMessages()))
    with pytest.raises(NotImplementedError):
        bare.embed(["x"])
