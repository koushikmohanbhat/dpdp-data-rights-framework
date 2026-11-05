"""Model provider abstraction: OpenAI (direct), Amazon Bedrock, Google Vertex AI.

Providers only ever receive tokenised text. Each returns an optional
``provider_ref`` describing state the provider persisted (e.g. an OpenAI
stored response) so it can be registered as an artifact and erased later.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..vault.vault import TOKEN_RE


@dataclass
class ProviderResult:
    text: str
    provider_ref: dict[str, Any] | None = None   # persisted provider-side state, if any
    usage: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    name: str

    def generate(self, prompt: str, system: str | None = None, **kw) -> ProviderResult: ...
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class EchoProvider:
    """Offline provider for tests/demos. Produces deterministic text that keeps
    tokens intact, so lineage behaviour can be exercised without any API key."""

    name = "echo"

    def __init__(self, model: str = "echo", **_):
        self.model = model

    def generate(self, prompt: str, system: str | None = None, **kw) -> ProviderResult:
        sources = [s for s in prompt.split("\n\n---\n\n") if s.strip()]
        if len(sources) > 1:
            return ProviderResult(text=f"[echo model] Summary rebuilt from {len(sources)} remaining sources.")
        toks = TOKEN_RE.findall(prompt)
        refs = " ".join(f"<{t}_{h}>" for t, h in toks[:6])
        first = prompt.strip().splitlines()[-1][:160] if prompt.strip() else ""
        return ProviderResult(text=f"[echo model] Re: {first}" + (f" | refs: {refs}" if refs else ""))

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            h = hashlib.sha256(t.encode()).digest()
            out.append([b / 255 for b in h[:16]])
        return out


def build_provider(cfg) -> LLMProvider:
    if cfg.type == "echo":
        return EchoProvider(cfg.model)
    if cfg.type == "openai":
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(cfg.model, cfg.embedding_model, store=cfg.store, **cfg.options)
    if cfg.type == "bedrock":
        from .bedrock_provider import BedrockProvider

        return BedrockProvider(cfg.model, cfg.embedding_model, region=cfg.region, **cfg.options)
    if cfg.type == "vertex":
        from .vertex_provider import VertexProvider

        return VertexProvider(cfg.model, cfg.embedding_model, project=cfg.project, location=cfg.region, **cfg.options)
    raise ValueError(f"Unknown provider {cfg.type}")
