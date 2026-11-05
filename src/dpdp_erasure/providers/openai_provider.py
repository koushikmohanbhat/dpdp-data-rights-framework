"""OpenAI API (direct) via the Responses API.

Defaults to ``store=False`` so no application state is kept on the platform.
If a partner turns ``store`` on, the response id is returned as a provider_ref
and the ``openai_platform`` connector can delete it during erasure.
"""
from __future__ import annotations

from .base import ProviderResult


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str, embedding_model: str | None = None, store: bool = False,
                 client=None, **client_kwargs):
        from openai import OpenAI

        self.client = client or OpenAI(**client_kwargs)
        self.model = model
        self.embedding_model = embedding_model or "text-embedding-3-small"
        self.store = store

    def generate(self, prompt: str, system: str | None = None, **kw) -> ProviderResult:
        resp = self.client.responses.create(
            model=self.model, input=prompt, instructions=system, store=self.store, **kw
        )
        ref = {"type": "response", "response_id": resp.id} if self.store else None
        usage = resp.usage.model_dump() if getattr(resp, "usage", None) else {}
        return ProviderResult(text=resp.output_text, provider_ref=ref, usage=usage)

    def embed(self, texts: list[str]) -> list[list[float]]:
        r = self.client.embeddings.create(model=self.embedding_model, input=texts)
        return [d.embedding for d in r.data]
