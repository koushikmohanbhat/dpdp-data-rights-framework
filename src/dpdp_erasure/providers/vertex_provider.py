"""Google Vertex AI via the google-genai SDK (Gemini and Model Garden models)."""
from __future__ import annotations

from .base import ProviderResult


class VertexProvider:
    name = "vertex"

    def __init__(self, model: str, embedding_model: str | None = None, project: str | None = None,
                 location: str | None = None, client=None, **_):
        from google import genai

        self.client = client or genai.Client(vertexai=True, project=project, location=location or "asia-south1")
        self.model = model
        self.embedding_model = embedding_model or "text-embedding-005"

    def generate(self, prompt: str, system: str | None = None, **kw) -> ProviderResult:
        from google.genai import types

        cfg = types.GenerateContentConfig(system_instruction=system, **kw) if (system or kw) else None
        r = self.client.models.generate_content(model=self.model, contents=prompt, config=cfg)
        usage = r.usage_metadata.model_dump() if getattr(r, "usage_metadata", None) else {}
        return ProviderResult(text=r.text or "", usage=usage)

    def embed(self, texts: list[str]) -> list[list[float]]:
        r = self.client.models.embed_content(model=self.embedding_model, contents=texts)
        return [e.values for e in r.embeddings]
