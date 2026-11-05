"""Anthropic Claude via the Anthropic SDK.

One provider, three platforms:
  platform=anthropic -> Claude API direct (Anthropic())
  platform=bedrock   -> Claude on Amazon Bedrock (AnthropicBedrock)
  platform=vertex    -> Claude on Google Vertex AI (AnthropicVertex)

The Messages API keeps no conversation state, so a plain call creates nothing
the kit needs to erase on the provider side. Files uploaded through the Files
API do persist until deleted; register them with ``kit.track_artifact(...,
store="anthropic_platform", locator={"type": "file", "file_id": ...})``.

Claude has no embeddings endpoint, so ``embed()`` delegates to the embedding
provider configured under ``provider.embedding_provider`` (OpenAI, Bedrock or Vertex).
"""
from __future__ import annotations

from .base import LLMProvider, ProviderResult


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, platform: str = "anthropic", region: str | None = None,
                 project: str | None = None, max_tokens: int = 1024,
                 embedder: LLMProvider | None = None, client=None, **client_kwargs):
        region, project = region or None, project or None   # YAML env defaults may be ""
        if client is None:
            import anthropic

            if platform == "bedrock":
                client = anthropic.AnthropicBedrock(aws_region=region, **client_kwargs)
            elif platform == "vertex":
                client = anthropic.AnthropicVertex(region=region, project_id=project, **client_kwargs)
            elif platform == "anthropic":
                client = anthropic.Anthropic(**client_kwargs)
            else:
                raise ValueError(f"Unknown Anthropic platform '{platform}' (anthropic | bedrock | vertex)")
        self.client, self.model, self.platform = client, model, platform
        self.max_tokens = max_tokens
        self.embedder = embedder

    def generate(self, prompt: str, system: str | None = None, **kw) -> ProviderResult:
        args = {"model": self.model, "max_tokens": kw.pop("max_tokens", self.max_tokens),
                "messages": [{"role": "user", "content": prompt}], **kw}
        if system:
            args["system"] = system
        msg = self.client.messages.create(**args)
        text = "".join(getattr(b, "text", "") for b in msg.content if getattr(b, "type", "") == "text")
        usage = msg.usage.model_dump() if getattr(msg, "usage", None) is not None and hasattr(msg.usage, "model_dump") else {}
        return ProviderResult(text=text, usage=usage)

    def embed(self, texts: list[str]) -> list[list[float]]:
        if self.embedder is None:
            raise NotImplementedError(
                "Claude has no embeddings endpoint. Set provider.embedding_provider "
                "(openai | bedrock | vertex) and provider.embedding_model in the config."
            )
        return self.embedder.embed(texts)
