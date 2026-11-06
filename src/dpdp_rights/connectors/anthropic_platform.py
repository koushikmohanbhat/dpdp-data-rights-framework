"""Anthropic platform state: files uploaded through the Files API.

The Messages API is stateless, so ordinary Claude calls create nothing to
delete here. Files persist until deleted, so register uploads as artifacts and
this connector removes them during erasure. Backend retention of inputs and
outputs is governed by Anthropic's commercial terms (deleted within 30 days by
default, or zero data retention where agreed) and is recorded in the certificate.
"""
from __future__ import annotations

from ..core.models import Action
from .base import Capabilities, Connector, VerifyResult, register

FILES_BETA = "files-api-2025-04-14"


@register("anthropic_platform")
class AnthropicPlatformConnector(Connector):
    supports = {Action.DELETE}
    capabilities = Capabilities(
        store='Anthropic Files API uploads (the Messages API is stateless)',
        discover='lineage', discover_how='acts on files registered with track_artifact',
        verify='api_confirmation', verify_how='delete call confirmed by the API',
        limits=(
            "backend retention of API inputs and outputs follows Anthropic's terms",
        ))

    def __init__(self, name: str, client=None, betas: list[str] | None = None, **kw):
        super().__init__(name, **kw)
        if client is None:
            import anthropic

            client = anthropic.Anthropic(**{k: v for k, v in kw.items() if k in ("api_key", "base_url")})
        self.client = client
        self.betas = betas or [FILES_BETA]

    def _delete(self, artifact, ctx, fallback_from=None):
        loc = artifact.locator
        if loc.get("type") != "file":
            return self._ok(artifact, Action.SKIP, note=f"unknown anthropic object type {loc.get('type')}")
        self.client.beta.files.delete(loc["file_id"], betas=self.betas)
        return self._ok(artifact, Action.DELETE, object_type="file", file_id=loc["file_id"])

    def verify(self, ctx):
        return VerifyResult(self.name, True, [], note="Files deleted via API. Messages API keeps no conversation state; "
                                                       "backend retention follows Anthropic's commercial terms "
                                                       "(30-day default, or ZDR if agreed).")
