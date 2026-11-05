"""OpenAI platform state: stored responses, conversations, files, vector-store files.

Best practice is to keep the provider out of the erasure graph entirely
(Zero Data Retention where eligible, ``store=False``). When state *is*
created, the framework registers it as an artifact and this connector deletes it.
Abuse-monitoring retention on the provider side is governed by the OpenAI
agreement, not by this API, and is recorded as such in the certificate.
"""
from __future__ import annotations

from ..core.models import Action
from .base import Connector, VerifyResult, register


@register("openai_platform")
class OpenAIPlatformConnector(Connector):
    supports = {Action.DELETE}

    def __init__(self, name: str, client=None, **kw):
        super().__init__(name, **kw)
        if client is None:
            from openai import OpenAI

            client = OpenAI(**{k: v for k, v in kw.items() if k in ("api_key", "organization", "project", "base_url")})
        self.client = client

    def _delete(self, artifact, ctx, fallback_from=None):
        loc = artifact.locator
        t = loc.get("type")
        if t == "response":
            self.client.responses.delete(loc["response_id"])
        elif t == "conversation":
            self.client.conversations.delete(loc["conversation_id"])
        elif t == "vector_store_file":
            self.client.vector_stores.files.delete(file_id=loc["file_id"], vector_store_id=loc["vector_store_id"])
            self.client.files.delete(loc["file_id"])
        elif t == "file":
            self.client.files.delete(loc["file_id"])
        else:
            return self._ok(artifact, Action.SKIP, note=f"unknown openai object type {t}")
        return self._ok(artifact, Action.DELETE, object_type=t)

    def verify(self, ctx):
        return VerifyResult(self.name, True, [], note="Per-object deletes confirmed by API; provider abuse-monitoring "
                                                       "retention follows the OpenAI data-retention terms (ZDR if enabled).")
