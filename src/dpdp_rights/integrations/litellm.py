"""LiteLLM proxy guardrail: the DPDP gateway in front of every model LiteLLM serves (docs/gateway.md).

    # litellm config.yaml
    guardrails:
      - guardrail_name: dpdp
        litellm_params:
          guardrail: dpdp_rights.integrations.litellm.DPDPGuardrail
          mode: [pre_call, post_call]
          default_on: true
          dpdp_config: /etc/dpdp/config.yaml      # or set DPDP_CONFIG

In enforce mode the person comes from ``gateway.principal_binding``: a signed ``X-DPDP-Assertion`` minted by the
app's backend (``signed``), or ``dpdp_principal`` in the virtual key's metadata (``key``), which only the proxy
admin can set. Request headers, request metadata and the ``user`` field are the caller's claims: they must agree
with the binding or the call is refused. ``dpdp_purpose`` in a key's metadata ties an app to its purpose.

LiteLLM is not a dependency of this package; install it in the proxy's image alongside ``dpdp-data-rights-framework``.
"""
from __future__ import annotations

import os
from collections import OrderedDict
from typing import Any

try:  # pragma: no cover - exercised against a real LiteLLM install
    from litellm.integrations.custom_guardrail import CustomGuardrail as _Base
except ImportError:  # the class still imports (and is testable) without LiteLLM
    class _Base:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            pass

from ..gateway import CallState, GatewayRefused

CALL_TYPES = {"completion": "chat", "acompletion": "chat", "responses": "responses", "aresponses": "responses",
              "embeddings": "embeddings", "aembedding": "embeddings", "embedding": "embeddings"}
_STATE_KEY = "dpdp_call"


def _refuse(status: int, message: str, code: str):
    try:
        from fastapi import HTTPException

        return HTTPException(status_code=status, detail={"error": message, "type": "dpdp_refused", "code": code})
    except ImportError:  # pragma: no cover
        return PermissionError(message)


class DPDPGuardrail(_Base):
    def __init__(self, dpdp=None, dpdp_config: str | None = None, **kwargs):
        super().__init__(**kwargs)
        if dpdp is None:
            from .. import DataRightsFramework
            from ..core.config import FrameworkConfig

            path = dpdp_config or os.environ.get("DPDP_CONFIG")
            if not path:
                raise ValueError("DPDPGuardrail needs dpdp_config (litellm_params) or the DPDP_CONFIG variable")
            dpdp = DataRightsFramework(FrameworkConfig.load(path))
        self.dpdp = dpdp
        self._states: OrderedDict[str, CallState] = OrderedDict()

    @staticmethod
    def _meta(data: dict) -> dict:
        for k in ("metadata", "litellm_metadata"):
            if isinstance(data.get(k), dict):
                return data[k]
        data["metadata"] = {}
        return data["metadata"]

    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type) -> dict:
        route = CALL_TYPES.get(str(call_type))
        if route is None:
            return data
        headers = ((data.get("proxy_server_request") or {}).get("headers")) or {}
        key_meta = dict(getattr(user_api_key_dict, "metadata", None) or {})
        # The virtual key's metadata is set by the proxy admin: trusted. Request metadata comes from the caller.
        trusted = {"key_principal": key_meta.get("dpdp_principal"), "key_purpose": key_meta.get("dpdp_purpose")}
        meta = self._meta(data)
        request_meta = {k: v for k, v in meta.items() if k.startswith("dpdp_")}
        body = {k: v for k, v in data.items() if k in ("model", "messages", "input", "instructions", "user",
                                                          "store", "safety_identifier")}
        try:
            out, st = self.dpdp.gateway.inbound(route, body, headers, request_meta, trusted=trusted)
        except GatewayRefused as e:
            raise _refuse(e.status, str(e), e.decision) from e
        for k in ("messages", "input", "instructions", "store"):
            if k in out:
                data[k] = out[k]
        if st.principal_id:
            key = os.urandom(8).hex()
            meta[_STATE_KEY] = key
            self._states[key] = st
            while len(self._states) > 10_000:
                self._states.popitem(last=False)
        return data

    async def async_post_call_success_hook(self, data: dict, user_api_key_dict, response: Any) -> Any:
        key = self._meta(data).get(_STATE_KEY)
        st = self._states.pop(key, None) if key else None
        if st is None:
            return response
        return self.dpdp.gateway.outbound(st, response)
